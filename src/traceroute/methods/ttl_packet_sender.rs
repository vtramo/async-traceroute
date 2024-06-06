use std::collections::HashSet;
use std::io;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Instant;

use libpacket::ip::IpNextHeaderProtocols::{Tcp, Udp};
use libpacket::ipv4::Ipv4;
use libpacket::ipv6::Ipv6;
use rand::prelude::ThreadRng;
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::traceroute::{IpDatagram, TracerouteHopResult, TracerouteProbeResponse};
use crate::traceroute::utils::bytes::ToBytes;
use crate::traceroute::utils::packet_utils;

pub struct TracerouteCompletableHop {
    id: String,
    sent_at: Instant,
    query_ids: HashSet<u16>
}

impl TracerouteCompletableHop {
    pub fn new(id: &str, query_ids: HashSet<u16>) -> Self {
        let tot_source_ports = query_ids.len();
        if tot_source_ports == 0 {
            panic!()
        }

        Self {
            id: id.to_string(),
            sent_at: Instant::now(),
            query_ids
        }
    }

    pub fn complete_query(&mut self, hop_response: TracerouteProbeResponse) -> Option<TracerouteHopResult> {
        if hop_response.id != self.id {
            return None;
        }

        // let hop_response_query_id = hop_response.query_id;
        // if !self.query_ids.contains(&hop_response_query_id) {
        //     return None;
        // }
        // 
        // self.query_ids.remove(&hop_response_query_id);
        Some(TracerouteHopResult {
            id: hop_response.id,
            address: hop_response.address,
            rtt: self.sent_at.elapsed()
        })
    }
}

pub trait TracerouteTtlPacketSender: Send {
    fn send(
        &mut self,
        ttl: u8,
    ) -> io::Result<TracerouteCompletableHop>;
}

pub struct UdpTracerouteTtlPacketSender {
    socket: Socket,
    destination_address: IpAddr,
    destination_port: u16,
    queries_per_hop: u16,
}

impl UdpTracerouteTtlPacketSender {
    pub fn new(
        destination_address: IpAddr,
        initial_destination_port: u16,
        queries_per_hop: u16,
    ) -> Self {
        Self {
            socket: Self::build_socket(
                if destination_address.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                }
            ),
            destination_address,
            destination_port: initial_destination_port,
            queries_per_hop
        }
    }

    fn build_socket(domain: Domain) -> Socket {
        let socket = Socket::new(domain, Type::RAW, Some(Protocol::UDP)).unwrap(); // todo:
        socket.set_header_included(true).unwrap(); // todo
        socket
    }

    pub fn build_empty_ip_datagram_with_ttl(&self, ttl: u8) -> IpDatagram {
        match self.destination_address {
            IpAddr::V4(ipv4_address) => {
                IpDatagram::V4(Self::build_empty_ipv4_datagram_with_ttl(ttl, ipv4_address))
            },
            IpAddr::V6(ipv6_address) => {
                IpDatagram::V6(Self::build_empty_ipv6_datagram_with_ttl(ttl, ipv6_address))
            }
        }
    }

    fn build_empty_ipv4_datagram_with_ttl(ttl: u8, destination_address: Ipv4Addr) -> Ipv4 {
        Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 28,
            identification: ttl as u16,
            flags: 0,
            fragment_offset: 0,
            ttl,
            next_level_protocol: Udp,
            checksum: 0,
            source: Ipv4Addr::UNSPECIFIED,
            destination: destination_address,
            options: vec![],
            payload: vec![]
        }
    }

    fn build_empty_ipv6_datagram_with_ttl(ttl: u8, destination_address: Ipv6Addr) -> Ipv6 {
        todo!()
    }

    fn generate_source_ports(&self) -> HashSet<u16> {
        let mut random_unique_port_gen = RandomUniquePort::new();
        random_unique_port_gen.generate_ports(self.queries_per_hop)
    }

    fn build_destination_sock_address(&self) -> SockAddr {
        let destination_address_str = self.destination_address.to_string();
        let destination_port = &self.destination_port;
        SocketAddr::from_str(&format!("{destination_address_str}:{destination_port}")).unwrap().into()
    }
}

impl TracerouteTtlPacketSender for UdpTracerouteTtlPacketSender {
    fn send(
        &mut self,
        ttl: u8,
    ) -> Result<TracerouteCompletableHop, Error> {
        let mut ip_datagram = self.build_empty_ip_datagram_with_ttl(ttl);
        let source_ports = self.generate_source_ports();
        let traceroute_hop = TracerouteCompletableHop::new(&ttl.to_string(), source_ports.clone());

        for source_port in source_ports {
            let udp_datagram = packet_utils::build_udp_datagram_with_ports(source_port, self.destination_port);
            let udp_datagram_bytes = udp_datagram.to_bytes();
            ip_datagram.set_payload(&udp_datagram_bytes);
            ip_datagram.set_length(IpDatagram::STANDARD_HEADER_LENGTH + udp_datagram_bytes.len() as u16);

            let socket_addr: SockAddr = self.build_destination_sock_address();
            self.socket.send_to(&ip_datagram.to_bytes(), &socket_addr)?;
            self.destination_port += 1;
        }

        Ok(traceroute_hop)
    }
}

pub struct TcpTracerouteTtlPacketSender {
    socket: Socket,
    destination_address: IpAddr,
    destination_port: u16,
    queries_per_hop: u16,
}

impl TcpTracerouteTtlPacketSender {
    pub fn new(
        destination_address: IpAddr,
        destination_port: u16,
        queries_per_hop: u16,
    ) -> Self {
        Self {
            socket: Self::build_socket(
                if destination_address.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                }
            ),
            destination_address,
            destination_port,
            queries_per_hop
        }
    }

    fn build_socket(domain: Domain) -> Socket {
        let socket = Socket::new(domain, Type::RAW, Some(Protocol::TCP)).unwrap(); // todo:
        socket.set_header_included(true).unwrap(); // todo
        socket
    }

    pub fn build_empty_ip_datagram_with_ttl(&self, ttl: u8) -> IpDatagram {
        match self.destination_address {
            IpAddr::V4(ipv4_address) => {
                IpDatagram::V4(Self::build_empty_ipv4_datagram_with_ttl(ttl, ipv4_address))
            },
            IpAddr::V6(ipv6_address) => {
                IpDatagram::V6(Self::build_empty_ipv6_datagram_with_ttl(ttl, ipv6_address))
            }
        }
    }

    fn build_empty_ipv4_datagram_with_ttl(ttl: u8, destination_address: Ipv4Addr) -> Ipv4 {
        Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 28,
            identification: ttl as u16,
            flags: 0,
            fragment_offset: 0,
            ttl,
            next_level_protocol: Tcp,
            checksum: 0,
            source: Ipv4Addr::UNSPECIFIED,
            destination: destination_address,
            options: vec![],
            payload: vec![]
        }
    }

    fn build_empty_ipv6_datagram_with_ttl(ttl: u8, destination_address: Ipv6Addr) -> Ipv6 {
        todo!()
    }

    fn generate_source_ports(&self) -> HashSet<u16> {
        let mut random_unique_port_gen = RandomUniquePort::new();
        random_unique_port_gen.generate_ports(self.queries_per_hop)
    }

    fn build_destination_sock_address(&self) -> SockAddr {
        let destination_address_str = self.destination_address.to_string();
        let destination_port = &self.destination_port;
        SocketAddr::from_str(&format!("{destination_address_str}:{destination_port}")).unwrap().into()
    }
}

impl TracerouteTtlPacketSender for TcpTracerouteTtlPacketSender {
    fn send(
        &mut self, 
        ttl: u8
    ) -> Result<TracerouteCompletableHop, Error> {
        todo!()
    }
}

pub struct RandomUniquePort {
    generated_ports: HashSet<u16>,
    rng: ThreadRng
}

impl RandomUniquePort {
    pub fn new() -> Self {
        Self {
            generated_ports: HashSet::with_capacity(10),
            rng: rand::thread_rng()
        }
    }

    pub fn generate_ports(&mut self, tot_ports: u16) -> HashSet<u16> {
        let mut generated_ports = HashSet::with_capacity(tot_ports as usize);

        for _ in 0..tot_ports {
            let generated_port = self.generate_port();
            generated_ports.insert(generated_port);
        }

        generated_ports
    }

    pub fn generate_port(&mut self) -> u16 {
        let mut generated_port: u16 = 0;

        let mut not_found = true;
        while not_found {
            generated_port = self.rng.gen_range(0..=65535);
            not_found = self.generated_ports.contains(&generated_port);
        }

        self.generated_ports.insert(generated_port);
        generated_port
    }
}

pub struct IcmpTracerouteTtlPacketSender;
impl TracerouteTtlPacketSender for IcmpTracerouteTtlPacketSender {
    fn send(&mut self, ttl: u8) -> io::Result<TracerouteCompletableHop> {
        todo!()
    }
}