use std::collections::HashSet;
use std::io;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use async_trait::async_trait;
use pnet::packet::ip::IpNextHeaderProtocols::Tcp;
use pnet::packet::ipv4::Ipv4;
use pnet::packet::ipv6::Ipv6;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::traceroute::IpDatagram;
use crate::traceroute::probe::task::CompletableProbe;
use crate::traceroute::utils::RandomUniquePort;

#[async_trait]
pub trait ProbeSender: Send {
    async fn send(
        &mut self,
        ttl: u8,
    ) -> io::Result<CompletableProbe>;
}

pub struct TcpProbeSender {
    socket: Socket,
    destination_address: IpAddr,
    destination_port: u16,
    queries_per_hop: u16,
}

impl TcpProbeSender {
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

#[async_trait]
impl ProbeSender for TcpProbeSender {
    async fn send(
        &mut self, 
        ttl: u8
    ) -> Result<CompletableProbe, Error> {
        todo!()
    }
}

pub struct IcmpProbeSender;

#[async_trait]
impl ProbeSender for IcmpProbeSender {
    async fn send(&mut self, ttl: u8) -> io::Result<CompletableProbe> {
        todo!()
    }
}