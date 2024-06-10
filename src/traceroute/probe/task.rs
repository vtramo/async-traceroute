use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use async_trait::async_trait;
use mio::net::UdpSocket;
use pnet::packet::ip::IpNextHeaderProtocols::{Icmp, Tcp, Udp};
use pnet::packet::ipv4::Ipv4;
use pnet::packet::ipv6::Ipv6;
use pnet::packet::tcp::Tcp;
use rand::{Rng, thread_rng};
use socket2::{Domain, Protocol, Type};
use tokio::select;
use tokio::time::sleep;

use crate::traceroute::probe::{CompletableProbe, ProbeId, ProbeResponse, ProbeResult};
use crate::traceroute::tokio_socket::AsyncTokioSocket;
use crate::traceroute::utils::bytes::ToBytes;
use crate::traceroute::utils::packet_utils;
use crate::traceroute::utils::packet_utils::{build_icmpv4_echo_request, get_default_ipv4_addr_interface, get_default_ipv6_addr_interface, icmpv4_checksum, internet_checksum, IpDatagram};

pub type ProbeResponseReceiver = tokio::sync::oneshot::Receiver<ProbeResponse>;

#[async_trait]
pub trait ProbeTask: Send {
    async fn send_probe(
        &mut self,
        ttl: u8,
        timeout_ms: u64,
    ) -> Result<ProbeResult, String>;

    fn get_probe_id(&self) -> ProbeId;
}

pub struct UdpProbeTask {
    id: ProbeId,
    socket: AsyncTokioSocket,
    destination_address: IpAddr,
    destination_port: u16,
    probe_response_receiver: Option<ProbeResponseReceiver>,
    ip_id_offset: u16,
}

#[async_trait]
impl ProbeTask for UdpProbeTask {
    async fn send_probe(
        &mut self,
        ttl: u8,
        timeout_ms: u64,
    ) -> Result<ProbeResult, String> {
        let mut completable_hop = self.send_udp_probe(ttl).await.unwrap(); // todo()

        let timer = sleep(Duration::from_millis(timeout_ms));

        let probe_response_receiver = match self.probe_response_receiver.take() {
            None => return Err("This task has already been started!".to_string()),
            Some(probe_response_receiver) => probe_response_receiver
        };
        
        let probe_result =
            select! {
                _ = timer => {
                    eprintln!("timeout");
                    Err("timeout")
                },
                Ok(probe_response) = probe_response_receiver => {
                    if let Some(probe_result) = completable_hop.complete(probe_response) {
                        Ok(probe_result)
                    } else {
                        eprintln!("Bad Probe Result");
                        Err("Bad Probe Result")
                    }
                },
            }?;

        Ok(probe_result)
    }

    fn get_probe_id(&self) -> ProbeId {
        self.id.clone()
    }
}

impl UdpProbeTask {
    pub fn new(
        destination_address: IpAddr,
        destination_port: u16,
        probe_response_receiver: ProbeResponseReceiver,
    ) -> io::Result<Self> {
        Ok(Self {
            id: destination_port.to_string(),
            socket: Self::build_socket(
                if destination_address.is_ipv4() { 
                    Domain::IPV4 
                } else { 
                    Domain::IPV6 
                }
            )?,
            destination_address,
            destination_port,
            probe_response_receiver: Some(probe_response_receiver),
            ip_id_offset: thread_rng().gen_range(0..32232)
        })
    }

    fn build_socket(domain: Domain) -> io::Result<AsyncTokioSocket> {
        let socket = AsyncTokioSocket::new(domain, Type::RAW, Some(Protocol::UDP))?;
        socket.set_header_included(true)?;
        Ok(socket)
    }

    async fn send_udp_probe(&self, ttl: u8) -> io::Result<CompletableProbe> {
        let completable_probe = CompletableProbe::new(&self.get_probe_id());

        let source_port = self.get_unused_source_port()?;
        let udp_datagram = packet_utils::build_udp_datagram_with_ports(source_port, self.destination_port);
        let udp_datagram_bytes = udp_datagram.to_bytes();

        let mut ip_datagram = self.build_empty_ip_datagram(ttl);
        ip_datagram.set_payload(&udp_datagram_bytes);
        ip_datagram.set_length(IpDatagram::STANDARD_HEADER_LENGTH + udp_datagram_bytes.len() as u16);

        let socket_addr = SocketAddr::new(self.destination_address, self.destination_port);
        self.socket.send_to(&ip_datagram.to_bytes(), socket_addr).await?;

        Ok(completable_probe)
    }

    fn get_unused_source_port(&self) -> io::Result<u16> {
        let udp_socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        let local_addr = udp_socket.local_addr()?;
        Ok(local_addr.port())
    }

    fn build_empty_ip_datagram(&self, ttl: u8) -> IpDatagram {
        match self.destination_address {
            IpAddr::V4(ipv4_address) => {
                IpDatagram::V4(self.build_empty_ipv4_datagram(ttl, ipv4_address))
            },
            IpAddr::V6(ipv6_address) => {
                IpDatagram::V6(Self::build_empty_ipv6_datagram(ttl, ipv6_address))
            }
        }
    }

    fn build_empty_ipv4_datagram(&self, ttl: u8, destination_address: Ipv4Addr) -> Ipv4 {
        Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 28,
            identification: self.ip_id_offset + ttl as u16,
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

    fn build_empty_ipv6_datagram(_ttl: u8, _destination_address: Ipv6Addr) -> Ipv6 {
        todo!()
    }
}

pub struct TcpProbeTask {
    id: ProbeId,
    ip_id: u16,
    socket: AsyncTokioSocket,
    destination_address: IpAddr,
    destination_port: u16,
    probe_response_receiver: Option<ProbeResponseReceiver>,
}

#[async_trait]
impl ProbeTask for TcpProbeTask {
    async fn send_probe(
        &mut self,
        ttl: u8, 
        timeout_ms: u64
    ) -> Result<ProbeResult, String> {
        let mut completable_hop = self.send_tcp_probe(ttl).await.unwrap(); // todo()

        let timer = sleep(Duration::from_millis(timeout_ms));

        let probe_response_receiver = match self.probe_response_receiver.take() {
            None => return Err("This task has already been started!".to_string()),
            Some(probe_response_receiver) => probe_response_receiver
        };
        
        let probe_result =
            select! {
                _ = timer => {
                    eprintln!("timeout"); // todo(): errori
                    Err("timeout")
                },
                Ok(probe_response) = probe_response_receiver => {
                    if let Some(probe_result) = completable_hop.complete(probe_response) {
                        Ok(probe_result)
                    } else {
                        eprintln!("Bad Probe Result");
                        Err("Bad Probe Result")
                    }
                },
                (ipv4_datagram, _) = Self::wait_syn_ack(&self.socket) => {
                    let from_address = ipv4_datagram.source;
                    
                    let probe_response = ProbeResponse { 
                        id: self.id.clone(),
                        from_address,
                    };
                    
                    let probe_result = completable_hop
                        .complete(probe_response)
                        .expect("");
                    
                    println!("TCP SYN ACK!! {:?}", probe_result);
                    
                    Ok(probe_result)
                },
            }?;

        Ok(probe_result)
    }

    fn get_probe_id(&self) -> ProbeId {
        self.id.clone()
    }
}

impl TcpProbeTask {
    pub fn new(
        ip_id: u16,
        destination_address: IpAddr,
        destination_port: u16,
        probe_response_receiver: ProbeResponseReceiver,
    ) -> io::Result<Self> {
        Ok(Self {
            id: ip_id.to_string(),
            ip_id,
            socket: Self::build_socket(
                if destination_address.is_ipv4() { 
                    Domain::IPV4 
                } else { 
                    Domain::IPV6 
                } 
            )?,
            destination_address,
            destination_port,
            probe_response_receiver: Some(probe_response_receiver),
        })
    }

    fn build_socket(domain: Domain) -> io::Result<AsyncTokioSocket> {
        let socket = AsyncTokioSocket::new(domain, Type::RAW, Some(Protocol::TCP))?;
        socket.set_header_included(true)?;
        Ok(socket)
    }

    async fn send_tcp_probe(&self, ttl: u8) -> io::Result<CompletableProbe> {
        let completable_probe = CompletableProbe::new(&self.get_probe_id());

        let source_port = Self::generate_source_port();
        let isn = Self::generate_isn();
        let mut tcp_syn_segment = packet_utils::build_tcp_syn_segment(source_port, self.destination_port, isn);
        let mut ip_datagram = self.build_empty_ip_datagram(ttl, self.ip_id);
        let checksum = internet_checksum(&tcp_syn_segment, &ip_datagram);
        tcp_syn_segment.checksum = checksum;
        
        let tcp_syn_segment_bytes = tcp_syn_segment.to_bytes();
        ip_datagram.set_payload(&tcp_syn_segment_bytes);
        ip_datagram.set_length(IpDatagram::STANDARD_HEADER_LENGTH + tcp_syn_segment_bytes.len() as u16);
        
        let socket_addr = SocketAddr::new(self.destination_address, self.destination_port);
        self.socket.send_to(&ip_datagram.to_bytes(), socket_addr).await?;

        Ok(completable_probe)
    }

    fn generate_source_port() -> u16 {
        let mut rng = thread_rng();
        rng.gen_range(1024..=65535)
    }

    fn generate_isn() -> u32 {
        let mut rng = thread_rng();
        rng.gen_range(114942611..=1070088077)
    }

    fn build_empty_ip_datagram(&self, ttl: u8, ip_id: u16) -> IpDatagram {
        match self.destination_address {
            IpAddr::V4(destination_ipv4) => {
                let source_address = get_default_ipv4_addr_interface();
                IpDatagram::V4(Self::build_empty_ipv4_datagram(ttl, source_address, destination_ipv4, ip_id))
            },
            IpAddr::V6(destination_ipv6) => {
                let source_ipv4 = get_default_ipv6_addr_interface();
                IpDatagram::V6(Self::build_empty_ipv6_datagram(ttl, source_ipv4, destination_ipv6))
            },
        }
    }

    fn build_empty_ipv4_datagram(
        ttl: u8, 
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr, 
        ip_id: u16
    ) -> Ipv4 {
        Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 60,
            identification: ip_id,
            flags: 0,
            fragment_offset: 0,
            ttl,
            next_level_protocol: Tcp,
            checksum: 0,
            source: source_address,
            destination: destination_address,
            options: vec![],
            payload: vec![]
        }
    }

    fn build_empty_ipv6_datagram(_ttl: u8, _source_address: Ipv6Addr, _destination_address: Ipv6Addr) -> Ipv6 {
        todo!()
    }
    
    async fn wait_syn_ack(socket: &AsyncTokioSocket) -> (Ipv4, Tcp){
        let mut buffer = [0u8; 1024];
        loop {
            match socket.recv(&mut buffer).await {
                Err(_) | Ok(0) => sleep(Duration::MAX).await,
                Ok(_) => {
                    let ipv4_datagram = match packet_utils::build_ipv4_datagram_from_bytes(&buffer) {
                        Some(ipv4_datagram) => ipv4_datagram,
                        None => continue,
                    };
                    
                    let tcp_segment = match packet_utils::build_tcp_segment_from_bytes(&ipv4_datagram.payload) {
                        Some(tcp_segment) => tcp_segment,
                        None => continue,
                    };
 
                    if packet_utils::is_tcp_syn_ack_segment(&tcp_segment) {
                        break (ipv4_datagram, tcp_segment);
                    }
                }
            }
        }
    }
}

pub struct IcmpProbeTask {
    id: ProbeId,
    icmp_id: u16,
    icmp_sqn: u16,
    socket: AsyncTokioSocket,
    destination_address: IpAddr,
    probe_response_receiver: Option<ProbeResponseReceiver>,
}

#[async_trait]
impl ProbeTask for IcmpProbeTask {
    async fn send_probe(
        &mut self, 
        ttl: u8, 
        timeout_ms: u64
    ) -> Result<ProbeResult, String> {
        let mut completable_hop = self.send_ping(ttl).await.unwrap(); // todo()

        let timer = sleep(Duration::from_millis(timeout_ms));

        let probe_response_receiver = match self.probe_response_receiver.take() {
            None => return Err("This task has already been started!".to_string()),
            Some(probe_response_receiver) => probe_response_receiver
        };
        
        let probe_result =
            select! {
                _ = timer => {
                    eprintln!("timeout");
                    Err("timeout")
                },
                Ok(probe_response) = probe_response_receiver => {
                    if let Some(probe_result) = completable_hop.complete(probe_response) {
                        Ok(probe_result)
                    } else {
                        eprintln!("Bad Probe Result");
                        Err("Bad Probe Result")
                    }
                },
            }?;
        
        Ok(probe_result)
    }

    fn get_probe_id(&self) -> ProbeId {
        self.id.clone()
    }
}

impl IcmpProbeTask {
    pub fn new(
        icmp_id: u16,
        icmp_sqn: u16,
        destination_address: IpAddr,
        probe_response_receiver: ProbeResponseReceiver,
    ) -> io::Result<Self> {
        Ok(Self {
            id: format!("{icmp_id}{icmp_sqn}"),
            icmp_id,
            icmp_sqn,
            socket: Self::build_socket(
                if destination_address.is_ipv4() {
                    Domain::IPV4
                } else { 
                    Domain::IPV6
                }
            )?,
            destination_address,
            probe_response_receiver: Some(probe_response_receiver),
        })
    }

    fn build_socket(domain: Domain) -> io::Result<AsyncTokioSocket> {
        let icmp_protocol = match domain { 
            Domain::IPV6 => Protocol::ICMPV6,
            _ => Protocol::ICMPV4,
        };
        let socket = AsyncTokioSocket::new(domain, Type::RAW, Some(icmp_protocol))?;
        socket.set_header_included(true)?;
        Ok(socket)
    }
    
    async fn send_ping(&self, ttl: u8) -> io::Result<CompletableProbe> {
        let completable_probe = CompletableProbe::new(&self.get_probe_id());
        
        let mut echo_request = build_icmpv4_echo_request(self.icmp_id, self.icmp_sqn);
        echo_request.checksum = icmpv4_checksum(&echo_request);
        let echo_request_bytes = echo_request.to_bytes();
        
        let mut ip_datagram = self.build_empty_ip_datagram(ttl);
        ip_datagram.set_length(IpDatagram::STANDARD_HEADER_LENGTH + echo_request_bytes.len() as u16);
        ip_datagram.set_payload(&echo_request_bytes);

        let socket_addr = SocketAddr::new(self.destination_address, 0);
        self.socket.send_to(&ip_datagram.to_bytes(), socket_addr).await?;
        
        Ok(completable_probe)
    }
    
    fn build_empty_ip_datagram(&self, ttl: u8) -> IpDatagram {
        match self.destination_address {
            IpAddr::V4(ipv4_address) => {
                IpDatagram::V4(self.build_empty_ipv4_datagram(ttl, ipv4_address))
            },
            IpAddr::V6(ipv6_address) => {
                IpDatagram::V6(Self::build_empty_ipv6_datagram(ttl, ipv6_address))
            }
        }
    }

    fn build_empty_ipv4_datagram(&self, ttl: u8, destination_address: Ipv4Addr) -> Ipv4 {
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
            next_level_protocol: Icmp,
            checksum: 0,
            source: Ipv4Addr::UNSPECIFIED,
            destination: destination_address,
            options: vec![],
            payload: vec![]
        }
    }

    fn build_empty_ipv6_datagram(_ttl: u8, _destination_address: Ipv6Addr) -> Ipv6 {
        todo!()
    }
}