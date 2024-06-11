use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use pnet::packet::ip::IpNextHeaderProtocols::{Icmp, Tcp};
use pnet::packet::ipv4::Ipv4;
use pnet::packet::ipv6::Ipv6;
use pnet::packet::tcp::Tcp;
use rand::{Rng, thread_rng};
use socket2::{Domain, Protocol, Type};
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

use crate::traceroute::async_socket::AsyncSocket;
use crate::traceroute::probe::{CompletableProbe, ProbeError, ProbeId, ProbeResponse, ProbeResult};
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
    ) -> Result<ProbeResult, ProbeError>;

    fn get_probe_id(&self) -> ProbeId;
}

pub struct UdpProbeTask {
    id: ProbeId,
    socket: AsyncSocket,
    destination_address: IpAddr,
    destination_port: u16,
    probe_response_receiver: Option<ProbeResponseReceiver>,
}

#[async_trait]
impl ProbeTask for UdpProbeTask {
    async fn send_probe(
        &mut self,
        ttl: u8,
        timeout_ms: u64,
    ) -> Result<ProbeResult, ProbeError> {
        let mut completable_hop = match self.send_udp_probe(ttl).await {
            Ok(completable_hop) => completable_hop,
            Err(io_error) => return Err(ProbeError::IoError { ttl, io_error: Some(io_error) })
        };

        let timer = sleep(Duration::from_millis(timeout_ms));

        let probe_response_receiver = match self.probe_response_receiver.take() {
            None => return Err(ProbeError::IoError { ttl, io_error: None }),
            Some(probe_response_receiver) => probe_response_receiver
        };
        
        let probe_result =
            select! {
                _ = timer => Err(ProbeError::Timeout { ttl }),
                Ok(probe_response) = probe_response_receiver => {
                    if let Some(probe_result) = completable_hop.complete(probe_response) {
                        Ok(probe_result)
                    } else {
                        Err(ProbeError::IoError { ttl, io_error: None })
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
        })
    }

    fn build_socket(domain: Domain) -> io::Result<AsyncSocket> {
        let socket = AsyncSocket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        Ok(socket)
    }

    async fn send_udp_probe(&self, ttl: u8) -> io::Result<CompletableProbe> {
        let completable_probe = CompletableProbe::new(&self.get_probe_id(), ttl);

        self.socket.set_ttl(ttl as u32)?;
        let socket_addr = SocketAddr::new(self.destination_address, self.destination_port);
        self.socket.send_to(&[], socket_addr).await?;

        Ok(completable_probe)
    }
}

pub struct TcpProbeTask {
    id: ProbeId,
    ip_id: u16,
    isn: u32,
    socket: AsyncSocket,
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
    ) -> Result<ProbeResult, ProbeError> {
        let mut completable_hop = match self.send_tcp_probe(ttl).await {
            Ok(completable_hop) => completable_hop,
            Err(io_error) => return Err(ProbeError::IoError { ttl, io_error: Some(io_error) })
        };

        let timer = sleep(Duration::from_millis(timeout_ms));

        let probe_response_receiver = match self.probe_response_receiver.take() {
            None => return Err(ProbeError::IoError { ttl, io_error: None }),
            Some(probe_response_receiver) => probe_response_receiver
        };
        
        let probe_result =
            select! {
                _ = timer => {
                    Err(ProbeError::Timeout { ttl })
                },
                Ok(probe_response) = probe_response_receiver => {
                    if let Some(probe_result) = completable_hop.complete(probe_response) {
                        Ok(probe_result)
                    } else {
                        Err(ProbeError::IoError { ttl, io_error: None })
                    }
                },
                Ok((ipv4_datagram, _)) = self.wait_syn_ack() => {
                    let from_address = ipv4_datagram.source;
                    
                    let probe_response = ProbeResponse { 
                        id: self.id.clone(),
                        from_address,
                    };

                    let probe_result = match completable_hop.complete(probe_response) {
                        None => return Err(ProbeError::IoError { ttl, io_error: None }),
                        Some(probe_result) => probe_result
                    };

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
            isn: Self::generate_isn(),
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

    fn build_socket(domain: Domain) -> io::Result<AsyncSocket> {
        let socket = AsyncSocket::new(domain, Type::RAW, Some(Protocol::TCP))?;
        socket.set_header_included(true)?;
        Ok(socket)
    }

    async fn send_tcp_probe(&self, ttl: u8) -> io::Result<CompletableProbe> {
        let completable_probe = CompletableProbe::new(&self.get_probe_id(), ttl);

        let source_port = Self::generate_source_port();
        let mut tcp_syn_segment = packet_utils::build_tcp_syn_segment(source_port, self.destination_port, self.isn);
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
    
    async fn wait_syn_ack(&self) -> io::Result<(Ipv4, Tcp)> {
        let mut buffer = [0u8; 1024];
        loop {
            self.socket.recv(&mut buffer).await?;

            let ipv4_datagram = match packet_utils::build_ipv4_datagram_from_bytes(&buffer) {
                Some(ipv4_datagram) => ipv4_datagram,
                None => continue,
            };

            let tcp_segment = match packet_utils::build_tcp_segment_from_bytes(&ipv4_datagram.payload) {
                Some(tcp_segment) => tcp_segment,
                None => continue,
            };

            if tcp_segment.acknowledgement != self.isn + 1 {
                continue;
            }

            if packet_utils::is_tcp_syn_ack_segment(&tcp_segment) {
                break Ok((ipv4_datagram, tcp_segment));
            }
        }
    }
}

pub struct IcmpProbeTask {
    id: ProbeId,
    icmp_id: u16,
    icmp_sqn: u16,
    tx_to_icmp_raw_socket: Sender<(Vec<u8>, SocketAddr)>,
    destination_address: IpAddr,
    probe_response_receiver: Option<ProbeResponseReceiver>,
}

#[async_trait]
impl ProbeTask for IcmpProbeTask {
    async fn send_probe(
        &mut self, 
        ttl: u8, 
        timeout_ms: u64
    ) -> Result<ProbeResult, ProbeError> {
        let mut completable_hop =  self.send_ping(ttl).await?;

        let timer = sleep(Duration::from_millis(timeout_ms));

        let probe_response_receiver = match self.probe_response_receiver.take() {
            None => return Err(ProbeError::IoError { ttl, io_error: None }),
            Some(probe_response_receiver) => probe_response_receiver
        };
        
        let probe_result =
            select! {
                _ = timer => {
                    Err(ProbeError::Timeout { ttl })
                },
                Ok(probe_response) = probe_response_receiver => {
                    if let Some(probe_result) = completable_hop.complete(probe_response) {
                        Ok(probe_result)
                    } else {
                        Err(ProbeError::IoError { ttl, io_error: None })
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
        tx_to_icmp_raw_socket: Sender<(Vec<u8>, SocketAddr)>,
    ) -> Self {
        Self {
            id: format!("{icmp_id}{icmp_sqn}"),
            icmp_id,
            icmp_sqn,
            tx_to_icmp_raw_socket,
            destination_address,
            probe_response_receiver: Some(probe_response_receiver),
        }
    }
    
    async fn send_ping(&self, ttl: u8) -> Result<CompletableProbe, ProbeError> {
        let completable_probe = CompletableProbe::new(&self.get_probe_id(), ttl);
        
        let mut echo_request = build_icmpv4_echo_request(self.icmp_id, self.icmp_sqn);
        echo_request.checksum = icmpv4_checksum(&echo_request);
        let echo_request_bytes = echo_request.to_bytes();
        
        let mut ip_datagram = self.build_empty_ip_datagram(ttl);
        ip_datagram.set_length(IpDatagram::STANDARD_HEADER_LENGTH + echo_request_bytes.len() as u16);
        ip_datagram.set_payload(&echo_request_bytes);

        let socket_addr = SocketAddr::new(self.destination_address, 1234);
        let ip_datagram_bytes = ip_datagram.to_bytes();
        match self.tx_to_icmp_raw_socket.send((ip_datagram_bytes, socket_addr)).await {
            Ok(_) => (),
            Err(_) => return Err(ProbeError::IoError { ttl, io_error: None }),
        };

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