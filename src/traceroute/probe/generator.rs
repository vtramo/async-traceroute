use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Protocol, Type};
use tokio::sync::{mpsc, oneshot};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::traceroute::async_socket::SharedAsyncTokioSocket;
use crate::traceroute::probe::ProbeId;
use crate::traceroute::probe::sniffer::{IcmpProbeResponseSniffer, Sniffer};
use crate::traceroute::probe::task::{IcmpProbeTask, ProbeTask, TcpProbeTask, UdpProbeTask};

pub type GeneratedProbeTask = (ProbeId, Box<dyn ProbeTask>);

pub trait ProbeTaskGenerator {
    fn generate_probe_task(
        &mut self,
        ip_addr: IpAddr,
        icmp_probe_response_sniffer: &IcmpProbeResponseSniffer
    ) -> io::Result<GeneratedProbeTask>;
}

pub struct UdpProbeTaskGenerator {
    destination_port: u16,
}

impl UdpProbeTaskGenerator {
    pub fn new(destination_port: u16) -> Self {
        Self {
            destination_port
        }
    }
}

impl ProbeTaskGenerator for UdpProbeTaskGenerator {
    fn generate_probe_task(
        &mut self,
        ip_addr: IpAddr,
        icmp_probe_response_sniffer: &IcmpProbeResponseSniffer
    ) -> io::Result<GeneratedProbeTask> {
        let (tx_probe_response_channel, rx_probe_response_channel) = oneshot::channel();
        let task = UdpProbeTask::new(ip_addr.clone(), self.destination_port, rx_probe_response_channel)?;
        icmp_probe_response_sniffer.register_oneshot(task.get_probe_id(), tx_probe_response_channel);
        let generated_probe_task = (self.destination_port.to_string(), Box::new(task) as Box<dyn ProbeTask>);
        self.destination_port += 1;
        Ok(generated_probe_task)
    }
}

pub struct TcpProbeTaskGenerator {
    ip_id: u16,
    destination_port: u16,
}

impl TcpProbeTaskGenerator {
    const DEFAULT_DESTINATION_PORT: u16 = 80;

    pub fn build(ip_id: u16, destination_port: u16) -> Self {
        Self {
            ip_id,
            destination_port,
        }
    }

    pub fn new() -> Self {
        Self {
            ip_id: crate::traceroute::utils::generate_u16(),
            destination_port: TcpProbeTaskGenerator::DEFAULT_DESTINATION_PORT
        }
    }
}

impl ProbeTaskGenerator for TcpProbeTaskGenerator {
    fn generate_probe_task(
        &mut self,
        ip_addr: IpAddr,
        icmp_probe_response_sniffer: &IcmpProbeResponseSniffer
    ) -> io::Result<GeneratedProbeTask> {
        let (tx_probe_response_channel, rx_probe_response_channel) = oneshot::channel();
        let task = TcpProbeTask::new(self.ip_id, ip_addr.clone(), self.destination_port, rx_probe_response_channel)?;
        icmp_probe_response_sniffer.register_oneshot(task.get_probe_id(), tx_probe_response_channel);
        let generated_probe_task = (self.ip_id.to_string(), Box::new(task) as Box<dyn ProbeTask>);
        self.ip_id += 1;
        Ok(generated_probe_task)
    }
}

pub struct IcmpProbeTaskGenerator {
    icmp_id: u16,
    icmp_sqn: u16,
    tx_to_shared_socket: Sender<(Vec<u8>, SocketAddr)>, 
}

impl IcmpProbeTaskGenerator {
    const SHARED_SOCKET_BUFFER_SIZE: usize = 255;
    
    pub fn new() -> io::Result<Self> {
        let (tx_to_shared_socket, rx_to_shared_socket) = mpsc::channel(Self::SHARED_SOCKET_BUFFER_SIZE);
        Self::spawn_shared_socket(rx_to_shared_socket)?;
        
        Ok(Self {
            icmp_id: crate::traceroute::utils::generate_u16(),
            icmp_sqn: 1,
            tx_to_shared_socket
        })
    }
    
    fn spawn_shared_socket(rx_to_shared_socket: Receiver<(Vec<u8>, SocketAddr)>) -> io::Result<()> {
        let mut shared_socket = SharedAsyncTokioSocket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::ICMPV4),
            rx_to_shared_socket,
        )?;
        
        shared_socket.set_header_included(true)?;
        
        tokio::spawn( async move {
            shared_socket.share().await
        });
        
        Ok(())
    }
}

impl ProbeTaskGenerator for IcmpProbeTaskGenerator {
    fn generate_probe_task(
        &mut self,
        ip_addr: IpAddr,
        icmp_probe_response_sniffer: &IcmpProbeResponseSniffer
    ) -> io::Result<GeneratedProbeTask> {
        let (tx_probe_response_channel, rx_probe_response_channel) = oneshot::channel();
        let task = IcmpProbeTask::new(
            self.icmp_id, self.icmp_sqn, ip_addr.clone(), 
            rx_probe_response_channel, 
            self.tx_to_shared_socket.clone(),
        );
        icmp_probe_response_sniffer.register_oneshot(task.get_probe_id(), tx_probe_response_channel);
        let probe_id = format!("{}{}", self.icmp_id, self.icmp_sqn);
        let generated_probe_task = (probe_id, Box::new(task) as Box<dyn ProbeTask>);
        self.icmp_sqn += 1;
        Ok(generated_probe_task)
    }
}