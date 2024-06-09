use std::io;
use std::net::IpAddr;

use tokio::sync::oneshot;

use crate::traceroute::icmp_sniffer::IcmpProbeResponseSniffer;
use crate::traceroute::probe::ProbeId;
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
        let channel = oneshot::channel();
        let task = UdpProbeTask::new(ip_addr.clone(), self.destination_port, channel.1)?;
        icmp_probe_response_sniffer.register_probe(task.get_probe_id(), channel.0);
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
        let channel = oneshot::channel();
        let task = TcpProbeTask::new(self.ip_id, ip_addr.clone(), self.destination_port, channel.1)?;
        icmp_probe_response_sniffer.register_probe(task.get_probe_id(), channel.0);
        let generated_probe_task = (self.ip_id.to_string(), Box::new(task) as Box<dyn ProbeTask>);
        self.ip_id += 1;
        Ok(generated_probe_task)
    }
}

pub struct IcmpProbeTaskGenerator {
    icmp_id: u16,
    icmp_sqn: u16,
}

impl IcmpProbeTaskGenerator {
    pub fn build(icmp_id: u16, icmp_sqn: u16) -> Self {
        Self {
            icmp_id,
            icmp_sqn,
        }
    }

    pub fn new() -> Self {
        Self {
            icmp_id: crate::traceroute::utils::generate_u16(),
            icmp_sqn: 1
        }
    }
}

impl ProbeTaskGenerator for IcmpProbeTaskGenerator {
    fn generate_probe_task(
        &mut self,
        ip_addr: IpAddr,
        icmp_probe_response_sniffer: &IcmpProbeResponseSniffer
    ) -> io::Result<GeneratedProbeTask> {
        let channel = oneshot::channel();
        let task = IcmpProbeTask::new(self.icmp_id, self.icmp_sqn, ip_addr.clone(), channel.1)?;
        icmp_probe_response_sniffer.register_probe(task.get_probe_id(), channel.0);
        let probe_id = format!("{}{}", self.icmp_id, self.icmp_sqn);
        let generated_probe_task = (probe_id, Box::new(task) as Box<dyn ProbeTask>);
        self.icmp_sqn += 1;
        Ok(generated_probe_task)
    }
}