use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
pub use parser::ProbeResponseParser;

// use crate::traceroute::probe::parser::UdpProbeResponseParser;
// use crate::traceroute::probe::sender::UdpProbeSender;
// use TracerouteMethod::{ICMP, TCP, UDP};

pub mod parser;
pub mod task;
pub mod generator;
pub type ProbeId = String;

#[derive(Clone, Debug)]
pub struct ProbeResponse {
    id: ProbeId,
    from_address: Ipv4Addr
}

impl ProbeResponse {
    pub fn probe_id(&self) -> ProbeId {
        self.id.clone()
    }
    
    pub fn from_address(&self) -> Ipv4Addr {
        self.from_address
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    id: String,
    from_address: Ipv4Addr,
    rtt: Duration
}

impl ProbeResult {
    pub fn probe_id(&self) -> ProbeId {
        self.id.clone()
    }

    pub fn from_address(&self) -> Ipv4Addr {
        self.from_address
    }
    
    pub fn rtt(&self) -> Duration {
        self.rtt
    }
}

struct CompletableProbe {
    id: ProbeId,
    sent_at: Instant,
    probe_result: Option<ProbeResult>,
}

impl CompletableProbe {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            sent_at: Instant::now(),
            probe_result: None,
        }
    }

    pub fn complete(&mut self, probe_response: ProbeResponse) -> Option<ProbeResult> {
        if probe_response.id != self.id {
            return None;
        }

        if let Some(probe_result) = &self.probe_result {
            return Some(probe_result.clone());
        }

        Some(ProbeResult {
            id: probe_response.id,
            from_address: probe_response.from_address,
            rtt: self.sent_at.elapsed()
        })
    }
}

pub enum ProbeMethod {
    UDP,
    TCP,
    ICMP
}