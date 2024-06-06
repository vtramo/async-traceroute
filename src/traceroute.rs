use std::{io, thread};
use std::cmp::min;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use libpacket::ipv4::Ipv4;
use libpacket::ipv6::Ipv6;

use crate::traceroute::icmp_sniffer::TracerouteIcmpSniffer;
use crate::traceroute::methods::{TracerouteMethod, TracerouteTtlPacketSender};

mod terminal;
mod icmp_sniffer;
mod methods;
mod utils;

pub enum TracerouteHopStatus {
    Completed,
    PartiallyCompleted,
    NoReply
}

pub struct TracerouteHopResult {
    pub id: String,
    pub address: Ipv4Addr,
    pub rtt: Duration
}

pub enum TracerouteError {
    HostnameNotResolved(String)
}

pub enum IpDatagram {
    V4(Ipv4), V6(Ipv6)
}

impl IpDatagram {
    pub const STANDARD_HEADER_LENGTH: u16 = 20;
    
    pub fn set_payload(&mut self, data: &[u8]) {
        let data_to_vec = data.to_vec();
        match self {
            IpDatagram::V4(ipv4_datagram) => {
                ipv4_datagram.payload = data_to_vec;
            },
            IpDatagram::V6(ipv6_datagram) => {
                ipv6_datagram.payload = data_to_vec;
            }
        }
    }

    pub fn set_length(&mut self, length: u16) {
        match self {
            IpDatagram::V4(ipv4_datagram) => {
                ipv4_datagram.total_length = length;
            },
            IpDatagram::V6(ipv6_datagram) => {
                ipv6_datagram.payload_length = length;
            }
        }
    }
}

pub struct Traceroute {
    hops: u16,
    queries_per_hop: u16,
    traceroute_method: TracerouteMethod,
    channel: Sender<TracerouteHopResult>,
    hops_by_id: HashMap<String, TracerouteCompletableHop>,
}

impl Traceroute {
    const MAX_TTL_PACKETS_AT_ONCE: u16 = 10;

    pub fn new(
        hops: u16,
        queries_per_hop: u16,
        traceroute_method: TracerouteMethod,
        channel: Sender<TracerouteHopResult>,
    ) -> Self {
        Self {
            hops,
            queries_per_hop,
            traceroute_method,
            channel,
            hops_by_id: HashMap::with_capacity(hops as usize)
        }
    }

    pub fn traceroute(mut self) -> Result<(), io::Error> {
        let (sender, receiver) = mpsc::channel();
        self.start_icmp_sniffer(sender);

        let mut ttl_packet_sender = self.traceroute_method.get_ttl_packet_sender();
        let mut ttl_counter = min(Self::MAX_TTL_PACKETS_AT_ONCE, self.hops * self.queries_per_hop);
        for ttl in 1..=ttl_counter {
            let hop = ttl_packet_sender.send(ttl as u8)?;
            self.hops_by_id.insert(hop.id.clone(), hop);
        }

        while let Ok(traceroute_hop_response) = receiver.recv() {
            ttl_counter += 1;
            ttl_packet_sender.send(ttl_counter as u8)?;
            let hop_response_id = &traceroute_hop_response.id;
            if let Some(hop) = self.hops_by_id.get_mut(hop_response_id) {
                if let Some(hop_result) = hop.complete_query(traceroute_hop_response) {
                    self.channel.send(hop_result).unwrap(); // todo
                }
            }
        }

        Ok(())
    }

    fn start_icmp_sniffer(&self, sender: Sender<TracerouteProbeResponse>) {
        let probe_response_builder = self.traceroute_method.get_probe_response_builder();
        let mut icmp_sniffer = match TracerouteIcmpSniffer::new(sender, Box::new(probe_response_builder)) {
            Ok(icmp_sniffer) => icmp_sniffer,
            Err(_error) => panic!("Unable to start ICMP sniffer: {_error}")
        };

        thread::spawn(move || {
            icmp_sniffer.sniff()
        });
    }
}

struct TracerouteProbeResponse {
    id: String,
    address: Ipv4Addr
}
