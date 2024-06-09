use std::net::Ipv4Addr;
use std::time::Duration;

use pnet::packet::ipv4::Ipv4;
use pnet::packet::ipv6::Ipv6;

// use crate::traceroute::probe::{TracerouteMethod, ProbeSender};

pub(crate) mod terminal;
pub mod icmp_sniffer;
pub mod probe;
mod utils;
mod tokio_socket;

pub enum TracerouteHopStatus {
    Completed,
    PartiallyCompleted,
    NoReply
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub id: String,
    pub from_address: Ipv4Addr,
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
// 
// pub struct Traceroute {
//     hops: u16,
//     queries_per_hop: u16,
//     traceroute_method: TracerouteMethod,
//     channel: Sender<ProbeResult>,
//     hops_by_id: HashMap<String, CompletableHop>,
// }
// 
// impl Traceroute {
//     const MAX_TTL_PACKETS_AT_ONCE: u16 = 10;
// 
//     pub fn new(
//         hops: u16,
//         queries_per_hop: u16,
//         traceroute_method: TracerouteMethod,
//         channel: Sender<ProbeResult>,
//     ) -> Self {
//         Self {
//             hops,
//             queries_per_hop,
//             traceroute_method,
//             channel,
//             hops_by_id: HashMap::with_capacity(hops as usize)
//         }
//     }
// 
//     pub fn traceroute(mut self) -> Result<(), io::Error> {
//         let (sender, receiver) = mpsc::channel();
//         self.start_icmp_sniffer(sender);
// 
//         let mut ttl_packet_sender = self.traceroute_method.get_probe_sender();
//         let mut ttl_counter = min(Self::MAX_TTL_PACKETS_AT_ONCE, self.hops * self.queries_per_hop);
//         for ttl in 1..=ttl_counter {
//             let hop = ttl_packet_sender.send(ttl as u8)?;
//             self.hops_by_id.insert(hop.id.clone(), hop);
//         }
// 
//         while let Ok(traceroute_hop_response) = receiver.recv() {
//             ttl_counter += 1;
//             ttl_packet_sender.send(ttl_counter as u8)?;
//             let hop_response_id = &traceroute_hop_response.id;
//             if let Some(hop) = self.hops_by_id.get_mut(hop_response_id) {
//                 if let Some(hop_result) = hop.complete_query(traceroute_hop_response) {
//                     self.channel.send(hop_result).unwrap(); // todo
//                 }
//             }
//         }
// 
//         Ok(())
//     }
// 
//     fn start_icmp_sniffer(&self, sender: Sender<ProbeResponse>) {
//         let probe_response_builder = self.traceroute_method.get_probe_response_parser();
//         let mut icmp_sniffer = match IcmpProbeResponseSniffer::new(sender, Box::new(probe_response_builder)) {
//             Ok(icmp_sniffer) => icmp_sniffer,
//             Err(_error) => panic!("Unable to start ICMP sniffer: {_error}")
//         };
// 
//         thread::spawn(move || {
//             icmp_sniffer.sniff()
//         });
//     }
// }

#[derive(Clone, Debug)]
pub struct ProbeResponse {
    id: String,
    from_address: Ipv4Addr
}
