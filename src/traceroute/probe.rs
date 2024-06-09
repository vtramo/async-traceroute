pub use parser::ProbeResponseParser;
pub use sender::ProbeSender;

// use crate::traceroute::probe::parser::UdpProbeResponseParser;
// use crate::traceroute::probe::sender::UdpProbeSender;
// use TracerouteMethod::{ICMP, TCP, UDP};

mod sender;
pub mod parser;
pub mod task;

// pub enum TracerouteMethod {
//     UDP { destination_address: IpAddr, initial_destination_port: u16, queries_per_hop: u16, },
//     TCP,
//     ICMP,
// }
// 
// impl TracerouteMethod {
//     pub fn get_probe_sender(&self) -> impl ProbeSender {
//         match self {
//             UDP {
//                 destination_address,
//                 initial_destination_port,
//                 queries_per_hop,
//             } => UdpProbeSender::new(*destination_address,
//                                      *initial_destination_port,
//                                      *queries_per_hop).unwrap(), // todo!()
//             TCP => todo!(),
//             ICMP => todo!(),
//         }
//     }
//     
//     pub fn get_probe_response_parser(&self) -> impl ProbeResponseParser {
//         match self {
//             UDP => UdpProbeResponseParser,
//             TCP => todo!(),
//             ICMP => todo!(),
//         }
//     }
// }
