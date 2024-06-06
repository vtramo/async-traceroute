use std::net::IpAddr;

pub use probe_response_builder::TracerouteProbeResponseBuilder;
pub use ttl_packet_sender::TracerouteTtlPacketSender;

use crate::traceroute::methods::probe_response_builder::UdpTracerouteProbeResponseBuilder;
use crate::traceroute::methods::ttl_packet_sender::UdpTracerouteTtlPacketSender;
use TracerouteMethod::{ICMP, TCP, UDP};

mod ttl_packet_sender;
mod probe_response_builder;

pub enum TracerouteMethod {
    UDP { destination_address: IpAddr, initial_destination_port: u16, queries_per_hop: u16, },
    TCP,
    ICMP,
}

impl TracerouteMethod {
    pub fn get_ttl_packet_sender(&self) -> impl TracerouteTtlPacketSender {
        match self {
            UDP {
                destination_address,
                initial_destination_port,
                queries_per_hop,
            } => UdpTracerouteTtlPacketSender::new(*destination_address, 
                                                   *initial_destination_port, 
                                                   *queries_per_hop),
            TCP => todo!(),
            ICMP => todo!(),
        }
    }
    
    pub fn get_probe_response_builder(&self) -> impl TracerouteProbeResponseBuilder {
        match self {
            UDP => UdpTracerouteProbeResponseBuilder,
            TCP => todo!(),
            ICMP => todo!(),
        }
    }
}
