use libpacket::icmp::Icmp;
use libpacket::ipv4::Ipv4;
use crate::traceroute::{TracerouteProbeResponse};
use crate::traceroute::utils::packet_utils;

pub trait TracerouteProbeResponseBuilder: Send {
    fn build_probe_response(&self, icmp_packet: &Icmp, ipv4_datagram: &Ipv4) -> Option<TracerouteProbeResponse>;
}

pub struct UdpTracerouteProbeResponseBuilder;
impl TracerouteProbeResponseBuilder for UdpTracerouteProbeResponseBuilder {
    fn build_probe_response(&self, icmp_packet: &Icmp, ipv4_datagram: &Ipv4) -> Option<TracerouteProbeResponse> {
        let udp_header = packet_utils::extract_udp_header_from_icmp_response(&icmp_packet)?;
        let probe_response_id = udp_header.destination;
        let node_address = ipv4_datagram.source;
        Some(TracerouteProbeResponse {
            id: probe_response_id.to_string(),
            address: node_address,
        })
    }
}