use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::Icmp;
use pnet::packet::ipv4::Ipv4;

use crate::traceroute::ProbeResponse;
use crate::traceroute::utils::packet_utils;
use crate::traceroute::utils::packet_utils::is_icmp_ttl_expired;

pub trait ProbeResponseParser: Send {
    fn new() -> Self;
    fn parse(&self, icmp_packet: &Icmp, ipv4_datagram: &Ipv4) -> Option<ProbeResponse>;
}

pub struct UdpProbeResponseParser;
impl ProbeResponseParser for UdpProbeResponseParser {
    fn new() -> Self {
        Self
    }

    fn parse(&self, icmp_packet: &Icmp, ipv4_datagram: &Ipv4) -> Option<ProbeResponse> {
        if !packet_utils::is_icmp_ttl_expired(&icmp_packet) &&
            !packet_utils::is_icmp_destination_port_unreachable(&icmp_packet) {
            return None;
        }

        let udp_header = packet_utils::extract_udp_header_from_icmp_error_response(&icmp_packet)?;
        let probe_response_id = udp_header.destination;
        let from_address = ipv4_datagram.source;
        Some(ProbeResponse {
            id: probe_response_id.to_string(),
            from_address,
        })
    }
}

pub struct TcpProbeResponseParser;

impl ProbeResponseParser for TcpProbeResponseParser {
    fn new() -> Self {
        Self
    }

    fn parse(&self, icmp_packet: &Icmp, ipv4_datagram: &Ipv4) -> Option<ProbeResponse> {
        if !packet_utils::is_icmp_ttl_expired(&icmp_packet) &&
            !packet_utils::is_icmp_destination_port_unreachable(&icmp_packet) {
            return None;
        }
        
        let ipv4_header = packet_utils::extract_ipv4_header_from_icmp_error_response(icmp_packet)?;
        let probe_response_id = ipv4_header.identification;
        let from_address = ipv4_datagram.source;
        Some(ProbeResponse {
            id: probe_response_id.to_string(),
            from_address,
        })
    }
}

pub struct IcmpProbeResponseParser;

impl ProbeResponseParser for IcmpProbeResponseParser {
    fn new() -> Self {
        Self
    }

    fn parse(&self, icmp_packet: &Icmp, ipv4_datagram: &Ipv4) -> Option<ProbeResponse> {
        let from_address = ipv4_datagram.source;
        if packet_utils::is_icmp_echo_reply(&icmp_packet) {
            let echo_reply_packet = EchoReplyPacket::new(&ipv4_datagram.payload)?;
            let icmp_id = echo_reply_packet.get_identifier();
            let icmp_sqn = echo_reply_packet.get_sequence_number();
            Some(ProbeResponse {
                id: format!("{icmp_id}{icmp_sqn}"),
                from_address,
            })
        } else if is_icmp_ttl_expired(&icmp_packet) {
            let ping_request = packet_utils::extract_icmp_ping_from_icmp_error_response(icmp_packet)?;
            let ping_request_id = ping_request.identifier;
            let ping_request_sqn = ping_request.sequence_number;
            let probe_response_id = format!("{ping_request_id}{ping_request_sqn}");
            Some(ProbeResponse {
                id: probe_response_id,
                from_address,
            })
        } else {
            return None;
        }
    }
}