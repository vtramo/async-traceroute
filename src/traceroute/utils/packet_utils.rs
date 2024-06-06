use libpacket::FromPacket;
use libpacket::icmp::{Icmp, IcmpPacket};
use libpacket::ipv4::{Ipv4, Ipv4Packet};
use libpacket::udp::{Udp, UdpPacket};

pub fn build_ipv4_datagram_from_bytes(data: &[u8]) -> Option<Ipv4> {
    let ipv4packet = Ipv4Packet::new(&data)?;
    Some(ipv4packet.from_packet())
}

pub fn build_icmpv4_packet_from_bytes(data: &[u8]) -> Option<Icmp> {
    let icmp_packet = IcmpPacket::new(data)?;
    Some(icmp_packet.from_packet())
}

pub fn is_icmp_ttl_expired(icmp_packet: &Icmp) -> bool {
    let icmp_type = icmp_packet.icmp_type.0;
    let icmp_code = icmp_packet.icmp_code.0;
    icmp_type == 11 && icmp_code == 0
}

pub fn is_icmp_destination_port_unreachable(icmp_packet: &Icmp) -> bool {
    let icmp_type = icmp_packet.icmp_type.0;
    let icmp_code = icmp_packet.icmp_code.0;
    icmp_type == 3 && icmp_code == 3
}

pub fn extract_ipv4_header_from_icmp_response(icmp_packet: &Icmp) -> Option<Ipv4> {
    let payload = &icmp_packet.payload;
    let payload: Vec<u8> = payload
        .into_iter()
        .skip_while(|byte| **byte != 69)
        .map(|byte| *byte)
        .collect();

    build_ipv4_datagram_from_bytes(&payload[..20])
}

pub fn extract_udp_header_from_icmp_response(icmp_packet: &Icmp) -> Option<Udp> {
    let payload = &icmp_packet.payload;
    let payload: Vec<u8> = payload
        .into_iter()
        .skip_while(|byte| **byte != 69)
        .map(|byte| *byte)
        .collect();

    let udp_packet = UdpPacket::new(&payload[20..28])?;
    Some(udp_packet.from_packet())
}

pub fn build_udp_datagram_with_ports(source_port: u16, destination_port: u16) -> Udp {
    Udp {
        source: source_port,
        destination: destination_port,
        length: 8,
        checksum: 0,
        payload: vec![]
    }
}