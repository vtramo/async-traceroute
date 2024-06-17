use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::UNIX_EPOCH;

use pnet::datalink::{interfaces, NetworkInterface};
use pnet::packet::FromPacket;
use pnet::packet::icmp::{Icmp, IcmpCode, IcmpPacket, IcmpType};
use pnet::packet::icmp::echo_request::{EchoRequest, EchoRequestPacket};
use pnet::packet::ipv4::{Ipv4, Ipv4Packet};
use pnet::packet::ipv6::Ipv6;
use pnet::packet::tcp::{ipv4_checksum, Tcp, TcpOption, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};

use crate::traceroute::utils::bytes::ToBytes;

const TCP_SYN_ACK: u8 = 18;

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

pub fn build_ipv4_datagram_from_bytes(data: &[u8]) -> Option<Ipv4> {
    let ipv4packet = Ipv4Packet::new(&data)?;
    Some(ipv4packet.from_packet())
}

pub fn build_icmpv4_packet_from_bytes(data: &[u8]) -> Option<Icmp> {
    let icmp_packet = IcmpPacket::new(data)?;
    Some(icmp_packet.from_packet())
}

pub fn build_tcp_segment_from_bytes(data: &[u8]) -> Option<Tcp> {
    let tcp_packet = TcpPacket::new(data)?;
    Some(tcp_packet.from_packet())
}

pub fn is_tcp_syn_ack_segment(tcp_segment: &Tcp) -> bool {
    tcp_segment.flags == TCP_SYN_ACK
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

pub fn is_icmp_echo_reply(icmp_packet: &Icmp) -> bool {
    let icmp_type = icmp_packet.icmp_type.0;
    let icmp_code = icmp_packet.icmp_code.0;
    icmp_type == 0 && icmp_code == 0
}

pub fn extract_ipv4_header_from_icmp_error_response(icmp_packet: &Icmp) -> Option<Ipv4> {
    let payload = &icmp_packet.payload;
    let payload: Vec<u8> = payload
        .into_iter()
        .skip_while(|byte| **byte != 69)
        .map(|byte| *byte)
        .collect();

    build_ipv4_datagram_from_bytes(&payload[..20])
}

pub fn extract_icmp_ping_from_icmp_error_response(icmp_packet: &Icmp) -> Option<EchoRequest> {
    let payload = &icmp_packet.payload;
    let payload: Vec<u8> = payload
        .into_iter()
        .skip(24)
        .map(|byte| *byte)
        .collect();

    let echo_request_packet = EchoRequestPacket::new(&payload)?;
    Some(echo_request_packet.from_packet())
}

pub fn extract_udp_header_from_icmp_error_response(icmp_packet: &Icmp) -> Option<Udp> {
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

pub fn build_tcp_syn_segment(source_port: u16, destination_port: u16, isn: u32) -> Tcp {
    Tcp {
        source: source_port,
        destination: destination_port,
        sequence: isn,
        acknowledgement: 0,
        data_offset: 10,
        reserved: 0,
        flags: 2,
        window: 5840,
        checksum: 0,
        urgent_ptr: 0,
        options: vec![
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::timestamp(UNIX_EPOCH.elapsed().unwrap().subsec_millis(), 0),
            TcpOption::nop(),
            TcpOption::wscale(2),
        ],
        payload: vec![],
    }
}

pub fn build_icmpv4_echo_request(id: u16, sqn: u16) -> Icmp {
    let mut payload = Vec::with_capacity(4);
    payload.extend_from_slice(id.to_be_bytes().as_ref());
    payload.extend_from_slice(sqn.to_be_bytes().as_ref());
    Icmp {
        icmp_type: IcmpType(8),
        icmp_code: IcmpCode(0),
        checksum: 0,
        payload,
    }
}

pub fn internet_checksum(tcp_segment: &Tcp, ip_datagram: &IpDatagram) -> u16 {
    match ip_datagram {
        IpDatagram::V4(ipv4_datagram) => {
            internet_checksum_ipv4(tcp_segment, ipv4_datagram)
        }
        IpDatagram::V6(ipv6_datagram) => todo!()
    }
}

fn internet_checksum_ipv4(tcp_segment: &Tcp, ipv4_datagram: &Ipv4) -> u16 {
    let tcp_segment_bytes = tcp_segment.to_bytes();
    let tcp_packet = TcpPacket::new(&tcp_segment_bytes).unwrap(); // todo
    ipv4_checksum(&tcp_packet, &ipv4_datagram.source, &ipv4_datagram.destination)
}

pub fn icmpv4_checksum(icmp: &Icmp) -> u16 {
    let icmp_bytes = icmp.to_bytes();
    let icmp_packet = IcmpPacket::new(&icmp_bytes).unwrap(); // todo
    pnet::packet::icmp::checksum(&icmp_packet)
}

pub fn get_default_ipv4_addr_interface() -> Ipv4Addr {
    let interfaces = interfaces();
    
    let first_interface = interfaces.get(1).unwrap(); // todo
    let ips = &first_interface.ips;
    let ip_addr = ips.get(0).unwrap().ip(); // todo
    match ip_addr {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        IpAddr::V6(_ipv6_addr) => panic!("")
    }
}

pub fn default_interface() -> Option<NetworkInterface> {
    interfaces()
        .iter()
        .find(|e| e. is_up() && !e. is_loopback() && !e. ips. is_empty())
        .cloned()
}

pub fn get_interface(interface: &str) -> Option<NetworkInterface> {
    for network_interface in interfaces() {
        if &network_interface.name == interface {
            return Some(network_interface);
        }
    }
    
    None
}

pub fn get_default_ipv6_addr_interface() -> Ipv6Addr {
    let interfaces = interfaces();
    let first_interface = interfaces.get(1).unwrap();
    let ips = &first_interface.ips;
    let ip_addr = ips.get(0).unwrap().ip();
    match ip_addr {
        IpAddr::V4(_ipv4_addr) => panic!(""), // todo
        IpAddr::V6(ipv6_addr) => ipv6_addr
    }
}
