use pnet::packet::{ipv4::Ipv4, PrimitiveValues, udp::Udp};
use pnet::packet::icmp::Icmp;
use pnet::packet::tcp::{Tcp, TcpOption};

use crate::traceroute::utils::packet_utils::IpDatagram;

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

impl ToBytes for Ipv4 {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(self.total_length as usize);

        let version_then_header_length: u8 = (self.version << 4) ^ self.header_length;
        bytes.extend_from_slice(version_then_header_length.to_be_bytes().as_ref());

        let tos: u8 = (self.dscp << 2) ^ self.ecn;
        bytes.extend_from_slice(tos.to_be_bytes().as_ref());

        bytes.extend_from_slice(self.total_length.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.identification.to_be_bytes().as_ref());

        let flags_then_frag_offset = ((self.flags as u16) << 13) ^ self.fragment_offset;
        bytes.extend_from_slice(flags_then_frag_offset.to_be_bytes().as_ref());

        let ttl_then_protocol = ((self.ttl as u16) << 8) ^ self.next_level_protocol.to_primitive_values().0 as u16;
        bytes.extend_from_slice(ttl_then_protocol.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.checksum.to_be_bytes().as_ref());

        let source_primitive_values = self.source.to_primitive_values();
        bytes.extend_from_slice(&[
            source_primitive_values.0,
            source_primitive_values.1,
            source_primitive_values.2,
            source_primitive_values.3,
        ]);

        let dest_primitive_values = self.destination.to_primitive_values();
        bytes.extend_from_slice(&[
            dest_primitive_values.0,
            dest_primitive_values.1,
            dest_primitive_values.2,
            dest_primitive_values.3,
        ]);

        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

impl ToBytes for Udp {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(self.length as usize);

        bytes.extend_from_slice(self.source.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.destination.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.length.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.checksum.to_be_bytes().as_ref());
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

impl ToBytes for IpDatagram {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            IpDatagram::V4(ipv4_datagram) => ipv4_datagram.to_bytes(),
            IpDatagram::V6(_ipv6_datagram) => todo!()
        }
    }
}

impl ToBytes for Tcp {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity((self.data_offset * 4) as usize);

        bytes.extend_from_slice(self.source.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.destination.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.sequence.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.acknowledgement.to_be_bytes().as_ref());

        let data_offset_then_reserved_then_flags: u16
            = ((self.data_offset as u16) << 12) ^
              ((self.reserved as u16) << 9)     ^
              (self.flags as u16);
        bytes.extend_from_slice(data_offset_then_reserved_then_flags.to_be_bytes().as_ref());

        bytes.extend_from_slice(self.window.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.checksum.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.urgent_ptr.to_be_bytes().as_ref());

        let tcp_options_bytes: Vec<_> = self.options
            .iter()
            .flat_map(|tcp_option| tcp_option.to_bytes())
            .collect();

        bytes.extend(tcp_options_bytes);
        bytes.extend_from_slice(self.payload.as_ref());
        
        bytes
    }
}

impl ToBytes for TcpOption {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(12);
        bytes.push(self.number.0);
        bytes.extend(&self.length);
        bytes.extend(&self.data);
        bytes
    }
}

impl ToBytes for Icmp {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(12);
        bytes.push(self.icmp_type.0);
        bytes.push(self.icmp_code.0);
        bytes.extend_from_slice(self.checksum.to_be_bytes().as_ref());
        bytes.extend_from_slice(self.payload.as_ref());
        bytes
    }
}

