use libpacket::{ipv4::Ipv4, PrimitiveValues, udp::Udp};

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