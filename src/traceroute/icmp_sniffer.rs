use std::io;
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::sync::mpsc::Sender;

use socket2::{Domain, Protocol, Socket, Type};

use crate::traceroute::methods::TracerouteProbeResponseBuilder;
use crate::traceroute::TracerouteProbeResponse;
use crate::traceroute::utils::packet_utils;

pub struct TracerouteIcmpSniffer {
    socket: Socket,
    buffer: [MaybeUninit<u8>; TracerouteIcmpSniffer::BUFFER_SIZE],
    channel: Sender<TracerouteProbeResponse>,
    probe_response_builder: Box<dyn TracerouteProbeResponseBuilder>,
    is_sniffing: bool,
}

impl TracerouteIcmpSniffer {
    const BUFFER_SIZE: usize = 128;
    
    pub fn new(
        channel: Sender<TracerouteProbeResponse>, 
        probe_response_builder: Box<dyn TracerouteProbeResponseBuilder>,
    ) -> io::Result<Self> {
        Ok(TracerouteIcmpSniffer {
            socket: Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            buffer: [MaybeUninit::new(0); TracerouteIcmpSniffer::BUFFER_SIZE],
            channel,
            probe_response_builder,
            is_sniffing: false,
        })
    }

    pub fn sniff(&mut self) {
        if self.is_sniffing {
            panic!("The sniffer is already listening!");
        }

        self.is_sniffing = true;

        while self.is_sniffing {
            let data = match self.socket.recv_from(&mut self.buffer) {
                Ok(_) => self.map_buffer_to_vec_u8(),
                Err(_) => break,
            };

            let ipv4_datagram = match packet_utils::build_ipv4_datagram_from_bytes(&data) {
                Some(ipv4_datagram) => ipv4_datagram,
                None => continue,
            };
            
            let icmp_packet = match packet_utils::build_icmpv4_packet_from_bytes(&ipv4_datagram.payload) {
                Some(ipv4_datagram) => ipv4_datagram,
                None => continue,
            };

            if !packet_utils::is_icmp_ttl_expired(&icmp_packet) &&
                !packet_utils::is_icmp_destination_port_unreachable(&icmp_packet) {
                continue;
            }
            
            if let Some(traceroute_probe_response) 
                = self.probe_response_builder.build_probe_response(&icmp_packet, &ipv4_datagram) {
                
                self.channel
                    .send(traceroute_probe_response)
                    .expect("The channel should be available after you start sniffing!");
            }
        }
    }

    fn map_buffer_to_vec_u8(&self) -> Vec<u8> {
        self.buffer
            .iter()
            .map(|maybe_uninit| unsafe { maybe_uninit.assume_init_read() })
            .collect()
    }
    
    pub fn stop(&mut self) -> io::Result<()> {
        self.is_sniffing = false;
        self.socket.shutdown(Shutdown::Both)
    }
}