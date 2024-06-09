use std::collections::HashMap;
use std::io;
use std::net::Shutdown;

use socket2::{Domain, Protocol, Type};

use crate::traceroute::probe::ProbeResponseParser;
use crate::traceroute::ProbeResponse;
use crate::traceroute::tokio_socket::AsyncTokioSocket;
use crate::traceroute::utils::packet_utils;


pub type ProbeResponseSender = tokio::sync::oneshot::Sender<ProbeResponse>;


pub struct IcmpProbeResponseSniffer<T: ProbeResponseParser> {
    socket: AsyncTokioSocket,
    buffer: [u8; 1024],
    oneshot_channels_by_probe_id: HashMap<String, ProbeResponseSender>,
    probe_response_parser: T,
    is_sniffing: bool,
}

impl<T: ProbeResponseParser> IcmpProbeResponseSniffer<T> {
    const BUFFER_SIZE: usize = 1024;
    
    pub fn new(probe_response_parser: T) -> io::Result<Self> {
        Ok(IcmpProbeResponseSniffer {
            socket: AsyncTokioSocket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            buffer: [0u8; 1024],
            oneshot_channels_by_probe_id: HashMap::with_capacity(120),
            probe_response_parser,
            is_sniffing: false,
        })
    }

    pub async fn sniff(&mut self) {
        if self.is_sniffing {
            panic!("The sniffer is already listening!");
        }

        self.is_sniffing = true;

        while self.is_sniffing {
            let data = match self.socket.recv(&mut self.buffer).await {
                Ok(_) => self.buffer.to_vec(),
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
            
            if let Some(probe_response)
                = self.probe_response_parser.parse(&icmp_packet, &ipv4_datagram) {
                
                if let Some(oneshot_channel) 
                    = self.oneshot_channels_by_probe_id.remove(&probe_response.id) {
                    
                    let _ = oneshot_channel.send(probe_response);
                }
            }
        }
    }
    
    pub fn register_probe(&mut self, probe_id: String, probe_response_sender: ProbeResponseSender) -> bool {
        if self.oneshot_channels_by_probe_id.contains_key(&probe_id) {
            return false;
        }
        
        self.oneshot_channels_by_probe_id.insert(probe_id, probe_response_sender);
        
        return true;
    }
    
    pub fn stop(&mut self) -> io::Result<()> {
        self.is_sniffing = false;
        self.socket.shutdown(Shutdown::Both)
    }
}