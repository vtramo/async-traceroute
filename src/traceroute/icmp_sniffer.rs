use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::Shutdown;
use std::ops::DerefMut;
use std::sync::{Arc, LockResult, Mutex};

use socket2::{Domain, Protocol, Type};

use crate::traceroute::probe::{ProbeResponse, ProbeResponseParser};
use crate::traceroute::probe::parser::ProbeReplyParser;
use crate::traceroute::tokio_socket::AsyncTokioSocket;
use crate::traceroute::utils::packet_utils;

pub type ProbeResponseSender = tokio::sync::oneshot::Sender<ProbeResponse>;


pub struct IcmpProbeResponseSniffer {
    socket: AsyncTokioSocket,
    oneshot_channels_by_probe_id: Mutex<HashMap<String, ProbeResponseSender>>,
    probe_reply_parser: ProbeReplyParser,
    is_sniffing: Mutex<bool>,
}

impl IcmpProbeResponseSniffer {
    const BUFFER_SIZE: usize = 1024;
    
    pub fn new(probe_reply_parser: ProbeReplyParser) -> io::Result<Self> {
        Ok(IcmpProbeResponseSniffer {
            socket: AsyncTokioSocket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            oneshot_channels_by_probe_id: Mutex::new(HashMap::with_capacity(120)),
            probe_reply_parser,
            is_sniffing: Mutex::new(false),
        })
    }

    pub async fn sniff(&self) {
        if self.is_sniffing() {
            panic!("The sniffer is already listening!");
        }

        self.set_is_sniffing(true);
        
        let mut buffer = [0u8; 1024];
        while self.is_sniffing() {
            let data = match self.socket.recv(&mut buffer).await {
                Ok(_) => buffer.to_vec(),
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
                = self.probe_reply_parser.parse(&icmp_packet, &ipv4_datagram) {
                
                match self.oneshot_channels_by_probe_id.lock() {
                    Ok(mut oneshot_channels_by_probe_id) => {
                        let oneshot_channels_by_probe_id = oneshot_channels_by_probe_id.deref_mut();
                        if let Some(oneshot_channel)
                            = oneshot_channels_by_probe_id.remove(&probe_response.probe_id()) {

                            let _ = oneshot_channel.send(probe_response);
                        }
                    }
                    Err(_) => continue // todo
                }
            }
        }
    }
    
    fn set_is_sniffing(&self, value: bool) {
        match self.is_sniffing.lock() {
            Ok(mut is_sniffing) => *is_sniffing = value,
            Err(_) => todo!()
        };
    }
    
    pub fn is_sniffing(&self) -> bool {
        match self.is_sniffing.lock() {
            Ok(is_sniffing) => *is_sniffing,
            Err(_) => todo!()
        }
    }
    
    pub fn register_probe(&self, probe_id: String, probe_response_sender: ProbeResponseSender) -> bool {
        match self.oneshot_channels_by_probe_id.lock() {
            Ok(mut oneshot_channels_by_probe_id) => {
                if oneshot_channels_by_probe_id.contains_key(&probe_id) {
                    return false;
                }
                oneshot_channels_by_probe_id.insert(probe_id, probe_response_sender);
                return true;
            }
            Err(_) => todo!()
        }
    }
    
    pub fn stop(&self) -> io::Result<()> {
        self.set_is_sniffing(false);
        self.socket.shutdown(Shutdown::Both)
    }
}