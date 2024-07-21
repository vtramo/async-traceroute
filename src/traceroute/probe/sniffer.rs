use std::collections::HashMap;
use std::io;
use std::net::Shutdown;
use std::ops::DerefMut;
use std::sync::Mutex;

use async_trait::async_trait;
use socket2::{Domain, Protocol, Type};
use tokio::sync::oneshot::Sender;

use crate::traceroute::async_socket::AsyncSocket;
use crate::traceroute::probe::{ProbeId, ProbeResponse, ProbeResponseParser};
use crate::traceroute::utils::packet_utils;

#[async_trait]
pub trait ObservableIcmpSniffer {
    type Response;

    async fn sniff(&self);
    fn register_oneshot(&self, id: String, oneshot_sender_channel: Sender<Self::Response>) -> bool;
    fn is_sniffing(&self) -> bool;
    fn stop(&self) -> io::Result<()>;
}

pub struct ObservableIcmpProbeResponseSniffer {
    socket: AsyncSocket,
    oneshot_channels_by_probe_id: Mutex<HashMap<String, Sender<ProbeResponse>>>,
    probe_response_parser: Box<dyn ProbeResponseParser>,
    is_sniffing: Mutex<bool>,
}

#[async_trait]
impl ObservableIcmpSniffer for ObservableIcmpProbeResponseSniffer {
    type Response = ProbeResponse;

    async fn sniff(&self) {
        if self.is_sniffing() {
            panic!("The sniffer is already listening!");
        }

        self.set_is_sniffing(true);

        let mut buffer = [0u8; Self::BUFFER_SIZE];
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
                = self.probe_response_parser.parse(&icmp_packet, &ipv4_datagram) {

                match self.oneshot_channels_by_probe_id.lock() {
                    Ok(mut oneshot_channels_by_probe_id) => {
                        let oneshot_channels_by_probe_id = oneshot_channels_by_probe_id.deref_mut();
                        if let Some(oneshot_channel)
                            = oneshot_channels_by_probe_id.remove(&probe_response.probe_id()) {

                            let _ = oneshot_channel.send(probe_response);
                        }
                    }
                    Err(_) => continue
                }
            }
        }
    }

    fn register_oneshot(&self, id: ProbeId, oneshot_sender_channel: Sender<Self::Response>) -> bool {
        if let Ok(mut oneshot_channels_by_probe_id) = self.oneshot_channels_by_probe_id.lock()  {
            if oneshot_channels_by_probe_id.contains_key(&id) {
                return false;
            }
            oneshot_channels_by_probe_id.insert(id, oneshot_sender_channel);
            return true;
        }
            
        false
    }

    fn is_sniffing(&self) -> bool {
        match self.is_sniffing.lock() {
            Ok(is_sniffing) => *is_sniffing,
            Err(error) => panic!("Unable to acquire lock (is_sniffing - ICMP): {:?}", error)
        }
    }

    fn stop(&self) -> io::Result<()> {
        self.set_is_sniffing(false);
        self.socket.shutdown(Shutdown::Both)
    }
}

impl ObservableIcmpProbeResponseSniffer {
    const BUFFER_SIZE: usize = 1024;

    pub fn new(probe_response_parser: Box<dyn ProbeResponseParser>) -> io::Result<Self> {
        Ok(ObservableIcmpProbeResponseSniffer {
            socket: AsyncSocket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?,
            oneshot_channels_by_probe_id: Mutex::new(HashMap::with_capacity(120)),
            probe_response_parser,
            is_sniffing: Mutex::new(false),
        })
    }

    fn set_is_sniffing(&self, value: bool) {
        match self.is_sniffing.lock() {
            Ok(mut is_sniffing) => *is_sniffing = value,
            Err(error) => panic!("Unable to acquire lock (set_is_sniffing - ICMP): {:?}", error)
        };
    }
}
