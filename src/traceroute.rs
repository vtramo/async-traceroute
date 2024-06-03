use std::{io, thread};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::io::Error;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use libpacket::ip::IpNextHeaderProtocols::Udp;
use libpacket::ipv4::Ipv4;
use libpacket::ipv6::Ipv6;
use rand::Rng;
use rand::rngs::ThreadRng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use TracerouteHopStatus::{Completed, NoReply, PartiallyCompleted};

use crate::bytes::ToBytes;
use crate::packet_utils;
use crate::TracerouteOptions;

pub struct RandomUniquePort {
    generated_ports: HashSet<u16>,
    rng: ThreadRng
}

impl RandomUniquePort {
    pub fn new() -> Self {
        Self {
            generated_ports: HashSet::with_capacity(10),
            rng: rand::thread_rng()
        }
    }

    pub fn generate_ports(&mut self, tot_ports: u16) -> HashSet<u16> {
        let mut generated_ports = HashSet::with_capacity(tot_ports as usize);

        for _ in 0..tot_ports {
            let generated_port = self.generate_port();
            generated_ports.insert(generated_port);
        }

        generated_ports
    }

    pub fn generate_port(&mut self) -> u16 {
        let mut generated_port: u16 = 0;

        let mut not_found = true;
        while not_found {
            generated_port = self.rng.gen_range(0..=65535);
            not_found = self.generated_ports.contains(&generated_port);
        }

        self.generated_ports.insert(generated_port);
        generated_port
    }
}

pub struct TracerouteHop {
    id: u16,
    sent_at: Instant,
    query_ids: HashSet<u16>
}

impl TracerouteHop {
    pub fn new(id: u16, query_ids: HashSet<u16>) -> Self {
        let tot_source_ports = query_ids.len();
        if tot_source_ports == 0 {
            panic!()
        }

        Self {
            id,
            sent_at: Instant::now(),
            query_ids
        }
    }

    pub fn complete_query(&mut self, hop_response: TracerouteHopResponse) -> Option<TracerouteHopResult> {
        if hop_response.id != self.id {
            return None;
        }

        let hop_response_query_id = hop_response.query_id;
        if !self.query_ids.contains(&hop_response_query_id) {
            return None;
        }

        self.query_ids.remove(&hop_response_query_id);
        Some(TracerouteHopResult { id: hop_response.id, address: hop_response.address, rtt: self.sent_at.elapsed() })
    }
}

pub struct TracerouteDisplayableHop {
    id: u16,
    tot_queries: u16,
    results: Vec<TracerouteHopResult>
}

impl TracerouteDisplayableHop {
    pub fn new(id: u16, tot_queries: u16) -> Self {
        Self {
            id,
            tot_queries,
            results: Vec::with_capacity(tot_queries as usize)
        }
    }
    
    pub fn add_result(&mut self, hop_result: TracerouteHopResult) {
        if self.results.len() as u16 == self.tot_queries {
            panic!()
        }
        
        self.results.push(hop_result);
    }

    pub fn contains_address(&self, address: &IpAddr) -> bool {
        let address_ipv4 = match address {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(ipv6) => &Ipv4Addr::UNSPECIFIED,
        };

        self.results
            .iter()
            .find(|&hop_result| hop_result.address.eq(address_ipv4))
            .is_some()
    }
    
    pub fn get_status(&self) -> TracerouteHopStatus {
        let tot_results = self.results.len() as u16;
        if tot_results == 0 {
            NoReply
        } else if tot_results == self.tot_queries {
            Completed
        } else {
            PartiallyCompleted
        }
    }

    pub fn get_address(&self) -> Option<Ipv4Addr> {
        self.results
            .get(0)
            .map(|result| result.address)
    }
}

impl Display for TracerouteDisplayableHop {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let hop_id = self.id;
        write!(f, "{hop_id} - ")?;
        match self.get_status() {
            Completed | PartiallyCompleted => {
                for hop_result in &self.results {
                    let addr = hop_result.address;
                    let rtt_ms = hop_result.rtt.as_secs_f64() * 1000f64;

                    write!(f, "{addr} {:.5} ms | ", rtt_ms)?;
                }
                writeln!(f, "")?;
            },
            NoReply => {
                writeln!(f, "* * * * *")?;
            }
        }
        
        Ok(())
    }
}

pub enum TracerouteHopStatus {
    Completed,
    PartiallyCompleted,
    NoReply
}

pub struct TracerouteHopResult {
    pub id: u16,
    pub address: Ipv4Addr,
    pub rtt: Duration
}

pub struct TracerouteHopResponse {
    pub id: u16,
    pub address: Ipv4Addr,
    pub query_id: u16,
}

pub trait TracerouteTtlPacketSender: Send {
    fn send(
        &mut self,
        ttl: u8,
    ) -> Result<TracerouteHop, Error>;
}

pub enum IpDatagram {
    V4(Ipv4), V6(Ipv6)
}

impl ToBytes for IpDatagram {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            IpDatagram::V4(ipv4_datagram) => ipv4_datagram.to_bytes(),
            IpDatagram::V6(ipv6_datagram) => todo!()
        }
    }
}

impl IpDatagram {
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

struct UdpTracerouteTtlPacketSender {
    socket: Socket,
    destination_address: IpAddr,
    destination_port: u16,
    queries_per_hop: u16,
}

impl UdpTracerouteTtlPacketSender {
    pub fn new(
        destination_address: IpAddr,
        initial_destination_port: u16,
        queries_per_hop: u16,
    ) -> Self {
        Self {
            socket: Self::build_socket(
                if destination_address.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                }
            ),
            destination_address,
            destination_port: initial_destination_port,
            queries_per_hop
        }
    }

    fn build_socket(domain: Domain) -> Socket {
        let socket_udp = Socket::new(domain, Type::RAW, Some(Protocol::UDP)).unwrap();
        socket_udp.set_header_included(true).unwrap();
        socket_udp
    }

    fn build_empty_ip_datagram_with_ttl(&self, ttl: u8) -> IpDatagram {
        match self.destination_address {
            IpAddr::V4(ipv4_address) => {
                IpDatagram::V4(Self::build_empty_ipv4_datagram_with_ttl(ttl, ipv4_address))
            },
            IpAddr::V6(ipv6_address) => {
                IpDatagram::V6(Self::build_empty_ipv6_datagram_with_ttl(ttl, ipv6_address))
            }
        }
    }

    fn build_empty_ipv4_datagram_with_ttl(ttl: u8, destination_address: Ipv4Addr) -> Ipv4 {
        Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 28,
            identification: ttl as u16,
            flags: 0,
            fragment_offset: 0,
            ttl,
            next_level_protocol: Udp,
            checksum: 0,
            source: Ipv4Addr::UNSPECIFIED,
            destination: destination_address,
            options: vec![],
            payload: vec![]
        }
    }

    fn build_empty_ipv6_datagram_with_ttl(ttl: u8, destination_address: Ipv6Addr) -> Ipv6 {
        todo!()
    }

    fn generate_source_ports(&self) -> HashSet<u16> {
        let mut random_unique_port_gen = RandomUniquePort::new();
        random_unique_port_gen.generate_ports(self.queries_per_hop)
    }

    fn build_destination_sock_address(&self) -> SockAddr {
        let destination_address_str = self.destination_address.to_string();
        let destination_port = &self.destination_port;
        SocketAddr::from_str(&format!("{destination_address_str}:{destination_port}")).unwrap().into()
    }
}

impl TracerouteTtlPacketSender for UdpTracerouteTtlPacketSender {
    fn send(
        &mut self,
        ttl: u8,
    ) -> Result<TracerouteHop, Error> {
        let mut ip_datagram = self.build_empty_ip_datagram_with_ttl(ttl);
        let source_ports = self.generate_source_ports();
        let traceroute_hop = TracerouteHop::new(ttl as u16, source_ports.clone());

        for source_port in source_ports {
            let udp_datagram = packet_utils::build_udp_datagram_with_ports(source_port, self.destination_port);
            let udp_datagram_bytes = udp_datagram.to_bytes();
            ip_datagram.set_payload(&udp_datagram_bytes);
            ip_datagram.set_length(20 + udp_datagram_bytes.len() as u16);

            let socket_addr: SockAddr = self.build_destination_sock_address();
            self.socket.send_to(&ip_datagram.to_bytes(), &socket_addr)?;
            self.destination_port += 1;
        }

        Ok(traceroute_hop)
    }
}

pub struct Traceroute {
    destination_address: Ipv4Addr,
    hops: u16,
    queries_per_hop: u16,
    destination_port: u16,
    ttl_packet_sender: Box<dyn TracerouteTtlPacketSender>,
    channel: Sender<TracerouteHopResult>,
    hops_by_id: HashMap<u16, TracerouteHop>,
}

impl Traceroute {
    const MAX_TTL_PACKETS_AT_ONCE: u16 = 10;

    pub fn new(
        destination_address: Ipv4Addr,
        hops: u16,
        queries_per_hop: u16,
        initial_destination_port: u16,
        ttl_packet_sender: Box<dyn TracerouteTtlPacketSender>,
        channel: Sender<TracerouteHopResult>,
    ) -> Self {
        Self {
            destination_address,
            hops,
            queries_per_hop,
            destination_port: initial_destination_port,
            ttl_packet_sender,
            channel,
            hops_by_id: HashMap::with_capacity(hops as usize)
        }
    }

    pub fn traceroute(mut self) -> Result<(), io::Error> {
        let (sender, receiver) = mpsc::channel();
        Self::start_icmp_receiver(sender);

        let mut ttl_counter = min(Self::MAX_TTL_PACKETS_AT_ONCE, self.hops * self.queries_per_hop);
        for ttl in 1..=ttl_counter {
            let hop = self.ttl_packet_sender.send(ttl as u8)?;
            self.hops_by_id.insert(hop.id, hop);
        }

        while let Ok(traceroute_hop_response) = receiver.recv() {
            ttl_counter += 1;
            self.ttl_packet_sender.send(ttl_counter as u8)?;
            let hop_response_id = &traceroute_hop_response.id;
            if let Some(hop) = self.hops_by_id.get_mut(hop_response_id) {
                if let Some(hop_result) = hop.complete_query(traceroute_hop_response) {
                    self.channel.send(hop_result).unwrap();
                }
            }
        }

        Ok(())
    }

    fn start_icmp_receiver(sender: Sender<TracerouteHopResponse>) {
        thread::spawn(move || {
            let mut icmp_receiver = TracerouteIcmpReceiver::new(sender);
            icmp_receiver.capture();
        });
    }
}

fn nslookup(hostname: &str) -> Option<IpAddr> {
    let sock_addrs = format!("{hostname}:1234").to_socket_addrs();
    if sock_addrs.is_err() {
        return None;
    }
    let mut sock_addrs = sock_addrs.unwrap();
    sock_addrs.next().map(|sock_addr| sock_addr.ip())
}

pub enum TracerouteProtocol {
    UDP(UdpTracerouteTtlPacketSender),
    TCP,
    ICMP
}

pub struct TracerouteTerminal {
    traceroute_options: TracerouteOptions,
    current_hop_id: u16,
    timeout: Duration,
    destination_address: IpAddr,
    displayable_hop_by_id: HashMap<u16, TracerouteDisplayableHop>,
}

pub enum TracerouteError {
    HostnameNotResolved(String)
}

impl TracerouteTerminal {
    pub fn new(traceroute_options: TracerouteOptions) -> Result<Self, TracerouteError> {
        let tot_hops = traceroute_options.hops;
        let timeout = Duration::from_secs(traceroute_options.wait as u64);
        let hostname = traceroute_options.host.clone();
        let destination_address = nslookup(&hostname)
            .ok_or_else(|| TracerouteError::HostnameNotResolved(hostname))?;

        Ok(Self {
            traceroute_options,
            current_hop_id: 1,
            timeout,
            destination_address,
            displayable_hop_by_id: HashMap::with_capacity(tot_hops as usize)
        })
    }

    pub fn start(&mut self) {
        let (sender, receiver) = mpsc::channel();

        let initial_destination_port = self.traceroute_options.initial_destination_port;
        let queries_per_hop = self.traceroute_options.queries_per_hop;
        let ttl_packet_sender = Box::new(UdpTracerouteTtlPacketSender::new(
            self.destination_address,
            initial_destination_port,
            queries_per_hop
        ));
        let traceroute = Traceroute::new(
            Ipv4Addr::from_str(&self.destination_address.to_string()).unwrap(),
            self.traceroute_options.hops,
            queries_per_hop,
            initial_destination_port,
            ttl_packet_sender,
            sender
        );

        thread::spawn(move || {
            traceroute.traceroute();
        });

        self.display(receiver);
    }

    fn display(&mut self, channel: Receiver<TracerouteHopResult>) {
        let mut timeout = self.timeout;
        let mut stop = false;

        let hops = self.traceroute_options.hops;
        while !stop && self.current_hop_id <= hops {
            let current_displayable_hop = self.get_or_default_displayable_hop(self.current_hop_id);
            let current_hop_address = current_displayable_hop.get_address().unwrap_or(Ipv4Addr::UNSPECIFIED);
            match current_displayable_hop.get_status() {
                Completed => {
                    if self.is_destination_address(&current_hop_address) {
                        stop = true;
                    }

                    self.print_current_displayable_hop();
                    self.current_hop_id += 1;
                    continue;
                },
                _ => (),
            }

            let start_recv_time = Instant::now();
            match channel.recv_timeout(timeout) {
                Ok(hop_result) => {
                    let hop_id = hop_result.id;
                    let displayable_hop = self.get_or_default_displayable_hop(hop_id);
                    displayable_hop.add_result(hop_result);

                    match displayable_hop.get_status() {
                        Completed => {
                            if hop_id == self.current_hop_id {
                                if self.is_destination_address(&current_hop_address) {
                                    stop = true;
                                }

                                self.print_current_displayable_hop();
                                self.current_hop_id += 1;
                                timeout = self.timeout;
                            }
                        },
                        PartiallyCompleted | NoReply => {
                            let elapsed = start_recv_time.elapsed();
                            timeout = timeout.saturating_sub(elapsed);
                        },
                    }
                },
                Err(_) => {
                    if self.is_destination_address(&current_hop_address) {
                        stop = true;
                    }

                    self.print_current_displayable_hop();
                    self.current_hop_id += 1;
                    timeout = self.timeout;
                },
            }
        }
    }

    fn reach_hop_by_force(&mut self, hop_id: u16) {
        if self.current_hop_id >= hop_id {
            panic!()
        }

        for _ in self.current_hop_id..hop_id {
            self.print_current_displayable_hop();
            self.current_hop_id += 1;
        }
    }

    fn get_or_default_displayable_hop(&mut self, hop_id: u16) -> &mut TracerouteDisplayableHop {
        self.displayable_hop_by_id
            .entry(hop_id)
            .or_insert(TracerouteDisplayableHop::new(
                hop_id,
                self.traceroute_options.queries_per_hop))
    }

    fn print_current_displayable_hop(&self) {
        let current_hop_id = &self.current_hop_id;
        let hop_string = self.displayable_hop_by_id
            .get(current_hop_id)
            .map(|current_displayable_hop| current_displayable_hop.to_string())
            .unwrap_or(format!("{current_hop_id} - * * * * *\n"));

        print!("{hop_string}");
    }

    fn is_destination_address(&self, address: &Ipv4Addr) -> bool {
        self.destination_address.eq(address)
    }
}

pub struct TracerouteIcmpReceiver {
    socket: Socket,
    buffer: [MaybeUninit<u8>; 100],
    channel: Sender<TracerouteHopResponse>,
    is_listening: bool,
}

impl TracerouteIcmpReceiver {
    pub fn new(channel: Sender<TracerouteHopResponse>) -> Self {
        TracerouteIcmpReceiver {
            socket: Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap(),
            buffer: [MaybeUninit::new(0); 100],
            channel,
            is_listening: false
        }
    }

    pub fn capture(&mut self) {
        if self.is_listening {
            panic!("")
        }
        self.is_listening = true;

        loop {
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

            let ipv4_header = match packet_utils::extract_ipv4_header_from_icmp_response(&icmp_packet) {
                Some(ipv4_header) => ipv4_header,
                None => continue
            };

            let udp_header = match packet_utils::extract_udp_header_from_icmp_response(&icmp_packet) {
                Some(udp_header) => udp_header,
                None => continue
            };

            let hop_response_id = ipv4_header.identification;
            let node_address = ipv4_datagram.source;
            let port = udp_header.source;

            match self.channel.send(TracerouteHopResponse {
                id: hop_response_id,
                address: node_address,
                query_id: port
            }) {
                Ok(_) => continue,
                Err(_) => panic!("")
            };
        }
    }

    fn map_buffer_to_vec_u8(&self) -> Vec<u8> {
        self.buffer
            .iter()
            .map(|maybe_uninit| unsafe { maybe_uninit.assume_init_read() })
            .collect()
    }
}