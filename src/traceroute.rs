use std::{sync, thread};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use libpacket::FromPacket;
use libpacket::icmp::{Icmp, IcmpPacket};
use libpacket::ip::IpNextHeaderProtocol;
use libpacket::ipv4::{Ipv4, Ipv4Packet};
use libpacket::udp::{Udp, UdpPacket};
use rand::Rng;
use rand::rngs::ThreadRng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use TracerouteHopStatus::{Completed, NoReply, PartiallyCompleted};

use crate::bytes::ToBytes;
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
    ports: HashSet<u16>
}

impl TracerouteHop {
    pub fn new(id: u16, source_ports: HashSet<u16>) -> Self {
        let tot_source_ports = source_ports.len();
        if tot_source_ports == 0 {
            panic!()
        }

        Self {
            id,
            sent_at: Instant::now(),
            ports: source_ports
        }
    }

    pub fn complete_query(&mut self, hop_response: TracerouteHopResponse) -> Option<TracerouteHopResult> {
        if hop_response.id != self.id {
            return None;
        }

        let hop_response_port = hop_response.port;
        if !self.ports.contains(&hop_response_port) {
            return None;
        }

        self.ports.remove(&hop_response_port);
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
    pub port: u16,
}

pub struct Traceroute {
    destination_address: Ipv4Addr,
    hops: u16,
    queries_per_hop: u16,
    destination_port: u16,
    channel: Sender<TracerouteHopResult>,
    hops_by_id: HashMap<u16, TracerouteHop>,
}

impl Traceroute {
    pub fn new(
        destination_address: Ipv4Addr,
        hops: u16,
        queries_per_hop: u16,
        initial_destination_port: u16,
        channel: Sender<TracerouteHopResult>,
    ) -> Self {
        Self {
            destination_address,
            hops,
            queries_per_hop,
            destination_port: initial_destination_port,
            channel,
            hops_by_id: HashMap::with_capacity(hops as usize)
        }
    }

    pub fn traceroute(mut self) {
        let (sender, receiver) = sync::mpsc::channel();

        thread::spawn(move || {
            let mut icmp_receiver = TracerouteIcmpReceiver::new(sender);
            icmp_receiver.capture();
        });

        let socket = self.build_socket();

        for ttl in 1..=self.hops {
            let ipv4_datagram = self.build_ipv4_datagram(ttl as u8);
            let source_ports = self.generate_source_ports();
            let traceroute_hop = TracerouteHop::new(ttl, source_ports.clone());
            self.hops_by_id.insert(traceroute_hop.id, traceroute_hop);
            
            for source_port in source_ports {
                let udp_segment = self.build_udp_segment(source_port);
                let packet = Self::encapsulate_udp_in_ipv4_as_bytes(&ipv4_datagram, &udp_segment);
                let socket_addr: SockAddr = self.build_destination_sock_address();
                socket.send_to(&packet, &socket_addr).unwrap();
                self.destination_port += 1;
            }
        }

        while let Ok(traceroute_hop_response) = receiver.recv() {
            let hop_response_id = &traceroute_hop_response.id;
            if let Some(hop) = self.hops_by_id.get_mut(hop_response_id) {
                if let Some(hop_result) = hop.complete_query(traceroute_hop_response) {
                    self.channel.send(hop_result).unwrap();
                }
            }
        }
    }

    fn build_socket(&self) -> Socket {
        let socket_udp = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)).unwrap();
        socket_udp.set_header_included(true).unwrap();
        socket_udp
    }

    fn build_ipv4_datagram(&self, ttl: u8) -> Ipv4 {
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
            next_level_protocol: IpNextHeaderProtocol::new(17),
            checksum: 0,
            source: Ipv4Addr::UNSPECIFIED,
            destination: self.destination_address,
            options: vec![],
            payload: vec![]
        }
    }

    fn generate_source_ports(&self) -> HashSet<u16> {
        let mut random_unique_port_gen = RandomUniquePort::new();
        random_unique_port_gen.generate_ports(self.queries_per_hop)
    }

    fn build_udp_segment(&self, source_port: u16) -> Udp {
        Udp {
            source: source_port,
            destination: self.destination_port,
            length: 8,
            checksum: 0,
            payload: vec![]
        }
    }

    fn encapsulate_udp_in_ipv4_as_bytes(ipv4_datagram: &Ipv4, udp_segment: &Udp) -> Vec<u8> {
        let udp_bytes = udp_segment.to_bytes();
        let mut ipv4_bytes = ipv4_datagram.to_bytes();
        ipv4_bytes.extend(udp_bytes);
        ipv4_bytes
    }

    fn build_destination_sock_address(&self) -> SockAddr {
        let destination_address_str = self.destination_address.to_string();
        let destination_port = &self.destination_port;
        SocketAddr::from_str(&format!("{destination_address_str}:{destination_port}")).unwrap().into()
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

pub struct TracerouteTerminal {
    traceroute_options: TracerouteOptions,
    current_hop: u16,
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
            current_hop: 1,
            timeout,
            destination_address,
            displayable_hop_by_id: HashMap::with_capacity(tot_hops as usize)
        })
    }

    pub fn start(&mut self) {
        let (sender, receiver) = mpsc::channel();

        let traceroute = Traceroute::new(
            Ipv4Addr::from_str(&self.destination_address.to_string()).unwrap(),
            self.traceroute_options.hops,
            self.traceroute_options.queries_per_hop,
            self.traceroute_options.initial_destination_port,
            sender
        );

        thread::spawn(move || {
            traceroute.traceroute();
        });

        self.display(receiver);
    }

    fn display(&mut self, channel: Receiver<TracerouteHopResult>) {
        let mut private_hop_ids = HashSet::with_capacity(self.traceroute_options.queries_per_hop as usize);
        let mut timeout = self.timeout;
        let mut private_address_encountered = false;
        let mut stop = false;

        while !stop {
            let current_displayable_hop = self.get_or_default_displayable_hop(self.current_hop);
            let current_hop_address = current_displayable_hop.get_address().unwrap_or(Ipv4Addr::UNSPECIFIED);
            match current_displayable_hop.get_status() {
                Completed => {
                    if self.is_destination_address(&current_hop_address) {
                        stop = true;
                    }

                    self.print_current_displayable_hop();
                    self.current_hop += 1;
                    continue;
                },
                _ => (),
            }

            let start_recv_time = Instant::now();
            match channel.recv_timeout(timeout) {
                Ok(hop_result) => {
                    if private_hop_ids.contains(&hop_result.id) {
                        continue;
                    }

                    if private_address_encountered {
                        private_address_encountered = false;
                        self.reach_hop_by_force(hop_result.id);
                        timeout = self.timeout;
                    }

                    if hop_result.address.is_private() {
                        private_hop_ids.insert(hop_result.id);
                        private_address_encountered = true;
                        if self.is_destination_address(&hop_result.address) {
                            stop = true;
                        }

                        self.print_current_displayable_hop();
                        self.current_hop += 1;
                        timeout = self.timeout;
                        continue;
                    }

                    let hop_id = hop_result.id;
                    let displayable_hop = self.get_or_default_displayable_hop(hop_id);
                    displayable_hop.add_result(hop_result);

                    match displayable_hop.get_status() {
                        Completed => {
                            if hop_id == self.current_hop {
                                if self.is_destination_address(&current_hop_address) {
                                    stop = true;
                                }

                                self.print_current_displayable_hop();
                                self.current_hop += 1;
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
                    self.current_hop += 1;
                    timeout = self.timeout;
                },
            }
        }
    }

    fn reach_hop_by_force(&mut self, hop_id: u16) {
        if self.current_hop >= hop_id {
            panic!()
        }

        for _ in self.current_hop..hop_id {
            self.print_current_displayable_hop();
            self.current_hop += 1;
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
        let current_hop_id = &self.current_hop;
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

            let ipv4_datagram = match Self::build_ipv4_datagram(&data) {
                Some(ipv4_datagram) => ipv4_datagram,
                None => continue,
            };

            let icmp_packet = match Self::build_icmpv4_packet(&ipv4_datagram.payload) {
                Some(ipv4_datagram) => ipv4_datagram,
                None => continue,
            };

            if !Self::is_icmp_ttl_expired(&icmp_packet) &&
               !Self::is_icmp_destination_port_unreachable(&icmp_packet) {
                continue;
            }

            let ipv4_header = match Self::extract_ipv4_header_from(&icmp_packet) {
                Some(ipv4_header) => ipv4_header,
                None => continue
            };

            let udp_header = match Self::extract_udp_header_from(&icmp_packet) {
                Some(udp_header) => udp_header,
                None => continue
            };

            let hop_response_id = ipv4_header.identification;
            let node_address = ipv4_datagram.source;
            let port = udp_header.source;

            match self.channel.send(TracerouteHopResponse {
                id: hop_response_id,
                address: node_address,
                port
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

    fn build_ipv4_datagram(data: &[u8]) -> Option<Ipv4> {
        let ipv4packet = Ipv4Packet::new(&data)?;
        Some(ipv4packet.from_packet())
    }

    fn build_icmpv4_packet(data: &[u8]) -> Option<Icmp> {
        let icmp_packet = IcmpPacket::new(data)?;
        Some(icmp_packet.from_packet())
    }

    fn is_icmp_ttl_expired(icmp_packet: &Icmp) -> bool {
        let icmp_type = icmp_packet.icmp_type.0;
        let icmp_code = icmp_packet.icmp_code.0;
        icmp_type == 11 && icmp_code == 0
    }

    fn is_icmp_destination_port_unreachable(icmp_packet: &Icmp) -> bool {
        let icmp_type = icmp_packet.icmp_type.0;
        let icmp_code = icmp_packet.icmp_code.0;
        icmp_type == 3 && icmp_code == 3
    }

    fn extract_ipv4_header_from(icmp_packet: &Icmp) -> Option<Ipv4> {
        let payload = &icmp_packet.payload;
        let payload: Vec<u8> = payload
            .into_iter()
            .skip_while(|byte| **byte != 69)
            .map(|byte| *byte)
            .collect();

        Self::build_ipv4_datagram(&payload[..20])
    }

    fn extract_udp_header_from(icmp_packet: &Icmp) -> Option<Udp> {
        let payload = &icmp_packet.payload;
        let payload: Vec<u8> = payload
            .into_iter()
            .skip_while(|byte| **byte != 69)
            .map(|byte| *byte)
            .collect();

        let udp_packet = UdpPacket::new(&payload[20..28])?;
        Some(udp_packet.from_packet())
    }
}