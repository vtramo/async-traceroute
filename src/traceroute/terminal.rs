use std::fmt::Display;

// 
// pub struct TracerouteDisplayableHop {
//     id: u16,
//     tot_queries: u16,
//     results: Vec<ProbeResult>
// }
// 
// impl TracerouteDisplayableHop {
//     pub fn new(id: u16, tot_queries: u16) -> Self {
//         Self {
//             id,
//             tot_queries,
//             results: Vec::with_capacity(tot_queries as usize)
//         }
//     }
// 
//     pub fn add_result(&mut self, hop_result: ProbeResult) {
//         if self.results.len() as u16 == self.tot_queries {
//             panic!()
//         }
// 
//         self.results.push(hop_result);
//     }
// 
//     pub fn contains_address(&self, address: &IpAddr) -> bool {
//         let address_ipv4 = match address {
//             IpAddr::V4(ipv4) => ipv4,
//             IpAddr::V6(ipv6) => &Ipv4Addr::UNSPECIFIED,
//         };
// 
//         self.results
//             .iter()
//             .find(|&hop_result| hop_result.from_address.eq(address_ipv4))
//             .is_some()
//     }
// 
//     pub fn get_status(&self) -> TracerouteHopStatus {
//         let tot_results = self.results.len() as u16;
//         if tot_results == 0 {
//             NoReply
//         } else if tot_results == self.tot_queries {
//             Completed
//         } else {
//             PartiallyCompleted
//         }
//     }
// }
// 
// impl Display for TracerouteDisplayableHop {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         let hop_id = self.id;
//         write!(f, "{hop_id} - ")?;
//         match self.get_status() {
//             Completed | PartiallyCompleted => {
//                 for hop_result in &self.results {
//                     let addr = hop_result.from_address;
//                     let rtt_ms = hop_result.rtt.as_secs_f64() * 1000f64;
// 
//                     write!(f, "{addr} {:.5} ms | ", rtt_ms)?;
//                 }
//                 writeln!(f, "")?;
//             },
//             NoReply => {
//                 writeln!(f, "*")?;
//             }
//         }
// 
//         Ok(())
//     }
// }
// 
// 
// pub struct TracerouteTerminal {
//     hops: u16,
//     queries_per_hop: u16,
//     traceroute: Traceroute,
//     current_hop_id: u16,
//     timeout: Duration,
//     destination_address: IpAddr,
//     displayable_hop_by_id: HashMap<u16, TracerouteDisplayableHop>,
// }
// 
// impl TracerouteTerminal {
//     pub fn new(
//         host: &str, 
//         hops: u16, 
//         queries_per_hop: u16, 
//         traceroute: Traceroute,
//         timeout: u64,
//     ) -> Result<Self, TracerouteError> {
//         let timeout = Duration::from_secs(timeout);
//         let destination_address = dns::nslookup(&host)
//             .ok_or_else(|| TracerouteError::HostnameNotResolved(host.to_string()))?;
// 
//         Ok(Self {
//             hops,
//             queries_per_hop,
//             traceroute,
//             current_hop_id: 1,
//             timeout,
//             destination_address,
//             displayable_hop_by_id: HashMap::with_capacity(hops as usize)
//         })
//     }
// 
//     pub fn start(&mut self) {
//         let (sender, receiver) = mpsc::channel();
// 
//         let traceroute = Traceroute::new(
//             self.hops,
//             self.queries_per_hop,
//             ttl_packet_sender,
//             sender
//         );
// 
//         thread::spawn(move || {
//             traceroute.traceroute();
//         });
// 
//         self.display(receiver);
//     }
// 
//     fn display(&mut self, channel: Receiver<ProbeResult>) {
//         let mut timeout = self.timeout;
//         let mut stop = false;
//         
//         while !stop && self.current_hop_id <= self.hops {
//             let current_displayable_hop = self.displayable_hop_by_id
//                 .entry(self.current_hop_id)
//                 .or_insert(TracerouteDisplayableHop::new(
//                     self.current_hop_id,
//                     self.queries_per_hop));
// 
//             match current_displayable_hop.get_status() {
//                 Completed => {
//                     if current_displayable_hop.contains_address(&self.destination_address) {
//                         stop = true;
//                     }
// 
//                     self.print_current_displayable_hop();
//                     self.current_hop_id += 1;
//                     continue;
//                 },
//                 _ => (),
//             }
// 
//             let start_recv_time = Instant::now();
//             match channel.recv_timeout(timeout) {
//                 Ok(hop_result) => {
//                     let hop_id = hop_result.id;
//                     let displayable_hop = self.displayable_hop_by_id
//                         .entry(hop_id)
//                         .or_insert(TracerouteDisplayableHop::new(
//                             hop_id,
//                             self.queries_per_hop));
//                     displayable_hop.add_result(hop_result);
// 
//                     match displayable_hop.get_status() {
//                         Completed => {
//                             if hop_id == self.current_hop_id {
//                                 if displayable_hop.contains_address(&self.destination_address) {
//                                     stop = true;
//                                 }
// 
//                                 self.print_current_displayable_hop();
//                                 self.current_hop_id += 1;
//                                 timeout = self.timeout;
//                             }
//                         },
//                         PartiallyCompleted | NoReply => {
//                             let elapsed = start_recv_time.elapsed();
//                             timeout = timeout.saturating_sub(elapsed);
//                         },
//                     }
//                 },
//                 Err(_) => {
//                     if current_displayable_hop.contains_address(&self.destination_address) {
//                         stop = true;
//                     }
// 
//                     self.print_current_displayable_hop();
//                     self.current_hop_id += 1;
//                     timeout = self.timeout;
//                 },
//             }
//         }
//     }
// 
//     fn reach_hop_by_force(&mut self, hop_id: u16) {
//         if self.current_hop_id >= hop_id {
//             panic!()
//         }
// 
//         for _ in self.current_hop_id..hop_id {
//             self.print_current_displayable_hop();
//             self.current_hop_id += 1;
//         }
//     }
// 
//     fn print_current_displayable_hop(&self) {
//         let current_hop_id = &self.current_hop_id;
//         let hop_string = self.displayable_hop_by_id
//             .get(current_hop_id)
//             .map(|current_displayable_hop| current_displayable_hop.to_string())
//             .unwrap_or(format!("{current_hop_id} - * * * * *\n"));
// 
//         print!("{hop_string}");
//     }
// 
//     fn is_destination_address(&self, address: &Ipv4Addr) -> bool {
//         self.destination_address.eq(address)
//     }
// }