use std::collections::HashMap;
use std::net::Ipv4Addr;

use futures::pin_mut;
use futures_util::StreamExt;

use crate::traceroute::probe::ProbeResult;
use crate::traceroute::Traceroute;

type Ttl = u8;

pub struct TracerouteTerminal {
    traceroute: Traceroute,
    current_ttl: u8,
    nqueries: u16,
    max_ttl: u8,
    hop_by_ttl: HashMap<Ttl, PrintableHop>,
}

impl TracerouteTerminal {
    pub fn new(traceroute: Traceroute) -> Self {
        let nqueries = traceroute.get_nqueries();
        let max_ttl = traceroute.get_max_ttl();
        Self {
            traceroute,
            current_ttl: 1,
            nqueries,
            max_ttl,
            hop_by_ttl: HashMap::with_capacity(max_ttl as usize)
        }
    }
    
    pub async fn print_trace(mut self) {
        let traceroute_stream= self.traceroute.trace();
        pin_mut!(traceroute_stream);

        let mut skip = true;
        self.hop_by_ttl.insert(1, PrintableHop::new(1));
        Self::print_current_hop_index(self.current_ttl);

        'outer: while let Some(probe_result) = traceroute_stream.next().await {
            let ttl = match probe_result {
                Ok(probe_result) => {
                    let probe_result_ttl = probe_result.ttl();

                    let hop = self.hop_by_ttl
                        .entry(probe_result_ttl)
                        .or_insert(PrintableHop::new(probe_result_ttl));

                    hop.add_printable_probe_result(
                        PrintableProbeResult::ProbeResult {
                            probe_result,
                            printed: false
                        }
                    );

                    probe_result_ttl
                },
                Err(probe_error) => {
                    let probe_error_ttl = probe_error.get_ttl();

                    let hop = self.hop_by_ttl
                        .entry(probe_error_ttl)
                        .or_insert(PrintableHop::new(probe_error_ttl));

                    hop.add_printable_probe_result(
                        PrintableProbeResult::Timeout {
                            printed: false
                        }
                    );

                    probe_error_ttl
                },
            };

            if ttl > self.current_ttl && skip {
                skip = false;
                
                for current_ttl in self.current_ttl+1..=ttl {
                    for _ in 0..self.nqueries {
                        print!("* ");
                    }

                    println!();
                    Self::print_current_hop_index(current_ttl);
                }
                
                self.current_ttl = ttl;
            }

            while let Some(hop) = self.hop_by_ttl.get_mut(&self.current_ttl) {
                hop.print();

                if hop.tot_completed_queries() == self.nqueries as usize {
                    self.current_ttl += 1;

                    if self.current_ttl > self.max_ttl {
                        break 'outer;
                    } else {
                        println!();
                        Self::print_current_hop_index(self.current_ttl);
                    }
                } else {
                    break;
                }
            }
        }

        println!()
    }
    fn print_current_hop_index(ttl: u8) {
        if ttl < 10 {
            print!(" {}  ", ttl);
        } else {
            print!("{}  ", ttl);
        }
    }
}

enum PrintableProbeResult {
    Timeout { printed: bool },
    ProbeResult { probe_result: ProbeResult, printed: bool },
}


impl PrintableProbeResult {
    fn mark_as_printed(&mut self) {
        let printed = match self {
            PrintableProbeResult::Timeout { ref mut printed } => printed,
            PrintableProbeResult::ProbeResult {ref mut printed, .. } => printed,
        };
        
        *printed = true;
    }

    fn is_printed(&self) -> bool {
        match self {
            PrintableProbeResult::Timeout { printed } => *printed,
            PrintableProbeResult::ProbeResult { printed, .. } => *printed
        }
    }
}

struct PrintableHop {
    ttl: u8,
    probe_results: Vec<PrintableProbeResult>,
    printed_hostnames: Vec<String>,
    printed_ip_addr: Vec<Ipv4Addr>,
}

impl PrintableHop {
    fn new(ttl: u8) -> PrintableHop {
        Self {
            ttl,
            probe_results: Vec::with_capacity(10),
            printed_hostnames: Vec::with_capacity(10),
            printed_ip_addr: Vec::with_capacity(10),
        }
    }

    fn add_printable_probe_result(&mut self, printable_probe_result: PrintableProbeResult) {
        self.probe_results.push(printable_probe_result)
    }

    fn tot_completed_queries(&self) -> usize {
        self.probe_results.len()
    }

    fn print(&mut self) {
        let printed_hostnames = &mut self.printed_hostnames;
        let printed_ip_addr = &mut self.printed_ip_addr;

        for printable_probe_result in self.probe_results.iter_mut() {
            if printable_probe_result.is_printed() {
                continue;
            }

            printable_probe_result.mark_as_printed();

            match printable_probe_result {
                PrintableProbeResult::Timeout { .. } => {
                    print!("* ");
                },
                PrintableProbeResult::ProbeResult { probe_result, .. } => {
                    let rtt = probe_result.rtt();
                    let hostname = probe_result.get_hostname();
                    if hostname.is_none() || printed_hostnames.contains(&hostname.as_ref().unwrap()) {
                        if printed_ip_addr.contains(&probe_result.from_address()) {
                            let mut rtt_micros = rtt.as_micros().to_string();
                            rtt_micros.insert(2, '.');
                            print!("{:2} ms  ", rtt_micros);
                        } else {
                            print!("{probe_result}  ");
                            printed_ip_addr.push(probe_result.from_address());
                        }
                    } else {
                        print!("{probe_result}  ");
                        printed_hostnames.push(hostname.unwrap());
                        printed_ip_addr.push(probe_result.from_address());
                    }
                }
            }
        }
    }
}