use std::cell::RefCell;
use std::cmp::min;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use futures::Stream;
use tokio::select;
use tokio::task::JoinSet;

use crate::traceroute::probe::{ProbeError, ProbeResponse, ProbeResult};
use crate::traceroute::probe::generator::ProbeTaskGenerator;
use crate::traceroute::probe::sniffer::ObservableIcmpSniffer;
use crate::traceroute::utils::dns;

pub mod utils;
pub mod terminal;
pub mod probe;
mod async_socket;
pub mod builder;

pub struct Traceroute {
    source_address: IpAddr,
    destination_address: IpAddr,
    max_ttl: u8,
    nqueries: u16,
    sim_queries: u16,
    max_wait_probe: Duration,
    is_active_dns_lookup: bool,
    current_ttl: RefCell<u8>,
    current_query: RefCell<u16>,
    probe_task_generator: RefCell<Box<dyn ProbeTaskGenerator>>,
    observable_icmp_sniffer: Arc<Box<dyn ObservableIcmpSniffer<Response = ProbeResponse> + Send + Sync>>,
}

impl Traceroute {
    pub fn new(
        source_address: IpAddr,
        destination_address: IpAddr,
        max_ttl: u8,
        nqueries: u16,
        sim_queries: u16,
        max_wait_probe: Duration,
        is_active_dns_lookup: bool,
        probe_task_generator: Box<dyn ProbeTaskGenerator>,
        observable_icmp_sniffer: Box<dyn ObservableIcmpSniffer<Response=ProbeResponse> + Send + Sync>
    ) -> Self {
        Self {
            source_address,
            destination_address,
            max_ttl,
            nqueries,
            sim_queries: min(sim_queries, (max_ttl as u16) * nqueries),
            max_wait_probe,
            is_active_dns_lookup,
            current_ttl: RefCell::new(1),
            current_query: RefCell::new(1),
            probe_task_generator: RefCell::new(probe_task_generator),
            observable_icmp_sniffer: Arc::new(observable_icmp_sniffer),
        }
    }

    pub fn trace(self) -> impl Stream<Item=Result<ProbeResult, ProbeError>> {
        let mut probe_tasks = JoinSet::new();

        for _ in 0..self.sim_queries {
            let probe_task = self.generate_probe_task();
            self.increment_ttl_query_counter();
            probe_tasks.spawn(probe_task);
        }

        let observable_icmp_sniffer = Arc::clone(&self.observable_icmp_sniffer);
        tokio::spawn(async move {
            observable_icmp_sniffer.sniff().await
        });

        let mut stop_send_probes = false;
        let mut query_count_by_ttl = HashMap::<u8, u16>::new();
        let mut ttl_target_address = u8::MAX;
        let mut target_address_found = false;

        stream! {
            loop {
                if *self.current_ttl.borrow() > self.max_ttl {
                    stop_send_probes = true;
                }

                select! {
                    Some(Ok(probe_result)) = probe_tasks.join_next() => {
                        let (probe_result, ttl) = match probe_result {
                            Ok(mut probe_result) => {
                                if self.is_active_dns_lookup {
                                    Self::reverse_dns_lookup(&mut probe_result).await;
                                }

                                if !target_address_found && probe_result.from_address() == self.destination_address {
                                    ttl_target_address = probe_result.ttl();
                                    target_address_found = true;
                                }

                                let ttl = probe_result.ttl();
                                (Ok(probe_result), ttl)
                            },
                            Err(probe_error) => {
                                let ttl = probe_error.get_ttl();
                                (Err(probe_error), ttl)
                            },
                        };

                        let query_count = query_count_by_ttl
                            .entry(ttl)
                            .or_insert(0);
                        *query_count += 1;

                        if ttl <= ttl_target_address {
                            yield probe_result;
                        }

                        if ttl == ttl_target_address && *query_count == self.nqueries {
                            stop_send_probes = true;
                        }

                        if !stop_send_probes {
                            let probe_task = self.generate_probe_task();

                            self.increment_ttl_query_counter();
                            probe_tasks.spawn(probe_task);
                        }
                    },
                    else => break
                }
            }
        }
    }

    fn generate_probe_task(&self) -> Pin<Box<impl Future<Output=Result<ProbeResult, ProbeError>>>> {
        let mut probe_task_generator = self.probe_task_generator.borrow_mut();
        match probe_task_generator.generate_probe_task(
            self.source_address,
            self.destination_address,
            &**self.observable_icmp_sniffer,
        ) {
            Ok((_, mut probe_task)) => {
                let current_ttl = *self.current_ttl.borrow();
                let timeout = self.max_wait_probe;
                let probe_task_future = Box::pin(async move {
                    probe_task.send_probe(current_ttl, timeout).await
                });
                probe_task_future
            }
            Err(io_error) => panic!("Failed to send a traceroute probe ({:?})", io_error.kind())
        }
    }

    fn increment_ttl_query_counter(&self) {
        let mut current_query = self.current_query.borrow_mut();
        *current_query += 1;
        if *current_query > self.nqueries {
            *current_query = 1;
            let mut current_ttl = self.current_ttl.borrow_mut();
            *current_ttl += 1;
        }
    }

    async fn reverse_dns_lookup(probe_result: &mut ProbeResult) {
        let ip_addr = &IpAddr::V4(probe_result.from_address());
        if let Some(hostname) = dns::reverse_dns_lookup_first_hostname(ip_addr).await {
            probe_result.set_hostname(&hostname);
        }
    }

    pub fn get_nqueries(&self) -> u16 {
        self.nqueries
    }

    pub fn get_max_ttl(&self) -> u8 {
        self.max_ttl
    }
}