use std::cell::RefCell;
use std::cmp::min;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use async_stream::stream;
use futures_core::stream::Stream;
use tokio::select;
use tokio::task::JoinSet;
use crate::traceroute::icmp_sniffer::IcmpProbeResponseSniffer;
use crate::traceroute::probe::generator::ProbeTaskGenerator;
use crate::traceroute::probe::ProbeResult;

pub(crate) mod terminal;
pub mod icmp_sniffer;
pub mod probe;
mod utils;
mod tokio_socket;

pub enum TracerouteHopStatus {
    Completed,
    PartiallyCompleted,
    NoReply
}

pub enum TracerouteError {
    HostnameNotResolved(String)
}

pub struct Traceroute {
    ip_addr: IpAddr,
    max_ttl: u8,
    nqueries: u8,
    sim_queries: u16,
    max_wait_probe_ms: u64,
    current_ttl: Box<RefCell<u8>>,
    current_query: Box<RefCell<u8>>,
    probe_task_generator: Box<RefCell<Box<dyn ProbeTaskGenerator>>>,
    icmp_probe_response_sniffer: Arc<IcmpProbeResponseSniffer>,
}

impl Traceroute {
    pub fn new(
        ip_addr: IpAddr,
        max_ttl: u8,
        nqueries: u8,
        sim_queries: u16,
        max_wait_probe_ms: u64,
        probe_task_generator: Box<dyn ProbeTaskGenerator>,
        icmp_probe_response_sniffer: IcmpProbeResponseSniffer
    ) -> Self {
        Self {
            ip_addr,
            max_ttl,
            nqueries,
            sim_queries: min(sim_queries, (max_ttl * nqueries) as u16),
            max_wait_probe_ms,
            current_ttl: Box::new(RefCell::new(1)),
            current_query: Box::new(RefCell::new(1)),
            probe_task_generator: Box::new(RefCell::new(probe_task_generator)),
            icmp_probe_response_sniffer: Arc::new(icmp_probe_response_sniffer),
        }
    }
    
    pub fn trace(self) -> impl Stream<Item = Result<ProbeResult, String>> {
        let mut probe_tasks = JoinSet::new();

        for _ in 0..self.sim_queries {
            let probe_task = self.generate_probe_task(&self.icmp_probe_response_sniffer);
            probe_tasks.spawn(probe_task);
            self.increment_ttl_query_counter();
        }
        
        let icmp_probe_response_sniffer = Arc::clone(&self.icmp_probe_response_sniffer);
        tokio::spawn(async move {
            icmp_probe_response_sniffer.sniff().await
        });

        let mut stop_send_probes = false;
        stream! {
            loop {
                if *self.current_ttl.borrow() > self.max_ttl {
                    stop_send_probes = true;
                }
    
                select! {
                    Some(Ok(probe_result)) = probe_tasks.join_next() => {
                        yield probe_result;
                        if !stop_send_probes {
                            let probe_task = self.generate_probe_task(&self.icmp_probe_response_sniffer);
                            self.increment_ttl_query_counter();
                            probe_tasks.spawn(probe_task);
                        }
                    },
                    else => break
                }
            }
        }
    }

    fn generate_probe_task(
        &self, 
        icmp_probe_response_sniffer: &IcmpProbeResponseSniffer
    ) -> Pin<Box<impl Future<Output=Result<ProbeResult, String>>>> {
        
        let mut probe_task_generator = self.probe_task_generator.borrow_mut();
        match probe_task_generator.generate_probe_task(
            self.ip_addr,
            &icmp_probe_response_sniffer
        ) {
            Ok((_, mut probe_task)) => {
                let current_ttl = *self.current_ttl.borrow();
                let timeout = self.max_wait_probe_ms;
                let probe_task_future = Box::pin(async move {
                    probe_task.send_probe(current_ttl, timeout).await
                });
                
                probe_task_future
            }
            Err(_) => todo!()
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
}