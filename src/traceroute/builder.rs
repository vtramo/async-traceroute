use std::net::IpAddr;
use std::time::Duration;

use crate::Traceroute;
use crate::traceroute::probe::generator::{IcmpProbeTaskGenerator, ProbeTaskGenerator, TcpProbeTaskGenerator, UdpProbeTaskGenerator};
use crate::traceroute::probe::parser::{IcmpProbeResponseParser, ProbeReplyParser, TcpProbeResponseParser, UdpProbeResponseParser};
use crate::traceroute::probe::sniffer::IcmpProbeResponseSniffer;

pub struct TracerouteBuilder;

impl TracerouteBuilder {
    pub fn udp() -> TracerouteUdpBuilder {
        let traceroute_base_builder = TracerouteBaseBuilder::new();
        TracerouteUdpBuilder::new(traceroute_base_builder)
    }

    pub fn icmp() -> TracerouteIcmpBuilder {
        let traceroute_base_builder = TracerouteBaseBuilder::new();
        TracerouteIcmpBuilder::new(traceroute_base_builder)
    }

    pub fn tcp() -> TracerouteTcpBuilder {
        let traceroute_base_builder = TracerouteBaseBuilder::new();
        TracerouteTcpBuilder::new(traceroute_base_builder)
    }
}

struct TracerouteBaseBuilder {
    target_ip_address: Option<IpAddr>,
    max_ttl: u8,
    nqueries: u16,
    sim_queries: u16,
    max_wait_probe: Duration,
    is_active_dns_lookup: bool,
}

impl TracerouteBaseBuilder {
    const DEFAULT_MAX_TTL: u8 = 30;
    const DEFAULT_QUERIES_PER_HOP: u16 = 3;
    const DEFAULT_SIM_QUERIES: u16 = 16;
    const DEFAULT_MAX_WAIT_PROBE: Duration = Duration::from_secs(3);
    const DEFAULT_IS_ACTIVE_DNS_LOOKUP: bool = true;

    fn new() -> Self {
        Self {
            target_ip_address: None,
            max_ttl: Self::DEFAULT_MAX_TTL,
            nqueries: Self::DEFAULT_QUERIES_PER_HOP,
            sim_queries: Self::DEFAULT_SIM_QUERIES,
            max_wait_probe: Self::DEFAULT_MAX_WAIT_PROBE,
            is_active_dns_lookup: Self::DEFAULT_IS_ACTIVE_DNS_LOOKUP,
        }
    }
    
    fn target_ip_address(&mut self, ip_addr: IpAddr) {
        self.target_ip_address = Some(ip_addr);
    }
    
    fn max_ttl(&mut self, max_ttl: u8) {
        self.max_ttl = max_ttl;
    }
    
    fn queries_per_hop(&mut self, nqueries: u16) {
        self.nqueries = nqueries;
    }

    fn simultaneous_queries(&mut self, sim_queries: u16) {
        self.sim_queries = sim_queries;
    }

    fn max_wait_probe(&mut self, max_wait_probe: Duration) {
        self.max_wait_probe = max_wait_probe;
    }

    fn active_dns_lookup(&mut self, active_dns_lookup: bool) {
        self.is_active_dns_lookup = active_dns_lookup;
    }
    
    fn build(
        self,
        probe_task_generator: Box<dyn ProbeTaskGenerator>,
        probe_reply_parser: ProbeReplyParser,
    ) -> Result<Traceroute, String> {
        if self.target_ip_address.is_none() {
            return Err(String::from("Target ip address required!"));
        }

        let icmp_sniffer = match IcmpProbeResponseSniffer::new(probe_reply_parser) {
            Ok(icmp_sniffer) => icmp_sniffer,
            Err(error) => return Err(String::from(&format!("{}", error.to_string())))
        };
        
        Ok(Traceroute::new(
            self.target_ip_address.unwrap(),
            self.max_ttl,
            self.nqueries,
            self.sim_queries,
            self.max_wait_probe,
            self.is_active_dns_lookup,
            probe_task_generator,
            icmp_sniffer,
        ))
    }
}

pub struct TracerouteUdpBuilder {
    traceroute_base_builder: TracerouteBaseBuilder,
    initial_destination_port: u16,
}

impl TracerouteUdpBuilder {
    const DEFAULT_INITIAL_DESTINATION_PORT: u16 = 33434;

    fn new(traceroute_base_builder: TracerouteBaseBuilder) -> Self {
        Self {
            initial_destination_port: Self::DEFAULT_INITIAL_DESTINATION_PORT,
            traceroute_base_builder,
        }
    }

    pub fn initial_destination_port(mut self, initial_destination_port: u16) -> Self {
        self.initial_destination_port = initial_destination_port;
        self
    }
    
    pub fn target_ip_address(mut self, ip_addr: IpAddr) -> Self {
        self.traceroute_base_builder.target_ip_address(ip_addr);
        self
    }

    pub fn max_ttl(mut self, max_ttl: u8) -> Self {
        self.traceroute_base_builder.max_ttl(max_ttl);
        self
    }

    pub fn queries_per_hop(mut self, nqueries: u16) -> Self {
        self.traceroute_base_builder.queries_per_hop(nqueries);
        self
    }

    pub fn simultaneous_queries(mut self, sim_queries: u16) -> Self {
        self.traceroute_base_builder.simultaneous_queries(sim_queries);
        self
    }

    pub fn max_wait_probe(mut self, max_wait_probe: Duration) -> Self {
        self.traceroute_base_builder.max_wait_probe(max_wait_probe);
        self
    }

    pub fn active_dns_lookup(mut self, active_dns_lookup: bool) -> Self {
        self.traceroute_base_builder.active_dns_lookup(active_dns_lookup);
        self
    }
    
    pub fn build(self) -> Result<Traceroute, String> {
        let (parser, generator) = (
            ProbeReplyParser::UDP(UdpProbeResponseParser), 
            Box::new(UdpProbeTaskGenerator::new(self.initial_destination_port))
        );
        
        self.traceroute_base_builder.build(generator, parser)
    }
}

pub struct TracerouteTcpBuilder {
    traceroute_base_builder: TracerouteBaseBuilder,
    destination_port: u16,
}

impl TracerouteTcpBuilder {
    const DEFAULT_DESTINATION_PORT: u16 = 80;

    fn new(traceroute_base_builder: TracerouteBaseBuilder) -> Self {
        Self {
            destination_port: Self::DEFAULT_DESTINATION_PORT,
            traceroute_base_builder,
        }
    }

    pub fn initial_destination_port(mut self, initial_destination_port: u16) -> Self {
        self.destination_port = initial_destination_port;
        self
    }
    
    pub fn target_ip_address(mut self, ip_addr: IpAddr) -> Self {
        self.traceroute_base_builder.target_ip_address(ip_addr);
        self
    }

    pub fn max_ttl(mut self, max_ttl: u8) -> Self {
        self.traceroute_base_builder.max_ttl(max_ttl);
        self
    }

    pub fn queries_per_hop(mut self, nqueries: u16) -> Self {
        self.traceroute_base_builder.queries_per_hop(nqueries);
        self
    }

    pub fn simultaneous_queries(mut self, sim_queries: u16) -> Self {
        self.traceroute_base_builder.simultaneous_queries(sim_queries);
        self
    }

    pub fn max_wait_probe(mut self, max_wait_probe: Duration) -> Self {
        self.traceroute_base_builder.max_wait_probe(max_wait_probe);
        self
    }

    pub fn active_dns_lookup(mut self, active_dns_lookup: bool) -> Self {
        self.traceroute_base_builder.active_dns_lookup(active_dns_lookup);
        self
    }

    pub fn build(self) -> Result<Traceroute, String> {
        let (parser, generator) = (
            ProbeReplyParser::TCP(TcpProbeResponseParser),
            Box::new(TcpProbeTaskGenerator::new())
        );

        self.traceroute_base_builder.build(generator, parser)
    }
}

pub struct TracerouteIcmpBuilder {
    traceroute_base_builder: TracerouteBaseBuilder,
    isn: u16,
}

impl TracerouteIcmpBuilder {
    const DEFAULT_ISN: u16 = 1;

    fn new(traceroute_base_builder: TracerouteBaseBuilder) -> Self {
        Self {
            isn: Self::DEFAULT_ISN,
            traceroute_base_builder,
        }
    }

    pub fn initial_sequence_number(mut self, isn: u16) -> Self {
        self.isn = isn;
        self
    }
    
    pub fn target_ip_address(mut self, ip_addr: IpAddr) -> Self {
        self.traceroute_base_builder.target_ip_address(ip_addr);
        self
    }

    pub fn max_ttl(mut self, max_ttl: u8) -> Self {
        self.traceroute_base_builder.max_ttl(max_ttl);
        self
    }

    pub fn queries_per_hop(mut self, nqueries: u16) -> Self {
        self.traceroute_base_builder.queries_per_hop(nqueries);
        self
    }

    pub fn simultaneous_queries(mut self, sim_queries: u16) -> Self {
        self.traceroute_base_builder.simultaneous_queries(sim_queries);
        self
    }

    pub fn max_wait_probe(mut self, max_wait_probe: Duration) -> Self {
        self.traceroute_base_builder.max_wait_probe(max_wait_probe);
        self
    }

    pub fn active_dns_lookup(mut self, active_dns_lookup: bool) -> Self {
        self.traceroute_base_builder.active_dns_lookup(active_dns_lookup);
        self
    }

    pub fn build(self) -> Result<Traceroute, String> {
        let (parser, generator) = (
            ProbeReplyParser::ICMP(IcmpProbeResponseParser),
            Box::new(match IcmpProbeTaskGenerator::new() {
                Ok(generator) => generator,
                Err(error) => return Err(error.to_string()),
            })
        );

        self.traceroute_base_builder.build(generator, parser)
    }
}