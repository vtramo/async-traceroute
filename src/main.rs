use std::time::Duration;

use clap::Parser;

use traceroute_rust::generator::{IcmpProbeTaskGenerator, ProbeTaskGenerator, TcpProbeTaskGenerator, UdpProbeTaskGenerator};
use traceroute_rust::parser::{IcmpProbeResponseParser, ProbeReplyParser, TcpProbeResponseParser, UdpProbeResponseParser};
use traceroute_rust::sniffer::IcmpProbeResponseSniffer;
use traceroute_rust::Traceroute;
use traceroute_rust::TracerouteTerminal;
use traceroute_rust::utils::dns::dns_lookup_first_ipv4_addr;

#[derive(Debug, clap::ValueEnum, Clone, Default)]
pub enum ProbeMethod {
    #[default]
    UDP,
    TCP,
    ICMP,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(name = "traceroute")]
#[command(bin_name = "traceroute")]
struct TracerouteOptions {
    #[arg(required = true, index = 1)]
    host: String,

    /// Set the max number of hops (max TTL to be reached)
    #[arg(short, long, default_value_t = 30, value_parser=clap::value_parser!(u8).range(1..=255))]
    max_hops: u8,

    /// Set the number of probes per each hop
    #[arg(short, long, default_value_t = 3, value_parser=clap::value_parser!(u16).range(1..=10))]
    queries: u16,

    /// Wait for a probe no more than <WAIT>
    #[arg(short, long, value_parser = humantime::parse_duration, default_value = "3s")]
    wait: Duration,

    /// Set the number of probes to be tried simultaneously
    #[arg(short = 'N', long, default_value_t = 16, value_parser=clap::value_parser!(u16).range(1..))]
    sim_queries: u16,

    #[arg(short = 'P', long, value_enum, default_value = "udp")]
    probe_method: ProbeMethod,

    /// Do not resolve IP addresses to their domain names
    #[arg(short = 'n', default_value_t = true)]
    dns_lookup: bool,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let traceroute_options = TracerouteOptions::parse();
    let hostname = traceroute_options.host;
    let ip_addr = match dns_lookup_first_ipv4_addr(&hostname).await {
        None => return Err(String::from("Hostname not resolvable")),
        Some(ip_addr) => ip_addr,
    };

    let (parser, task_generator): (ProbeReplyParser, Box<dyn ProbeTaskGenerator>) = match traceroute_options.probe_method {
        ProbeMethod::TCP => (ProbeReplyParser::TCP(TcpProbeResponseParser), Box::new(TcpProbeTaskGenerator::new())),
        ProbeMethod::UDP => (ProbeReplyParser::UDP(UdpProbeResponseParser), Box::new(UdpProbeTaskGenerator::new(33434))),
        ProbeMethod::ICMP => (ProbeReplyParser::ICMP(IcmpProbeResponseParser), Box::new(IcmpProbeTaskGenerator::new().unwrap())),
    };

    let icmp_sniffer = match IcmpProbeResponseSniffer::new(parser) {
        Ok(icmp_sniffer) => icmp_sniffer,
        Err(error) => return Err(String::from(&format!("{}", error.to_string())))
    };

    let traceroute = Traceroute::new(
        ip_addr,
        traceroute_options.max_hops,
        traceroute_options.queries,
        traceroute_options.sim_queries,
        traceroute_options.wait,
        traceroute_options.dns_lookup,
        task_generator,
        icmp_sniffer
    );

    println!("traceroute to {ip_addr} ({hostname}), {} hops max", traceroute_options.max_hops);
    let traceroute_terminal = TracerouteTerminal::new(traceroute);
    traceroute_terminal.print_trace().await;

    Ok(())
}