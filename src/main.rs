use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use clap::Parser;

use async_traceroute::{dns_lookup_first_ipv4_addr, ProbeMethod, TracerouteBuilder};
use async_traceroute::TracerouteTerminal;

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

    let ip_addr = match IpAddr::from_str(&hostname) {
        Ok(ip_addr) => ip_addr,
        Err(_) => match dns_lookup_first_ipv4_addr(&hostname).await {
            None => return Err(String::from(format!("{hostname}: Hostname not resolvable."))),
            Some(ip_addr) => ip_addr,
        }
    };

    let traceroute = match traceroute_options.probe_method {
        ProbeMethod::TCP => TracerouteBuilder::tcp()
            .target_ip_address(ip_addr)
            .max_ttl(traceroute_options.max_hops)
            .queries_per_hop(traceroute_options.queries)
            .simultaneous_queries(traceroute_options.sim_queries)
            .max_wait_probe(traceroute_options.wait)
            .active_dns_lookup(traceroute_options.dns_lookup)
            .initial_destination_port(80)
            .build(),
        ProbeMethod::UDP => TracerouteBuilder::udp()
            .target_ip_address(ip_addr)
            .max_ttl(traceroute_options.max_hops)
            .queries_per_hop(traceroute_options.queries)
            .simultaneous_queries(traceroute_options.sim_queries)
            .max_wait_probe(traceroute_options.wait)
            .active_dns_lookup(traceroute_options.dns_lookup)
            .initial_destination_port(33434)
            .build(),
        ProbeMethod::ICMP => TracerouteBuilder::icmp()
            .target_ip_address(ip_addr)
            .max_ttl(traceroute_options.max_hops)
            .queries_per_hop(traceroute_options.queries)
            .simultaneous_queries(traceroute_options.sim_queries)
            .max_wait_probe(traceroute_options.wait)
            .active_dns_lookup(traceroute_options.dns_lookup)
            .initial_sequence_number(1)
            .build(),
    };

    let traceroute = match traceroute {
        Ok(traceroute) => traceroute,
        Err(error) => return Err(error),
    };

    println!("traceroute to {ip_addr} ({hostname}), {} hops max", traceroute_options.max_hops);
    let traceroute_terminal = TracerouteTerminal::new(traceroute);
    traceroute_terminal.print_trace().await;

    Ok(())
}