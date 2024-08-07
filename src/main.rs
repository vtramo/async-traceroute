use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use clap::Parser;

use async_traceroute::{default_interface, dns_lookup_first_ipv4_addr, get_interface, ProbeMethod, TracerouteBuilder};
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

    /// This value changes semantics based on the probe method selected.
    /// It is either initial udp port value for "udp" probe method
    /// (incremented by each probe, default is 33434), or
    /// initial seq for "icmp" probe method (incremented as well,
    /// default from 1), or destination port for "tcp" probe method (default is 80)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Do not resolve IP addresses to their domain names
    #[arg(short = 'n', default_value_t = true)]
    dns_lookup: bool,
    
    /// Specify a network interface to operate with
    #[arg(short = 'i', long)]
    interface: Option<String>,
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
    
    let interface = match traceroute_options.interface {
        None => match default_interface() {
            None => return Err(String::from("Network interface not found!")),
            Some(network_interface) => network_interface.name
        },
        Some(interface_name) => match get_interface(&interface_name) {
            None => return Err(format!("Network interface {} not found!", interface_name)),
            Some(network_interface) => network_interface.name,
        }
    };

    let port = traceroute_options.port;
    let traceroute = match traceroute_options.probe_method {
        ProbeMethod::TCP => TracerouteBuilder::tcp()
            .destination_address(ip_addr)
            .max_ttl(traceroute_options.max_hops)
            .queries_per_hop(traceroute_options.queries)
            .simultaneous_queries(traceroute_options.sim_queries)
            .max_wait_probe(traceroute_options.wait)
            .active_dns_lookup(traceroute_options.dns_lookup)
            .initial_destination_port(port.unwrap_or(80))
            .network_interface(&interface)
            .build(),
        ProbeMethod::UDP => TracerouteBuilder::udp()
            .destination_address(ip_addr)
            .max_ttl(traceroute_options.max_hops)
            .queries_per_hop(traceroute_options.queries)
            .simultaneous_queries(traceroute_options.sim_queries)
            .max_wait_probe(traceroute_options.wait)
            .active_dns_lookup(traceroute_options.dns_lookup)
            .initial_destination_port(port.unwrap_or(33434))
            .network_interface(&interface)
            .build(),
        ProbeMethod::ICMP => TracerouteBuilder::icmp()
            .destination_address(ip_addr)
            .max_ttl(traceroute_options.max_hops)
            .queries_per_hop(traceroute_options.queries)
            .simultaneous_queries(traceroute_options.sim_queries)
            .max_wait_probe(traceroute_options.wait)
            .active_dns_lookup(traceroute_options.dns_lookup)
            .initial_sequence_number(port.unwrap_or(1))
            .network_interface(&interface)
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