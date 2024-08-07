use std::time::Duration;

use futures::{pin_mut, StreamExt};

use async_traceroute::{dns_lookup_first_ipv4_addr, TracerouteBuilder};

#[tokio::main]
async fn main() -> Result<(), String> {
    let ip_addr = match dns_lookup_first_ipv4_addr("google.com").await {
        None => return Err(String::from("Hostname not resolvable")),
        Some(ip_addr) => ip_addr,
    };

    let traceroute = TracerouteBuilder::udp()
        .destination_address(ip_addr)
        .max_ttl(15)
        .queries_per_hop(3)
        .max_wait_probe(Duration::from_secs(3))
        .simultaneous_queries(16)
        .active_dns_lookup(true)
        .initial_destination_port(33434)
        .network_interface("eth0")
        .build();

    let traceroute_stream = match traceroute {
        Ok(traceroute) => traceroute.trace(),
        Err(error) => return Err(error),
    };

    pin_mut!(traceroute_stream);
    while let Some(probe_result) = traceroute_stream.next().await {
        println!("{:?}", probe_result);
    }

    Ok(())
}