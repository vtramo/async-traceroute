use std::time::Duration;

use futures::pin_mut;
use futures_util::StreamExt;

use async_traceroute::TracerouteBuilder;
use async_traceroute::utils::dns::dns_lookup_first_ipv4_addr;

#[tokio::main]
async fn main() -> Result<(), String> {
    let ip_addr = match dns_lookup_first_ipv4_addr("youtube.com").await {
        None => return Err(String::from("Hostname not resolvable")),
        Some(ip_addr) => ip_addr,
    };

    let traceroute = TracerouteBuilder::udp()
        .target_ip_address(ip_addr)
        .max_ttl(15)
        .queries_per_hop(3)
        .max_wait_probe(Duration::from_secs(2))
        .simultaneous_queries(16)
        .active_dns_lookup(true)
        .initial_destination_port(33666)
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