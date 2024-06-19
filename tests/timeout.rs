use std::net::IpAddr;
use std::time::Duration;
use futures::pin_mut;
use futures_util::StreamExt;
use ntest::timeout;
use async_traceroute::{dns_lookup_first_ipv4_addr, TracerouteBuilder};

async fn get_google_ip() -> IpAddr {
    match dns_lookup_first_ipv4_addr("google.com").await {
        None => panic!("Hostname not resolvable"),
        Some(ip_addr) => ip_addr,
    }
}

const MAX_HOPS: u8 = 5;
const QUERIES_PER_HOPS: u16 = 3;
const SIM_QUERIES: u16 = 16;

#[tokio::test]
#[timeout(4000)]
async fn timeout_udp() {
    let ip_addr = get_google_ip().await;
    let max_wait_probe: Duration = Duration::from_secs(3);

    let traceroute = TracerouteBuilder::udp()
        .destination_address(ip_addr)
        .max_ttl(MAX_HOPS)
        .queries_per_hop(QUERIES_PER_HOPS)
        .simultaneous_queries(SIM_QUERIES)
        .max_wait_probe(max_wait_probe)
        .active_dns_lookup(false)
        .initial_destination_port(33434)
        .build();

    let traceroute_stream = match traceroute {
        Ok(traceroute) => traceroute.trace(),
        Err(error) => panic!("Unable to start traceroute: {}", error),
    };

    pin_mut!(traceroute_stream);
    while let Some(_) = traceroute_stream.next().await {}
}

#[tokio::test]
#[timeout(4000)]
async fn timeout_icmp() {
    let ip_addr = get_google_ip().await;
    let max_wait_probe: Duration = Duration::from_secs(3);

    let traceroute = TracerouteBuilder::icmp()
        .destination_address(ip_addr)
        .max_ttl(MAX_HOPS)
        .queries_per_hop(QUERIES_PER_HOPS)
        .simultaneous_queries(SIM_QUERIES)
        .max_wait_probe(max_wait_probe)
        .active_dns_lookup(false)
        .build();

    let traceroute_stream = match traceroute {
        Ok(traceroute) => traceroute.trace(),
        Err(error) => panic!("Unable to start traceroute: {}", error),
    };

    pin_mut!(traceroute_stream);
    while let Some(_) = traceroute_stream.next().await {}
}

#[tokio::test]
#[timeout(4000)]
async fn timeout_tcp() {
    let ip_addr = get_google_ip().await;
    let max_wait_probe: Duration = Duration::from_secs(3);

    let traceroute = TracerouteBuilder::tcp()
        .destination_address(ip_addr)
        .max_ttl(MAX_HOPS)
        .queries_per_hop(QUERIES_PER_HOPS)
        .simultaneous_queries(SIM_QUERIES)
        .max_wait_probe(max_wait_probe)
        .active_dns_lookup(false)
        .initial_destination_port(33434)
        .build();

    let traceroute_stream = match traceroute {
        Ok(traceroute) => traceroute.trace(),
        Err(error) => panic!("Unable to start traceroute: {}", error),
    };

    pin_mut!(traceroute_stream);
    while let Some(_) = traceroute_stream.next().await {}
}