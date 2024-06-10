use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use futures_util::{pin_mut, StreamExt};

use traceroute_rust::traceroute::icmp_sniffer::IcmpProbeResponseSniffer;
use traceroute_rust::traceroute::probe::generator::{IcmpProbeTaskGenerator, TcpProbeTaskGenerator, UdpProbeTaskGenerator};
use traceroute_rust::traceroute::probe::parser::{IcmpProbeResponseParser, ProbeReplyParser, TcpProbeResponseParser, UdpProbeResponseParser};
use traceroute_rust::traceroute::Traceroute;

#[tokio::main]
async fn main() -> io::Result<()> {
    let parser = ProbeReplyParser::TCP(TcpProbeResponseParser);
    let ip_addr = IpAddr::V4(Ipv4Addr::from_str("216.58.204.238").unwrap());

    let mut icmp_sniffer = IcmpProbeResponseSniffer::new(parser)?;

    let generator = Box::new(TcpProbeTaskGenerator::new());
    let traceroute = Traceroute::new(
        ip_addr,
        20,
        3,
        16,
        10000,
        generator,
        icmp_sniffer
    );

    let traceroute_stream= traceroute.trace();
    pin_mut!(traceroute_stream);
    
    while let Some(Ok(probe_result)) = traceroute_stream.next().await {
        println!("{:?}", probe_result);
    }

    Ok(())
}