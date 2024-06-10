use std::env::args;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use futures_util::{pin_mut, StreamExt};

use traceroute_rust::traceroute::icmp_sniffer::IcmpProbeResponseSniffer;
use traceroute_rust::traceroute::probe::generator::{IcmpProbeTaskGenerator, ProbeTaskGenerator, TcpProbeTaskGenerator, UdpProbeTaskGenerator};
use traceroute_rust::traceroute::probe::parser::{IcmpProbeResponseParser, ProbeReplyParser, TcpProbeResponseParser, UdpProbeResponseParser};
use traceroute_rust::traceroute::Traceroute;

#[tokio::main]
async fn main() -> io::Result<()> {
    let probe_method = args().last().unwrap().to_owned();
    
    let (parser, generator): (ProbeReplyParser, Box<dyn ProbeTaskGenerator>) = match probe_method.as_str() {
        "TCP" => (ProbeReplyParser::TCP(TcpProbeResponseParser), Box::new(TcpProbeTaskGenerator::new())),
        "UDP" => (ProbeReplyParser::UDP(UdpProbeResponseParser), Box::new(UdpProbeTaskGenerator::new(33434))),
        "ICMP" => (ProbeReplyParser::ICMP(IcmpProbeResponseParser), Box::new(IcmpProbeTaskGenerator::new().unwrap())),
        _ => panic!(),
    };
    
    let ip_addr = IpAddr::V4(Ipv4Addr::from_str("216.58.204.238").unwrap());

    let icmp_sniffer = IcmpProbeResponseSniffer::new(parser)?;

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
    
    while let Some(probe_result) = traceroute_stream.next().await {
        println!("{:?}", probe_result);
    }

    Ok(())
}