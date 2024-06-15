use std::env::args;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

use async_traceroute::traceroute::probe::generator::{IcmpProbeTaskGenerator, ProbeTaskGenerator, TcpProbeTaskGenerator, UdpProbeTaskGenerator};
use async_traceroute::traceroute::probe::parser::{IcmpProbeResponseParser, ProbeReplyParser, TcpProbeResponseParser, UdpProbeResponseParser};
use async_traceroute::traceroute::probe::sniffer::IcmpProbeResponseSniffer;
use async_traceroute::traceroute::Traceroute;
use async_traceroute::TracerouteTerminal;

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
        Duration::from_secs(3),
        true,
        generator,
        icmp_sniffer
    );
    
    let traceroute_terminal = TracerouteTerminal::new(traceroute);
    traceroute_terminal.print_trace().await;

    Ok(())
}