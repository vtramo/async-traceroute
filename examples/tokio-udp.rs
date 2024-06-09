use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use tokio::join;
use tokio::sync::oneshot;

use traceroute_rust::traceroute::icmp_sniffer::IcmpProbeResponseSniffer;
use traceroute_rust::traceroute::probe::parser::UdpProbeResponseParser;
use traceroute_rust::traceroute::probe::ProbeResponseParser;
use traceroute_rust::traceroute::probe::task::{ProbeTask, UdpProbeTask};

#[tokio::main]
async fn main() -> io::Result<()> {
    let parser = UdpProbeResponseParser::new();
    let ip_addr = IpAddr::V4(Ipv4Addr::from_str("216.58.204.238").unwrap());
    
    let mut icmp_sniffer = IcmpProbeResponseSniffer::new(parser)?;
    
    let mut task1 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33434)?;
    let mut task2 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33435)?;
    let mut task3 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33436)?;
    let mut task4 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33437)?;
    let mut task5 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33438)?;
    let mut task6 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33439)?;
    let mut task7 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33440)?;
    let mut task8 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33441)?;
    let mut task9 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33442)?;
    let mut task10 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33443)?;
    let mut task11 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33444)?;
    let mut task12 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33445)?;
    let mut task13 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33446)?;
    let mut task14 = generate_udp_task(&mut icmp_sniffer, &ip_addr, 33447)?;
    
    join!(
        icmp_sniffer.sniff(),
        task1.send_probe(1, 10000),
        task2.send_probe(2, 10000),
        task3.send_probe(3, 10000),
        task4.send_probe(4, 10000),
        task5.send_probe(5, 10000),
        task6.send_probe(6, 10000),
        task7.send_probe(7, 10000),
        task8.send_probe(8, 10000),
        task9.send_probe(9, 10000),
        task10.send_probe(10, 10000),
        task11.send_probe(11, 10000),
        task12.send_probe(12, 10000),
        task13.send_probe(13, 10000),
        task14.send_probe(14, 10000),
    );
    
    Ok(())
}

fn generate_udp_task(
    icmp_probe_response_sniffer: &mut IcmpProbeResponseSniffer<UdpProbeResponseParser>,
    ip_addr: &IpAddr,
    dest_port: u16,
) -> io::Result<UdpProbeTask> {
    let channel = oneshot::channel();
    let task = UdpProbeTask::new(ip_addr.clone(), dest_port, channel.1)?;
    icmp_probe_response_sniffer.register_probe(task.get_probe_id(), channel.0);
    Ok(task)
}