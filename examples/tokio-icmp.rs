use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use tokio::join;
use tokio::sync::oneshot;

use traceroute_rust::traceroute::icmp_sniffer::IcmpProbeResponseSniffer;
use traceroute_rust::traceroute::probe::parser::IcmpProbeResponseParser;
use traceroute_rust::traceroute::probe::ProbeResponseParser;
use traceroute_rust::traceroute::probe::task::{IcmpProbeTask, ProbeTask};

#[tokio::main]
async fn main() -> io::Result<()> {
    let parser = IcmpProbeResponseParser::new();
    let ip_addr = IpAddr::V4(Ipv4Addr::from_str("216.58.204.238").unwrap());

    let mut icmp_sniffer = IcmpProbeResponseSniffer::new(parser)?;

    let mut task1 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 1)?;
    let mut task2 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 2)?;
    let mut task3 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 3)?;
    let mut task4 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 4)?;
    let mut task5 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 5)?;
    let mut task6 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 6)?;
    let mut task7 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 7)?;
    let mut task8 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 8)?;
    let mut task9 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 9)?;
    let mut task10 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 10)?;
    let mut task11 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 11)?;
    let mut task12 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 12)?;
    let mut task13 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 13)?;
    let mut task14 = generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, 14)?;

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

fn generate_icmp_task(
    icmp_probe_response_sniffer: &mut IcmpProbeResponseSniffer<IcmpProbeResponseParser>,
    ip_addr: &IpAddr,
    icmp_id: u16,
    icmp_sqn: u16,
) -> io::Result<IcmpProbeTask> {
    let channel = oneshot::channel();
    let task = IcmpProbeTask::new(icmp_id, icmp_sqn, ip_addr.clone(), channel.1)?;
    icmp_probe_response_sniffer.register_probe(task.get_probe_id(), channel.0);
    Ok(task)
}