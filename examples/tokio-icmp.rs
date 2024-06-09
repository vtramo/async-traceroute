use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use tokio::join;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use traceroute_rust::traceroute::icmp_sniffer::IcmpProbeResponseSniffer;
use traceroute_rust::traceroute::probe::parser::{IcmpProbeResponseParser, ProbeReplyParser};
use traceroute_rust::traceroute::probe::task::{IcmpProbeTask, ProbeTask};

#[tokio::main]
async fn main() -> io::Result<()> {
    let parser = ProbeReplyParser::ICMP(IcmpProbeResponseParser);
    let ip_addr = IpAddr::V4(Ipv4Addr::from_str("216.58.204.238").unwrap());

    let mut icmp_sniffer = IcmpProbeResponseSniffer::new(parser)?;

    let mut tasks: JoinSet<_> = (1..=14)
        .filter_map(|i| {
            generate_icmp_task(&mut icmp_sniffer, &ip_addr, 666, i)
                .ok()
                .map(|mut task| 
                    task.send_probe(i as u8, 10000))
        })
        .collect();
    
   join!(
       async {
           while let Some(Ok(_)) = tasks.join_next().await {}
       },
       icmp_sniffer.sniff()
   );

    Ok(())
}

fn generate_icmp_task(
    icmp_probe_response_sniffer: &mut IcmpProbeResponseSniffer,
    ip_addr: &IpAddr,
    icmp_id: u16,
    icmp_sqn: u16,
) -> io::Result<IcmpProbeTask> {
    let channel = oneshot::channel();
    let task = IcmpProbeTask::new(icmp_id, icmp_sqn, ip_addr.clone(), channel.1)?;
    icmp_probe_response_sniffer.register_probe(task.get_probe_id(), channel.0);
    Ok(task)
}