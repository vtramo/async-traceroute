use std::{sync, thread};
use std::error::Error;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;

use libpacket::{FromPacket, PrimitiveValues};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};

use crate::bytes::ToBytes;
use crate::traceroute::{Traceroute, TracerouteTerminal};

mod bytes;
mod traceroute;

fn main() -> Result<(), Box<dyn Error>> {
    let socket_udp = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    socket_udp.set_header_included(true)?;

    let destination_address_str = "142.250.180.174".to_string();
    let destination_address = Ipv4Addr::from_str(&destination_address_str)?;

    let tot_hops = 30;
    let queries_per_hop = 3;
    let destination_port = 33434u16;

    let (sender, receiver) = sync::mpsc::channel();

    thread::spawn(move || {
        let mut traceroute = Traceroute::new(
            destination_address,
            tot_hops,
            queries_per_hop,
            destination_port,
            sender
        );

        traceroute.traceroute();
    });

    let mut traceroute_terminal = TracerouteTerminal::new(
        destination_address,
        tot_hops,
        queries_per_hop,
        Duration::from_secs(3),
        receiver
    );

    traceroute_terminal.display();

    Ok(())
}