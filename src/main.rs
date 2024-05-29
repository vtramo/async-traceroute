use std::error::Error;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::str::FromStr;

use clap::Parser;
use libpacket::{FromPacket, PrimitiveValues};
use rand::Rng;

use crate::bytes::ToBytes;
use crate::traceroute::TracerouteTerminal;

mod bytes;
mod traceroute;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(name = "traceroute")]
#[command(bin_name = "traceroute")]
struct TracerouteOptions {
    #[clap(required = true, index = 1)]
    destination_address: Ipv4Addr,

    #[clap(long, default_value_t = 30)]
    hops: u16,

    #[clap(short, long, default_value_t = 3)]
    queries_per_hop: u16,

    #[clap(short = 'p', long, default_value_t = 33434u16)]
    initial_destination_port: u16,

    #[clap(short, long, default_value_t = 3)]
    wait: u8
}

fn main() -> Result<(), Box<dyn Error>> {
    let traceroute_options = TracerouteOptions::parse();
    let mut traceroute_terminal = TracerouteTerminal::new(traceroute_options);
    traceroute_terminal.start();
    Ok(())
}