# traceroute-rust

This is an implementation of the Traceroute program written in Rust.
```
Usage: traceroute [OPTIONS] <HOST>

Arguments:
  <HOST>  

Options:
  -m, --max-hops <MAX_HOPS>          Set the max number of hops (max TTL to be reached) [default: 30]
  -q, --queries <QUERIES>            Set the number of probes per each hop [default: 3]
  -w, --wait <WAIT>                  Wait for a probe no more than <WAIT> [default: 3s]
  -N, --sim-queries <SIM_QUERIES>    Set the number of probes to be tried simultaneously [default: 16]
  -P, --probe-method <PROBE_METHOD>  [default: udp] [possible values: udp, tcp, icmp]
  -n                                 Do not resolve IP addresses to their domain names
  -h, --help                         Print help
  -V, --version                      Print version
```

## What is Traceroute
Traceroute allows you to see the path an IP packet takes from one host to another. It uses the **TTL (Time To Live)** field
in the IP packet to elicit an **ICMP Time to Live Exceeded** message from each router along the path. Each router that handles the
packet decreases the TTL field, which effectively acts as a Hop Counter. When a router receives an IP datagram with the
TTL field set to 0, it responds with an ICMP Time to Live Exceeded that reveals its IP address. 

Several traceroute probe methods exist. This diagram shows how the UDP-based traceroute method works.
![traceroute.svg](traceroute.svg)

## Main Libraries
- [tokio](https://tokio.rs/) (async runtime)
- [socket2](https://crates.io/crates/socket2) (includes raw sockets)
- [libpnet](https://github.com/libpnet/libpnet) (API for low level networking)
- [clap](https://docs.rs/clap/latest/clap/) (command-line argument parser)