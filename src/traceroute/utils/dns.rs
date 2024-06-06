use std::net::{IpAddr, ToSocketAddrs};

pub fn nslookup(hostname: &str) -> Option<IpAddr> {
    let sock_addrs = format!("{hostname}:1234").to_socket_addrs();
    if sock_addrs.is_err() {
        return None;
    }
    let mut sock_addrs = sock_addrs.unwrap();
    sock_addrs.next().map(|sock_addr| sock_addr.ip())
}