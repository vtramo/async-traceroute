use std::net::IpAddr;

use domain::base::Name;
use domain::resolv::lookup::lookup_host;
use domain::resolv::stub::StubResolver;

pub async fn dns_lookup(hostname: &str) -> Option<Vec<IpAddr>> {
    let hostname = match Name::bytes_from_str(hostname) {
        Ok(hostname) => hostname,
        Err(_) => return None,
    };

    let stub_resolver = StubResolver::new();


    match lookup_host(&&stub_resolver, hostname).await {
        Ok(answers) => {
            let ip_addrs: Vec<_> = answers
                .iter()
                .collect();
            
            if ip_addrs.is_empty() { None } else { Some(ip_addrs) }
        }
        Err(_) => None,
    }
}

pub async fn dns_lookup_first_ipv4_addr(hostname: &str) -> Option<IpAddr> {
    if let Some(ip_addrs) = dns_lookup(hostname).await {
        for ip_addr in ip_addrs.iter() {
            if ip_addr.is_ipv4() {
                return Some(*ip_addr)
            }
        }
    }
    
    None
}

pub async fn reverse_dns_lookup(ip_address: &IpAddr) -> Option<Vec<String>> {
    let resolver = StubResolver::new();
    match resolver.lookup_addr(*ip_address).await {
        Ok(addrs) => {
            let hostnames: Vec<_> = addrs.into_iter()
                .map(|addr| addr.to_string())
                .collect();
            
            if hostnames.is_empty() { None } else { Some(hostnames) }
        },
        Err(_) => None
    }
}

pub async fn reverse_dns_lookup_first_hostname(ip_address: &IpAddr) -> Option<String> {
    reverse_dns_lookup(ip_address)
        .await
        .map(|hostnames|
                hostnames.first()
                    .expect("hostnames should contain at least one hostname")
                    .to_string())
} 