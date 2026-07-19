// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use regex_lite::Regex;
use sb_dns::message::{self, TYPE_A, TYPE_AAAA};
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;

pub fn url_hostname(raw: &str) -> String {
    let s = match raw.split_once("://") {
        Some((_, rest)) => rest,
        None => raw,
    };

    let s = s.split(['/', '?', '#']).next().unwrap_or("");

    let s = match s.rsplit_once('@') {
        Some((_, h)) => h,
        None => s,
    };

    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }

    match s.rsplit_once(':') {
        Some((h, p))
            if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && !h.contains(':') =>
        {
            h.to_string()
        }
        _ => s.to_string(),
    }
}

pub fn ipv6_enabled() -> bool {
    std::fs::read_to_string("/etc/config/network")
        .map(|s| s.contains("eth06"))
        .unwrap_or(false)
}

pub fn nslookup(host: &str, server: &str, port: i64, ipv6_enabled: bool) -> Option<IpAddr> {

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Some(ip) = lookup_hosts(host, ipv6_enabled) {
        return Some(ip);
    }

    if !server.is_empty() {
        if let Some(addr) = server_addr(server, port) {
            if let Some(ip) = query_one(host, addr, ipv6_enabled) {
                return Some(ip);
            }
        }
    }

    for addr in ex_dns_env_servers() {
        if let Some(ip) = query_one(host, addr, ipv6_enabled) {
            return Some(ip);
        }
    }

    system_resolve(host, ipv6_enabled)
}

fn query_one(host: &str, addr: SocketAddr, ipv6_enabled: bool) -> Option<IpAddr> {
    if let Some(resp) = query(host, addr, TYPE_A) {
        if let Some(ip) = resp.v4.first() {
            return Some(IpAddr::V4(*ip));
        }
    }
    if ipv6_enabled {
        if let Some(resp) = query(host, addr, TYPE_AAAA) {
            if let Some(ip) = resp.v6.first() {
                return Some(IpAddr::V6(*ip));
            }
        }
    }
    None
}

fn system_resolve(host: &str, ipv6_enabled: bool) -> Option<IpAddr> {
    let addrs: Vec<IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .map(|s| s.ip())
        .collect();
    if let Some(ip) = addrs.iter().find(|a| a.is_ipv4()) {
        return Some(*ip);
    }
    if ipv6_enabled {
        if let Some(ip) = addrs.iter().find(|a| a.is_ipv6()) {
            return Some(*ip);
        }
    }
    None
}

pub(crate) fn ex_dns_env_servers() -> Vec<SocketAddr> {
    std::env::var("ex_dns")
        .map(|ex| ex.split(',').filter_map(parse_dns_server).collect())
        .unwrap_or_default()
}

pub fn lookup_hosts(host: &str, ipv6_enabled: bool) -> Option<IpAddr> {
    let content = std::fs::read_to_string("/etc/hosts").ok()?;
    lookup_hosts_in(&content, host, ipv6_enabled)
}

fn lookup_hosts_in(content: &str, host: &str, ipv6_enabled: bool) -> Option<IpAddr> {
    let mut v6: Option<IpAddr> = None;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut it = line.split_whitespace();
        let Some(ip_s) = it.next() else { continue };
        let Ok(ip) = ip_s.parse::<IpAddr>() else {
            continue;
        };
        if it.any(|name| name.eq_ignore_ascii_case(host)) {
            if ip.is_ipv4() {
                return Some(ip);
            }
            if ipv6_enabled && v6.is_none() {
                v6 = Some(ip);
            }
        }
    }
    v6
}

pub fn resolve_domain_ips(domain: &str, dns_servers: &[String], ipv6_enabled: bool) -> Vec<IpAddr> {
    let mut set = query_servers(domain, dns_servers, ipv6_enabled);
    if set.is_empty() {
        let fallback = ["223.5.5.5".to_string(), "1.0.0.1".to_string()];
        set = query_servers(domain, &fallback, ipv6_enabled);
    }
    set.into_iter().collect()
}

pub fn resolve_domains_concurrent(
    domains: &[String],
    dns_servers: &[String],
    ipv6_enabled: bool,
) -> std::collections::HashMap<String, Vec<IpAddr>> {
    use std::sync::Mutex;
    let out: Mutex<std::collections::HashMap<String, Vec<IpAddr>>> =
        Mutex::new(std::collections::HashMap::new());
    let out_ref = &out;
    for chunk in domains.chunks(16) {
        std::thread::scope(|s| {
            for domain in chunk {
                let domain = domain.clone();
                s.spawn(move || {
                    let ips = resolve_domain_ips(&domain, dns_servers, ipv6_enabled);
                    if !ips.is_empty() {
                        out_ref.lock().unwrap().insert(domain, ips);
                    }
                });
            }
        });
    }
    out.into_inner().unwrap()
}

fn query_servers(domain: &str, servers: &[String], ipv6_enabled: bool) -> BTreeSet<IpAddr> {
    let mut set = BTreeSet::new();
    for s in servers {
        let Some(addr) = parse_dns_server(s) else {
            continue;
        };
        if let Some(resp) = query(domain, addr, TYPE_A) {
            for ip in resp.v4 {
                if !ip.is_loopback() {
                    set.insert(IpAddr::V4(ip));
                }
            }
        }
        if ipv6_enabled {
            if let Some(resp) = query(domain, addr, TYPE_AAAA) {
                for ip in resp.v6 {
                    if !ip.is_loopback() {
                        set.insert(IpAddr::V6(ip));
                    }
                }
            }
        }
    }
    set
}

pub fn resolve_host_via(host: &str, server: SocketAddr, ipv6_enabled: bool) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Some(resp) = query(host, server, TYPE_A) {
        out.extend(resp.v4.into_iter().map(IpAddr::V4));
    }
    if ipv6_enabled {
        if let Some(resp) = query(host, server, TYPE_AAAA) {
            out.extend(resp.v6.into_iter().map(IpAddr::V6));
        }
    }
    out
}

pub(crate) fn parse_dns_server(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    if s.contains(':') {
        s.to_socket_addrs().ok()?.next()
    } else {
        (s, 53u16).to_socket_addrs().ok()?.next()
    }
}

pub fn extract_hosts(text: &str) -> Vec<String> {
    let re = Regex::new(r"https?://[A-Za-z0-9.-]+").expect("static regex");
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in re.find_iter(text) {
        let host = url_hostname(m.as_str());
        if !host.is_empty() && seen.insert(host.clone()) {
            out.push(host);
        }
    }
    out
}

pub fn resolve_hosts_batch(
    hosts: &[String],
    server: &str,
    port: i64,
    ipv6: bool,
) -> Vec<(String, IpAddr)> {
    let results: Mutex<Vec<(String, IpAddr)>> = Mutex::new(Vec::new());
    let results_ref = &results;
    for chunk in hosts.chunks(16) {
        std::thread::scope(|s| {
            for host in chunk {
                s.spawn(move || {
                    if let Some(ip) = nslookup(host, server, port, ipv6) {
                        results_ref.lock().unwrap().push((host.clone(), ip));
                    }
                });
            }
        });
    }
    results.into_inner().unwrap()
}

fn server_addr(server: &str, port: i64) -> Option<SocketAddr> {
    let p: u16 = if (1..=65535).contains(&port) {
        port as u16
    } else {
        53
    };
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, p));
    }
    (server, p).to_socket_addrs().ok()?.next()
}

fn query(host: &str, addr: SocketAddr, qtype: u16) -> Option<message::DnsResponse> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .subsec_nanos()
        & 0xffff) as u16;
    let q = message::build_query(id, host, qtype).ok()?;
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    sock.connect(addr).ok()?;
    sock.send(&q).ok()?;
    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).ok()?;
    let resp = message::parse_response(&buf[..n]).ok()?;
    if resp.id != id {
        return None;
    }
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_extraction() {
        assert_eq!(url_hostname("http://paopao.dns"), "paopao.dns");
        assert_eq!(url_hostname("http://host:7889/x/y"), "host");
        assert_eq!(url_hostname("ovpn://vpn.example.com"), "vpn.example.com");
        assert_eq!(url_hostname("https://1.2.3.4:443"), "1.2.3.4");
        assert_eq!(url_hostname("http://user:pw@h.com/p"), "h.com");
        assert_eq!(url_hostname("http://[2001:db8::1]:80"), "2001:db8::1");
        assert_eq!(url_hostname("bare.host"), "bare.host");
    }

    #[test]
    fn server_addr_parsing() {
        let a = server_addr("223.5.5.5", 53).unwrap();
        assert_eq!(a.to_string(), "223.5.5.5:53");
        let a = server_addr("127.0.0.1", 5353).unwrap();
        assert_eq!(a.port(), 5353);

        let a = server_addr("8.8.8.8", 0).unwrap();
        assert_eq!(a.port(), 53);
    }

    #[test]
    fn parse_dns_server_forms() {
        assert_eq!(
            parse_dns_server("8.8.8.8:53").unwrap().to_string(),
            "8.8.8.8:53"
        );
        assert_eq!(
            parse_dns_server("1.1.1.1").unwrap().to_string(),
            "1.1.1.1:53"
        );
        assert_eq!(parse_dns_server("  223.5.5.5  ").unwrap().port(), 53);
        assert!(parse_dns_server("").is_none());
        assert!(parse_dns_server("   ").is_none());
    }

    #[test]
    fn nslookup_ip_literal_short_circuits() {

        assert_eq!(
            nslookup("10.10.10.8", "192.0.2.1", 5304, false),
            Some("10.10.10.8".parse().unwrap())
        );
        assert_eq!(
            nslookup("1.2.3.4", "", 53, false),
            Some("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn lookup_hosts_parsing() {
        let hosts = "127.0.0.1 localhost\n10.10.10.8  paopao.dns gw.lan  # comment\n::1 ip6-localhost\n2001:db8::5 v6host\n";

        assert_eq!(
            lookup_hosts_in(hosts, "paopao.dns", false),
            Some("10.10.10.8".parse().unwrap())
        );
        assert_eq!(
            lookup_hosts_in(hosts, "GW.LAN", false),
            Some("10.10.10.8".parse().unwrap())
        );
        assert_eq!(
            lookup_hosts_in(hosts, "localhost", false),
            Some("127.0.0.1".parse().unwrap())
        );

        assert_eq!(lookup_hosts_in(hosts, "absent.dns", false), None);

        assert_eq!(lookup_hosts_in(hosts, "v6host", false), None);
        assert_eq!(
            lookup_hosts_in(hosts, "v6host", true),
            Some("2001:db8::5".parse().unwrap())
        );

        assert_eq!(
            lookup_hosts_in("1.2.3.4 a # paopao.dns\n", "paopao.dns", false),
            None
        );
    }

    #[test]
    fn extract_hosts_dedup_in_order() {
        let yaml = "proxy-providers:\n  p1: {url: \"https://example.com/sub.yaml\"}\nrule-providers:\n  ads: {url: \"http://list.example.org:8080/ads.txt\"}\n  dup: {url: \"https://example.com/other\"}\n";
        let hosts = extract_hosts(yaml);
        assert_eq!(
            hosts,
            vec!["example.com", "list.example.org"],
            "deduplicate in order, strip port/path: {hosts:?}"
        );
        assert!(extract_hosts("no urls here").is_empty());
    }
}
