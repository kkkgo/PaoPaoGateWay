// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::resolvepool::{Budget, Deadline, Outcome};
use sb_dns::message::{self, TYPE_A, TYPE_AAAA};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use yaml_rust2::Yaml;

const TIMEOUT: Duration = Duration::from_secs(5);

const DOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

const HARD_TIMEOUT: Duration = Duration::from_secs(6);

const RETRY_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_BOOTSTRAP_SERVERS: usize = 8;

const CLASH_SOCKS5: &str = "socks5h://127.0.0.1:1080";

const CLASH_SOCKS5_ADDR: &str = "127.0.0.1:1080";

const SOCKS5_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

const DNS_FIELDS: [&str; 7] = [
    "default-nameserver",
    "nameserver",
    "fallback",
    "proxy-server-nameserver",
    "direct-nameserver",
    "nameserver-policy",
    "proxy-server-nameserver-policy",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsSpec {
    Udp(SocketAddr),
    Doh(String),
    Dot(String, u16),
}

pub fn parse_dns_spec(raw: &str) -> Option<DnsSpec> {
    let s = raw.trim().split('#').next().unwrap_or("").trim();
    if s.is_empty()
        || s == "system"
        || s.starts_with("system://")
        || s.starts_with("dhcp://")
        || s.starts_with("quic://")
        || s.starts_with("doq://")
        || s.starts_with("rcode://")
    {
        return None;
    }
    if s.starts_with("https://") {
        return Some(DnsSpec::Doh(s.to_string()));
    }
    if let Some(rest) = s.strip_prefix("tls://") {
        let (host, port) = split_host_port(rest, 853);
        if host.is_empty() {
            return None;
        }
        return Some(DnsSpec::Dot(host, port));
    }

    let bare = s
        .strip_prefix("udp://")
        .or_else(|| s.strip_prefix("tcp://"))
        .unwrap_or(s);
    crate::dnsutil::parse_dns_server(bare).map(DnsSpec::Udp)
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {

    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(default_port)),
        _ => (s.to_string(), default_port),
    }
}

pub fn extract_dns_servers(dns: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for field in DNS_FIELDS {
        collect_strings(&dns[field], &mut |s| {
            if parse_dns_spec(s).is_some() && seen.insert(s.to_string()) {
                out.push(s.to_string());
            }
        });
    }
    out
}

fn collect_strings(y: &Yaml, f: &mut impl FnMut(&str)) {
    match y {
        Yaml::String(s) => f(s),
        Yaml::Array(a) => a.iter().for_each(|v| collect_strings(v, f)),
        Yaml::Hash(h) => h.iter().for_each(|(_, v)| collect_strings(v, f)),
        _ => {}
    }
}

pub fn resolve_via_servers(domain: &str, specs: &[String], ipv6: bool) -> Vec<IpAddr> {
    let dl = Deadline::after(Budget::subdns().per_domain);
    resolve_via_servers_traced(domain, specs, ipv6, dl).ips
}

pub fn resolve_via_servers_traced(
    domain: &str,
    specs: &[String],
    ipv6: bool,
    dl: Deadline,
) -> Outcome {
    let mut set = BTreeSet::new();
    let mut trace: Vec<String> = Vec::new();
    let parsed: Vec<(String, DnsSpec)> = specs
        .iter()
        .filter_map(|s| parse_dns_spec(s).map(|p| (spec_label(s), p)))
        .collect();

    let boot = bootstrap_servers(specs);

    bootstrap_all(&parsed, &boot, ipv6, dl);

    let socks = !parsed.is_empty() && clash_socks5_ready();

    let pending: Vec<(String, std::sync::mpsc::Receiver<Vec<IpAddr>>)> = parsed
        .iter()
        .map(|(label, spec)| {
            let (domain, spec, boot) = (domain.to_string(), spec.clone(), boot.to_vec());
            (
                label.clone(),
                spawn_bounded(move || resolve_via(&domain, &spec, ipv6, &boot, socks, dl)),
            )
        })
        .collect();
    for (label, rx) in pending {
        let Some(wait) = dl.clamp(HARD_TIMEOUT) else {
            trace.push(format!("{label}=skipped(budget)"));
            continue;
        };
        match rx.recv_timeout(wait) {
            Ok(ips) => trace.push(format!("{label}={}", absorb(ips, &mut set))),
            Err(_) => trace.push(format!("{label}=timeout")),
        }
    }

    if set.is_empty() {
        for addr in crate::fallback::servers(&udp_specs(specs)) {
            if dl.expired() {
                trace.push(format!("fb:{addr}=skipped(budget)"));
                break;
            }
            let ips = crate::dnsutil::resolve_host_via(domain, addr, ipv6);
            trace.push(format!("fb:{addr}={}", absorb(ips, &mut set)));
            if !set.is_empty() {
                break;
            }
        }
    }
    Outcome::new(set.into_iter().collect(), trace)
}

fn absorb(ips: Vec<IpAddr>, set: &mut BTreeSet<IpAddr>) -> String {
    let total = ips.len();
    if total == 0 {
        return "none".to_string();
    }
    let mut kept = 0usize;
    for ip in ips {
        if crate::fallback::is_usable_node_ip(ip) {
            set.insert(ip);
            kept += 1;
        }
    }
    if kept < total {
        format!("{kept}/{total}ip")
    } else {
        format!("{kept}ip")
    }
}

fn spec_label(spec: &str) -> String {
    match parse_dns_spec(spec) {
        Some(DnsSpec::Doh(url)) => format!("doh:{}", crate::dnsutil::url_hostname(&url)),
        Some(DnsSpec::Dot(host, _)) => format!("dot:{host}"),
        Some(DnsSpec::Udp(addr)) => addr.to_string(),
        None => spec.to_string(),
    }
}

fn bootstrap_all(parsed: &[(String, DnsSpec)], boot: &[SocketAddr], ipv6: bool, dl: Deadline) {
    let hosts: Vec<String> = {
        let mut seen = HashSet::new();
        parsed
            .iter()
            .filter_map(|(_, spec)| match spec {
                DnsSpec::Doh(url) => Some(crate::dnsutil::url_hostname(url)),
                DnsSpec::Dot(host, _) => Some(host.clone()),
                DnsSpec::Udp(_) => None,
            })
            .filter(|h| seen.insert(h.clone()))
            .collect()
    };
    if hosts.is_empty() || dl.expired() {
        return;
    }
    std::thread::scope(|s| {
        for host in &hosts {
            s.spawn(move || {
                bootstrap_resolve(host, boot, ipv6, dl);
            });
        }
    });
}

fn udp_specs(specs: &[String]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for spec in specs {
        if let Some(DnsSpec::Udp(addr)) = parse_dns_spec(spec) {
            if !out.iter().any(|a| a.ip() == addr.ip()) {
                out.push(addr);
            }
        }
    }
    out
}

fn bootstrap_servers(specs: &[String]) -> Vec<SocketAddr> {
    fn push(out: &mut Vec<SocketAddr>, addr: SocketAddr) {
        if !out.iter().any(|a| a.ip() == addr.ip()) {
            out.push(addr);
        }
    }
    let mut out: Vec<SocketAddr> = udp_specs(specs);
    for addr in crate::dnsutil::ex_dns_env_servers() {
        push(&mut out, addr);
    }
    for addr in crate::fallback::servers(&out.clone()) {
        push(&mut out, addr);
    }
    out
}

fn bootstrap_resolve(host: &str, boot: &[SocketAddr], ipv6: bool, dl: Deadline) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }

    type BootCache = Mutex<HashMap<String, Arc<OnceLock<Vec<IpAddr>>>>>;
    static CACHE: OnceLock<BootCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cell = {
        let mut guard = cache.lock().unwrap();
        Arc::clone(guard.entry(host.to_string()).or_default())
    };
    if let Some(hit) = cell.get() {
        return hit.clone();
    }

    if dl.expired() {
        return Vec::new();
    }

    cell.get_or_init(|| {
        let boot: Vec<SocketAddr> = boot.iter().copied().take(MAX_BOOTSTRAP_SERVERS).collect();
        let results: Mutex<Vec<(usize, Vec<IpAddr>)>> = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for (i, server) in boot.iter().enumerate() {
                let (server, results) = (*server, &results);
                s.spawn(move || {
                    let ips: Vec<IpAddr> = crate::dnsutil::resolve_host_via(host, server, ipv6)
                        .into_iter()
                        .filter(|ip| crate::fallback::is_usable_node_ip(*ip))
                        .collect();
                    if !ips.is_empty() {
                        results.lock().unwrap().push((i, ips));
                    }
                });
            }
        });

        let mut by_server = results.into_inner().unwrap();
        by_server.sort_by_key(|(i, _)| *i);
        let mut found: Vec<IpAddr> = Vec::new();
        for (_, ips) in by_server {
            for ip in ips {
                if !found.contains(&ip) {
                    found.push(ip);
                }
            }
        }
        found
    })
    .clone()
}

fn spawn_bounded<F>(f: F) -> std::sync::mpsc::Receiver<Vec<IpAddr>>
where
    F: FnOnce() -> Vec<IpAddr> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx
}

pub fn clash_socks5_ready() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| match CLASH_SOCKS5_ADDR.parse::<SocketAddr>() {
        Ok(addr) => socks5_ready_at(addr),
        Err(_) => false,
    })
}

fn socks5_ready_at(addr: SocketAddr) -> bool {
    let Ok(mut sock) = TcpStream::connect_timeout(&addr, SOCKS5_PROBE_TIMEOUT) else {
        return false;
    };
    if sock.set_read_timeout(Some(SOCKS5_PROBE_TIMEOUT)).is_err()
        || sock.set_write_timeout(Some(SOCKS5_PROBE_TIMEOUT)).is_err()
    {
        return false;
    }

    if sock.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut reply = [0u8; 2];

    sock.read_exact(&mut reply).is_ok() && reply[0] == 0x05 && reply[1] != 0xFF
}

fn resolve_via(
    domain: &str,
    spec: &DnsSpec,
    ipv6: bool,
    boot: &[SocketAddr],
    socks: bool,
    dl: Deadline,
) -> Vec<IpAddr> {
    match spec {
        DnsSpec::Udp(addr) => crate::dnsutil::resolve_host_via(domain, *addr, ipv6),
        DnsSpec::Dot(host, port) => resolve_dot(domain, host, *port, ipv6, boot, dl),
        DnsSpec::Doh(url) => {
            let host = crate::dnsutil::url_hostname(url);
            let ips = doh_resolve(&host, url, domain, ipv6, boot, dl);
            if !ips.is_empty() || !socks || dl.expired() {
                return ips;
            }
            resolve_doh(
                crate::httpcli::insecure_client(),
                CLASH_SOCKS5,
                domain,
                url,
                ipv6,
                TIMEOUT,
            )
        }
    }
}

fn next_id() -> u16 {
    static ID: AtomicU16 = AtomicU16::new(1);
    ID.fetch_add(1, Ordering::Relaxed)
}

fn doh_client_pinned(key: &str, ips: Vec<IpAddr>) -> wreq::Client {
    static CACHE: OnceLock<Mutex<HashMap<String, wreq::Client>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().unwrap().get(key) {
        return hit.clone();
    }
    let client = crate::httpcli::client_for_ips(ips);
    cache
        .lock()
        .unwrap()
        .insert(key.to_string(), client.clone());
    client
}

fn doh_resolve(
    host: &str,
    url: &str,
    domain: &str,
    ipv6: bool,
    boot: &[SocketAddr],
    dl: Deadline,
) -> Vec<IpAddr> {
    static WINNER: OnceLock<Mutex<HashMap<String, IpAddr>>> = OnceLock::new();
    let winner = WINNER.get_or_init(|| Mutex::new(HashMap::new()));

    let candidates = bootstrap_resolve(host, boot, ipv6, dl);
    if candidates.is_empty() {
        return resolve_doh(
            crate::httpcli::insecure_client(),
            "",
            domain,
            url,
            ipv6,
            TIMEOUT,
        );
    }

    if let Some(ip) = winner.lock().unwrap().get(host).copied() {
        let client = doh_client_pinned(&format!("{host}|{ip}"), vec![ip]);
        let ips = resolve_doh(&client, "", domain, url, ipv6, TIMEOUT);
        if !ips.is_empty() {
            return ips;
        }

        winner.lock().unwrap().remove(host);
    }

    let all = doh_client_pinned(host, candidates.clone());
    let ips = resolve_doh(&all, "", domain, url, ipv6, TIMEOUT);
    if !ips.is_empty() {
        return ips;
    }

    for ip in candidates {

        if dl.expired() {
            break;
        }
        let client = doh_client_pinned(&format!("{host}|{ip}"), vec![ip]);
        let ips = resolve_doh(&client, "", domain, url, ipv6, RETRY_TIMEOUT);
        if !ips.is_empty() {
            winner.lock().unwrap().insert(host.to_string(), ip);
            return ips;
        }
    }
    Vec::new()
}

fn resolve_doh(
    client: &wreq::Client,
    proxy: &str,
    domain: &str,
    url: &str,
    ipv6: bool,
    timeout: Duration,
) -> Vec<IpAddr> {
    crate::rt::block_on(async {
        let mut out = Vec::new();
        if let Some(resp) = doh_query(client, proxy, domain, url, TYPE_A, timeout).await {
            out.extend(resp.v4.into_iter().map(IpAddr::V4));
        }
        if ipv6 && let Some(resp) = doh_query(client, proxy, domain, url, TYPE_AAAA, timeout).await
        {
            out.extend(resp.v6.into_iter().map(IpAddr::V6));
        }
        out
    })
}

async fn doh_query(
    client: &wreq::Client,
    proxy: &str,
    domain: &str,
    url: &str,
    qtype: u16,
    timeout: Duration,
) -> Option<message::DnsResponse> {
    let id = next_id();
    let query = message::build_query(id, domain, qtype).ok()?;
    let mut rb = crate::httpcli::bare_identity(client.post(url))
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .timeout(timeout)
        .body(query);
    if let Some(p) = crate::httpcli::proxy_for(proxy).ok()? {
        rb = rb.proxy(p);
    }

    let resp = tokio::time::timeout(timeout, rb.send()).await.ok()?.ok()?;
    if !(200..300).contains(&resp.status().as_u16()) {
        return None;
    }
    let (body, truncated) = crate::httpcli::read_body_bounded(resp, 65536).await.ok()?;
    if truncated {
        return None;
    }
    let parsed = message::parse_response(&body).ok()?;
    if parsed.id != id {
        return None;
    }
    Some(parsed)
}

fn dot_connector() -> &'static btls::ssl::SslConnector {
    static CFG: OnceLock<btls::ssl::SslConnector> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut b = btls::ssl::SslConnector::builder(btls::ssl::SslMethod::tls())
            .expect("btls connector builder");
        b.set_verify(btls::ssl::SslVerifyMode::NONE);
        b.build()
    })
}

fn resolve_dot(
    domain: &str,
    host: &str,
    port: u16,
    ipv6: bool,
    boot: &[SocketAddr],
    dl: Deadline,
) -> Vec<IpAddr> {
    for addr in dot_addrs(host, port, ipv6, boot, dl) {
        if dl.expired() {
            break;
        }
        if let Some(ips) = dot_query(domain, host, addr, ipv6) {
            if !ips.is_empty() {
                return ips;
            }
        }
    }
    Vec::new()
}

fn dot_addrs(
    host: &str,
    port: u16,
    ipv6: bool,
    boot: &[SocketAddr],
    dl: Deadline,
) -> Vec<SocketAddr> {
    let ips = bootstrap_resolve(host, boot, ipv6, dl);
    if !ips.is_empty() {
        return ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
    }
    (host, port)
        .to_socket_addrs()
        .map(|it| it.collect())
        .unwrap_or_default()
}

fn dot_query(domain: &str, host: &str, addr: SocketAddr, ipv6: bool) -> Option<Vec<IpAddr>> {
    crate::rt::block_on(dot_query_async(domain, host, addr, ipv6))
}

async fn dot_query_async(
    domain: &str,
    host: &str,
    addr: SocketAddr,
    ipv6: bool,
) -> Option<Vec<IpAddr>> {
    let tcp = tokio::time::timeout(DOT_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let mut cfg = dot_connector().configure().ok()?;

    cfg.set_verify_hostname(false);
    if host.parse::<IpAddr>().is_ok() {
        cfg.set_use_server_name_indication(false);
    }
    let ssl = cfg.into_ssl(host).ok()?;
    let mut tls = tokio_btls::SslStream::new(ssl, tcp).ok()?;
    tokio::time::timeout(TIMEOUT, std::pin::Pin::new(&mut tls).connect())
        .await
        .ok()?
        .ok()?;

    let mut out = Vec::new();
    if let Some(resp) = dot_one(&mut tls, domain, TYPE_A).await {
        out.extend(resp.v4.into_iter().map(IpAddr::V4));
    }
    if ipv6 && let Some(resp) = dot_one(&mut tls, domain, TYPE_AAAA).await {
        out.extend(resp.v6.into_iter().map(IpAddr::V6));
    }
    Some(out)
}

async fn dot_one(
    tls: &mut tokio_btls::SslStream<tokio::net::TcpStream>,
    domain: &str,
    qtype: u16,
) -> Option<message::DnsResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let id = next_id();
    let query = message::build_query(id, domain, qtype).ok()?;

    let len = u16::try_from(query.len()).ok()?;
    let exchange = async {
        tls.write_all(&len.to_be_bytes()).await.ok()?;
        tls.write_all(&query).await.ok()?;
        tls.flush().await.ok()?;
        let mut lenbuf = [0u8; 2];
        tls.read_exact(&mut lenbuf).await.ok()?;
        let rlen = u16::from_be_bytes(lenbuf) as usize;
        if rlen == 0 {
            return None;
        }
        let mut buf = vec![0u8; rlen];
        tls.read_exact(&mut buf).await.ok()?;
        Some(buf)
    };
    let buf = tokio::time::timeout(TIMEOUT, exchange).await.ok()??;
    let parsed = message::parse_response(&buf).ok()?;
    if parsed.id != id {
        return None;
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use yaml_rust2::YamlLoader;

    fn test_dl() -> Deadline {
        Deadline::after(Duration::from_secs(30))
    }

    #[test]
    fn doh_blackhole_server_does_not_hang() {
        use std::net::TcpListener;
        use std::time::Instant;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in listener.incoming() {
                match s {
                    Ok(s) => held.push(s),
                    Err(_) => break,
                }
            }
        });
        let spec = format!("https://127.0.0.1:{port}/dns-query");
        let start = Instant::now();

        let ips = resolve_via_servers("blackhole.invalid", std::slice::from_ref(&spec), false);
        let elapsed = start.elapsed();
        assert!(
            ips.is_empty(),
            "blackhole DoH should not resolve to any IP: {ips:?}"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "resolve_via_servers stuck {elapsed:?} (should return near HARD_TIMEOUT + fallback budget)"
        );
    }

    #[test]
    fn dot_connector_builds_and_failed_handshake_returns_none() {
        use std::net::TcpListener;
        let _ = dot_connector();

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();

        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                drop(s);
            }
        });
        assert!(
            dot_query("example.com", "dot.example", addr, false).is_none(),
            "handshake failure must be None, not a panic"
        );
    }

    #[test]
    fn socks5_probe_distinguishes_real_proxy_from_dead_port() {
        use std::net::TcpListener;

        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        assert!(!socks5_ready_at(dead_addr), "no listener must not be ready");

        let mute = TcpListener::bind("127.0.0.1:0").unwrap();
        let mute_addr = mute.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in mute.incoming().flatten() {
                held.push(s);
            }
        });
        let start = std::time::Instant::now();
        assert!(
            !socks5_ready_at(mute_addr),
            "mute listener must not be ready"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "probe should give up fast, took {:?}",
            start.elapsed()
        );

        let real = TcpListener::bind("127.0.0.1:0").unwrap();
        let real_addr = real.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = real.accept() {
                let mut greet = [0u8; 3];
                if s.read_exact(&mut greet).is_ok() {
                    let _ = s.write_all(&[0x05, 0x00]);
                }
            }
        });
        assert!(socks5_ready_at(real_addr), "a real SOCKS5 greeter is ready");
    }

    #[test]
    fn bootstrap_unions_all_servers_not_just_first() {
        let polluted = mock_dns(Ipv4Addr::new(1, 2, 3, 4));
        let clean = mock_dns(Ipv4Addr::new(104, 16, 0, 1));
        let boot = vec![
            format!("127.0.0.1:{}", polluted.port).parse().unwrap(),
            format!("127.0.0.1:{}", clean.port).parse().unwrap(),
        ];
        let got = bootstrap_resolve("boot-union.test", &boot, false, test_dl());
        assert_eq!(
            got,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "104.16.0.1".parse::<IpAddr>().unwrap(),
            ],
            "both servers' answers must survive, in server priority order: {got:?}"
        );
    }

    #[test]
    fn bootstrap_dedups_across_servers() {
        let a = mock_dns(Ipv4Addr::new(9, 9, 9, 9));
        let b = mock_dns(Ipv4Addr::new(9, 9, 9, 9));
        let boot = vec![
            format!("127.0.0.1:{}", a.port).parse().unwrap(),
            format!("127.0.0.1:{}", b.port).parse().unwrap(),
        ];
        let got = bootstrap_resolve("boot-dedup.test", &boot, false, test_dl());
        assert_eq!(got, vec!["9.9.9.9".parse::<IpAddr>().unwrap()], "{got:?}");
    }

    #[test]
    fn bootstrap_filters_fakeip_but_keeps_clean_peer() {
        let fake = mock_dns(Ipv4Addr::new(7, 7, 7, 7));
        let clean = mock_dns(Ipv4Addr::new(104, 16, 0, 2));
        let boot = vec![
            format!("127.0.0.1:{}", fake.port).parse().unwrap(),
            format!("127.0.0.1:{}", clean.port).parse().unwrap(),
        ];
        let got = bootstrap_resolve("boot-fakeip.test", &boot, false, test_dl());
        assert_eq!(
            got,
            vec!["104.16.0.2".parse::<IpAddr>().unwrap()],
            "{got:?}"
        );
    }

    #[test]
    fn bootstrap_order_udp_then_fallback() {

        let specs = vec![
            "https://doh.example.com:8443/dns-query".to_string(),
            "119.28.28.28".to_string(),
            "tls://dot.pub:853".to_string(),
            "223.5.5.5".to_string(),
        ];
        let boot: Vec<String> = bootstrap_servers(&specs)
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        assert_eq!(
            boot,
            vec![
                "119.28.28.28",
                "223.5.5.5",
                "119.29.29.29",
                "8.8.4.4",
                "1.0.0.1"
            ],
            "{boot:?}"
        );

        assert!(udp_specs(&specs).len() == 2);
    }

    #[test]
    fn fakeip_answers_are_discarded() {
        let fake = mock_dns(Ipv4Addr::new(7, 1, 2, 3));
        let real = mock_dns(Ipv4Addr::new(104, 16, 0, 1));
        let specs = vec![
            format!("127.0.0.1:{}", fake.port),
            format!("127.0.0.1:{}", real.port),
        ];
        let ips = resolve_via_servers("hk.example.com", &specs, false);
        assert_eq!(
            ips,
            vec!["104.16.0.1".parse::<IpAddr>().unwrap()],
            "fakeip must be dropped, real IP kept: {ips:?}"
        );
    }

    struct MockDns {
        port: u16,
        stop: Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for MockDns {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn mock_dns(answer: std::net::Ipv4Addr) -> MockDns {
        use std::net::UdpSocket;
        use std::sync::atomic::AtomicBool;
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let port = sock.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                    if let Ok(q) = message::parse_query(&buf[..n]) {
                        let _ = sock.send_to(&q.answer_a(answer, 60), peer);
                    }
                }
            }
        });
        MockDns {
            port,
            stop,
            handle: Some(handle),
        }
    }

    #[test]
    fn parse_spec_variants() {
        assert_eq!(
            parse_dns_spec("223.5.5.5"),
            Some(DnsSpec::Udp("223.5.5.5:53".parse().unwrap()))
        );
        assert_eq!(
            parse_dns_spec("223.5.5.5:5353"),
            Some(DnsSpec::Udp("223.5.5.5:5353".parse().unwrap()))
        );
        assert_eq!(
            parse_dns_spec("udp://1.1.1.1"),
            Some(DnsSpec::Udp("1.1.1.1:53".parse().unwrap()))
        );
        assert_eq!(
            parse_dns_spec("tcp://8.8.8.8"),
            Some(DnsSpec::Udp("8.8.8.8:53".parse().unwrap()))
        );
        assert_eq!(
            parse_dns_spec("https://doh.pub/dns-query"),
            Some(DnsSpec::Doh("https://doh.pub/dns-query".to_string()))
        );

        assert_eq!(
            parse_dns_spec("https://dns.alidns.com/dns-query#h3=true"),
            Some(DnsSpec::Doh("https://dns.alidns.com/dns-query".to_string()))
        );
        assert_eq!(
            parse_dns_spec("tls://dot.pub:853"),
            Some(DnsSpec::Dot("dot.pub".to_string(), 853))
        );
        assert_eq!(
            parse_dns_spec("tls://dns.alidns.com"),
            Some(DnsSpec::Dot("dns.alidns.com".to_string(), 853))
        );

        assert!(parse_dns_spec("quic://dns.adguard.com:784").is_none());
        assert!(parse_dns_spec("dhcp://en0").is_none());
        assert!(parse_dns_spec("system").is_none());
        assert!(parse_dns_spec("fake-ip").is_none());
        assert!(parse_dns_spec("198.18.0.1/16").is_none());
    }

    #[test]
    #[ignore = "requires network: real DoH/DoT resolution against real servers"]
    fn live_doh_dot_resolve_cp_cloudflare() {
        let doh = resolve_doh(
            crate::httpcli::insecure_client(),
            "",
            "cp.cloudflare.com",
            "https://dns.alidns.com/dns-query",
            false,
            TIMEOUT,
        );
        println!("DoH  https://dns.alidns.com/dns-query  cp.cloudflare.com -> {doh:?}");
        assert!(!doh.is_empty(), "DoH should resolve at least one IP");

        let dot = resolve_dot("cp.cloudflare.com", "dot.pub", 853, false, &[], test_dl());
        println!("DoT  tls://dot.pub:853                  cp.cloudflare.com -> {dot:?}");
        assert!(!dot.is_empty(), "DoT should resolve at least one IP");

        let mixed = resolve_via_servers(
            "cp.cloudflare.com",
            &[
                "https://dns.alidns.com/dns-query".to_string(),
                "tls://dot.pub:853".to_string(),
                "223.5.5.5".to_string(),
            ],
            false,
        );
        println!("MIX  (DoH+DoT+UDP)                      cp.cloudflare.com -> {mixed:?}");
        assert!(!mixed.is_empty());
    }

    #[test]
    #[ignore = "requires network: real DoH/DoT IPv6(AAAA) resolution (cp.cloudflare.com has AAAA)"]
    fn live_doh_dot_resolve_ipv6() {

        let doh = resolve_doh(
            crate::httpcli::insecure_client(),
            "",
            "cp.cloudflare.com",
            "https://dns.alidns.com/dns-query",
            true,
            TIMEOUT,
        );
        println!("DoH ipv6  cp.cloudflare.com -> {doh:?}");
        let dot = resolve_dot("cp.cloudflare.com", "dot.pub", 853, true, &[], test_dl());
        println!("DoT ipv6  cp.cloudflare.com -> {dot:?}");
        assert!(
            doh.iter().any(|ip| ip.is_ipv6()),
            "DoH should resolve AAAA: {doh:?}"
        );
        assert!(
            dot.iter().any(|ip| ip.is_ipv6()),
            "DoT should resolve AAAA: {dot:?}"
        );
    }

    #[test]
    fn extract_matches_user_examples() {
        let y1 = "dns:\n  enable: true\n  ipv6: false\n  default-nameserver: [223.5.5.5, 119.29.29.29]\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  use-hosts: true\n  nameserver-policy:\n    +.google.com: \"https://dns.cloudflare.com/dns-query\"\n    +.googleapis.com: \"https://dns.cloudflare.com/dns-query\"\n  nameserver:\n    - \"https://doh.pub/dns-query\"\n    - \"https://dns.alidns.com/dns-query\"\n    - \"tls://dot.pub:853\"\n    - \"tls://dns.alidns.com:853\"\n";
        let doc = &YamlLoader::load_from_str(y1).unwrap()[0];
        let got = extract_dns_servers(&doc["dns"]);
        assert_eq!(
            got,
            vec![
                "223.5.5.5",
                "119.29.29.29",
                "https://doh.pub/dns-query",
                "https://dns.alidns.com/dns-query",
                "tls://dot.pub:853",
                "tls://dns.alidns.com:853",
                "https://dns.cloudflare.com/dns-query",
            ],
            "{got:?}"
        );

        let y2 = "dns:\n  ipv6: false\n  enable: true\n  listen: 0.0.0.0:1053\n  use-hosts: false\n  default-nameserver:\n    - 119.28.28.28\n    - 119.29.29.29\n  nameserver:\n    - https://doh.example.com:8443/dns-query/0f1e2d3c4b5a69788796a5b4\n    - https://doh2.example.com:443/dns-query/0f1e2d3c4b5a69788796a5b4\n";
        let doc2 = &YamlLoader::load_from_str(y2).unwrap()[0];
        let got2 = extract_dns_servers(&doc2["dns"]);
        assert_eq!(
            got2,
            vec![
                "119.28.28.28",
                "119.29.29.29",
                "https://doh.example.com:8443/dns-query/0f1e2d3c4b5a69788796a5b4",
                "https://doh2.example.com:443/dns-query/0f1e2d3c4b5a69788796a5b4",
            ],
            "listen should not be extracted: {got2:?}"
        );
    }
}
