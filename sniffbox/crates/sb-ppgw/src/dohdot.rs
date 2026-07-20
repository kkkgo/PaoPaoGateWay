// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use sb_dns::message::{self, TYPE_A, TYPE_AAAA};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use yaml_rust2::Yaml;

const DOH_UA: &str = "sniffbox-dns/1";
const TIMEOUT: Duration = Duration::from_secs(5);

const HARD_TIMEOUT: Duration = Duration::from_secs(6);

const RETRY_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_BOOTSTRAP_SERVERS: usize = 8;

const CLASH_SOCKS5: &str = "socks5h://127.0.0.1:1080";

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
    let mut set = BTreeSet::new();

    let clash = clash_running();
    let boot = bootstrap_servers(specs);

    for spec in specs {
        match parse_dns_spec(spec) {
            Some(DnsSpec::Doh(url)) => {
                bootstrap_resolve(&crate::dnsutil::url_hostname(&url), &boot, ipv6);
            }
            Some(DnsSpec::Dot(host, _)) => {
                bootstrap_resolve(&host, &boot, ipv6);
            }
            _ => {}
        }
    }
    for spec in specs {
        if let Some(parsed) = parse_dns_spec(spec) {
            for ip in resolve_bounded(domain, &parsed, ipv6, clash, &boot) {

                if crate::fallback::is_usable_node_ip(ip) {
                    set.insert(ip);
                }
            }
        }
    }

    if set.is_empty() {
        for addr in crate::fallback::servers(&udp_specs(specs)) {
            for ip in crate::dnsutil::resolve_host_via(domain, addr, ipv6) {
                if crate::fallback::is_usable_node_ip(ip) {
                    set.insert(ip);
                }
            }
            if !set.is_empty() {
                break;
            }
        }
    }
    set.into_iter().collect()
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

fn bootstrap_resolve(host: &str, boot: &[SocketAddr], ipv6: bool) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<IpAddr>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let mut guard = cache.lock().unwrap();
    if let Some(hit) = guard.get(host) {
        return hit.clone();
    }

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
    guard.insert(host.to_string(), found.clone());
    found
}

fn resolve_bounded(
    domain: &str,
    spec: &DnsSpec,
    ipv6: bool,
    clash: bool,
    boot: &[SocketAddr],
) -> Vec<IpAddr> {
    let ips = run_bounded({
        let (domain, spec, boot) = (domain.to_string(), spec.clone(), boot.to_vec());
        move || resolve_via(&domain, &spec, ipv6, &boot)
    });
    if !ips.is_empty() {
        return ips;
    }

    if clash {
        if let DnsSpec::Doh(url) = spec {
            return run_bounded({
                let (domain, url) = (domain.to_string(), url.clone());
                move || resolve_doh(doh_socks_agent().clone(), &domain, &url, ipv6)
            });
        }
    }
    ips
}

fn run_bounded<F>(f: F) -> Vec<IpAddr>
where
    F: FnOnce() -> Vec<IpAddr> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(HARD_TIMEOUT).unwrap_or_default()
}

pub fn clash_running() -> bool {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            if comm.trim() == "clash" {
                return true;
            }
        }
    }
    false
}

fn resolve_via(domain: &str, spec: &DnsSpec, ipv6: bool, boot: &[SocketAddr]) -> Vec<IpAddr> {
    match spec {
        DnsSpec::Udp(addr) => crate::dnsutil::resolve_host_via(domain, *addr, ipv6),
        DnsSpec::Doh(url) => {
            let host = crate::dnsutil::url_hostname(url);
            doh_resolve(&host, url, domain, ipv6, boot)
        }
        DnsSpec::Dot(host, port) => resolve_dot(domain, host, *port, ipv6, boot),
    }
}

fn next_id() -> u16 {
    static ID: AtomicU16 = AtomicU16::new(1);
    ID.fetch_add(1, Ordering::Relaxed)
}

fn doh_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| crate::httpcli::agent("", DOH_UA, TIMEOUT).expect("doh agent"))
}

fn doh_agent_pinned(key: &str, ips: Vec<IpAddr>, timeout: Duration) -> ureq::Agent {
    static CACHE: OnceLock<Mutex<HashMap<String, ureq::Agent>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().unwrap().get(key) {
        return hit.clone();
    }
    let agent = crate::httpcli::agent_with_ips(ips, DOH_UA, timeout);
    cache.lock().unwrap().insert(key.to_string(), agent.clone());
    agent
}

fn doh_resolve(host: &str, url: &str, domain: &str, ipv6: bool, boot: &[SocketAddr]) -> Vec<IpAddr> {
    static WINNER: OnceLock<Mutex<HashMap<String, IpAddr>>> = OnceLock::new();
    let winner = WINNER.get_or_init(|| Mutex::new(HashMap::new()));

    let candidates = bootstrap_resolve(host, boot, ipv6);
    if candidates.is_empty() {
        return resolve_doh(doh_agent().clone(), domain, url, ipv6);
    }

    if let Some(ip) = winner.lock().unwrap().get(host).copied() {
        let agent = doh_agent_pinned(&format!("{host}|{ip}"), vec![ip], TIMEOUT);
        let ips = resolve_doh(agent, domain, url, ipv6);
        if !ips.is_empty() {
            return ips;
        }

        winner.lock().unwrap().remove(host);
    }

    let all = doh_agent_pinned(host, candidates.clone(), TIMEOUT);
    let ips = resolve_doh(all, domain, url, ipv6);
    if !ips.is_empty() {
        return ips;
    }

    for ip in candidates {
        let agent = doh_agent_pinned(&format!("{host}|{ip}"), vec![ip], RETRY_TIMEOUT);
        let ips = resolve_doh(agent, domain, url, ipv6);
        if !ips.is_empty() {
            winner.lock().unwrap().insert(host.to_string(), ip);
            return ips;
        }
    }
    Vec::new()
}

fn doh_socks_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        crate::httpcli::agent(CLASH_SOCKS5, DOH_UA, TIMEOUT).expect("doh socks agent")
    })
}

fn resolve_doh(agent: ureq::Agent, domain: &str, url: &str, ipv6: bool) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Some(resp) = doh_query(&agent, domain, url, TYPE_A) {
        out.extend(resp.v4.into_iter().map(IpAddr::V4));
    }
    if ipv6 {
        if let Some(resp) = doh_query(&agent, domain, url, TYPE_AAAA) {
            out.extend(resp.v6.into_iter().map(IpAddr::V6));
        }
    }
    out
}

fn doh_query(
    agent: &ureq::Agent,
    domain: &str,
    url: &str,
    qtype: u16,
) -> Option<message::DnsResponse> {
    let id = next_id();
    let query = message::build_query(id, domain, qtype).ok()?;
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .send(&query[..])
        .ok()?;
    if !(200..300).contains(&resp.status().as_u16()) {
        return None;
    }
    let body = resp
        .body_mut()
        .with_config()
        .limit(65536)
        .read_to_vec()
        .ok()?;
    let parsed = message::parse_response(&body).ok()?;
    if parsed.id != id {
        return None;
    }
    Some(parsed)
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end: &rustls::pki_types::CertificateDer,
        _inter: &[rustls::pki_types::CertificateDer],
        _name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("rustls protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

fn resolve_dot(domain: &str, host: &str, port: u16, ipv6: bool, boot: &[SocketAddr]) -> Vec<IpAddr> {
    for addr in dot_addrs(host, port, ipv6, boot) {
        if let Some(ips) = dot_query(domain, host, addr, ipv6) {
            if !ips.is_empty() {
                return ips;
            }
        }
    }
    Vec::new()
}

fn dot_addrs(host: &str, port: u16, ipv6: bool, boot: &[SocketAddr]) -> Vec<SocketAddr> {
    let ips = bootstrap_resolve(host, boot, ipv6);
    if !ips.is_empty() {
        return ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
    }
    (host, port)
        .to_socket_addrs()
        .map(|it| it.collect())
        .unwrap_or_default()
}

fn dot_query(
    domain: &str,
    host: &str,
    addr: SocketAddr,
    ipv6: bool,
) -> Option<Vec<IpAddr>> {
    let sock = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    sock.set_read_timeout(Some(TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(TIMEOUT)).ok()?;
    let server_name = match host.parse::<IpAddr>() {
        Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => rustls::pki_types::ServerName::try_from(host.to_string()).ok()?,
    };
    let conn = rustls::ClientConnection::new(tls_config(), server_name).ok()?;
    let mut tls = rustls::StreamOwned::new(conn, sock);

    let mut out = Vec::new();
    if let Some(resp) = dot_one(&mut tls, domain, TYPE_A) {
        out.extend(resp.v4.into_iter().map(IpAddr::V4));
    }
    if ipv6 {
        if let Some(resp) = dot_one(&mut tls, domain, TYPE_AAAA) {
            out.extend(resp.v6.into_iter().map(IpAddr::V6));
        }
    }
    Some(out)
}

fn dot_one(
    tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    domain: &str,
    qtype: u16,
) -> Option<message::DnsResponse> {
    let id = next_id();
    let query = message::build_query(id, domain, qtype).ok()?;

    let len = u16::try_from(query.len()).ok()?;
    tls.write_all(&len.to_be_bytes()).ok()?;
    tls.write_all(&query).ok()?;
    tls.flush().ok()?;
    let mut lenbuf = [0u8; 2];
    tls.read_exact(&mut lenbuf).ok()?;
    let rlen = u16::from_be_bytes(lenbuf) as usize;
    if rlen == 0 || rlen > 65535 {
        return None;
    }
    let mut buf = vec![0u8; rlen];
    tls.read_exact(&mut buf).ok()?;
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
        assert!(ips.is_empty(), "blackhole DoH should not resolve to any IP: {ips:?}");
        assert!(
            elapsed < Duration::from_secs(30),
            "resolve_via_servers stuck {elapsed:?} (should return near HARD_TIMEOUT + fallback budget)"
        );
    }

    #[test]
    fn bootstrap_unions_all_servers_not_just_first() {
        let polluted = mock_dns(Ipv4Addr::new(1, 2, 3, 4));
        let clean = mock_dns(Ipv4Addr::new(104, 16, 0, 1));
        let boot = vec![
            format!("127.0.0.1:{}", polluted.port).parse().unwrap(),
            format!("127.0.0.1:{}", clean.port).parse().unwrap(),
        ];
        let got = bootstrap_resolve("boot-union.test", &boot, false);
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
        let got = bootstrap_resolve("boot-dedup.test", &boot, false);
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
        let got = bootstrap_resolve("boot-fakeip.test", &boot, false);
        assert_eq!(got, vec!["104.16.0.2".parse::<IpAddr>().unwrap()], "{got:?}");
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
            doh_agent().clone(),
            "cp.cloudflare.com",
            "https://dns.alidns.com/dns-query",
            false,
        );
        println!("DoH  https://dns.alidns.com/dns-query  cp.cloudflare.com -> {doh:?}");
        assert!(!doh.is_empty(), "DoH should resolve at least one IP");

        let dot = resolve_dot("cp.cloudflare.com", "dot.pub", 853, false, &[]);
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
            doh_agent().clone(),
            "cp.cloudflare.com",
            "https://dns.alidns.com/dns-query",
            true,
        );
        println!("DoH ipv6  cp.cloudflare.com -> {doh:?}");
        let dot = resolve_dot("cp.cloudflare.com", "dot.pub", 853, true, &[]);
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
