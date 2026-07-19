// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use sb_dns::message::{self, TYPE_A, TYPE_AAAA};
use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use yaml_rust2::Yaml;

const DOH_UA: &str = "sniffbox-dns/1";
const TIMEOUT: Duration = Duration::from_secs(5);

const HARD_TIMEOUT: Duration = Duration::from_secs(6);

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
    for spec in specs {
        if let Some(parsed) = parse_dns_spec(spec) {
            for ip in resolve_bounded(domain, &parsed, ipv6, clash) {
                set.insert(ip);
            }
        }
    }
    set.into_iter().collect()
}

fn resolve_bounded(domain: &str, spec: &DnsSpec, ipv6: bool, clash: bool) -> Vec<IpAddr> {
    let ips = run_bounded({
        let (domain, spec) = (domain.to_string(), spec.clone());
        move || resolve_via(&domain, &spec, ipv6)
    });
    if !ips.is_empty() {
        return ips;
    }

    if clash {
        if let DnsSpec::Doh(url) = spec {
            return run_bounded({
                let (domain, url) = (domain.to_string(), url.clone());
                move || resolve_doh(doh_socks_agent(), &domain, &url, ipv6)
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

fn resolve_via(domain: &str, spec: &DnsSpec, ipv6: bool) -> Vec<IpAddr> {
    match spec {
        DnsSpec::Udp(addr) => crate::dnsutil::resolve_host_via(domain, *addr, ipv6),
        DnsSpec::Doh(url) => resolve_doh(doh_agent(), domain, url, ipv6),
        DnsSpec::Dot(host, port) => resolve_dot(domain, host, *port, ipv6),
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

fn doh_socks_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        crate::httpcli::agent(CLASH_SOCKS5, DOH_UA, TIMEOUT).expect("doh socks agent")
    })
}

fn resolve_doh(agent: &ureq::Agent, domain: &str, url: &str, ipv6: bool) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Some(resp) = doh_query(agent, domain, url, TYPE_A) {
        out.extend(resp.v4.into_iter().map(IpAddr::V4));
    }
    if ipv6 {
        if let Some(resp) = doh_query(agent, domain, url, TYPE_AAAA) {
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

fn resolve_dot(domain: &str, host: &str, port: u16, ipv6: bool) -> Vec<IpAddr> {
    dot_query(domain, host, port, ipv6).unwrap_or_default()
}

fn dot_query(domain: &str, host: &str, port: u16, ipv6: bool) -> Option<Vec<IpAddr>> {
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
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
        let ips = resolve_via_servers("example.com", std::slice::from_ref(&spec), false);
        let elapsed = start.elapsed();
        assert!(ips.is_empty(), "blackhole DoH should not resolve to any IP: {ips:?}");
        assert!(
            elapsed < Duration::from_secs(25),
            "resolve_via_servers stuck {elapsed:?} (should return near HARD_TIMEOUT)"
        );
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
            doh_agent(),
            "cp.cloudflare.com",
            "https://dns.alidns.com/dns-query",
            false,
        );
        println!("DoH  https://dns.alidns.com/dns-query  cp.cloudflare.com -> {doh:?}");
        assert!(!doh.is_empty(), "DoH should resolve at least one IP");

        let dot = resolve_dot("cp.cloudflare.com", "dot.pub", 853, false);
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
            doh_agent(),
            "cp.cloudflare.com",
            "https://dns.alidns.com/dns-query",
            true,
        );
        println!("DoH ipv6  cp.cloudflare.com -> {doh:?}");
        let dot = resolve_dot("cp.cloudflare.com", "dot.pub", 853, true);
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
