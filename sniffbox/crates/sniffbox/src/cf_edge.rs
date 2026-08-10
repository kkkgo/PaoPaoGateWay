// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cf_ctl::Egress;
use crate::config::Protocol;

pub const EDGE_PORT: u16 = 7844;

pub const PICK: usize = 4;

const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

const PROBE_TIMEOUT_PROXIED: Duration = Duration::from_millis(3000);

const ROUND_BUDGET: Duration = Duration::from_secs(8);

const ROUND_BUDGET_PROXIED: Duration = Duration::from_secs(15);

fn round_budget(egress: Egress) -> Duration {
    match egress {
        Egress::Direct => ROUND_BUDGET,
        Egress::Proxied => ROUND_BUDGET_PROXIED,
    }
}

const CONCURRENCY: usize = 8;

const HEALTH_SOCKS5: &str = "127.0.0.1:1079";

const DNS_VIA_PROXY: &str = "1.1.1.1:53";

const DNS_DIRECT: &str = "223.5.5.5:53";

const EDGE_SRV: &str = "_v2-origintunneld._tcp.argotunnel.com";

const PER_REGION: usize = 10;

pub const BUILTIN_V4: &[&str] = &[

    "198.41.192.167",
    "198.41.192.67",
    "198.41.192.57",
    "198.41.192.107",
    "198.41.192.27",
    "198.41.192.7",
    "198.41.192.227",
    "198.41.192.47",
    "198.41.192.37",
    "198.41.192.77",

    "198.41.200.13",
    "198.41.200.193",
    "198.41.200.33",
    "198.41.200.233",
    "198.41.200.53",
    "198.41.200.63",
    "198.41.200.113",
    "198.41.200.73",
    "198.41.200.43",
    "198.41.200.23",
];

pub const BUILTIN_V6: &[&str] = &[

    "2606:4700:a0::1",
    "2606:4700:a0::2",
    "2606:4700:a0::3",
    "2606:4700:a0::4",
    "2606:4700:a0::5",
    "2606:4700:a0::6",
    "2606:4700:a0::7",
    "2606:4700:a0::8",
    "2606:4700:a0::9",
    "2606:4700:a0::10",

    "2606:4700:a8::1",
    "2606:4700:a8::2",
    "2606:4700:a8::3",
    "2606:4700:a8::4",
    "2606:4700:a8::5",
    "2606:4700:a8::6",
    "2606:4700:a8::7",
    "2606:4700:a8::8",
    "2606:4700:a8::9",
    "2606:4700:a8::10",
];

const V6_WIN_MIN: Duration = Duration::from_millis(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeRtt {
    pub ip: IpAddr,
    pub rtt: Duration,

    pub quic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeMode {

    Auto,

    QuicOnly,

    TcpOnly,
}

impl EdgeMode {

    pub fn for_protocol(p: Protocol) -> Self {
        match p {
            Protocol::Quic => Self::QuicOnly,
            Protocol::Http2 => Self::TcpOnly,
        }
    }
}

pub async fn pick_edges(egress: Egress) -> Vec<EdgeRtt> {
    pick_edges_mode(egress, EdgeMode::Auto).await
}

pub async fn pick_edges_proto(egress: Egress, proto: Protocol) -> Vec<EdgeRtt> {
    if egress == Egress::Proxied && proto == Protocol::Http2 {
        let by_quic = pick_edges_mode(egress, EdgeMode::QuicOnly).await;
        if !by_quic.is_empty() {
            return by_quic;
        }
    }
    pick_edges_mode(egress, EdgeMode::for_protocol(proto)).await
}

pub async fn pick_edges_mode(egress: Egress, mode: EdgeMode) -> Vec<EdgeRtt> {

    let deadline = Instant::now() + round_budget(egress);
    let v6_ok = v6_usable(egress);

    let builtin4 = builtin_candidates();
    let mut got4 = measure(egress, builtin4.clone(), mode, deadline).await;

    let builtin6 = if v6_ok {
        builtin_v6_candidates()
    } else {
        Vec::new()
    };
    let mut got6 = Vec::new();
    if !builtin6.is_empty() && !v6_recently_down(egress) && Instant::now() < deadline {
        match measure_v6(egress, &builtin6, mode, deadline).await {
            Some(v) => {
                note_v6(egress, true);
                got6 = v;
            }
            None => note_v6(egress, false),
        }
    }

    if got4.is_empty() && got6.is_empty() && Instant::now() < deadline {

        let tried: BTreeSet<IpAddr> = builtin4.iter().chain(builtin6.iter()).copied().collect();
        let fresh: Vec<IpAddr> = discover_edges(egress, v6_ok)
            .await
            .into_iter()
            .filter(|ip| !tried.contains(ip))
            .collect();
        if fresh.is_empty() {

            tracing::info!(
                egress = egress.as_str(),
                "cf edge: discovery returned no addresses beyond the builtin list; skipping re-probe"
            );
        } else {
            tracing::info!(
                egress = egress.as_str(),
                n = fresh.len(),
                "cf edge: builtin list unreachable; probing newly discovered addresses"
            );
            for r in measure(egress, fresh, mode, deadline).await {
                if r.ip.is_ipv4() { &mut got4 } else { &mut got6 }.push(r);
            }
        }
    }

    let best = pick_family(got4, got6);
    if best.is_empty() {
        tracing::warn!(
            egress = egress.as_str(),
            "cf edge: no reachable edge; starting cloudflared without --edge"
        );
    } else {
        tracing::info!(
            egress = egress.as_str(),
            family = if best[0].ip.is_ipv4() { "v4" } else { "v6" },
            picks = %fmt_picks(&best),
            "cf edge: picked fastest edges"
        );
    }
    best
}

fn pick_family(mut v4: Vec<EdgeRtt>, mut v6: Vec<EdgeRtt>) -> Vec<EdgeRtt> {
    v4.sort_by_key(|e| e.rtt);
    v4.truncate(PICK);
    v6.sort_by_key(|e| e.rtt);
    v6.truncate(PICK);
    match (v4.first().map(|e| e.rtt), v6.first().map(|e| e.rtt)) {
        (Some(a), Some(b)) if v6_clearly_faster(b, a) => v6,
        (Some(_), _) => v4,
        (None, _) => v6,
    }
}

fn v6_clearly_faster(v6: Duration, v4: Duration) -> bool {
    v6 + V6_WIN_MIN <= v4 && v6.as_micros() * 4 <= v4.as_micros() * 3
}

fn v6_usable(egress: Egress) -> bool {
    match egress {
        Egress::Proxied => false,
        Egress::Direct => has_global_v6_route(),
    }
}

fn has_global_v6_route() -> bool {
    let Ok(sock) = std::net::UdpSocket::bind("[::]:0") else {
        return false;
    };
    let probe: SocketAddr = match BUILTIN_V6[0].parse::<Ipv6Addr>() {
        Ok(ip) => SocketAddr::new(IpAddr::V6(ip), EDGE_PORT),
        Err(_) => return false,
    };
    if sock.connect(probe).is_err() {
        return false;
    }
    match sock.local_addr() {
        Ok(SocketAddr::V6(a)) => is_global_v6(a.ip()),
        _ => false,
    }
}

fn is_global_v6(ip: &Ipv6Addr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local() || ip.is_unique_local())
}

async fn measure_v6(
    egress: Egress,
    all: &[IpAddr],
    mode: EdgeMode,
    deadline: Instant,
) -> Option<Vec<EdgeRtt>> {
    let canary: Vec<IpAddr> = all.iter().copied().step_by(PER_REGION).take(2).collect();
    let mut out = measure(egress, canary.clone(), mode, deadline).await;
    if out.is_empty() {
        tracing::debug!(
            egress = egress.as_str(),
            "cf edge: no IPv6 answer from the canaries; skipping the rest of the v6 list"
        );
        return None;
    }
    let rest: Vec<IpAddr> = all
        .iter()
        .copied()
        .filter(|ip| !canary.contains(ip))
        .collect();
    out.extend(measure(egress, rest, mode, deadline).await);
    Some(out)
}

static V6_DOWN_UNTIL: Mutex<[Option<Instant>; 2]> = Mutex::new([None, None]);

const V6_DOWN_TTL: Duration = Duration::from_secs(300);

fn v6_recently_down(egress: Egress) -> bool {
    let g = V6_DOWN_UNTIL.lock().unwrap_or_else(|e| e.into_inner());
    g[egress.idx()].is_some_and(|until| Instant::now() < until)
}

fn note_v6(egress: Egress, reachable: bool) {
    let mut g = V6_DOWN_UNTIL.lock().unwrap_or_else(|e| e.into_inner());
    g[egress.idx()] = (!reachable).then(|| Instant::now() + V6_DOWN_TTL);
}

pub fn edge_arg(ip: IpAddr) -> String {
    SocketAddr::new(ip, EDGE_PORT).to_string()
}

fn fmt_picks(picks: &[EdgeRtt]) -> String {
    picks
        .iter()
        .map(|e| {
            format!(
                "{}={}ms{}",
                e.ip,
                e.rtt.as_millis(),
                if e.quic { "" } else { "/tcp" }
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn builtin_candidates() -> Vec<IpAddr> {
    BUILTIN_V4
        .iter()
        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
        .map(IpAddr::V4)
        .collect()
}

fn builtin_v6_candidates() -> Vec<IpAddr> {
    BUILTIN_V6
        .iter()
        .filter_map(|s| s.parse::<Ipv6Addr>().ok())
        .map(IpAddr::V6)
        .collect()
}

async fn measure(
    egress: Egress,
    candidates: Vec<IpAddr>,
    mode: EdgeMode,
    deadline: Instant,
) -> Vec<EdgeRtt> {
    if mode == EdgeMode::TcpOnly {
        return measure_with(egress, &candidates, false, deadline).await;
    }
    let quic = measure_with(egress, &candidates, true, deadline).await;
    if !quic.is_empty() || mode == EdgeMode::QuicOnly {
        return quic;
    }
    tracing::debug!(
        egress = egress.as_str(),
        "cf edge: no QUIC answer from any candidate; falling back to TCP connect timing"
    );
    measure_with(egress, &candidates, false, deadline).await
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EdgeRtts {
    pub quic: Option<Duration>,
    pub http2: Option<Duration>,
}

impl EdgeRtts {

    pub fn reference_ms(&self) -> u128 {
        [self.http2, self.quic]
            .into_iter()
            .flatten()
            .map(|d| d.as_millis())
            .find(|&ms| ms > 0)
            .unwrap_or(0)
    }
}

pub async fn edge_rtts(egress: Egress) -> EdgeRtts {
    let quic = pick_edges_mode(egress, EdgeMode::QuicOnly)
        .await
        .first()
        .map(|e| e.rtt);

    let http2 = pick_edges_mode(egress, EdgeMode::TcpOnly)
        .await
        .first()
        .map(|e| e.rtt)
        .filter(|d| !d.is_zero());
    EdgeRtts { quic, http2 }
}

async fn measure_with(
    egress: Egress,
    candidates: &[IpAddr],
    quic: bool,
    deadline: Instant,
) -> Vec<EdgeRtt> {
    let mut out = Vec::new();
    for chunk in candidates.chunks(CONCURRENCY) {
        if Instant::now() >= deadline {
            break;
        }
        let mut tasks = Vec::with_capacity(chunk.len());
        for &ip in chunk {
            tasks.push(tokio::spawn(async move {
                let addr = SocketAddr::new(ip, EDGE_PORT);
                let rtt = if quic {
                    probe_quic(egress, addr).await
                } else {
                    probe_tcp(egress, addr).await
                };
                rtt.map(|rtt| EdgeRtt { ip, rtt, quic })
            }));
        }
        for t in tasks {
            if let Ok(Some(r)) = t.await {
                out.push(r);
            }
        }
    }
    out
}

async fn probe_quic(egress: Egress, dst: SocketAddr) -> Option<Duration> {
    let pkt = vn_probe_packet();
    let t0 = Instant::now();
    let reply = match egress {
        Egress::Direct => udp_roundtrip_direct(dst, &pkt).await?,
        Egress::Proxied => udp_roundtrip_socks5(dst, &pkt).await?,
    };
    is_version_negotiation(&reply).then(|| t0.elapsed())
}

async fn probe_tcp(egress: Egress, dst: SocketAddr) -> Option<Duration> {
    let t0 = Instant::now();
    match egress {
        Egress::Direct => {
            tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(dst))
                .await
                .ok()?
                .ok()?;
        }
        Egress::Proxied => {
            let mut s = tokio::time::timeout(
                PROBE_TIMEOUT_PROXIED,
                tokio::net::TcpStream::connect(HEALTH_SOCKS5),
            )
            .await
            .ok()?
            .ok()?;

            tokio::time::timeout(
                PROBE_TIMEOUT_PROXIED,
                sb_outbound::socks5::handshake_no_auth(&mut s),
            )
            .await
            .ok()?
            .ok()?;
            tokio::time::timeout(
                PROBE_TIMEOUT_PROXIED,
                sb_outbound::socks5::send_connect(&mut s, dst, None),
            )
            .await
            .ok()?
            .ok()?;
        }
    }
    Some(t0.elapsed())
}

fn vn_probe_packet() -> Vec<u8> {
    let mut p = Vec::with_capacity(1200);
    p.push(0xc0);
    p.extend_from_slice(&0x0a0a0a0au32.to_be_bytes());
    let cid = rand_bytes8();
    p.push(8);
    p.extend_from_slice(&cid);
    p.push(8);
    p.extend_from_slice(&rand_bytes8());
    p.resize(1200, 0);
    p
}

fn is_version_negotiation(buf: &[u8]) -> bool {
    buf.len() >= 5 && buf[0] & 0x80 != 0 && buf[1..5] == [0, 0, 0, 0]
}

fn rand_bytes8() -> [u8; 8] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (t ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_be_bytes()
}

async fn udp_roundtrip_direct(dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let bind: SocketAddr = if dst.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
    sock.send_to(payload, dst).await.ok()?;
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(PROBE_TIMEOUT, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    Some(buf)
}

async fn udp_roundtrip_socks5(dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let mut ctrl = tokio::time::timeout(
        PROBE_TIMEOUT_PROXIED,
        tokio::net::TcpStream::connect(HEALTH_SOCKS5),
    )
    .await
    .ok()?
    .ok()?;
    let relay = tokio::time::timeout(
        PROBE_TIMEOUT_PROXIED,
        sb_outbound::socks5_udp::udp_associate(&mut ctrl, "0.0.0.0:0".parse().ok()?),
    )
    .await
    .ok()?
    .ok()?;

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let frame = sb_outbound::socks5_udp::encode_udp_request(dst, payload);
    sock.send_to(&frame, relay).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(PROBE_TIMEOUT_PROXIED, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let (_src, off) = sb_outbound::socks5_udp::decode_udp_reply(&buf[..n]).ok()?;
    Some(buf[off..n].to_vec())
}

async fn discover_edges(egress: Egress, v6: bool) -> Vec<IpAddr> {
    let mut hosts: Vec<String> = Vec::new();
    for (server, via) in dns_plan(egress) {
        if let Some(list) = dns_srv(server, via).await
            && !list.is_empty()
        {
            hosts = list;
            break;
        }
    }
    if hosts.is_empty() {
        tracing::debug!("cf edge: SRV discovery returned nothing");
        return Vec::new();
    }

    let mut seen: BTreeSet<IpAddr> = BTreeSet::new();
    for host in hosts {
        for (server, via) in dns_plan(egress) {
            if let Some(ips) = dns_addrs(server, via, &host, v6).await {
                seen.extend(ips);
                break;
            }
        }
    }
    seen.into_iter().collect()
}

async fn dns_addrs(server: &str, via: Egress, host: &str, v6: bool) -> Option<Vec<IpAddr>> {
    let mut out = dns_a(server, via, host).await.unwrap_or_default();
    if v6 && let Some(v) = dns_aaaa(server, via, host).await {
        out.extend(v);
    }
    (!out.is_empty()).then_some(out)
}

pub async fn resolve_a(egress: Egress, host: &str) -> Option<IpAddr> {
    for (server, via) in dns_plan(egress) {
        if let Some(ips) = dns_a(server, via, host).await
            && let Some(ip) = ips.first()
        {
            return Some(*ip);
        }
    }
    None
}

fn dns_plan(egress: Egress) -> [(&'static str, Egress); 2] {
    match egress {
        Egress::Proxied => [
            (DNS_VIA_PROXY, Egress::Proxied),
            (DNS_DIRECT, Egress::Direct),
        ],
        Egress::Direct => [
            (DNS_DIRECT, Egress::Direct),
            (DNS_VIA_PROXY, Egress::Proxied),
        ],
    }
}

async fn dns_srv(server: &str, via: Egress) -> Option<Vec<String>> {
    let q = sb_dns::message::build_query(dns_id(), EDGE_SRV, sb_dns::message::TYPE_SRV).ok()?;
    let resp = dns_exchange(server, via, &q).await?;
    let parsed = sb_dns::message::parse_response(&resp).ok()?;
    Some(parsed.srv.into_iter().map(|(name, _port)| name).collect())
}

async fn dns_a(server: &str, via: Egress, host: &str) -> Option<Vec<IpAddr>> {
    let q = sb_dns::message::build_query(dns_id(), host, sb_dns::message::TYPE_A).ok()?;
    let resp = dns_exchange(server, via, &q).await?;
    let parsed = sb_dns::message::parse_response(&resp).ok()?;
    let v4: Vec<IpAddr> = parsed.v4.into_iter().map(IpAddr::V4).collect();
    (!v4.is_empty()).then_some(v4)
}

async fn dns_aaaa(server: &str, via: Egress, host: &str) -> Option<Vec<IpAddr>> {
    let q = sb_dns::message::build_query(dns_id(), host, sb_dns::message::TYPE_AAAA).ok()?;
    let resp = dns_exchange(server, via, &q).await?;
    let parsed = sb_dns::message::parse_response(&resp).ok()?;
    let v6: Vec<IpAddr> = parsed.v6.into_iter().map(IpAddr::V6).collect();
    (!v6.is_empty()).then_some(v6)
}

async fn dns_exchange(server: &str, via: Egress, query: &[u8]) -> Option<Vec<u8>> {
    let dst: SocketAddr = server.parse().ok()?;
    match via {
        Egress::Direct => udp_roundtrip_direct(dst, query).await,
        Egress::Proxied => udp_roundtrip_socks5(dst, query).await,
    }
}

fn dns_id() -> u16 {
    u16::from_be_bytes([rand_bytes8()[0], rand_bytes8()[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_list_is_sane() {
        let ips = builtin_candidates();
        assert_eq!(ips.len(), BUILTIN_V4.len(), "every builtin must parse");
        assert_eq!(ips.len(), 20);
        let r1 = ips
            .iter()
            .filter(|ip| ip.to_string().starts_with("198.41.192."))
            .count();
        let r2 = ips
            .iter()
            .filter(|ip| ip.to_string().starts_with("198.41.200."))
            .count();
        assert_eq!((r1, r2), (10, 10), "both regions must be represented");

        let uniq: BTreeSet<_> = ips.iter().collect();
        assert_eq!(uniq.len(), ips.len());
    }

    #[test]
    fn builtin_v6_list_is_sane() {
        let ips = builtin_v6_candidates();
        assert_eq!(ips.len(), BUILTIN_V6.len(), "every v6 builtin must parse");
        assert_eq!(ips.len(), BUILTIN_V4.len(), "one v6 address per v4 address");
        let r1 = ips[..PER_REGION].iter().all(|ip| match ip {
            IpAddr::V6(v) => v.segments()[..3] == [0x2606, 0x4700, 0x00a0],
            _ => false,
        });
        let r2 = ips[PER_REGION..].iter().all(|ip| match ip {
            IpAddr::V6(v) => v.segments()[..3] == [0x2606, 0x4700, 0x00a8],
            _ => false,
        });
        assert!(r1 && r2, "region1 then region2, matching region.md");
        let uniq: BTreeSet<_> = ips.iter().collect();
        assert_eq!(uniq.len(), ips.len());

        let canary: Vec<IpAddr> = ips.iter().copied().step_by(PER_REGION).take(2).collect();
        assert_eq!(canary, vec![ips[0], ips[PER_REGION]]);
    }

    #[test]
    fn edge_arg_brackets_ipv6() {
        assert_eq!(
            edge_arg("198.41.192.7".parse().unwrap()),
            "198.41.192.7:7844"
        );
        assert_eq!(
            edge_arg("2606:4700:a0::1".parse().unwrap()),
            "[2606:4700:a0::1]:7844"
        );
    }

    #[test]
    fn pick_family_never_mixes_families() {
        let mk = |ip: &str, ms: u64| EdgeRtt {
            ip: ip.parse().unwrap(),
            rtt: Duration::from_millis(ms),
            quic: true,
        };
        let v4 = vec![
            mk("198.41.192.7", 100),
            mk("198.41.192.27", 110),
            mk("198.41.200.13", 120),
            mk("198.41.200.23", 130),
        ];
        let v6 = vec![mk("2606:4700:a0::1", 20), mk("2606:4700:a8::1", 21)];
        let picked = pick_family(v4.clone(), v6.clone());
        assert!(
            picked.iter().all(|e| e.ip.is_ipv6()),
            "v6 won, so every pick must be v6"
        );
        let picked = pick_family(v4.clone(), Vec::new());
        assert!(picked.iter().all(|e| e.ip.is_ipv4()));

        let picked = pick_family(Vec::new(), v6);
        assert_eq!(picked.len(), 2);
        assert!(picked.iter().all(|e| e.ip.is_ipv6()));
        assert!(pick_family(Vec::new(), Vec::new()).is_empty());

        let picked = pick_family(v4, Vec::new());
        assert_eq!(picked.len(), PICK);
        assert!(picked.windows(2).all(|w| w[0].rtt <= w[1].rtt));
    }

    #[test]
    fn v6_must_win_by_a_clear_margin() {
        let ms = Duration::from_millis;
        assert!(!v6_clearly_faster(ms(100), ms(100)), "a tie keeps v4");
        assert!(!v6_clearly_faster(ms(190), ms(200)), "10ms is not enough");
        assert!(
            !v6_clearly_faster(ms(180), ms(200)),
            "20ms but only 10% — noise-sized on a long path"
        );
        assert!(v6_clearly_faster(ms(20), ms(200)), "10x faster wins");
        assert!(v6_clearly_faster(ms(150), ms(200)), "25% and 50ms wins");

        assert!(!v6_clearly_faster(ms(2), ms(8)));
    }

    #[test]
    fn only_the_direct_replica_probes_v6() {
        assert!(
            !v6_usable(Egress::Proxied),
            "pinned v6 edges would break the tunnel on the next node switch"
        );
        assert_eq!(v6_usable(Egress::Direct), has_global_v6_route());
    }

    #[test]
    fn link_local_and_ula_do_not_count_as_v6() {
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        assert!(is_global_v6(&v6("2606:4700:a0::1")));
        assert!(is_global_v6(&v6("2001:db8::1")));
        assert!(!is_global_v6(&v6("::1")));
        assert!(!is_global_v6(&v6("::")));
        assert!(!is_global_v6(&v6("fe80::1")));
        assert!(!is_global_v6(&v6("fd00::1")));
    }

    #[test]
    fn edge_mode_follows_the_protocol() {
        assert_eq!(EdgeMode::for_protocol(Protocol::Quic), EdgeMode::QuicOnly);
        assert_eq!(EdgeMode::for_protocol(Protocol::Http2), EdgeMode::TcpOnly);
    }

    #[test]
    fn http2_over_the_proxy_borrows_the_quic_ranking() {

        assert_eq!(EdgeMode::for_protocol(Protocol::Http2), EdgeMode::TcpOnly);
        assert_eq!(EdgeMode::for_protocol(Protocol::Quic), EdgeMode::QuicOnly);

        let borrows = |e: Egress, p: Protocol| e == Egress::Proxied && p == Protocol::Http2;
        assert!(borrows(Egress::Proxied, Protocol::Http2));
        assert!(!borrows(Egress::Proxied, Protocol::Quic));
        assert!(!borrows(Egress::Direct, Protocol::Http2));
        assert!(!borrows(Egress::Direct, Protocol::Quic));

        let src = include_str!("cf_edge.rs");
        let body = src
            .split("pub async fn pick_edges_proto")
            .nth(1)
            .expect("pick_edges_proto exists");
        assert!(
            body.contains("egress == Egress::Proxied && proto == Protocol::Http2"),
            "the borrow condition moved; update this test"
        );
    }

    #[test]
    fn the_proxied_path_gets_a_longer_budget() {
        assert!(PROBE_TIMEOUT_PROXIED > PROBE_TIMEOUT);
        assert_eq!(round_budget(Egress::Direct), ROUND_BUDGET);
        assert_eq!(round_budget(Egress::Proxied), ROUND_BUDGET_PROXIED);
        let batches = BUILTIN_V4.len().div_ceil(CONCURRENCY) as u32;
        assert!(
            ROUND_BUDGET_PROXIED >= PROBE_TIMEOUT_PROXIED * batches,
            "the budget must fit every batch, else the last one is silently dropped"
        );
        assert!(ROUND_BUDGET >= PROBE_TIMEOUT * batches);
    }

    #[test]
    fn edge_rtts_reference_prefers_the_tcp_handshake() {
        let both = EdgeRtts {
            quic: Some(Duration::from_millis(20)),
            http2: Some(Duration::from_millis(30)),
        };
        assert_eq!(both.reference_ms(), 30);
        let quic_only = EdgeRtts {
            quic: Some(Duration::from_millis(20)),
            http2: None,
        };
        assert_eq!(quic_only.reference_ms(), 20);
        assert_eq!(EdgeRtts::default().reference_ms(), 0);
    }

    #[test]
    fn vn_probe_packet_shape() {
        let p = vn_probe_packet();
        assert_eq!(
            p.len(),
            1200,
            "must be padded to the anti-amplification floor"
        );
        assert_eq!(p[0] & 0xc0, 0xc0, "long header + fixed bit");
        assert_eq!(
            &p[1..5],
            &[0x0a, 0x0a, 0x0a, 0x0a],
            "reserved 'force VN' version"
        );
        assert_eq!(p[5], 8, "DCID len");
        assert_eq!(p[14], 8, "SCID len");

        assert_ne!(&p[6..14], &p[15..23]);
    }

    #[test]
    fn probe_packets_have_distinct_ids() {
        let ids: BTreeSet<Vec<u8>> = (0..8).map(|_| vn_probe_packet()[6..14].to_vec()).collect();
        assert_eq!(ids.len(), 8, "connection ids must not repeat");
    }

    #[test]
    fn version_negotiation_detection() {

        let mut vn = vec![0xc0, 0, 0, 0, 0];
        vn.extend_from_slice(&[0, 0, 0, 1]);
        assert!(is_version_negotiation(&vn));

        assert!(!is_version_negotiation(&[0xc0, 0, 0, 0, 1]));

        assert!(!is_version_negotiation(&[0x40, 0, 0, 0, 0]));
        assert!(!is_version_negotiation(&[0xc0, 0, 0]));
        assert!(!is_version_negotiation(&[]));
    }

    #[test]
    fn dns_plan_prefers_matching_path_then_falls_back() {
        let p = dns_plan(Egress::Proxied);
        assert_eq!(p[0], (DNS_VIA_PROXY, Egress::Proxied));
        assert_eq!(p[1], (DNS_DIRECT, Egress::Direct));
        let d = dns_plan(Egress::Direct);
        assert_eq!(d[0], (DNS_DIRECT, Egress::Direct));
        assert_eq!(d[1], (DNS_VIA_PROXY, Egress::Proxied));
    }

    #[test]
    fn discovery_results_already_tried_are_skipped() {
        let builtin = builtin_candidates();
        let tried: BTreeSet<IpAddr> = builtin.iter().copied().collect();

        let same: Vec<IpAddr> = builtin
            .iter()
            .copied()
            .filter(|ip| !tried.contains(ip))
            .collect();
        assert!(
            same.is_empty(),
            "identical list must yield nothing to probe"
        );

        let discovered: Vec<IpAddr> = vec![
            builtin[0],
            "198.41.208.11".parse().unwrap(),
            "198.41.208.12".parse().unwrap(),
        ];
        let fresh: Vec<IpAddr> = discovered
            .into_iter()
            .filter(|ip| !tried.contains(ip))
            .collect();
        assert_eq!(fresh.len(), 2, "only addresses we have not tried yet");
        assert!(!fresh.contains(&builtin[0]));
    }

    #[tokio::test]
    async fn measure_unreachable_returns_empty_within_budget() {
        let dead: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let t0 = Instant::now();
        let deadline = t0 + ROUND_BUDGET;
        let got = measure(Egress::Direct, dead, EdgeMode::Auto, deadline).await;
        assert!(got.is_empty());
        assert!(
            t0.elapsed() < ROUND_BUDGET + Duration::from_secs(2),
            "probing must stay inside its budget, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn a_spent_deadline_stops_probing_immediately() {
        let dead: Vec<IpAddr> = (1..=20)
            .map(|i| format!("192.0.2.{i}").parse().unwrap())
            .collect();
        let t0 = Instant::now();
        let got = measure(Egress::Direct, dead, EdgeMode::QuicOnly, t0).await;
        assert!(got.is_empty());
        assert!(
            t0.elapsed() < Duration::from_millis(200),
            "an expired deadline must skip every batch, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn v6_canary_failure_skips_the_rest_of_the_list() {
        let all: Vec<IpAddr> = (1..=20)
            .map(|i| format!("2001:db8::{i:x}").parse().unwrap())
            .collect();
        let t0 = Instant::now();
        let got = measure_v6(Egress::Direct, &all, EdgeMode::QuicOnly, t0 + ROUND_BUDGET).await;
        assert!(got.is_none(), "canary failure must be distinguishable");

        assert!(
            t0.elapsed() < PROBE_TIMEOUT * 2,
            "the canary must short-circuit the rest, took {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn an_unreachable_v6_family_is_remembered_for_a_while() {
        let e = Egress::Direct;
        note_v6(e, true);
        assert!(!v6_recently_down(e), "a reachable family is never skipped");
        note_v6(e, false);
        assert!(v6_recently_down(e), "the negative result must stick");

        V6_DOWN_UNTIL.lock().unwrap()[e.idx()] = Some(Instant::now() - Duration::from_secs(1));
        assert!(!v6_recently_down(e));

        note_v6(e, false);
        assert!(!v6_recently_down(Egress::Proxied));
        note_v6(e, true);
    }
}
