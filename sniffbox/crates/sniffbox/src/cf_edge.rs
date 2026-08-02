// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::cf_ctl::Egress;

pub const EDGE_PORT: u16 = 7844;

pub const PICK: usize = 4;

const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

const ROUND_BUDGET: Duration = Duration::from_secs(8);

const CONCURRENCY: usize = 8;

const HEALTH_SOCKS5: &str = "127.0.0.1:1079";

const DNS_VIA_PROXY: &str = "1.1.1.1:53";

const DNS_DIRECT: &str = "223.5.5.5:53";

const EDGE_SRV: &str = "_v2-origintunneld._tcp.argotunnel.com";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeRtt {
    pub ip: IpAddr,
    pub rtt: Duration,

    pub quic: bool,
}

pub async fn pick_edges(egress: Egress) -> Vec<EdgeRtt> {
    let started = Instant::now();
    let builtin = builtin_candidates();
    let mut best = measure(egress, builtin.clone()).await;
    if best.is_empty() && started.elapsed() < ROUND_BUDGET {

        let tried: BTreeSet<IpAddr> = builtin.iter().copied().collect();
        let fresh: Vec<IpAddr> = discover_edges(egress)
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
            best = measure(egress, fresh).await;
        }
    }
    best.sort_by_key(|e| e.rtt);
    best.truncate(PICK);
    if best.is_empty() {
        tracing::warn!(
            egress = egress.as_str(),
            "cf edge: no reachable edge; starting cloudflared without --edge"
        );
    } else {
        tracing::info!(
            egress = egress.as_str(),
            picks = %fmt_picks(&best),
            "cf edge: picked fastest edges"
        );
    }
    best
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

async fn measure(egress: Egress, candidates: Vec<IpAddr>) -> Vec<EdgeRtt> {
    let quic = measure_with(egress, &candidates, true).await;
    if !quic.is_empty() {
        return quic;
    }
    tracing::debug!(
        egress = egress.as_str(),
        "cf edge: no QUIC answer from any candidate; falling back to TCP connect timing"
    );
    measure_with(egress, &candidates, false).await
}

async fn measure_with(egress: Egress, candidates: &[IpAddr], quic: bool) -> Vec<EdgeRtt> {
    let mut out = Vec::new();
    let deadline = Instant::now() + ROUND_BUDGET;
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
            let mut s =
                tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(HEALTH_SOCKS5))
                    .await
                    .ok()?
                    .ok()?;
            tokio::time::timeout(
                PROBE_TIMEOUT,
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
    let mut ctrl =
        tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(HEALTH_SOCKS5))
            .await
            .ok()?
            .ok()?;
    let relay = tokio::time::timeout(
        PROBE_TIMEOUT,
        sb_outbound::socks5_udp::udp_associate(&mut ctrl, "0.0.0.0:0".parse().ok()?),
    )
    .await
    .ok()?
    .ok()?;

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let frame = sb_outbound::socks5_udp::encode_udp_request(dst, payload);
    sock.send_to(&frame, relay).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(PROBE_TIMEOUT, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let (_src, off) = sb_outbound::socks5_udp::decode_udp_reply(&buf[..n]).ok()?;
    Some(buf[off..n].to_vec())
}

async fn discover_edges(egress: Egress) -> Vec<IpAddr> {
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
            if let Some(ips) = dns_a(server, via, &host).await {
                seen.extend(ips);
                break;
            }
        }
    }
    seen.into_iter().collect()
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
        let got = measure(Egress::Direct, dead).await;
        assert!(got.is_empty());
        assert!(
            t0.elapsed() < ROUND_BUDGET + Duration::from_secs(2),
            "probing must stay inside its budget, took {:?}",
            t0.elapsed()
        );
    }
}
