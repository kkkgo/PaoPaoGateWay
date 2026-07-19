// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::runtime::SharedState;
use sb_sniff::peek::{PeekBuf, PeekBufPool};
use sb_sniff::{SniffedProto, sniff_all};
use sb_stats::adaptive_copy::adaptive_copy_bidirectional;
use sb_stats::types::{ConnRecord, InboundKind, Transport};
use sb_stats::{ConnId, counting_copy_bidirectional};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct Established {

    pub dest: SocketAddr,

    pub inbound: InboundKind,

    pub domain: Option<String>,

    pub prelude: Vec<u8>,

    pub sniff: bool,
}

pub async fn handle_conn(
    client: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
) -> std::io::Result<()> {

    if !shared.proxy_allowed(peer.ip()) {
        tracing::debug!(%peer, "tproxy peer not in proxy_cidr; reject");
        return Ok(());
    }
    let orig = sb_tproxy::tcp::original_dst(&client)?;
    let est = Established {
        dest: orig,
        inbound: InboundKind::TProxy,
        domain: None,
        prelude: Vec::new(),
        sniff: true,
    };
    serve_established(shared, client, peer, est).await
}

pub async fn serve_established(
    shared: Arc<SharedState>,
    mut client: TcpStream,
    peer: SocketAddr,
    est: Established,
) -> std::io::Result<()> {
    let dest = est.dest;

    let _ = client.set_nodelay(true);

    sb_tproxy::tcp::set_tcp_keepalive(&client, 30, 10, 4);

    let port_skip = is_server_first_port(dest.port());

    let ip_group = crate::ip_rules::match_group(dest.ip());
    let (sniffed, peek) = if !est.sniff
        || port_skip
        || ip_group.is_some()
        || shared.sniff_neg.is_hit(dest.ip(), dest.port())
    {
        (
            sb_sniff::Sniffed {
                proto: SniffedProto::Unknown,
                domain: None,
                ech_outer: false,
            },

            PeekBuf::empty(),
        )
    } else {
        let r = peek_and_sniff(&mut client, &shared.peek_pool, shared.sniff_timeout()).await?;

        if matches!(r.0.proto, SniffedProto::Unknown) {
            shared.sniff_neg.mark(dest.ip(), dest.port());
        }
        r
    };
    let route = shared.route.load();

    let known_domain = est.domain.is_some();
    let ResolvedDomains {
        routing: domain,
        stats: stats_domain,
        fakeip_unresolved,
    } = resolve_domains(est.domain.clone(), &sniffed, shared.fakeip.as_deref(), dest);

    if route.log_sniffed {
        tracing::info!(
            "{}",
            crate::logging::fmt_flow(
                peer.ip(),
                dest,
                proto_scheme(sniffed.proto),
                stats_domain.as_deref(),
                false
            )
        );
    }

    let should_block = ip_group.is_none()
        && (fakeip_unresolved
            || match sniffed.proto {
                SniffedProto::Bittorrent => route.block_bittorrent,
                SniffedProto::Unknown => route.block_unknown && !known_domain,

                _ => false,
            });
    if should_block {
        let reason = if fakeip_unresolved {
            "fakeip-unresolved"
        } else if matches!(sniffed.proto, SniffedProto::Bittorrent) {
            "bittorrent"
        } else {
            "unknown"
        };
        tracing::info!(
            "{} {} ({reason})",
            crate::logging::fmt_flow(
                peer.ip(),
                dest,
                proto_scheme(sniffed.proto),
                stats_domain.as_deref(),
                false
            ),
            crate::logging::paint(crate::logging::RED, "blocked"),
        );
        return Ok(());
    }

    let conn_id: ConnId = shared.id_gen.next_id();
    let rec = Arc::new(
        ConnRecord::new(
            conn_id,
            (peer.ip(), peer.port()),
            (dest.ip(), dest.port()),
            if let Some(label) = ip_group {
                sb_stats::SniffedProto::IpGroup(label)
            } else if port_skip {
                sb_stats::SniffedProto::Skipped
            } else {
                match sniffed.proto {
                    SniffedProto::Tls => sb_stats::SniffedProto::Tls,
                    SniffedProto::Http => sb_stats::SniffedProto::Http,
                    SniffedProto::Bittorrent => sb_stats::SniffedProto::Bittorrent,

                    SniffedProto::Unknown => {
                        unknown_label(est.inbound, stats_domain.is_some(), dest.port())
                    }
                }
            },

            stats_domain.clone(),
        )
        .with_inbound(est.inbound, Transport::Tcp),
    );

    if matches!(sniffed.proto, SniffedProto::Unknown) && !peek.bytes().is_empty() {
        rec.set_head(peek.bytes());
    }
    shared.conn_table.insert(Arc::clone(&rec));
    if let Some(p) = &shared.pplog {
        p.open(&rec);
    }

    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    shared.close_registry.insert(conn_id, cancel_tx);
    let result = tokio::select! {
        r = run_proxy(&shared, &rec, client, peek, est.prelude, dest, domain.as_deref()) => r,

        _ = cancel_rx => Ok(()),
    };
    shared.close_registry.remove(&conn_id);

    let sp = rec
        .socks_src_port
        .load(std::sync::atomic::Ordering::Relaxed);
    if sp != 0 {
        shared.socks_src_index.remove(&sp);
    }

    let (du, dd) = rec.drain_delta();
    if du != 0 || dd != 0 {
        shared.traffic.add_totals(dd, du);
    }

    shared.conn_table.close(rec.id);
    if let Some(p) = &shared.pplog {
        p.close(&rec);
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_proxy(
    shared: &SharedState,
    rec: &Arc<ConnRecord>,
    mut client: TcpStream,
    peek: PeekBuf,
    prelude: Vec<u8>,
    orig: SocketAddr,
    domain: Option<&str>,
) -> std::io::Result<()> {

    let mut upstream = match shared.outbound.connect_tcp(orig, domain).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%orig, ?e, "outbound connect failed");

            let _ = client.shutdown().await;
            return Ok(());
        }
    };

    let socks_port = upstream.local_addr().map(|a| a.port()).unwrap_or(0);
    if socks_port != 0 {
        rec.socks_src_port
            .store(socks_port, std::sync::atomic::Ordering::Relaxed);
        shared.socks_src_index.insert(
            socks_port,
            crate::runtime::SocksSrc {
                ip: rec.src.0,
                port: rec.src.1,
                inbound: rec.inbound,
            },
        );
    }

    if !prelude.is_empty() {
        if let Err(e) = upstream.write_all(&prelude).await {
            tracing::debug!(%orig, ?e, "writing prelude failed");
            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
            return Ok(());
        }
        rec.add_up(prelude.len() as u64);
    }
    if shared.splice_copy() {

        let peeked_len = peek.bytes().len() as u64;
        if peeked_len > 0
            && let Err(e) = upstream.write_all(peek.bytes()).await
        {
            tracing::debug!(%orig, ?e, "writing peek prelude failed");

            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
            return Ok(());
        }

        drop(peek);

        if peeked_len > 0 {
            rec.add_up(peeked_len);
        }
        match adaptive_copy_bidirectional(
            client,
            upstream,
            &rec.upload,
            &rec.download,
            shared.splice_threshold(),
        )
        .await
        {
            Ok((u, d)) => tracing::debug!(%orig, up = u, down = d, "splice conn closed"),
            Err(e) => tracing::debug!(%orig, ?e, "splice conn ended"),
        }
        return Ok(());
    }

    let replay = peek.into_replay(client);
    match counting_copy_bidirectional(replay, upstream, &rec.upload, &rec.download).await {
        Ok((u, d)) => tracing::debug!(%orig, up = u, down = d, "conn closed"),
        Err(e) => tracing::debug!(%orig, ?e, "conn ended"),
    }
    Ok(())
}

struct ResolvedDomains {

    routing: Option<String>,

    stats: Option<String>,

    fakeip_unresolved: bool,
}

fn resolve_domains(
    handshake: Option<String>,
    sniffed: &sb_sniff::Sniffed,
    fakeip: Option<&sb_dns::FakeIpPool>,
    dest: SocketAddr,
) -> ResolvedDomains {
    let mut routing = handshake;
    let mut fakeip_unresolved = false;
    let in_fakeip = fakeip.is_some_and(|fk| fk.contains(dest.ip()));
    if routing.is_none() {
        if in_fakeip {

            routing = sniffed.domain.clone();
            if routing.is_none()
                && let Some(fk) = fakeip
                && let std::net::IpAddr::V4(v4) = dest.ip()
            {
                match fk.lookback(v4) {
                    Some(d) => routing = Some(d.to_string()),
                    None => fakeip_unresolved = true,
                }
            }
        } else if !sniffed.ech_outer {

            routing = sniffed.domain.clone();
        }
    }

    let stats = routing.clone().or_else(|| sniffed.domain.clone());
    ResolvedDomains {
        routing,
        stats,
        fakeip_unresolved,
    }
}

fn unknown_label(inbound: InboundKind, has_domain: bool, port: u16) -> sb_stats::SniffedProto {
    match inbound {

        InboundKind::HealthCheck => match port {
            80 | 8080 => sb_stats::SniffedProto::Http,
            _ => sb_stats::SniffedProto::Tls,
        },
        InboundKind::Socks5 => sb_stats::SniffedProto::Socks5,
        InboundKind::Http => sb_stats::SniffedProto::HttpProxy,
        InboundKind::TProxy => {
            if has_domain {
                sb_stats::SniffedProto::FakeIp
            } else {
                sb_stats::SniffedProto::RealIp
            }
        }

        InboundKind::Clash(_) => sb_stats::SniffedProto::Unknown,
    }
}

fn proto_scheme(p: SniffedProto) -> Option<&'static str> {
    match p {
        SniffedProto::Tls => Some("tls"),
        SniffedProto::Http => Some("http"),
        SniffedProto::Bittorrent => Some("bt"),
        SniffedProto::Unknown => None,
    }
}

fn is_server_first_port(port: u16) -> bool {
    matches!(port, 21 | 22 | 23 | 25 | 110 | 143 | 587)
}

fn could_start_known_proto(b: u8) -> bool {
    matches!(b, 0x16 | 0x13 | b'G' | b'P' | b'H' | b'D' | b'O')
}

pub async fn peek_and_sniff(
    client: &mut TcpStream,
    pool: &Arc<PeekBufPool>,
    timeout: Duration,
) -> std::io::Result<(sb_sniff::Sniffed, PeekBuf)> {
    let mut peek = pool.take();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if peek.is_full() {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, peek.read_some(client)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                let s = sniff_all(peek.bytes());
                if !matches!(s.proto, SniffedProto::Unknown) {
                    break;
                }

                if let Some(&b0) = peek.bytes().first()
                    && !could_start_known_proto(b0)
                {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => break,
        }
    }
    let s = sniff_all(peek.bytes());
    Ok((s, peek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream as TS};

    #[tokio::test]
    async fn peek_returns_unknown_on_empty() {

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acc = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let _client = TS::connect(addr).await.unwrap();
        let mut server = acc.await.unwrap();
        let pool = Arc::new(PeekBufPool::with_defaults());
        let (s, peek) = peek_and_sniff(&mut server, &pool, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(s.proto, SniffedProto::Unknown);
        assert_eq!(peek.len(), 0);
    }

    #[test]
    fn server_first_ports_bypassed_not_implicit_tls() {
        for p in [21, 22, 23, 25, 110, 143, 587] {
            assert!(is_server_first_port(p), "port {p} should bypass");
        }

        for p in [443, 465, 993, 995, 8443] {
            assert!(!is_server_first_port(p), "port {p} must still be sniffed");
        }
    }

    #[test]
    fn prefix_gate_only_admits_known_first_bytes() {
        assert!(could_start_known_proto(0x16));
        assert!(could_start_known_proto(0x13));
        assert!(could_start_known_proto(b'G'));
        assert!(could_start_known_proto(b'P'));
        assert!(!could_start_known_proto(b'S'));
        assert!(!could_start_known_proto(0x00));
        assert!(!could_start_known_proto(0xff));
    }

    #[tokio::test]
    async fn peek_bails_early_on_non_proto_first_byte() {

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acc = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TS::connect(addr).await.unwrap();
        let mut server = acc.await.unwrap();
        client.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
        let pool = Arc::new(PeekBufPool::with_defaults());
        let start = std::time::Instant::now();

        let (s, _peek) = peek_and_sniff(&mut server, &pool, Duration::from_secs(5))
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(s.proto, SniffedProto::Unknown);
        assert!(
            elapsed < Duration::from_secs(1),
            "prefix gate should bail early, took {elapsed:?}"
        );
        drop(client);
    }

    #[tokio::test]
    async fn peek_finds_http_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acc = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TS::connect(addr).await.unwrap();
        let mut server = acc.await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let pool = Arc::new(PeekBufPool::with_defaults());
        let (s, _peek) = peek_and_sniff(&mut server, &pool, Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(s.proto, SniffedProto::Http);
        assert_eq!(s.domain.as_deref(), Some("example.com"));
    }

    fn tls_sniff(domain: Option<&str>, ech_outer: bool) -> sb_sniff::Sniffed {
        sb_sniff::Sniffed {
            proto: SniffedProto::Tls,
            domain: domain.map(str::to_string),
            ech_outer,
        }
    }

    fn fakeip_pool() -> sb_dns::FakeIpPool {
        sb_dns::FakeIpPool::new(sb_dns::FakeIpConfig {
            cidr: "7.0.0.0/8".parse().unwrap(),
            max_entries: 65536,
            ttl: 3,
            shards: 4,
        })
        .unwrap()
    }

    #[test]
    fn resolve_non_ech_sni_is_routing_and_stats() {

        let s = tls_sniff(Some("a.com"), false);
        let r = resolve_domains(None, &s, None, "1.2.3.4:443".parse().unwrap());
        assert_eq!(r.routing.as_deref(), Some("a.com"));
        assert_eq!(r.stats.as_deref(), Some("a.com"));
        assert!(!r.fakeip_unresolved);
    }

    #[test]
    fn resolve_fakeip_sniff_first_ignores_ech() {

        let pool = fakeip_pool();
        let fake = pool.intern("real-target.com");
        let s = tls_sniff(Some("cloudflare-ech.com"), true);
        let dest = SocketAddr::new(fake.into(), 443);
        let r = resolve_domains(None, &s, Some(&pool), dest);
        assert_eq!(r.routing.as_deref(), Some("cloudflare-ech.com"));
        assert_eq!(r.stats.as_deref(), Some("cloudflare-ech.com"));
        assert!(!r.fakeip_unresolved);
    }

    #[test]
    fn resolve_fakeip_sniff_fails_falls_back_to_lookback() {

        let pool = fakeip_pool();
        let fake = pool.intern("real-target.com");
        let s = tls_sniff(None, false);
        let dest = SocketAddr::new(fake.into(), 443);
        let r = resolve_domains(None, &s, Some(&pool), dest);
        assert_eq!(r.routing.as_deref(), Some("real-target.com"));
        assert!(!r.fakeip_unresolved);
    }

    #[test]
    fn resolve_no_fakeip_ech_routes_by_ip_keeps_cover_for_stats() {

        let s = tls_sniff(Some("cloudflare-ech.com"), true);
        let r = resolve_domains(None, &s, None, "1.2.3.4:443".parse().unwrap());
        assert_eq!(r.routing, None);
        assert_eq!(r.stats.as_deref(), Some("cloudflare-ech.com"));
        assert!(!r.fakeip_unresolved);
    }

    #[test]
    fn resolve_handshake_domain_wins_over_ech() {

        let s = tls_sniff(Some("cloudflare-ech.com"), true);
        let r = resolve_domains(
            Some("explicit.com".into()),
            &s,
            None,
            "1.2.3.4:443".parse().unwrap(),
        );
        assert_eq!(r.routing.as_deref(), Some("explicit.com"));
        assert_eq!(r.stats.as_deref(), Some("explicit.com"));
    }

    #[test]
    fn resolve_fakeip_miss_blocks() {

        let pool = fakeip_pool();
        let s = tls_sniff(None, false);
        let r = resolve_domains(None, &s, Some(&pool), "7.1.2.3:443".parse().unwrap());
        assert_eq!(r.routing, None);
        assert!(r.fakeip_unresolved);
    }

    #[test]
    fn healthcheck_label_by_port_http_else_tls() {
        use sb_stats::SniffedProto as S;

        assert_eq!(unknown_label(InboundKind::HealthCheck, true, 80), S::Http);
        assert_eq!(unknown_label(InboundKind::HealthCheck, true, 8080), S::Http);
        assert_eq!(unknown_label(InboundKind::HealthCheck, true, 443), S::Tls);
        assert_eq!(unknown_label(InboundKind::HealthCheck, true, 8443), S::Tls);

        assert_eq!(unknown_label(InboundKind::Socks5, true, 80), S::Socks5);
        assert_eq!(unknown_label(InboundKind::Http, true, 443), S::HttpProxy);
    }
}
