// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use sb_dns::message::{self, TYPE_A};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

type QueryResult = Result<Vec<Ipv4Addr>, (io::ErrorKind, String)>;
type Inflight = DashMap<String, watch::Sender<Option<QueryResult>>>;

const FALLBACK_DNS: &str = "8.8.8.8:53";

const CACHE_TTL_MIN: u64 = 2;
const CACHE_TTL_MAX: u64 = 600;

const CACHE_SOFT_CAP: usize = 8192;

struct CacheEntry {
    ips: Vec<Ipv4Addr>,
    expire: Instant,
}

pub struct Resolver {

    server: ArcSwap<SocketAddr>,
    timeout: Duration,
    cache: DashMap<String, CacheEntry>,

    inflight: Inflight,
}

impl Resolver {

    pub fn from_cfg(server: Option<SocketAddr>) -> Self {
        Self {
            server: ArcSwap::from_pointee(resolve_server(server)),
            timeout: Duration::from_secs(3),
            cache: DashMap::new(),
            inflight: DashMap::new(),
        }
    }

    pub fn server(&self) -> SocketAddr {
        **self.server.load()
    }

    pub fn set_from_cfg(&self, server: Option<SocketAddr>) {
        self.server
            .store(std::sync::Arc::new(resolve_server(server)));
    }

    pub async fn resolve_v4(&self, host: &str) -> io::Result<Ipv4Addr> {
        self.resolve_all_v4(host)
            .await?
            .first()
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A record"))
    }

    pub async fn resolve_all_v4(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
        self.resolve_shared(host, tokio::time::Instant::now() + self.timeout)
            .await
    }

    async fn resolve_shared(
        &self,
        host: &str,
        deadline: tokio::time::Instant,
    ) -> io::Result<Vec<Ipv4Addr>> {
        loop {
            if let Some(ips) = self.cache_get(host) {
                return Ok(ips);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let (leader, tx) = match self.inflight.entry(host.to_string()) {
                Entry::Occupied(e) => (false, e.get().clone()),
                Entry::Vacant(e) => {
                    let (tx, _) = watch::channel(None);
                    e.insert(tx.clone());
                    (true, tx)
                }
            };
            if !leader {
                let mut rx = tx.subscribe();
                drop(tx);
                loop {
                    if let Some(result) = rx.borrow_and_update().clone() {
                        return result.map_err(|(kind, message)| io::Error::new(kind, message));
                    }
                    if tokio::time::timeout_at(deadline, rx.changed())
                        .await
                        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
                        .is_err()
                    {
                        break;
                    }
                }

                continue;
            }
            struct Guard<'a> {
                map: &'a Inflight,
                host: &'a str,
            }
            impl Drop for Guard<'_> {
                fn drop(&mut self) {
                    self.map.remove(self.host);
                }
            }
            let _guard = Guard {
                map: &self.inflight,
                host,
            };
            let result = tokio::time::timeout_at(deadline, self.query_upstream(host))
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
                .map(|(ips, ttl)| {
                    self.cache_put(host, ips.clone(), ttl);
                    ips
                });

            tx.send_replace(Some(match &result {
                Ok(ips) => Ok(ips.clone()),
                Err(e) => Err((e.kind(), e.to_string())),
            }));
            return result;
        }
    }

    async fn query_upstream(&self, host: &str) -> io::Result<(Vec<Ipv4Addr>, u32)> {
        let id = random_query_id()?;
        let query = message::build_query(id, host, TYPE_A).map_err(io::Error::other)?;
        let server = **self.server.load();
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(server).await?;
        let start = tokio::time::Instant::now();
        let mut buf = [0u8; 4096];

        for attempt in 1..=3 {
            sock.send(&query).await?;
            let until = start + self.timeout.mul_f64(attempt as f64 / 3.0);
            loop {
                let n = match tokio::time::timeout_at(until, sock.recv(&mut buf)).await {
                    Ok(n) => n?,
                    Err(_) => break,
                };

                if n < query.len()
                    || buf[..2] != query[..2]
                    || buf[2] & 0xf8 != 0x80
                    || buf[4..6] != [0, 1]
                    || !buf[12..query.len()].eq_ignore_ascii_case(&query[12..])
                {
                    continue;
                }
                if buf[2] & 0x02 != 0 {
                    return query_tcp(server, &query).await;
                }
                let Ok(resp) = message::parse_response(&buf[..n]) else {
                    continue;
                };
                if resp.rcode != 0 || resp.v4.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no A record in DNS response",
                    ));
                }
                return Ok((resp.v4, resp.min_ttl));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "dns query timed out",
        ))
    }

    fn cache_get(&self, host: &str) -> Option<Vec<Ipv4Addr>> {
        let e = self.cache.get(host)?;
        (Instant::now() < e.expire).then(|| e.ips.clone())
    }

    fn cache_put(&self, host: &str, ips: Vec<Ipv4Addr>, ttl: u32) {
        if self.cache.len() >= CACHE_SOFT_CAP {
            let now = Instant::now();
            self.cache.retain(|_, e| now < e.expire);
            if self.cache.len() >= CACHE_SOFT_CAP {
                return;
            }
        }
        let secs = (ttl as u64).clamp(CACHE_TTL_MIN, CACHE_TTL_MAX);
        self.cache.insert(
            host.to_string(),
            CacheEntry {
                ips,
                expire: Instant::now() + Duration::from_secs(secs),
            },
        );
    }
}

async fn query_tcp(server: SocketAddr, query: &[u8]) -> io::Result<(Vec<Ipv4Addr>, u32)> {
    let mut stream = TcpStream::connect(server).await?;
    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query).await?;
    let len = stream.read_u16().await? as usize;
    if len < query.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short TCP DNS response",
        ));
    }
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).await?;
    if response[..2] != query[..2]
        || response[2] & 0xfa != 0x80
        || response[4..6] != [0, 1]
        || !response[12..query.len()].eq_ignore_ascii_case(&query[12..])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TCP DNS response",
        ));
    }
    let resp = message::parse_response(&response).map_err(io::Error::other)?;
    if resp.rcode != 0 || resp.v4.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no A record in TCP DNS response",
        ));
    }
    Ok((resp.v4, resp.min_ttl))
}

fn random_query_id() -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    let mut filled = 0;
    while filled < bytes.len() {

        let n = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += n as usize;
    }
    Ok(u16::from_ne_bytes(bytes))
}

fn resolve_server(server: Option<SocketAddr>) -> SocketAddr {
    server.or_else(resolv_conf_nameserver).unwrap_or_else(|| {
        tracing::warn!(
            fallback = FALLBACK_DNS,
            "no dns_ip and no resolv.conf nameserver; direct-mode resolver falls back to public DNS \
             (set dns_ip in ppgw.ini for free/ovpn on a dedicated line)"
        );
        FALLBACK_DNS.parse().unwrap()
    })
}

fn resolv_conf_nameserver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver")
            && let Some(ip) = rest.split_whitespace().next()
            && let Ok(addr) = ip.parse::<std::net::IpAddr>()
        {
            return Some(SocketAddr::new(addr, 53));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_dns::message::parse_query;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    async fn mock_dns(answer: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if let Ok(q) = parse_query(&buf[..n]) {
                    let resp = q.answer_a(answer, 60);
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        addr
    }

    async fn truncated_server() -> (UdpSocket, tokio::net::TcpListener, SocketAddr) {

        for _ in 0..32 {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap();
            match UdpSocket::bind(addr).await {
                Ok(udp) => return (udp, tcp, addr),
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
                Err(e) => panic!("bind DNS fixture: {e}"),
            }
        }
        panic!("no free TCP/UDP port for DNS fixture")
    }

    async fn request_tcp(udp: &UdpSocket, tcp: &tokio::net::TcpListener) -> (TcpStream, Vec<u8>) {
        let mut buf = [0; 4096];
        let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
        let query = buf[..n].to_vec();
        let mut tc = parse_query(&query).unwrap().nodata();
        tc[2] |= 2;
        udp.send_to(&tc, peer).await.unwrap();
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), tcp.accept())
            .await
            .unwrap()
            .unwrap();
        let size = stream.read_u16().await.unwrap() as usize;
        let mut framed = vec![0; size];
        stream.read_exact(&mut framed).await.unwrap();
        assert_eq!(
            framed, query,
            "TCP fallback must retain query ID and question"
        );
        (stream, query)
    }

    #[tokio::test]
    async fn tcp_fallback_is_framed_shared_and_cached_with_all_addresses() {
        let (udp, tcp, addr) = truncated_server().await;
        let resolver = Arc::new(Resolver::from_cfg(Some(addr)));
        let server = tokio::spawn(async move {
            let (mut stream, query) = request_tcp(&udp, &tcp).await;
            let q = parse_query(&query).unwrap();
            let mut answer = q.answer_a(Ipv4Addr::new(127, 0, 0, 2), 60);
            let extra = q.answer_a(Ipv4Addr::LOCALHOST, 60);
            answer[7] = 2;
            answer.extend_from_slice(&extra[extra.len() - 16..]);
            let prefix = (answer.len() as u16).to_be_bytes();
            stream.write_all(&prefix[..1]).await.unwrap();
            tokio::task::yield_now().await;
            stream.write_all(&prefix[1..]).await.unwrap();
            for part in answer.chunks(3) {
                stream.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }

            let mut probe = [0; 4096];
            assert!(
                tokio::time::timeout(Duration::from_millis(100), udp.recv_from(&mut probe))
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), tcp.accept())
                    .await
                    .is_err()
            );
        });
        let mut calls = Vec::new();
        for _ in 0..32 {
            let r = Arc::clone(&resolver);
            calls.push(tokio::spawn(async move {
                r.resolve_all_v4("tcp.example").await
            }));
        }
        let expected = vec![Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::LOCALHOST];
        for call in calls {
            assert_eq!(call.await.unwrap().unwrap(), expected);
        }
        server.await.unwrap();
        assert_eq!(
            resolver.resolve_all_v4("tcp.example").await.unwrap(),
            expected
        );
        assert!(resolver.inflight.is_empty());
    }

    #[tokio::test]
    async fn tcp_fallback_rejects_invalid_or_incomplete_frames_without_caching() {
        for fault in [
            "id",
            "question",
            "tc",
            "rcode",
            "zero",
            "short-prefix",
            "short-body",
            "max-length-short-body",
        ] {
            let (udp, tcp, addr) = truncated_server().await;
            let r = Resolver::from_cfg(Some(addr));
            let server = tokio::spawn(async move {
                let (mut stream, query) = request_tcp(&udp, &tcp).await;
                let mut answer = parse_query(&query)
                    .unwrap()
                    .answer_a(Ipv4Addr::LOCALHOST, 60);
                match fault {
                    "id" => answer[0] ^= 1,
                    "question" => answer[13] ^= 1,
                    "tc" => answer[2] |= 2,
                    "rcode" => answer[3] |= 3,
                    "zero" => {
                        stream.write_all(&[0, 0]).await.unwrap();
                        return;
                    }
                    "short-prefix" => {
                        stream.write_all(&[0]).await.unwrap();
                        return;
                    }
                    "max-length-short-body" => {
                        stream.write_all(&[255, 255, 0]).await.unwrap();
                        return;
                    }
                    _ => {}
                }
                stream.write_u16(answer.len() as u16).await.unwrap();
                if fault == "short-body" {
                    answer.truncate(answer.len() - 1);
                }
                stream.write_all(&answer).await.unwrap();
            });
            assert!(r.resolve_v4("tcp.example").await.is_err(), "{fault}");
            assert!(r.cache.is_empty() && r.inflight.is_empty(), "{fault}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn tcp_fallback_stall_uses_original_deadline_and_cleans_inflight() {
        let (udp, tcp, addr) = truncated_server().await;
        let mut r = Resolver::from_cfg(Some(addr));
        r.timeout = Duration::from_millis(300);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = request_tcp(&udp, &tcp).await;
            ready_tx.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(
                stream.read(&mut byte).await.unwrap(),
                0,
                "timeout must close TCP"
            );
        });
        let r = Arc::new(r);
        let rr = Arc::clone(&r);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        let call = tokio::spawn(async move { rr.resolve_shared("tcp.example", deadline).await });
        ready_rx.await.unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(151)).await;
        assert_eq!(
            call.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(r.cache.is_empty() && r.inflight.is_empty());
        tokio::time::resume();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_fallback_cancellation_releases_socket_and_re_elects_leader() {
        let (udp, tcp, addr) = truncated_server().await;
        let r = Arc::new(Resolver::from_cfg(Some(addr)));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut first, _) = request_tcp(&udp, &tcp).await;
            ready_tx.send(()).unwrap();
            let mut b = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), first.read(&mut b))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            let (mut next, query) = request_tcp(&udp, &tcp).await;
            let answer = parse_query(&query)
                .unwrap()
                .answer_a(Ipv4Addr::LOCALHOST, 60);
            next.write_u16(answer.len() as u16).await.unwrap();
            next.write_all(&answer).await.unwrap();
        });
        let leader_r = Arc::clone(&r);
        let leader = tokio::spawn(async move { leader_r.resolve_v4("cancel.example").await });
        ready_rx.await.unwrap();
        let follower_r = Arc::clone(&r);
        let follower = tokio::spawn(async move { follower_r.resolve_v4("cancel.example").await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while r.inflight.get("cancel.example").unwrap().receiver_count() < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        leader.abort();
        let _ = leader.await;
        assert_eq!(follower.await.unwrap().unwrap(), Ipv4Addr::LOCALHOST);
        assert!(r.inflight.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_fallback_failure_is_shared_without_independent_connections() {
        let (udp, tcp, addr) = truncated_server().await;
        let r = Arc::new(Resolver::from_cfg(Some(addr)));
        let rr = Arc::clone(&r);
        let server = tokio::spawn(async move {
            let (mut stream, query) = request_tcp(&udp, &tcp).await;
            tokio::time::timeout(Duration::from_secs(2), async {
                while rr.inflight.get("fail.example").unwrap().receiver_count() < 15 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let answer = parse_query(&query).unwrap().error(3);
            stream.write_u16(answer.len() as u16).await.unwrap();
            stream.write_all(&answer).await.unwrap();
            let mut b = [0; 1024];
            assert!(
                tokio::time::timeout(Duration::from_millis(100), udp.recv_from(&mut b))
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), tcp.accept())
                    .await
                    .is_err()
            );
        });
        let mut calls = Vec::new();
        for _ in 0..16 {
            let rr = Arc::clone(&r);
            calls.push(tokio::spawn(
                async move { rr.resolve_v4("fail.example").await },
            ));
        }
        for call in calls {
            assert_eq!(
                call.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
        }
        server.await.unwrap();
        assert!(r.cache.is_empty() && r.inflight.is_empty());
    }

    #[tokio::test]
    async fn resolves_via_mock_and_caches() {
        let dns = mock_dns(Ipv4Addr::new(93, 184, 216, 34)).await;
        let r = Resolver::from_cfg(Some(dns));
        let ip = r.resolve_v4("example.com").await.unwrap();
        assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));

        assert!(r.cache_get("example.com").is_some());
        let ip2 = r.resolve_v4("example.com").await.unwrap();
        assert_eq!(ip2, ip);
    }

    #[tokio::test]
    async fn dropped_query_is_retried_once_for_all_concurrent_callers() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut resolver = Resolver::from_cfg(Some(sock.local_addr().unwrap()));
        resolver.timeout = Duration::from_millis(300);
        let resolver = Arc::new(resolver);
        let server = tokio::spawn(async move {
            let mut buf = [0; 1500];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let first = buf[..n].to_vec();
            let (n, retry_peer) = sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(retry_peer, peer);
            assert_eq!(
                &buf[..n],
                first,
                "retransmission retains socket, ID and question"
            );
            let q = parse_query(&buf[..n]).unwrap();
            sock.send_to(&q.answer_a(Ipv4Addr::LOCALHOST, 60), peer)
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(150), sock.recv_from(&mut buf))
                    .await
                    .is_err(),
                "followers must not send independent retries"
            );
        });
        let mut callers = Vec::new();
        for _ in 0..32 {
            let resolver = Arc::clone(&resolver);
            callers.push(tokio::spawn(async move {
                resolver.resolve_v4("retry.example").await
            }));
        }
        for caller in callers {
            assert_eq!(caller.await.unwrap().unwrap(), Ipv4Addr::LOCALHOST);
        }
        assert!(resolver.inflight.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn negative_response_is_shared_without_a_retry_storm() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Arc::new(Resolver::from_cfg(Some(sock.local_addr().unwrap())));
        let server = tokio::spawn(async move {
            let mut buf = [0; 1500];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let response = parse_query(&buf[..n])
                .unwrap()
                .error(message::RCODE_NXDOMAIN);
            tokio::time::sleep(Duration::from_millis(40)).await;
            sock.send_to(&response, peer).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), sock.recv_from(&mut buf))
                    .await
                    .is_err()
            );
        });
        let mut callers = Vec::new();
        for _ in 0..32 {
            let resolver = Arc::clone(&resolver);
            callers.push(tokio::spawn(async move {
                resolver.resolve_v4("missing.example").await
            }));
        }
        for caller in callers {
            assert_eq!(
                caller.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_id_and_question_do_not_preempt_the_valid_response() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Resolver::from_cfg(Some(sock.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let mut buf = [0; 1500];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let q = parse_query(&buf[..n]).unwrap();
            let good = q.answer_a(Ipv4Addr::LOCALHOST, 60);
            let mut bad_id = good.clone();
            bad_id[0] ^= 1;
            let mut bad_question = good.clone();
            bad_question[13] ^= 1;
            sock.send_to(&bad_id, peer).await.unwrap();
            sock.send_to(&bad_question, peer).await.unwrap();
            sock.send_to(&good, peer).await.unwrap();
        });
        assert_eq!(
            resolver.resolve_v4("valid.example").await.unwrap(),
            Ipv4Addr::LOCALHOST
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn retries_are_bounded_and_timeout_is_not_cached() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut resolver = Resolver::from_cfg(Some(sock.local_addr().unwrap()));
        resolver.timeout = Duration::from_millis(120);
        let server = tokio::spawn(async move {
            let mut buf = [0; 1500];
            let mut packets = 0;
            while tokio::time::timeout(Duration::from_millis(180), sock.recv_from(&mut buf))
                .await
                .is_ok()
            {
                packets += 1;
            }
            packets
        });
        let error = tokio::time::timeout(
            Duration::from_millis(500),
            resolver.resolve_v4("silent.example"),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(resolver.cache_get("silent.example").is_none());
        assert!(resolver.inflight.is_empty());
        assert_eq!(server.await.unwrap(), 3);
    }

    #[tokio::test]
    async fn set_from_cfg_swaps_server() {

        let dns1 = mock_dns(Ipv4Addr::new(1, 1, 1, 1)).await;
        let dns2 = mock_dns(Ipv4Addr::new(2, 2, 2, 2)).await;
        let r = Resolver::from_cfg(Some(dns1));
        assert_eq!(r.server(), dns1);
        assert_eq!(
            r.resolve_v4("a.example").await.unwrap(),
            Ipv4Addr::new(1, 1, 1, 1)
        );

        r.set_from_cfg(Some(dns2));
        assert_eq!(r.server(), dns2);
        assert_eq!(
            r.resolve_v4("b.example").await.unwrap(),
            Ipv4Addr::new(2, 2, 2, 2)
        );
    }

    #[tokio::test]
    async fn literal_ip_skips_upstream() {

        let r = Resolver::from_cfg(Some("127.0.0.1:1".parse().unwrap()));
        assert_eq!(
            r.resolve_v4("203.0.113.7").await.unwrap(),
            Ipv4Addr::new(203, 0, 113, 7)
        );
    }

    #[tokio::test]
    async fn times_out_on_silent_server() {

        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap();
        let mut r = Resolver::from_cfg(Some(addr));
        r.timeout = Duration::from_millis(200);
        let res = r.resolve_v4("nowhere.example").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn follower_recovers_when_leader_cancelled() {

        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap();
        let mut r = Resolver::from_cfg(Some(addr));
        r.timeout = Duration::from_millis(200);
        let r = Arc::new(r);

        let leader = tokio::spawn({
            let r = Arc::clone(&r);
            async move {
                let _ = r.resolve_v4("poison.example").await;
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        leader.abort();
        let _ = leader.await;

        let res =
            tokio::time::timeout(Duration::from_secs(3), r.resolve_v4("poison.example")).await;
        let res = res.expect("resolve must not hang after leader cancellation");
        assert!(
            res.is_err(),
            "silent upstream → bounded timeout error, not a hang"
        );
    }

    #[test]
    fn cache_put_is_bounded() {
        let r = Resolver::from_cfg(Some("127.0.0.1:1".parse().unwrap()));
        for i in 0..(CACHE_SOFT_CAP + 64) {
            r.cache_put(&format!("h{i}.example"), vec![Ipv4Addr::LOCALHOST], 600);
        }
        assert!(
            r.cache.len() <= CACHE_SOFT_CAP,
            "cache must stay bounded, got {}",
            r.cache.len()
        );
    }

    #[tokio::test]
    async fn inflight_dedup_shares_one_roundtrip() {

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = Arc::clone(&count);
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                c2.fetch_add(1, Ordering::Relaxed);

                tokio::time::sleep(Duration::from_millis(50)).await;
                if let Ok(q) = parse_query(&buf[..n]) {
                    let _ = sock
                        .send_to(&q.answer_a(Ipv4Addr::new(1, 1, 1, 1), 60), peer)
                        .await;
                }
            }
        });
        let r = Arc::new(Resolver::from_cfg(Some(addr)));
        let mut hs = Vec::new();
        for _ in 0..50 {
            let r = Arc::clone(&r);
            hs.push(tokio::spawn(
                async move { r.resolve_v4("dedup.example").await },
            ));
        }
        for h in hs {
            assert_eq!(h.await.unwrap().unwrap(), Ipv4Addr::new(1, 1, 1, 1));
        }
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "inflight dedup → exactly one upstream query"
        );
    }
}
