// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use sb_dns::message::{self, TYPE_A};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

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

    inflight: DashMap<String, broadcast::Sender<Option<Vec<Ipv4Addr>>>>,
    id_gen: AtomicU16,
}

impl Resolver {

    pub fn from_cfg(server: Option<SocketAddr>) -> Self {
        Self {
            server: ArcSwap::from_pointee(resolve_server(server)),
            timeout: Duration::from_secs(3),
            cache: DashMap::new(),
            inflight: DashMap::new(),
            id_gen: AtomicU16::new(1),
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
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
        if let Some(ip) = self.cache_get(host) {
            return Ok(ip);
        }

        let (is_leader, tx) = match self.inflight.entry(host.to_string()) {
            Entry::Occupied(e) => (false, e.get().clone()),
            Entry::Vacant(e) => {
                let (tx, _rx) = broadcast::channel(1);
                e.insert(tx.clone());
                (true, tx)
            }
        };

        if !is_leader {
            let mut rx = tx.subscribe();

            drop(tx);

            let fed = tokio::time::timeout(self.timeout + Duration::from_secs(1), rx.recv()).await;
            if let Ok(Ok(Some(ips))) = fed
                && let Some(ip) = ips.first().copied()
            {
                return Ok(ip);
            }

            if let Some(ip) = self.cache_get(host) {
                return Ok(ip);
            }
            return self.query_and_cache(host, None).await;
        }

        struct InflightGuard<'a> {
            map: &'a DashMap<String, broadcast::Sender<Option<Vec<Ipv4Addr>>>>,
            host: &'a str,
        }
        impl Drop for InflightGuard<'_> {
            fn drop(&mut self) {
                self.map.remove(self.host);
            }
        }
        let _guard = InflightGuard {
            map: &self.inflight,
            host,
        };
        self.query_and_cache(host, Some(&tx)).await
    }

    async fn query_and_cache(
        &self,
        host: &str,
        broadcast_tx: Option<&broadcast::Sender<Option<Vec<Ipv4Addr>>>>,
    ) -> io::Result<Ipv4Addr> {
        let res = self.query_upstream(host).await;
        match &res {
            Ok((ips, ttl)) => {
                self.cache_put(host, ips.clone(), *ttl);
                if let Some(tx) = broadcast_tx {
                    let _ = tx.send(Some(ips.clone()));
                }
                ips.first()
                    .copied()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A record"))
            }
            Err(_) => {
                if let Some(tx) = broadcast_tx {
                    let _ = tx.send(None);
                }
                Err(io::Error::other("dns query failed"))
            }
        }
    }

    async fn query_upstream(&self, host: &str) -> io::Result<(Vec<Ipv4Addr>, u32)> {
        let id = self.id_gen.fetch_add(1, Ordering::Relaxed);
        let query = message::build_query(id, host, TYPE_A).map_err(io::Error::other)?;
        let server = **self.server.load();
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(server).await?;
        sock.send(&query).await?;
        let mut buf = [0u8; 1500];
        let n = match tokio::time::timeout(self.timeout, sock.recv(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "dns query timed out",
                ));
            }
        };
        let resp = message::parse_response(&buf[..n]).map_err(io::Error::other)?;

        if resp.id != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns response id mismatch",
            ));
        }
        if resp.v4.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no A record in response",
            ));
        }
        Ok((resp.v4, resp.min_ttl))
    }

    fn cache_get(&self, host: &str) -> Option<Ipv4Addr> {
        let e = self.cache.get(host)?;
        if Instant::now() < e.expire {
            e.ips.first().copied()
        } else {
            None
        }
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
