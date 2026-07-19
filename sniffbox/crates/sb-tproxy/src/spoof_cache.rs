// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::udp::bind_spoof_udp;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const NX_TTL: Duration = Duration::from_secs(2);

const NX_CAP: usize = 1024;

pub struct SpoofCache {
    inner: Mutex<Inner>,
    cap: usize,
}

struct Inner {
    map: HashMap<SocketAddr, Arc<UdpSocket>>,

    order: VecDeque<SocketAddr>,

    nx: HashMap<SocketAddr, Instant>,
}

impl SpoofCache {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(cap.min(1024)),
                order: VecDeque::with_capacity(cap.min(1024)),
                nx: HashMap::new(),
            }),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn nx_len(&self) -> usize {
        let now = Instant::now();
        self.inner
            .lock()
            .nx
            .values()
            .filter(|t| now.duration_since(**t) < NX_TTL)
            .count()
    }

    pub fn get_or_bind(&self, spoof_src: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        let now = Instant::now();
        let mut g = self.inner.lock();
        if let Some(s) = g.map.get(&spoof_src) {
            return Ok(Arc::clone(s));
        }
        if let Some(t) = g.nx.get(&spoof_src) {
            if now.duration_since(*t) < NX_TTL {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "spoof bind cached failure (nx)",
                ));
            }
            g.nx.remove(&spoof_src);
        }

        match bind_spoof_udp(spoof_src) {
            Ok(sock) => {
                let sock = Arc::new(sock);
                if g.map.len() >= self.cap
                    && let Some(evict) = g.order.pop_front()
                {
                    g.map.remove(&evict);
                }
                g.order.push_back(spoof_src);
                g.map.insert(spoof_src, Arc::clone(&sock));
                g.nx.remove(&spoof_src);
                Ok(sock)
            }
            Err(e) => {
                if g.nx.len() >= NX_CAP {
                    g.nx.retain(|_, t| now.duration_since(*t) < NX_TTL);
                }
                g.nx.insert(spoof_src, now);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TUdp;

    #[test]
    fn lru_evicts_oldest() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let cache = SpoofCache::new(2);

            let a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
            let b: SocketAddr = "127.0.0.1:10002".parse().unwrap();
            let c: SocketAddr = "127.0.0.1:10003".parse().unwrap();
            let sa = Arc::new(TUdp::bind(a).await.unwrap());
            let sb = Arc::new(TUdp::bind(b).await.unwrap());
            let sc = Arc::new(TUdp::bind(c).await.unwrap());
            {
                let mut g = cache.inner.lock();
                g.map.insert(a, sa);
                g.order.push_back(a);
                g.map.insert(b, sb);
                g.order.push_back(b);

                if g.map.len() >= cache.cap {
                    if let Some(ev) = g.order.pop_front() {
                        g.map.remove(&ev);
                    }
                }
                g.map.insert(c, sc);
                g.order.push_back(c);
            }
            let g = cache.inner.lock();
            assert_eq!(g.map.len(), 2);
            assert!(!g.map.contains_key(&a));
            assert!(g.map.contains_key(&b));
            assert!(g.map.contains_key(&c));
        });
    }

    #[test]
    fn cap_zero_does_not_panic() {
        let _ = SpoofCache::new(0);
    }

    #[test]
    fn nx_cache_short_circuits() {
        let cache = SpoofCache::new(8);
        let dead: SocketAddr = "192.0.2.1:9".parse().unwrap();
        {
            let mut g = cache.inner.lock();
            g.nx.insert(dead, Instant::now());
        }
        let err = cache
            .get_or_bind(dead)
            .expect_err("nx should short-circuit");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(cache.nx_len(), 1);
    }

    #[test]
    fn nx_cache_expires_after_ttl() {
        let cache = SpoofCache::new(8);
        let dead: SocketAddr = "192.0.2.2:9".parse().unwrap();
        {
            let mut g = cache.inner.lock();
            g.nx.insert(dead, Instant::now() - Duration::from_secs(10));
        }

        let err = cache.get_or_bind(dead).expect_err("syscall path expected");
        assert_ne!(err.to_string(), "spoof bind cached failure (nx)");
    }
}
