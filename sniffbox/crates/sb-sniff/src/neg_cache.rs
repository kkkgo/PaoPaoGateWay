// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const DEFAULT_NEG_TTL: Duration = Duration::from_secs(30);

const CAP_BEFORE_GC: usize = 4096;

pub struct SniffNegCache {
    inner: DashMap<(IpAddr, u16), Instant>,
    ttl: Duration,
}

impl Default for SniffNegCache {
    fn default() -> Self {
        Self::new(DEFAULT_NEG_TTL)
    }
}

impl SniffNegCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            ttl,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_hit(&self, ip: IpAddr, port: u16) -> bool {
        if let Some(e) = self.inner.get(&(ip, port))
            && e.elapsed() < self.ttl
        {
            return true;
        }
        false
    }

    pub fn mark(&self, ip: IpAddr, port: u16) {
        if self.inner.len() >= CAP_BEFORE_GC {
            self.gc();
        }
        self.inner.insert((ip, port), Instant::now());
    }

    pub fn gc(&self) {
        let ttl = self.ttl;
        self.inner.retain(|_, t| t.elapsed() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_then_expire() {
        let c = SniffNegCache::new(Duration::from_millis(20));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!c.is_hit(ip, 22));
        c.mark(ip, 22);
        assert!(c.is_hit(ip, 22));
        std::thread::sleep(Duration::from_millis(40));
        assert!(!c.is_hit(ip, 22));
    }

    #[test]
    fn miss_for_different_dst() {
        let c = SniffNegCache::new(Duration::from_secs(60));
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        c.mark(a, 22);
        assert!(c.is_hit(a, 22));
        assert!(!c.is_hit(b, 22));
        assert!(!c.is_hit(a, 443));
    }

    #[test]
    fn gc_drops_expired() {
        let c = SniffNegCache::new(Duration::from_millis(10));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        c.mark(ip, 22);
        c.mark(ip, 80);
        std::thread::sleep(Duration::from_millis(30));
        c.gc();
        assert_eq!(c.len(), 0);
    }
}
