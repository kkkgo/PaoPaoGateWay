// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const DEFAULT_NEG_TTL: Duration = Duration::from_secs(30);

pub const DEFAULT_FAIL_THRESHOLD: u8 = 3;

const CAP_BEFORE_GC: usize = 4096;

#[derive(Clone, Copy)]
struct Entry {

    fails: u8,

    expires: Instant,
}

pub struct SniffNegCache {
    inner: DashMap<(IpAddr, u16), Entry>,
    ttl: Duration,
    threshold: u8,

    count: AtomicUsize,
}

impl Default for SniffNegCache {
    fn default() -> Self {
        Self::new(DEFAULT_NEG_TTL)
    }
}

impl SniffNegCache {
    pub fn new(ttl: Duration) -> Self {
        Self::with_threshold(ttl, DEFAULT_FAIL_THRESHOLD)
    }

    pub fn with_threshold(ttl: Duration, threshold: u8) -> Self {
        Self {
            inner: DashMap::new(),
            ttl,
            threshold: threshold.max(1),
            count: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_hit(&self, ip: IpAddr, port: u16) -> bool {
        if self.count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        match self.inner.get(&(ip, port)) {
            Some(e) => e.fails >= self.threshold && Instant::now() < e.expires,
            None => false,
        }
    }

    pub fn note_failure(&self, ip: IpAddr, port: u16) {
        let now = Instant::now();
        if self.inner.len() >= CAP_BEFORE_GC {
            self.gc();
        }
        let mut fresh = false;
        self.inner
            .entry((ip, port))
            .and_modify(|e| {
                if now >= e.expires {
                    e.fails = 0;
                }
                e.fails = (e.fails + 1).min(self.threshold);
                e.expires = now + self.ttl;
            })
            .or_insert_with(|| {
                fresh = true;
                Entry {
                    fails: 1.min(self.threshold),
                    expires: now + self.ttl,
                }
            });
        if fresh {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn note_success(&self, ip: IpAddr, port: u16) {
        if self.count.load(Ordering::Relaxed) == 0 {
            return;
        }
        if self.inner.remove(&(ip, port)).is_some() {
            self.count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn gc(&self) {
        let now = Instant::now();
        self.inner.retain(|_, e| now < e.expires);
        self.count.store(self.inner.len(), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail_n(c: &SniffNegCache, ip: IpAddr, port: u16, n: usize) {
        for _ in 0..n {
            c.note_failure(ip, port);
        }
    }

    #[test]
    fn hit_then_expire() {
        let c = SniffNegCache::with_threshold(Duration::from_millis(20), 1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!c.is_hit(ip, 22));
        c.note_failure(ip, 22);
        assert!(c.is_hit(ip, 22));
        std::thread::sleep(Duration::from_millis(40));
        assert!(!c.is_hit(ip, 22));
    }

    #[test]
    fn miss_for_different_dst() {
        let c = SniffNegCache::with_threshold(Duration::from_secs(60), 1);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        c.note_failure(a, 22);
        assert!(c.is_hit(a, 22));
        assert!(!c.is_hit(b, 22));
        assert!(!c.is_hit(a, 443));
    }

    #[test]
    fn gc_drops_expired() {
        let c = SniffNegCache::new(Duration::from_millis(10));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        c.note_failure(ip, 22);
        c.note_failure(ip, 80);
        std::thread::sleep(Duration::from_millis(30));
        c.gc();
        assert_eq!(c.len(), 0);
        assert!(!c.is_hit(ip, 22));
    }

    #[test]
    fn one_failure_does_not_suppress_sniffing() {
        let c = SniffNegCache::default();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        c.note_failure(ip, 443);
        assert!(!c.is_hit(ip, 443), "a single miss must not poison the dst");
        c.note_failure(ip, 443);
        assert!(!c.is_hit(ip, 443), "two misses are still not enough");
        c.note_failure(ip, 443);
        assert!(
            c.is_hit(ip, 443),
            "three consecutive misses do suppress (server-first ports still benefit)"
        );
    }

    #[test]
    fn success_clears_the_failure_streak() {
        let c = SniffNegCache::default();
        let ip: IpAddr = "203.0.113.6".parse().unwrap();
        fail_n(&c, ip, 443, 2);
        c.note_success(ip, 443);
        assert_eq!(c.len(), 0, "success drops the entry");
        fail_n(&c, ip, 443, 2);
        assert!(!c.is_hit(ip, 443), "streak restarted after the success");
        c.note_failure(ip, 443);
        assert!(c.is_hit(ip, 443));
    }

    #[test]
    fn stale_failures_do_not_accumulate() {
        let c = SniffNegCache::new(Duration::from_millis(20));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        fail_n(&c, ip, 22, 2);
        std::thread::sleep(Duration::from_millis(40));
        c.note_failure(ip, 22);
        assert!(!c.is_hit(ip, 22), "expired streak restarts from zero");
        c.note_failure(ip, 22);
        c.note_failure(ip, 22);
        assert!(c.is_hit(ip, 22));
    }

    #[test]
    fn suppression_does_not_extend_itself_on_hits() {
        let c = SniffNegCache::new(Duration::from_millis(30));
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        fail_n(&c, ip, 443, 3);
        assert!(c.is_hit(ip, 443));
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(10));
            let _ = c.is_hit(ip, 443);
        }
        assert!(
            !c.is_hit(ip, 443),
            "hits must not keep the suppression alive forever"
        );
    }

    #[test]
    fn success_on_empty_table_is_a_noop() {
        let c = SniffNegCache::default();
        c.note_success("10.1.1.1".parse().unwrap(), 443);
        assert_eq!(c.len(), 0);
    }
}
