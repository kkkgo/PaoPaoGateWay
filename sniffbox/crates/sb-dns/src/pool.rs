// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::hash::{RAPIDHASH_SEED, fastrange, fmix64, probe_step, rapidhash};
use ipnet::Ipv4Net;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const PROBE_LIMIT: u32 = 32;

const FIRST_OFFSET: u32 = 4;

const MIN_USABLE: u32 = 16;

const MIN_SHARD_USABLE: u32 = 16;

pub const DEFAULT_SHARDS: u32 = 16;

pub const APPROX_BYTES_PER_ENTRY: usize = 160;

#[derive(thiserror::Error, Debug)]
pub enum FakeIpError {
    #[error("fake_cidr too small: /{prefix} has only {usable} usable addrs (need >= {min})")]
    CidrTooSmall { prefix: u8, usable: u32, min: u32 },
}

#[derive(Debug, Clone)]
pub struct FakeIpConfig {
    pub cidr: Ipv4Net,

    pub max_entries: usize,

    pub ttl: u32,

    pub shards: u32,
}

const NIL: u32 = u32::MAX;

struct Node {
    ip: u32,
    domain: Arc<str>,
    older: u32,
    newer: u32,
}

struct Shard {
    nodes: Vec<Node>,
    free: Vec<u32>,
    by_domain: HashMap<Arc<str>, u32>,
    by_ip: HashMap<u32, u32>,
    head: u32,
    tail: u32,
    count: usize,
    cap: usize,
    lo: u32,
    usable: u32,
}

pub struct FakeIpPool {
    shards: Box<[Mutex<Shard>]>,
    net: Ipv4Net,
    ttl: u32,
    lo: u32,
    span: u32,
    n_shards: u32,
}

fn cidr_geometry(cidr: Ipv4Net) -> (Ipv4Net, u32, u32) {
    let net = cidr.trunc();
    let base = u32::from(net.network());
    let bcast = u32::from(net.broadcast());
    let lo = base.saturating_add(FIRST_OFFSET);
    (net, lo, bcast.saturating_sub(lo))
}

pub fn usable_addrs(cidr: Ipv4Net) -> u32 {
    cidr_geometry(cidr).2
}

impl FakeIpPool {
    pub fn new(cfg: FakeIpConfig) -> Result<Self, FakeIpError> {
        let (net, lo, usable) = cidr_geometry(cfg.cidr);
        if usable < MIN_USABLE {
            return Err(FakeIpError::CidrTooSmall {
                prefix: net.prefix_len(),
                usable,
                min: MIN_USABLE,
            });
        }

        let max_shards = (usable / MIN_SHARD_USABLE).max(1);
        let requested = cfg.shards.max(1);
        let n = requested.min(max_shards);
        if n < requested {
            tracing::warn!(
                requested,
                usable,
                n,
                "fakeip shards clamped (cidr too small for that many)"
            );
        }
        let span = usable / n;
        let total_cap = cfg.max_entries.clamp(1, usable as usize);

        let per_shard_cap = total_cap.div_ceil(n as usize).clamp(1, span as usize);
        if per_shard_cap * (n as usize) < cfg.max_entries.min(usable as usize) {
            tracing::warn!(
                requested = cfg.max_entries,
                effective = per_shard_cap * n as usize,
                "fakeip max_entries reduced by per-shard slice cap"
            );
        }
        let shards: Vec<Mutex<Shard>> = (0..n)
            .map(|s| Mutex::new(Shard::new(lo + s * span, span, per_shard_cap)))
            .collect();
        Ok(Self {
            shards: shards.into_boxed_slice(),
            net,
            ttl: cfg.ttl,
            lo,
            span,
            n_shards: n,
        })
    }

    pub fn intern(&self, domain: &str) -> Ipv4Addr {
        let lowered;
        let d: &str = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = domain.to_ascii_lowercase();
            &lowered
        } else {
            domain
        };
        let h = rapidhash(d.as_bytes(), RAPIDHASH_SEED);
        let shard_idx = fastrange(h, self.n_shards) as usize;
        let place_hash = fmix64(h);
        let ip = self.shards[shard_idx].lock().intern(d, place_hash);
        Ipv4Addr::from(ip)
    }

    pub fn lookback(&self, ip: Ipv4Addr) -> Option<Arc<str>> {
        let ip_u = u32::from(ip);
        if ip_u < self.lo {
            return None;
        }
        let idx = ((ip_u - self.lo) / self.span) as usize;
        if idx >= self.shards.len() {
            return None;
        }
        self.shards[idx].lock().lookback(ip_u)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.net.contains(&v4),
            IpAddr::V6(_) => false,
        }
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }
    pub fn cidr(&self) -> Ipv4Net {
        self.net
    }
    pub fn shard_count(&self) -> u32 {
        self.n_shards
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().count).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Shard {
    fn new(lo: u32, usable: u32, cap: usize) -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            by_domain: HashMap::new(),
            by_ip: HashMap::new(),
            head: NIL,
            tail: NIL,
            count: 0,
            cap,
            lo,
            usable,
        }
    }

    fn intern(&mut self, domain: &str, place_hash: u64) -> u32 {
        if let Some(&idx) = self.by_domain.get(domain) {
            self.promote(idx);
            return self.nodes[idx as usize].ip;
        }
        if self.count >= self.cap {
            self.evict_tail();
        }
        let ip = self.find_free_ip(place_hash);
        let dom: Arc<str> = Arc::from(domain);
        let idx = self.alloc_node(ip, Arc::clone(&dom));
        self.by_domain.insert(dom, idx);
        self.by_ip.insert(ip, idx);
        self.push_front(idx);
        ip
    }

    fn lookback(&mut self, ip: u32) -> Option<Arc<str>> {
        let idx = *self.by_ip.get(&ip)?;
        self.promote(idx);
        Some(Arc::clone(&self.nodes[idx as usize].domain))
    }

    fn find_free_ip(&self, h: u64) -> u32 {
        let n = self.usable;
        let idx0 = fastrange(h, n);
        let ip0 = self.lo + idx0;
        if !self.by_ip.contains_key(&ip0) {
            return ip0;
        }
        let step = probe_step(h, n);
        let mut s = idx0;
        for _ in 0..PROBE_LIMIT {
            s = ((s as u64 + step as u64) % n as u64) as u32;
            let ip = self.lo + s;
            if !self.by_ip.contains_key(&ip) {
                return ip;
            }
        }
        let mut s = idx0;
        for _ in 0..n {
            s = if s + 1 == n { 0 } else { s + 1 };
            let ip = self.lo + s;
            if !self.by_ip.contains_key(&ip) {
                return ip;
            }
        }
        unreachable!(
            "find_free_ip: count {} < usable {} but no free slot",
            self.count, n
        )
    }

    fn alloc_node(&mut self, ip: u32, domain: Arc<str>) -> u32 {
        self.count += 1;
        if let Some(idx) = self.free.pop() {
            self.nodes[idx as usize] = Node {
                ip,
                domain,
                older: NIL,
                newer: NIL,
            };
            idx
        } else {
            let idx = self.nodes.len() as u32;
            self.nodes.push(Node {
                ip,
                domain,
                older: NIL,
                newer: NIL,
            });
            idx
        }
    }

    fn evict_tail(&mut self) {
        let idx = self.tail;
        debug_assert_ne!(idx, NIL, "evict on empty shard");
        let (ip, dom) = {
            let node = &self.nodes[idx as usize];
            (node.ip, Arc::clone(&node.domain))
        };
        self.unlink(idx);
        self.by_ip.remove(&ip);
        self.by_domain.remove(&*dom);
        self.nodes[idx as usize].domain = empty_arc();
        self.free.push(idx);
        self.count -= 1;
    }

    fn unlink(&mut self, idx: u32) {
        let (older, newer) = {
            let n = &self.nodes[idx as usize];
            (n.older, n.newer)
        };
        if newer != NIL {
            self.nodes[newer as usize].older = older;
        } else {
            self.head = older;
        }
        if older != NIL {
            self.nodes[older as usize].newer = newer;
        } else {
            self.tail = newer;
        }
        let n = &mut self.nodes[idx as usize];
        n.older = NIL;
        n.newer = NIL;
    }

    fn push_front(&mut self, idx: u32) {
        let old_head = self.head;
        self.nodes[idx as usize].older = old_head;
        self.nodes[idx as usize].newer = NIL;
        if old_head != NIL {
            self.nodes[old_head as usize].newer = idx;
        }
        self.head = idx;
        if self.tail == NIL {
            self.tail = idx;
        }
    }

    fn promote(&mut self, idx: u32) {
        if self.head == idx {
            return;
        }
        self.unlink(idx);
        self.push_front(idx);
    }
}

fn empty_arc() -> Arc<str> {
    Arc::from("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_sharded(cidr: &str, max_entries: usize, shards: u32) -> FakeIpPool {
        FakeIpPool::new(FakeIpConfig {
            cidr: cidr.parse().unwrap(),
            max_entries,
            ttl: 3,
            shards,
        })
        .unwrap()
    }
    fn pool(cidr: &str, max_entries: usize) -> FakeIpPool {
        pool_sharded(cidr, max_entries, DEFAULT_SHARDS)
    }

    #[test]
    fn intern_in_range_and_idempotent() {
        let p = pool("7.0.0.0/8", 65536);
        let a = p.intern("google.com");
        assert_eq!(a, p.intern("google.com"), "same domain → same ip");
        assert!(p.contains(IpAddr::V4(a)));
        assert_ne!(p.intern("facebook.com"), a);
    }

    #[test]
    fn reverse_lookup_roundtrips() {
        let p = pool("7.0.0.0/8", 65536);
        let ip = p.intern("example.com");
        assert_eq!(p.lookback(ip).as_deref(), Some("example.com"));
        assert!(p.lookback("7.255.255.254".parse().unwrap()).is_none());
    }

    #[test]
    fn case_insensitive() {
        let p = pool("7.0.0.0/8", 65536);
        assert_eq!(p.intern("Google.COM"), p.intern("google.com"));
        let ip = p.intern("EXAMPLE.org");
        assert_eq!(p.lookback(ip).as_deref(), Some("example.org"));
    }

    #[test]
    fn deterministic_across_restart_regardless_of_order() {

        let domains: Vec<String> = (0..2000).map(|i| format!("host{i}.example.com")).collect();
        let p1 = pool("7.0.0.0/8", 65536);
        let map1: Vec<_> = domains.iter().map(|d| p1.intern(d)).collect();
        let p2 = pool("7.0.0.0/8", 65536);
        for d in domains.iter().rev() {
            p2.intern(d);
        }
        for (d, ip1) in domains.iter().zip(&map1) {
            assert_eq!(
                p2.intern(d),
                *ip1,
                "domain {d} must map to same ip across restart"
            );
        }
    }

    #[test]
    fn sharding_reverse_finds_right_shard() {

        let p = pool("7.0.0.0/8", 65536);
        let mut seen = std::collections::HashSet::new();
        for i in 0..5000 {
            let d = format!("h{i}.test.com");
            let ip = p.intern(&d);
            assert!(p.contains(IpAddr::V4(ip)));
            assert!(seen.insert(ip), "ip {ip} reused across shards");
            assert_eq!(
                p.lookback(ip).as_deref(),
                Some(d.as_str()),
                "reverse must find owning shard"
            );
        }
        assert_eq!(p.len(), 5000);
    }

    #[test]
    fn shards_clamped_on_small_cidr() {

        let p = pool_sharded("7.0.0.0/24", 100, 1000);
        assert!(p.shard_count() >= 1 && p.shard_count() <= 251 / MIN_SHARD_USABLE);
        let ip = p.intern("a.com");
        assert!(p.contains(IpAddr::V4(ip)));
        assert_eq!(p.lookback(ip).as_deref(), Some("a.com"));
    }

    #[test]
    fn lru_evicts_oldest() {

        let p = pool_sharded("7.0.0.0/24", 4, 1);
        let ips: Vec<_> = (0..4).map(|i| p.intern(&format!("d{i}.com"))).collect();
        assert_eq!(p.len(), 4);
        let ip5 = p.intern("d4.com");
        assert_eq!(p.len(), 4, "cap holds");
        assert!(p.lookback(ips[0]).is_none(), "d0 (LRU) evicted");
        assert!(p.lookback(ips[1]).is_some(), "d1 retained");
        assert!(p.contains(IpAddr::V4(ip5)));
    }

    #[test]
    fn lru_promote_protects_active() {
        let p = pool_sharded("7.0.0.0/24", 2, 1);
        let a = p.intern("a.com");
        let _b = p.intern("b.com");
        assert_eq!(p.intern("a.com"), a);
        let _c = p.intern("c.com");
        assert_eq!(p.intern("a.com"), a, "a was promoted, must survive");
    }

    #[test]
    fn reverse_lookup_promotes() {
        let p = pool_sharded("7.0.0.0/24", 2, 1);
        let a = p.intern("a.com");
        let _b = p.intern("b.com");
        assert!(p.lookback(a).is_some());
        let _c = p.intern("c.com");
        assert!(
            p.lookback(a).is_some(),
            "a promoted via lookback must survive"
        );
    }

    #[test]
    fn dense_shard_all_distinct_no_panic() {

        const USABLE: usize = 251;
        let p = pool_sharded("7.0.0.0/24", 1000, 1);
        let mut seen = std::collections::HashSet::new();
        for i in 0..USABLE {
            let ip = p.intern(&format!("x{i}.test"));
            assert!(p.contains(IpAddr::V4(ip)));
            assert!(seen.insert(ip), "ip {ip} assigned twice at i={i}");
        }
        assert_eq!(p.len(), USABLE);
        let extra = p.intern("overflow.test");
        assert!(p.contains(IpAddr::V4(extra)));
        assert_eq!(p.len(), USABLE);
    }

    #[test]
    fn rejects_tiny_cidr() {
        let r = FakeIpPool::new(FakeIpConfig {
            cidr: "7.0.0.0/30".parse().unwrap(),
            max_entries: 10,
            ttl: 3,
            shards: 1,
        });
        assert!(matches!(r, Err(FakeIpError::CidrTooSmall { .. })));
    }

    #[test]
    fn first_ip_skips_network_and_gateway() {
        let p = pool("7.0.0.0/8", 65536);
        let min = (0..2000)
            .map(|i| u32::from(p.intern(&format!("h{i}.net"))))
            .min()
            .unwrap();
        assert!(
            min >= u32::from("7.0.0.4".parse::<Ipv4Addr>().unwrap()),
            "must skip reserved head"
        );
    }
}
