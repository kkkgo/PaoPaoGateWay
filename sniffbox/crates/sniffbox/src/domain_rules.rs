// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

type Group = (&'static str, &'static [&'static str]);

const CLOUDFLARED_DOMAINS: &[&str] = &["cftunnel.com", "argotunnel.com"];

const GROUPS: &[Group] = &[("cloudflared", CLOUDFLARED_DOMAINS)];

pub fn match_group(domain: &str) -> Option<&'static str> {
    let d = domain.strip_suffix('.').unwrap_or(domain);
    if d.is_empty() {
        return None;
    }
    GROUPS
        .iter()
        .find(|(_, suffixes)| suffixes.iter().any(|s| is_suffix_match(d, s)))
        .map(|(label, _)| *label)
}

fn is_suffix_match(d: &str, suffix: &str) -> bool {
    if d.len() == suffix.len() {
        return d.eq_ignore_ascii_case(suffix);
    }
    match d.len().checked_sub(suffix.len()) {
        Some(cut) if cut >= 2 => {
            d.as_bytes()[cut - 1] == b'.' && d[cut..].eq_ignore_ascii_case(suffix)
        }
        _ => false,
    }
}

const HINTS_CAP: usize = 512;

struct Hint {
    label: &'static str,

    seq: AtomicU64,
}

pub struct IpHints {
    map: DashMap<IpAddr, Hint>,
    seq: AtomicU64,

    count: AtomicUsize,
    cap: usize,
}

impl Default for IpHints {
    fn default() -> Self {
        Self::with_cap(HINTS_CAP)
    }
}

impl IpHints {
    pub fn with_cap(cap: usize) -> Self {
        Self {
            map: DashMap::new(),
            seq: AtomicU64::new(0),
            count: AtomicUsize::new(0),
            cap: cap.max(1),
        }
    }

    pub fn get(&self, ip: IpAddr) -> Option<&'static str> {
        if self.count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let e = self.map.get(&ip)?;
        e.seq
            .store(self.seq.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
        Some(e.label)
    }

    pub fn note(&self, ip: IpAddr, label: &'static str) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        if let Some(e) = self.map.get(&ip) {
            e.seq.store(seq, Ordering::Relaxed);
            return;
        }
        if self.map.len() >= self.cap {
            self.evict_oldest();
        }
        if self
            .map
            .insert(
                ip,
                Hint {
                    label,
                    seq: AtomicU64::new(seq),
                },
            )
            .is_none()
        {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn evict_oldest(&self) {
        let mut seqs: Vec<u64> = self
            .map
            .iter()
            .map(|e| e.value().seq.load(Ordering::Relaxed))
            .collect();
        if seqs.is_empty() {
            return;
        }
        let drop_n = (seqs.len() / 4).max(1);
        seqs.sort_unstable();
        let threshold = seqs[drop_n.min(seqs.len() - 1)];
        self.map
            .retain(|_, h| h.seq.load(Ordering::Relaxed) >= threshold);
        self.count.store(self.map.len(), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_group_domain_and_subdomains() {
        for d in [
            "argotunnel.com",
            "region1.v2.argotunnel.com",
            "update.argotunnel.com",
            "cftunnel.com",
            "h2.cftunnel.com",
        ] {
            assert_eq!(match_group(d), Some("cloudflared"), "{d} should match");
        }
    }

    #[test]
    fn match_is_case_insensitive_and_tolerates_fqdn_dot() {
        assert_eq!(
            match_group("Region1.V2.ArgoTunnel.COM"),
            Some("cloudflared")
        );
        assert_eq!(match_group("argotunnel.com."), Some("cloudflared"));
    }

    #[test]
    fn rejects_non_group_and_label_boundary_lookalikes() {
        for d in [
            "example.com",
            "cloudflare.com",
            "notargotunnel.com",
            "xargotunnel.com",
            "argotunnel.com.evil.net",
            "cfargotunnel.com",
            "cloudflareaccess.com",
            "trycloudflare.com",
            "cloudflareclient.com",
            "",
            ".",
        ] {
            assert_eq!(match_group(d), None, "{d} must not match");
        }
    }

    #[test]
    fn hints_roundtrip() {
        let h = IpHints::default();
        let ip: IpAddr = "198.41.192.7".parse().unwrap();
        assert_eq!(h.get(ip), None);
        h.note(ip, "cloudflared");
        assert_eq!(h.get(ip), Some("cloudflared"));

        h.note(ip, "cloudflared");
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn empty_hints_short_circuit_without_touching_map() {

        let h = IpHints::default();
        assert!(h.is_empty());
        assert_eq!(h.get("8.8.8.8".parse().unwrap()), None);
        assert_eq!(h.count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn count_mirrors_map_len_across_evictions() {
        let h = IpHints::with_cap(8);
        for i in 0..40u8 {
            h.note(IpAddr::from([10, 0, 1, i]), "cloudflared");
        }
        assert_eq!(
            h.count.load(Ordering::Relaxed),
            h.map.len(),
            "count mirror must survive eviction"
        );
        assert!(h.len() <= 8);
    }

    #[test]
    fn hints_evict_when_full_but_keep_recent() {
        let h = IpHints::with_cap(8);
        for i in 0..8u8 {
            h.note(IpAddr::from([10, 0, 0, i]), "cloudflared");
        }
        let hot: IpAddr = IpAddr::from([10, 0, 0, 7]);

        for i in 100..110u8 {
            h.note(IpAddr::from([10, 0, 0, i]), "cloudflared");
            assert_eq!(h.get(hot), Some("cloudflared"));
        }
        assert!(h.len() <= 8 + 1, "cap must bound growth, got {}", h.len());
        assert_eq!(h.get(hot), Some("cloudflared"), "recent entry survives");
    }
}
