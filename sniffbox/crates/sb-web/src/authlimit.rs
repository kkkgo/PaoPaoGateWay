// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const BURST: u32 = 10;

pub const REFILL: Duration = Duration::from_secs(6);

pub const MAX_TRACKED: usize = 4096;

const OVERFLOW: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

pub struct AuthLimiter {

    tat: Mutex<HashMap<IpAddr, Instant>>,
    burst: u32,
    refill: Duration,
    max_tracked: usize,
    exempt_loopback: bool,
}

impl Default for AuthLimiter {
    fn default() -> Self {
        Self::new(BURST, REFILL, MAX_TRACKED)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {

    Allowed,

    JustBlocked,
}

impl AuthLimiter {
    pub fn new(burst: u32, refill: Duration, max_tracked: usize) -> Self {
        Self {
            tat: Mutex::new(HashMap::new()),
            burst: burst.max(1),
            refill,
            max_tracked: max_tracked.max(1),
            exempt_loopback: true,
        }
    }

    pub fn strict(mut self) -> Self {
        self.exempt_loopback = false;
        self
    }

    fn tau(&self) -> Duration {
        self.refill * (self.burst - 1)
    }

    pub fn key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(_) => ip,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => {
                    let s = v6.segments();
                    IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
                }
            },
        }
    }

    fn exempt(&self, ip: IpAddr) -> bool {
        self.exempt_loopback && ip.to_canonical().is_loopback()
    }

    pub fn blocked(&self, ip: IpAddr) -> Option<Duration> {
        self.blocked_at(ip, Instant::now())
    }

    pub fn blocked_at(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        if self.exempt(ip) {
            return None;
        }
        let map = self.tat.lock().unwrap_or_else(|e| e.into_inner());
        let key = Self::key(ip);
        let tat = map.get(&key).or_else(|| {

            (map.len() >= self.max_tracked)
                .then(|| map.get(&OVERFLOW))
                .flatten()
        })?;
        let ahead = tat.checked_duration_since(now)?;
        ahead.checked_sub(self.tau()).filter(|d| !d.is_zero())
    }

    pub fn fail(&self, ip: IpAddr) -> Charge {
        self.fail_at(ip, Instant::now())
    }

    pub fn fail_at(&self, ip: IpAddr, now: Instant) -> Charge {
        if self.exempt(ip) {
            return Charge::Allowed;
        }
        let mut map = self.tat.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = Self::key(ip);
        if !map.contains_key(&key) && map.len() >= self.max_tracked {

            map.retain(|_, tat| *tat > now);
            if map.len() >= self.max_tracked {
                key = OVERFLOW;
            }
        }
        let tau = self.tau();
        let was_over = map
            .get(&key)
            .and_then(|t| t.checked_duration_since(now))
            .is_some_and(|ahead| ahead > tau);
        let tat = map.entry(key).or_insert(now);
        *tat = (*tat).max(now) + self.refill;
        let over = tat.checked_duration_since(now).is_some_and(|a| a > tau);
        if over && !was_over {
            Charge::JustBlocked
        } else {
            Charge::Allowed
        }
    }

    pub fn success(&self, ip: IpAddr) {
        if self.exempt(ip) {
            return;
        }
        let mut map = self.tat.lock().unwrap_or_else(|e| e.into_inner());
        if !map.is_empty() {
            map.remove(&Self::key(ip));
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.tat.lock().unwrap().len()
    }
}

pub fn bearer_presented(auth_header: Option<&[u8]>) -> bool {
    auth_header.is_some_and(|v| {
        let v = v.trim_ascii_start();
        v.len() > 7 && v[..7].eq_ignore_ascii_case(b"bearer ")
    })
}

pub fn retry_after_secs(d: Duration) -> u64 {
    (d.as_secs() + u64::from(d.subsec_nanos() > 0)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_then_blocked_then_one_try_per_refill() {
        let l = AuthLimiter::new(10, Duration::from_secs(6), 64);
        let t0 = Instant::now();
        let a = ip("192.168.1.50");
        for i in 0..9 {
            assert_eq!(
                l.fail_at(a, t0),
                Charge::Allowed,
                "failure {i} is within the burst"
            );
            assert_eq!(l.blocked_at(a, t0), None);
        }
        assert_eq!(
            l.fail_at(a, t0),
            Charge::JustBlocked,
            "10th failure crosses the threshold"
        );
        let wait = l.blocked_at(a, t0).expect("blocked after the burst");
        assert_eq!(wait, Duration::from_secs(6));

        assert!(l.blocked_at(a, t0 + Duration::from_millis(5999)).is_some());
        assert_eq!(l.blocked_at(a, t0 + Duration::from_secs(6)), None);

        let t1 = t0 + Duration::from_secs(6);
        assert_eq!(l.fail_at(a, t1), Charge::JustBlocked);
        assert_eq!(l.blocked_at(a, t1), Some(Duration::from_secs(6)));
    }

    #[test]
    fn hammering_while_blocked_does_not_report_just_blocked_again() {
        let l = AuthLimiter::new(3, Duration::from_secs(6), 64);
        let t0 = Instant::now();
        let a = ip("10.0.0.9");
        l.fail_at(a, t0);
        l.fail_at(a, t0);
        assert_eq!(l.fail_at(a, t0), Charge::JustBlocked);
        assert_eq!(
            l.fail_at(a, t0),
            Charge::Allowed,
            "only the crossing is reported"
        );
    }

    #[test]
    fn success_clears_the_source_but_not_others() {
        let l = AuthLimiter::new(2, Duration::from_secs(6), 64);
        let t0 = Instant::now();
        let (a, b) = (ip("10.0.0.1"), ip("10.0.0.2"));
        for _ in 0..2 {
            l.fail_at(a, t0);
            l.fail_at(b, t0);
        }
        assert!(l.blocked_at(a, t0).is_some() && l.blocked_at(b, t0).is_some());
        l.success(a);
        assert_eq!(
            l.blocked_at(a, t0),
            None,
            "a correct token clears its own record"
        );
        assert!(l.blocked_at(b, t0).is_some(), "other sources stay blocked");
    }

    #[test]
    fn loopback_is_never_limited() {
        let l = AuthLimiter::new(1, Duration::from_secs(60), 64);
        let t0 = Instant::now();
        for lo in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            for _ in 0..50 {
                assert_eq!(l.fail_at(ip(lo), t0), Charge::Allowed);
            }
            assert_eq!(l.blocked_at(ip(lo), t0), None, "{lo} must stay exempt");
        }
        assert_eq!(l.tracked(), 0);
    }

    #[test]
    fn ipv6_counts_per_slash_64_and_mapped_v4_as_v4() {
        let l = AuthLimiter::new(2, Duration::from_secs(6), 64);
        let t0 = Instant::now();

        l.fail_at(ip("2001:db8:1:2::aaaa"), t0);
        l.fail_at(ip("2001:db8:1:2:ffff::1"), t0);
        assert!(l.blocked_at(ip("2001:db8:1:2::9"), t0).is_some());
        assert_eq!(
            l.blocked_at(ip("2001:db8:1:3::9"), t0),
            None,
            "another /64 is independent"
        );

        l.fail_at(ip("::ffff:192.0.2.7"), t0);
        l.fail_at(ip("192.0.2.7"), t0);
        assert!(l.blocked_at(ip("192.0.2.7"), t0).is_some());
    }

    #[test]
    fn full_table_spills_new_sources_into_a_shared_bucket() {
        let l = AuthLimiter::new(3, Duration::from_secs(6), 4);
        let t0 = Instant::now();
        for i in 1..=4 {
            l.fail_at(ip(&format!("10.1.0.{i}")), t0);
        }
        assert_eq!(l.tracked(), 4);

        let mut blocked_seen = false;
        for i in 1..=6 {
            let src = ip(&format!("10.2.0.{i}"));
            l.fail_at(src, t0);
            blocked_seen |= l.blocked_at(src, t0).is_some();
        }
        assert!(
            blocked_seen,
            "overflow bucket must block once it is over the burst"
        );
        assert!(
            l.tracked() <= 5,
            "table stays bounded (4 sources + overflow), got {}",
            l.tracked()
        );

        let later = t0 + Duration::from_secs(600);
        let fresh = ip("10.3.0.1");
        assert_eq!(l.fail_at(fresh, later), Charge::Allowed);
        assert_eq!(l.blocked_at(fresh, later), None);
        assert!(
            l.tracked() <= 2,
            "decayed entries are pruned, got {}",
            l.tracked()
        );
    }

    #[test]
    fn decayed_entries_do_not_block() {
        let l = AuthLimiter::new(2, Duration::from_secs(6), 64);
        let t0 = Instant::now();
        let a = ip("10.0.0.5");
        l.fail_at(a, t0);
        l.fail_at(a, t0);
        assert!(l.blocked_at(a, t0).is_some());
        assert_eq!(l.blocked_at(a, t0 + Duration::from_secs(13)), None);
        assert_eq!(l.fail_at(a, t0 + Duration::from_secs(13)), Charge::Allowed);
    }

    #[test]
    fn bearer_presence() {
        assert!(bearer_presented(Some(b"Bearer abc")));
        assert!(bearer_presented(Some(b"bearer abc")));
        assert!(bearer_presented(Some(b"BEARER abc")));
        assert!(!bearer_presented(Some(b"Bearer ")));
        assert!(!bearer_presented(Some(b"Basic abc")));
        assert!(!bearer_presented(Some(b"")));
        assert!(!bearer_presented(None));
    }

    #[test]
    fn retry_after_rounds_up() {
        assert_eq!(retry_after_secs(Duration::from_secs(6)), 6);
        assert_eq!(retry_after_secs(Duration::from_millis(5001)), 6);
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
    }
}
