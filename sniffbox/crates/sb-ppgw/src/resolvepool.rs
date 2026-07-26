// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const HEARTBEAT: Duration = Duration::from_secs(5);

const TICK: Duration = Duration::from_millis(200);

const HEARTBEAT_SHOWN: usize = 5;

#[derive(Clone, Copy, Debug)]
pub struct Deadline(Instant);

impl Deadline {
    pub fn after(d: Duration) -> Self {
        let now = Instant::now();
        Self(now.checked_add(d).unwrap_or(now))
    }

    pub fn remaining(&self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }

    pub fn clamp(&self, want: Duration) -> Option<Duration> {
        let left = self.remaining();
        (!left.is_zero()).then(|| want.min(left))
    }

    pub fn earliest(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }
}

pub struct Outcome {
    pub ips: Vec<IpAddr>,

    pub trace: String,
}

impl Outcome {
    pub fn new(ips: Vec<IpAddr>, trace: Vec<String>) -> Self {
        Self {
            ips,
            trace: trace.join(", "),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Budget {

    pub total: Duration,

    pub per_domain: Duration,

    pub workers: usize,
}

impl Budget {

    pub fn dns_burn() -> Self {
        Self::from_env("dns_burn", 60, 12, 16)
    }

    pub fn subdns() -> Self {
        Self::from_env("subdns", 60, 20, 8)
    }

    fn from_env(prefix: &str, total: u64, per_domain: u64, workers: usize) -> Self {
        Self {
            total: env_secs(&format!("{prefix}_budget"), total),
            per_domain: env_secs(&format!("{prefix}_domain_budget"), per_domain),
            workers: env_usize(&format!("{prefix}_workers"), workers, 1, 64),
        }
    }
}

fn env_secs(key: &str, default: u64) -> Duration {
    Duration::from_secs(env_usize(key, default as usize, 1, 3600) as u64)
}

fn env_usize(key: &str, default: usize, lo: usize, hi: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| (lo..=hi).contains(v))
        .unwrap_or(default)
}

#[derive(Clone, Copy)]
pub struct Log {
    pub info: fn(&str),
    pub step: fn(&str),
    pub warn: fn(&str),
}

pub const DNS_LOG: Log = Log {
    info: dns_info,
    step: dns_step,
    warn: dns_warn,
};

fn dns_write(prefix: String, msg: &str) {
    let _ = writeln!(std::io::stdout(), "{prefix}{msg}");
}
fn dns_info(msg: &str) {
    dns_write(crate::term::green("[PaoPaoGW DNS]"), msg);
}
fn dns_step(msg: &str) {
    dns_write(crate::term::orange("[PaoPaoGW DNS]"), msg);
}
fn dns_warn(msg: &str) {
    dns_write(crate::term::red("[PaoPaoGW DNS]"), msg);
}

pub fn resolve_batch<F>(
    log: Log,
    tag: &str,
    domains: &[String],
    budget: Budget,
    resolve: F,
) -> HashMap<String, Vec<IpAddr>>
where
    F: Fn(&str, Deadline) -> Outcome + Sync,
{
    let total = domains.len();
    if total == 0 {
        return HashMap::new();
    }
    let started = Instant::now();
    let deadline = Deadline::after(budget.total);
    let workers = budget.workers.clamp(1, total);

    (log.step)(&format!(
        "{tag}: start — {total} domain(s), {workers} worker(s), budget {}s total / {}s per domain",
        budget.total.as_secs(),
        budget.per_domain.as_secs()
    ));

    let out: Mutex<HashMap<String, Vec<IpAddr>>> = Mutex::new(HashMap::new());
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);

    let inflight: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());
    let stop = AtomicBool::new(false);

    let work = || {
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            if i >= total {
                break;
            }
            let domain = &domains[i];
            if deadline.expired() {
                let n = skipped.fetch_add(1, Ordering::Relaxed) + 1;
                (log.warn)(&format!(
                    "{tag}: {domain} -> SKIPPED (batch budget {}s exhausted; {n} skipped so far)",
                    budget.total.as_secs()
                ));
                continue;
            }
            let start = Instant::now();
            inflight.lock().unwrap().push((domain.clone(), start));

            let dl = Deadline::after(budget.per_domain).earliest(deadline);
            let o = resolve(domain, dl);

            inflight
                .lock()
                .unwrap()
                .retain(|(d, t)| !(d == domain && *t == start));
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            let el = start.elapsed().as_secs_f64();
            if o.ips.is_empty() {
                failed.fetch_add(1, Ordering::Relaxed);
                (log.warn)(&format!(
                    "{tag}: [{n}/{total}] {domain} -> FAILED in {el:.1}s [{}]",
                    o.trace
                ));
            } else {
                let list: Vec<String> = o.ips.iter().map(|ip| ip.to_string()).collect();
                (log.info)(&format!(
                    "{tag}: [{n}/{total}] {domain} -> {} in {el:.1}s [{}]",
                    list.join(", "),
                    o.trace
                ));
                out.lock().unwrap().insert(domain.clone(), o.ips);
            }
        }
    };

    std::thread::scope(|outer| {
        outer.spawn(|| {
            let mut last = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(TICK);
                if last.elapsed() < HEARTBEAT || stop.load(Ordering::Relaxed) {
                    continue;
                }
                last = Instant::now();
                let mut busy: Vec<(String, f64)> = inflight
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(d, t)| (d.clone(), t.elapsed().as_secs_f64()))
                    .collect();
                if busy.is_empty() {
                    continue;
                }
                busy.sort_by(|a, b| b.1.total_cmp(&a.1));
                let shown: Vec<String> = busy
                    .iter()
                    .take(HEARTBEAT_SHOWN)
                    .map(|(d, s)| format!("{d} {s:.0}s"))
                    .collect();
                let more = busy.len().saturating_sub(HEARTBEAT_SHOWN);
                let more = if more > 0 {
                    format!(" +{more} more")
                } else {
                    String::new()
                };
                (log.step)(&format!(
                    "{tag}: still working — {}/{total} done, {} in flight (slowest: {}{}), \
                     elapsed {:.0}s, batch budget left {:.0}s",
                    done.load(Ordering::Relaxed),
                    busy.len(),
                    shown.join(", "),
                    more,
                    started.elapsed().as_secs_f64(),
                    deadline.remaining().as_secs_f64(),
                ));
            }
        });
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(work);
            }
        });
        stop.store(true, Ordering::Relaxed);
    });

    let map = out.into_inner().unwrap();
    let (failed, skipped) = (failed.into_inner(), skipped.into_inner());
    let msg = format!(
        "{tag}: done in {:.1}s — {} resolved, {failed} failed, {skipped} skipped of {total}",
        started.elapsed().as_secs_f64(),
        map.len()
    );
    if skipped > 0 {
        (log.warn)(&format!(
            "{msg} — batch budget {}s exhausted, remaining domain(s) abandoned",
            budget.total.as_secs()
        ));
    } else {
        (log.step)(&msg);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn silent() -> Log {
        fn nop(_: &str) {}
        Log {
            info: nop,
            step: nop,
            warn: nop,
        }
    }

    fn budget(total: u64, per_domain: u64, workers: usize) -> Budget {
        Budget {
            total: Duration::from_secs(total),
            per_domain: Duration::from_secs(per_domain),
            workers,
        }
    }

    #[test]
    fn deadline_clamps_and_expires() {
        let dl = Deadline::after(Duration::from_millis(50));
        assert_eq!(dl.clamp(Duration::from_secs(3)).unwrap().as_secs(), 0);
        assert!(!dl.expired());
        std::thread::sleep(Duration::from_millis(80));
        assert!(dl.expired());
        assert!(dl.clamp(Duration::from_secs(3)).is_none());

        let a = Deadline::after(Duration::from_secs(10));
        let b = Deadline::after(Duration::from_secs(1));
        assert!(a.earliest(b).remaining() <= Duration::from_secs(1));
    }

    #[test]
    fn empty_input_short_circuits() {
        let got = resolve_batch(silent(), "t", &[], budget(5, 1, 4), |_, _| {
            panic!("must not be called")
        });
        assert!(got.is_empty());
    }

    #[test]
    fn slow_domain_does_not_block_the_batch() {
        let domains: Vec<String> = (0..12).map(|i| format!("d{i}.test")).collect();
        let start = Instant::now();
        let got = resolve_batch(silent(), "t", &domains, budget(4, 1, 4), |d, dl| {
            if d == "d0.test" {

                std::thread::sleep(dl.remaining());
                return Outcome::new(vec![], vec!["blackhole=timeout".into()]);
            }
            Outcome::new(vec!["1.2.3.4".parse().unwrap()], vec!["ok=1ip".into()])
        });
        assert_eq!(got.len(), 11, "只有黑洞域名该失败: {got:?}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "慢域名把整批钉住了: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn batch_budget_stops_dispatching() {
        let domains: Vec<String> = (0..40).map(|i| format!("d{i}.test")).collect();
        let calls = AtomicUsize::new(0);
        let start = Instant::now();
        let got = resolve_batch(silent(), "t", &domains, budget(1, 1, 2), |_, dl| {
            calls.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(dl.remaining());
            Outcome::new(vec![], vec!["timeout".into()])
        });
        assert!(got.is_empty());
        assert!(
            calls.load(Ordering::Relaxed) <= 4,
            "预算耗尽后仍在发查询: {} 次",
            calls.load(Ordering::Relaxed)
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "整批预算没兜住: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn env_budget_override_ignores_garbage() {

        unsafe { std::env::set_var("resolvepool_test_budget", "not-a-number") };
        assert_eq!(env_secs("resolvepool_test_budget", 42).as_secs(), 42);
        unsafe { std::env::set_var("resolvepool_test_budget", "0") };
        assert_eq!(env_secs("resolvepool_test_budget", 42).as_secs(), 42);
        unsafe { std::env::set_var("resolvepool_test_budget", "7") };
        assert_eq!(env_secs("resolvepool_test_budget", 42).as_secs(), 7);
        unsafe { std::env::remove_var("resolvepool_test_budget") };
    }
}
