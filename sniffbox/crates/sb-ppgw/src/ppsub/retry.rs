// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::state::{DomainState, RetryState, SubState};
use super::{LOG, SubResult, pp_log, pp_step, pp_warn, state};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(600);

const READY_POLL: Duration = Duration::from_secs(10);

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

const PROBE_HARD_TIMEOUT: Duration = Duration::from_secs(15);

const DEFAULT_READY_URL: &str = "https://github.com";

const DEFAULT_MONITOR_URL: &str = "http://cp.cloudflare.com/generate_204";

const CLASH_YAML: &str = "/tmp/clash.yaml";

const CLASH_BASE: &str = "/tmp/clash_base.yaml";

fn note(msg: &str) {
    pp_log(msg);
    record(msg);
}
fn note_step(msg: &str) {
    pp_step(msg);
    record(msg);
}
fn note_warn(msg: &str) {
    pp_warn(msg);
    record(msg);
}
fn record(msg: &str) {
    record_to(&state::log_file(), msg);
}
fn record_to(path: &str, msg: &str) {
    use std::io::Write;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(f, "{} {msg}", stamp());
}

fn stamp() -> String {

    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}
pub fn run(io: &mut crate::Io) -> i32 {
    let Some(st) = RetryState::load(&state::state_file()) else {
        return 0;
    };
    if !st.pending() {
        return 0;
    }
    if st.clash_socks5 {

        return 0;
    }
    let Some(_lock) = Lock::acquire(&state::lock_file()) else {
        note("retry: another gap-fill is already running, skipping");
        return 0;
    };

    let (bad_subs, bad_specs, bad_burn) = st.gaps();
    note_step(&format!(
        "retry: {bad_subs} subscription(s) + {bad_specs} (domain, DNS) pair(s) + {bad_burn} dns_burn domain(s) to fill once clash is up"
    ));

    let cfg: serde_json::Value = match std::fs::read_to_string(&st.config)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
    {
        Some(v) => v,
        None => {
            note_warn(&format!("retry: cannot read cached config {}", st.config));
            return 1;
        }
    };

    if !wait_ready(&cfg) {
        note_warn("retry: clash never became ready, giving up (gaps stay until the next update)");
        return 0;
    }

    if taken_over(&st) {
        note("retry: another ppsub run took over while waiting, nothing left to fill");
        return 0;
    }

    match fill_gaps(&cfg, st, io) {
        Ok(_) => 0,
        Err(e) => {
            note_warn(&format!("retry: {e}"));
            1
        }
    }
}

fn fill_gaps(
    cfg: &serde_json::Value,
    mut st: RetryState,
    io: &mut crate::Io,
) -> Result<bool, String> {
    let ipv6 = crate::dnsutil::ipv6_enabled();

    let mut fresh_subs: Vec<String> = Vec::new();
    let mut sub_results: Vec<SubResult> = Vec::new();
    for i in 0..st.subs.len() {
        if st.subs[i].ok {

            match load_cached(&st.subs[i]) {
                Some(r) => sub_results.push(r),
                None => {
                    return Err(format!(
                        "[{}] cached payload is gone, cannot rebuild a complete config",
                        st.subs[i].name
                    ));
                }
            }
            continue;
        }
        let sub = super::SubProvider {
            name: st.subs[i].name.clone(),
            url: st.subs[i].url.clone(),
            is_forced: st.subs[i].forced,
        };
        let r = super::sub::download_subscription(&sub);
        if r.success {
            fresh_subs.push(r.name.clone());
            adopt_fresh(&mut st.subs[i], &r);
        }
        sub_results.push(r);
    }

    let mut new_ips = 0usize;
    if st.dns_burn {
        new_ips += fill_subdns(&mut st, &sub_results, &fresh_subs, ipv6);

        new_ips += fill_burn(&mut st, &sub_results, ipv6);
    }

    if taken_over(&st) {
        return Err(format!(
            "{} changed while filling gaps, another ppsub run took over; skipping",
            st.output
        ));
    }

    let changed = !fresh_subs.is_empty() || new_ips > 0;
    if !changed {
        note("retry: nothing new resolved, config left untouched");
        let _ = st.save(&state::state_file());
        return Ok(false);
    }
    note_step(&format!(
        "retry: {} new subscription(s) + {new_ips} new IP(s) → rebuilding config",
        fresh_subs.len()
    ));

    let prev_text =
        std::fs::read_to_string(&st.output).map_err(|e| format!("read {}: {e}", st.output))?;
    let prev = yaml_rust2::YamlLoader::load_from_str(&prev_text)
        .ok()
        .and_then(|d| d.into_iter().next());
    let resolution = to_resolution(&st, &sub_results, ipv6);
    let yaml = super::emit_config(cfg, &sub_results, &resolution, st.dns_burn, prev.as_ref())
        .map_err(|e| e.to_string())?;
    write_atomic(&st.output, &yaml).map_err(|e| format!("write {}: {e}", st.output))?;
    st.output_hash = state::file_hash(&st.output);
    if !fresh_subs.is_empty() {
        refresh_subinfo(&super::subinfo::file(), &st, &fresh_subs);
    }

    combine_and_reload(&st.output, io)?;
    note("retry: gap-fill applied, clash reloaded");
    let _ = st.save(&state::state_file());
    Ok(true)
}

fn fill_subdns(
    st: &mut RetryState,
    sub_results: &[SubResult],
    fresh: &[String],
    ipv6: bool,
) -> usize {
    let mut added = 0usize;
    for r in sub_results.iter().filter(|r| r.success) {
        let Some(idx) = st.subs.iter().position(|s| s.name == r.name) else {
            continue;
        };
        let specs = st.subs[idx].specs.clone();
        if specs.is_empty() {
            continue;
        }

        let full = fresh.iter().any(|n| n == &r.name);
        let todo: Vec<(String, Vec<String>)> = super::proxies::lookup_domains(r)
            .into_iter()
            .filter_map(|d| {
                let want = specs_to_retry(&st.subs[idx], &d, &specs, full);
                (!want.is_empty()).then_some((d, want))
            })
            .collect();
        if todo.is_empty() {
            continue;
        }
        let tag = format!("[{}] subdns-retry", r.name);
        pp_step(&format!(
            "{tag}: re-asking {} unanswered (domain, DNS) pair(s) via the proxy",
            todo.iter().map(|(_, s)| s.len()).sum::<usize>()
        ));
        let domains: Vec<String> = todo.iter().map(|(d, _)| d.clone()).collect();
        let want: HashMap<String, Vec<String>> = todo.into_iter().collect();
        let still_bad: std::sync::Mutex<HashMap<String, Vec<String>>> =
            std::sync::Mutex::new(HashMap::new());
        let got = crate::resolvepool::resolve_batch(
            LOG,
            &tag,
            &domains,
            crate::resolvepool::Budget::subdns(),
            |domain, dl| {
                let specs = want.get(domain).cloned().unwrap_or_default();

                let (outcome, per_spec) =
                    crate::dohdot::resolve_via_servers_detailed(domain, &specs, ipv6, dl, false);
                let bad: Vec<String> = per_spec
                    .into_iter()
                    .filter(|s| !s.ok)
                    .map(|s| s.spec)
                    .collect();
                still_bad.lock().unwrap().insert(domain.to_string(), bad);
                outcome
            },
        );
        let still_bad = still_bad.into_inner().unwrap();
        for d in domains {
            let entry = st.subs[idx].domains.entry(d.clone()).or_default();
            if let Some(ips) = got.get(&d) {
                added += merge_ips(&mut entry.ips, ips);
            }

            entry.failed_specs = still_bad.get(&d).cloned().unwrap_or_default();
        }
    }
    added
}

fn specs_to_retry(sub: &SubState, domain: &str, all: &[String], full: bool) -> Vec<String> {
    if full {
        return all.to_vec();
    }
    match sub.domains.get(domain) {
        Some(d) => d.failed_specs.clone(),
        None => all.to_vec(),
    }
}

fn fill_burn(st: &mut RetryState, sub_results: &[SubResult], ipv6: bool) -> usize {
    let servers = super::proxies::collect_dns_servers(&st.ex_dns);
    if servers.is_empty() {
        return 0;
    }
    let todo = burn_todo(st, sub_results);
    if todo.is_empty() {
        return 0;
    }
    pp_step(&format!(
        "dns_burn-retry: re-resolving {} domain(s) that came back empty",
        todo.len()
    ));
    let got = crate::dnsutil::resolve_domains_logged(LOG, "dns_burn-retry", &todo, &servers, ipv6);
    let mut added = 0usize;
    for d in todo {
        let entry = st.burn.entry(d.clone()).or_default();
        if let Some(ips) = got.get(&d) {
            added += merge_ips(entry, ips);
        }
    }
    added
}

fn burn_todo(st: &RetryState, sub_results: &[SubResult]) -> Vec<String> {
    let mut todo: Vec<String> = Vec::new();
    for r in sub_results.iter().filter(|r| r.success) {
        for d in super::proxies::lookup_domains(r) {
            let empty = st.burn.get(&d).map(|v| v.is_empty()).unwrap_or(true);
            if empty && !todo.contains(&d) {
                todo.push(d);
            }
        }
    }
    todo
}

fn taken_over(st: &RetryState) -> bool {
    state::file_hash(&st.output) != st.output_hash
}

fn merge_ips(known: &mut Vec<String>, fresh: &[IpAddr]) -> usize {
    let mut added = 0;
    for ip in fresh {
        let s = ip.to_string();
        if !known.contains(&s) {
            known.push(s);
            added += 1;
        }
    }
    added
}

fn to_resolution(
    st: &RetryState,
    sub_results: &[SubResult],
    ipv6: bool,
) -> super::proxies::Resolution {
    let parse =
        |v: &Vec<String>| -> Vec<IpAddr> { v.iter().filter_map(|s| s.parse().ok()).collect() };
    let burn = st
        .burn
        .iter()
        .filter(|(_, ips)| !ips.is_empty())
        .map(|(d, ips)| (d.clone(), parse(ips)))
        .collect();
    let subdns = st
        .subs
        .iter()
        .filter(|s| s.ok)
        .map(|s| {
            let m: HashMap<String, Vec<IpAddr>> = s
                .domains
                .iter()
                .filter(|(_, d)| !d.ips.is_empty())
                .map(|(k, d)| (k.clone(), parse(&d.ips)))
                .collect();
            (s.name.clone(), m)
        })
        .collect();
    super::proxies::Resolution {
        burn,
        subdns,
        failed: HashMap::new(),
        hosts: super::proxies::static_hosts(sub_results, ipv6),
    }
}

fn load_cached(s: &SubState) -> Option<SubResult> {
    if s.cache.is_empty() {
        return None;
    }
    let raw = std::fs::read_to_string(&s.cache).ok()?;
    let (proxies, hosts) = super::sub::parse_payload(&raw, &s.name);
    Some(SubResult {
        name: s.name.clone(),
        success: true,
        proxies,
        hosts,
        userinfo: s.userinfo.clone(),
        raw_yaml: raw,
        error: String::new(),
    })
}

fn adopt_fresh(s: &mut SubState, r: &SubResult) {
    s.ok = true;
    s.userinfo = r.userinfo.clone();
    let path = state::cache_path(&s.name);
    if std::fs::write(&path, &r.raw_yaml).is_ok() {
        s.cache = path;
    }
    s.specs = super::proxies::sub_dns_servers(&r.raw_yaml);
    s.domains = super::proxies::lookup_domains(r)
        .into_iter()
        .map(|d| (d, DomainState::default()))
        .collect::<BTreeMap<_, _>>();
}

fn refresh_subinfo(path: &str, st: &RetryState, fresh: &[String]) {
    let mut entries = super::subinfo::load(path);
    let at = super::subinfo::now();
    for s in st.subs.iter().filter(|s| fresh.contains(&s.name)) {
        let e = super::subinfo::Entry {
            name: s.name.clone(),
            info: s.userinfo.clone(),
            at,
        };
        match entries.iter_mut().find(|x| x.name == s.name) {
            Some(x) => *x = e,
            None => entries.push(e),
        }
    }
    if let Err(e) = super::subinfo::save(path, &entries) {
        note_warn(&format!(
            "retry: cannot update subscription usage file: {e}"
        ));
    }
}

fn combine_and_reload(output: &str, io: &mut crate::Io) -> Result<(), String> {
    if !std::path::Path::new(CLASH_BASE).exists() {
        return Err(format!("{CLASH_BASE} missing, cannot rebuild {CLASH_YAML}"));
    }
    let combined = crate::yamltx::combine(&[output.to_string(), CLASH_BASE.to_string()])
        .map_err(|e| e.to_string())?;

    if combined.contains("{clashmode}") || !combined.contains("tproxy-port") {
        return Err("combined config looks unfinished (placeholder left), not writing".to_string());
    }
    write_atomic(CLASH_YAML, &combined).map_err(|e| format!("write {CLASH_YAML}: {e}"))?;

    let client = crate::clash::ClashClient::from_api_url("unix:///tmp/clash.sock", "");
    client.reload_yaml().map_err(|e| e.to_string())?;
    let _ = writeln!(
        io.out,
        "{}gap-fill applied, clash reloaded {CLASH_YAML}",
        crate::term::green("[PaoPaoGW PPSub]")
    );
    Ok(())
}

fn write_atomic(path: &str, text: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

fn wait_ready(cfg: &serde_json::Value) -> bool {
    let target = HealthTarget::from_config(cfg);
    wait_ready_until(
        Instant::now() + READY_TIMEOUT,
        READY_POLL,
        crate::dohdot::clash_socks5_probe,
        || health_ok(&target),
    )
}

fn wait_ready_until(
    deadline: Instant,
    poll: Duration,
    socks_ready: impl Fn() -> bool,
    healthy: impl Fn() -> bool,
) -> bool {
    let mut announced = false;
    loop {
        if socks_ready() {
            if !announced {
                note("retry: clash SOCKS5 is serving, checking health");
                announced = true;
            }
            if healthy() {
                note_step("retry: proxy is healthy, filling gaps now");
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(poll);
    }
}

struct HealthTarget {

    monitor: bool,
    url: String,
    expected: String,
}

impl HealthTarget {
    fn from_config(cfg: &serde_json::Value) -> Self {
        let m = cfg.get("global_monitor");
        let enabled = m
            .and_then(|m| m.get("enable"))
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        if !enabled {
            return Self {
                monitor: false,
                url: DEFAULT_READY_URL.to_string(),
                expected: String::new(),
            };
        }
        Self {
            monitor: true,
            url: m
                .and_then(|m| m.get("url"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_MONITOR_URL)
                .to_string(),
            expected: m
                .and_then(|m| m.get("expected_status"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("0")
                .to_string(),
        }
    }
}

fn health_ok(t: &HealthTarget) -> bool {
    crate::rt::block_on(async {
        let probe = async {
            if t.monitor {
                matches!(
                    crate::httpcli::check_url_connectivity_via(
                        &t.url,
                        crate::HEALTHCHECK_SOCKS5,
                        None,
                        &t.expected,
                        PROBE_TIMEOUT,
                    )
                    .await,
                    Ok((true, _))
                )
            } else {
                crate::httpcli::head_status_via(
                    &t.url,
                    crate::HEALTHCHECK_SOCKS5,
                    None,
                    PROBE_TIMEOUT,
                )
                .await
                .is_ok()
            }
        };
        tokio::time::timeout(PROBE_HARD_TIMEOUT, probe)
            .await
            .unwrap_or(false)
    })
}

struct Lock(String);

impl Lock {
    fn acquire(path: &str) -> Option<Self> {
        match Self::try_create(path) {
            Some(l) => Some(l),
            None => {
                if !Self::holder_alive(path) {
                    let _ = std::fs::remove_file(path);
                    return Self::try_create(path);
                }
                None
            }
        }
    }

    fn try_create(path: &str) -> Option<Self> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .ok()?;
        let _ = write!(f, "{}", std::process::id());
        Some(Self(path.to_string()))
    }

    fn holder_alive(path: &str) -> bool {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
            .unwrap_or(false)
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn merge_ips_dedups_and_counts() {
        let mut known = vec!["1.1.1.1".to_string()];
        let fresh: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2.2.2.2".parse().unwrap(),
            "2.2.2.2".parse().unwrap(),
        ];
        assert_eq!(merge_ips(&mut known, &fresh), 1, "only new IPs count");
        assert_eq!(known, vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(merge_ips(&mut known, &fresh), 0, "second pass adds nothing");
    }

    #[test]
    fn state_to_resolution_drops_empty_entries() {
        let mut st = RetryState {
            dns_burn: true,
            ..Default::default()
        };
        st.burn.insert("a.com".into(), vec!["1.2.3.4".into()]);
        st.burn.insert("b.com".into(), vec![]);
        let mut domains = BTreeMap::new();
        domains.insert(
            "a.com".to_string(),
            DomainState {
                ips: vec!["5.6.7.8".into()],
                failed_specs: vec![],
            },
        );
        domains.insert("c.com".to_string(), DomainState::default());
        st.subs.push(SubState {
            name: "S".into(),
            ok: true,
            domains,
            ..Default::default()
        });

        let res = to_resolution(&st, &[], false);
        assert_eq!(res.burn.len(), 1, "empty burn entries are dropped");
        assert_eq!(res.subdns["S"].len(), 1, "empty domains are dropped");
        assert_eq!(
            res.subdns["S"]["a.com"],
            vec!["5.6.7.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn waiting_for_readiness_gives_up_at_the_deadline() {
        let started = Instant::now();
        let probes = AtomicUsize::new(0);
        let ok = wait_ready_until(
            started + Duration::from_millis(300),
            Duration::from_millis(50),
            || true,
            || {
                probes.fetch_add(1, Ordering::Relaxed);
                false
            },
        );
        assert!(!ok, "must give up, not report ready");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "gave up late: {:?}",
            started.elapsed()
        );
        assert!(
            probes.load(Ordering::Relaxed) >= 2,
            "should have retried a few times before giving up, got {}",
            probes.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn without_socks5_it_never_probes_health_and_still_expires() {
        let probes = AtomicUsize::new(0);
        let ok = wait_ready_until(
            Instant::now() + Duration::from_millis(200),
            Duration::from_millis(50),
            || false,
            || {
                probes.fetch_add(1, Ordering::Relaxed);
                true
            },
        );
        assert!(!ok);
        assert_eq!(
            probes.load(Ordering::Relaxed),
            0,
            "health must not be probed while the proxy is not even listening"
        );
    }

    #[test]
    fn milestones_are_appended_to_the_on_disk_log() {

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retry.log");
        let path = path.to_str().unwrap();

        record_to(path, "retry: nothing new resolved, config left untouched");
        record_to(path, "retry: clash never became ready, giving up");

        let text = std::fs::read_to_string(path).expect("log written");
        assert!(
            text.contains("nothing new resolved") && text.contains("never became ready"),
            "both milestones must be on disk: {text}"
        );
        assert!(
            text.lines()
                .all(|l| l.len() > 9 && l.as_bytes()[2] == b':' && l.as_bytes()[5] == b':'),
            "each line starts with a HH:MM:SS stamp: {text}"
        );
    }

    #[test]
    fn health_target_falls_back_to_github_without_global_monitor() {
        let none = HealthTarget::from_config(&serde_json::json!({}));
        assert!(!none.monitor);
        assert_eq!(none.url, DEFAULT_READY_URL);

        let off = HealthTarget::from_config(&serde_json::json!({
            "global_monitor": {"enable": false, "url": "http://ignored"}
        }));
        assert!(!off.monitor, "disabled monitor must not be used");
        assert_eq!(off.url, DEFAULT_READY_URL);

        let on = HealthTarget::from_config(&serde_json::json!({
            "global_monitor": {"enable": true, "url": "http://x/204", "expected_status": "204"}
        }));
        assert!(on.monitor);
        assert_eq!(on.url, "http://x/204");
        assert_eq!(on.expected, "204");

        let bare = HealthTarget::from_config(&serde_json::json!({
            "global_monitor": {"enable": true}
        }));
        assert_eq!(bare.url, DEFAULT_MONITOR_URL);
        assert_eq!(bare.expected, "0");
    }

    #[test]
    fn subinfo_follows_a_gap_filled_sub() {
        use super::super::{UserInfo, subinfo};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("subinfo.json");
        let p = p.to_str().unwrap();
        let kept = subinfo::Entry {
            name: "A".into(),
            info: Some(UserInfo {
                total: 10,
                ..Default::default()
            }),
            at: 123,
        };
        let missed = subinfo::Entry {
            name: "B".into(),
            info: None,
            at: 0,
        };
        subinfo::save(p, &[kept.clone(), missed]).unwrap();

        let fresh_info = UserInfo {
            total: 50,
            download: 5,
            expire: 1_700_000_000,
            ..Default::default()
        };
        let st = RetryState {
            subs: vec![
                SubState {
                    name: "A".into(),
                    ok: true,
                    userinfo: Some(UserInfo {
                        total: 999,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                SubState {
                    name: "B".into(),
                    ok: true,
                    userinfo: Some(fresh_info.clone()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        refresh_subinfo(p, &st, &["B".to_string()]);

        let back = subinfo::load(p);
        assert_eq!(back.len(), 2);
        assert_eq!(
            back[0], kept,
            "subs that were not re-downloaded stay as they were"
        );
        assert_eq!(back[1].name, "B", "order is kept");
        assert_eq!(back[1].info, Some(fresh_info));
        assert!(back[1].at > 0, "a freshly fetched sub gets a timestamp");
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("retry.lock");
        let p = p.to_str().unwrap();
        let first = Lock::acquire(p).expect("first acquire");
        assert!(Lock::acquire(p).is_none(), "second acquire must fail");
        drop(first);
        assert!(Lock::acquire(p).is_some(), "lock is released on drop");
    }

    #[test]
    fn stale_lock_from_a_dead_holder_is_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("retry.lock");
        let p = p.to_str().unwrap();

        std::fs::write(p, "0").unwrap();
        assert!(
            Lock::acquire(p).is_some(),
            "dead holder's lock is reclaimed"
        );

        std::fs::write(p, format!("{}", std::process::id())).unwrap();
        assert!(Lock::acquire(p).is_none(), "live holder's lock is honored");
    }

    #[test]
    fn only_unanswered_dns_servers_are_re_asked() {
        let all = vec![
            "https://doh.a/dns-query".to_string(),
            "223.5.5.5".to_string(),
        ];
        let mut domains = BTreeMap::new();
        domains.insert(
            "seen.com".to_string(),
            DomainState {
                ips: vec!["1.2.3.4".into()],
                failed_specs: vec!["https://doh.a/dns-query".into()],
            },
        );
        domains.insert(
            "clean.com".to_string(),
            DomainState {
                ips: vec!["1.2.3.4".into()],
                failed_specs: vec![],
            },
        );
        let sub = SubState {
            name: "S".into(),
            ok: true,
            domains,
            ..Default::default()
        };

        assert_eq!(
            specs_to_retry(&sub, "seen.com", &all, false),
            vec!["https://doh.a/dns-query"]
        );

        assert!(specs_to_retry(&sub, "clean.com", &all, false).is_empty());

        assert_eq!(specs_to_retry(&sub, "unknown.com", &all, false), all);

        assert_eq!(specs_to_retry(&sub, "clean.com", &all, true), all);
    }

    fn cached_sub(name: &str, yaml: &str) -> SubResult {
        let (proxies, hosts) = super::super::sub::parse_payload(yaml, name);
        SubResult {
            name: name.into(),
            success: true,
            proxies,
            hosts,
            userinfo: None,
            raw_yaml: yaml.into(),
            error: String::new(),
        }
    }

    #[test]
    fn burn_retry_includes_alias_targets() {
        let r = cached_sub(
            "S",
            "hosts:\n  hk.example.com: entry.example.net\nproxies:\n  - {name: HK, server: hk.example.com}\n",
        );
        let subs = std::slice::from_ref(&r);
        let mut st = RetryState {
            dns_burn: true,
            ..Default::default()
        };
        st.burn
            .insert("hk.example.com".into(), vec!["11.0.0.1".into()]);
        assert_eq!(
            burn_todo(&st, subs),
            vec!["entry.example.net"],
            "never recorded → re-ask"
        );
        st.burn.insert("entry.example.net".into(), vec![]);
        assert_eq!(
            burn_todo(&st, subs),
            vec!["entry.example.net"],
            "came back empty → re-ask"
        );
        st.burn
            .insert("entry.example.net".into(), vec!["11.0.0.3".into()]);
        assert!(burn_todo(&st, subs).is_empty());
    }

    #[test]
    fn gap_fill_rebuild_keeps_hosts_nodes() {
        let r = cached_sub(
            "S",
            "hosts:\n  hk.example.com: entry.example.net\n  jp.example.com: 12.0.0.7\nproxies:\n  - {name: HK, server: hk.example.com, type: ss}\n  - {name: JP, server: jp.example.com, type: ss}\n",
        );
        let mut st = RetryState {
            dns_burn: true,
            ..Default::default()
        };
        st.burn
            .insert("hk.example.com".into(), vec!["11.0.0.1".into()]);
        st.burn
            .insert("entry.example.net".into(), vec!["11.0.0.3".into()]);
        let mut domains = BTreeMap::new();
        domains.insert(
            "entry.example.net".to_string(),
            DomainState {
                ips: vec!["11.0.1.3".into()],
                failed_specs: vec![],
            },
        );
        st.subs.push(SubState {
            name: "S".into(),
            ok: true,
            domains,
            ..Default::default()
        });
        let subs = [r];
        let res = to_resolution(&st, &subs, false);
        let names: Vec<String> = super::super::proxies::build_proxies(&subs, &res, true)
            .iter()
            .filter_map(|p| p["name"].as_str().map(String::from))
            .collect();
        assert_eq!(
            names,
            vec![
                "S_HK@subdns3",
                "S_JP@hosts7",
                "S_HK",
                "S_HK@1",
                "S_HK@3",
                "S_JP"
            ]
        );
    }
}
