// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::web_proxies::{RawNode, RawProviders, RawProxies};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

pub use sb_ppgw::ppsub::SMART_HIDE_NODE;

const HIST_CAP: usize = 8;

const REGULAR_TIMEOUT_MS: u64 = 5000;

const LADDER_MS: [u64; 10] = [500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000];

const MAX_CONCURRENT: usize = 16;

const CYCLE_GAP: Duration = Duration::from_secs(30);

const CYCLE_GAP_MAX: Duration = Duration::from_secs(300);

const ANCHOR_CHECK: Duration = Duration::from_secs(30);

#[cfg(not(test))]
const CONFIRM_DELAY: Duration = Duration::from_secs(5);
#[cfg(test)]
const CONFIRM_DELAY: Duration = Duration::from_millis(20);

#[cfg(not(test))]
const DRAIN_PROBE: Duration = Duration::from_secs(3);
#[cfg(test)]
const DRAIN_PROBE: Duration = Duration::from_millis(20);
#[cfg(not(test))]
const DRAIN_RECHECK: Duration = Duration::from_secs(12);
#[cfg(test)]
const DRAIN_RECHECK: Duration = Duration::from_millis(20);

const BACKOFF_AFTER: u32 = 3;

const BACKOFF_BASE: Duration = Duration::from_secs(120);
const BACKOFF_MAX: Duration = Duration::from_secs(16 * 60);

const SUPERVISOR_TICK: Duration = Duration::from_secs(30);

const ERR_BACKOFF: Duration = Duration::from_secs(15);

const WAIT_CLASH: Duration = Duration::from_secs(5);

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(15);

const SELECT_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_RESP_BYTES: u64 = 64 * 1024 * 1024;

const JITTER_WEIGHT: f64 = 1.5;
const LOSS_PENALTY_MS: f64 = 2000.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartGroup {
    pub name: String,

    pub url: String,
}

#[derive(Debug, Default, Clone)]
pub struct NodeHist {
    samples: VecDeque<Option<u32>>,
}

impl NodeHist {
    pub fn push(&mut self, sample: Option<u32>) {
        if self.samples.len() == HIST_CAP {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn score(&self) -> f64 {
        let total = self.samples.len();
        if total == 0 {
            return f64::INFINITY;
        }
        let ok: Vec<f64> = self.samples.iter().flatten().map(|&d| d as f64).collect();
        if ok.is_empty() {
            return f64::INFINITY;
        }
        let mean = ok.iter().sum::<f64>() / ok.len() as f64;
        let var = ok.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / ok.len() as f64;
        let loss = (total - ok.len()) as f64 / total as f64;
        mean + JITTER_WEIGHT * var.sqrt() + LOSS_PENALTY_MS * loss
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn last(&self) -> Option<Option<u32>> {
        self.samples.back().copied()
    }

    fn mean_ok(&self) -> Option<f64> {
        let ok: Vec<f64> = self.samples.iter().flatten().map(|&d| d as f64).collect();
        (!ok.is_empty()).then(|| ok.iter().sum::<f64>() / ok.len() as f64)
    }

    fn has_failures(&self) -> bool {
        self.samples.iter().any(Option::is_none)
    }
}

#[derive(Default)]
pub struct SmartStats(Mutex<HashMap<String, Value>>);

impl SmartStats {

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Value>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn group_scores(&self, group: &str) -> Option<Value> {
        self.lock().get(group).cloned()
    }

    fn publish(&self, group: &str, hist: &HashMap<String, NodeHist>) {
        let obj: serde_json::Map<String, Value> = hist
            .iter()
            .map(|(name, h)| (name.clone(), node_json(h)))
            .collect();
        self.lock().insert(group.to_string(), Value::Object(obj));
    }

    fn publish_node(&self, group: &str, name: &str, h: &NodeHist) {
        let v = node_json(h);
        let mut g = self.lock();
        match g.get_mut(group) {
            Some(Value::Object(obj)) => {
                obj.insert(name.to_string(), v);
            }
            _ => {
                let mut obj = serde_json::Map::new();
                obj.insert(name.to_string(), v);
                g.insert(group.to_string(), Value::Object(obj));
            }
        }
    }

    fn retain_groups(&self, keep: &[SmartGroup]) {
        let keep: std::collections::HashSet<&str> = keep.iter().map(|g| g.name.as_str()).collect();
        self.lock().retain(|k, _| keep.contains(k.as_str()));
    }
}

fn node_json(h: &NodeHist) -> Value {
    let score = h.score();
    let samples: Vec<Value> = h
        .samples
        .iter()
        .map(|s| s.map(Value::from).unwrap_or(Value::Null))
        .collect();
    serde_json::json!({
        "score": if score.is_finite() { Value::from(score.round() as u64) } else { Value::Null },
        "samples": samples,
    })
}

macro_rules! st_log {
    ($($arg:tt)*) => {
        tracing::debug!("[PaoPaoGW Smart Test] {}", format!($($arg)*))
    };
}

macro_rules! st_info {
    ($($arg:tt)*) => {
        tracing::info!("[PaoPaoGW Smart Test] {}", format!($($arg)*))
    };
}

fn backoff_delay(streak: u32) -> Option<Duration> {
    let shift = streak.checked_sub(BACKOFF_AFTER)?.min(16);
    Some(BACKOFF_BASE.saturating_mul(1 << shift).min(BACKOFF_MAX))
}

fn next_gap(gap: Duration, settled: bool) -> Duration {
    if settled {
        gap.saturating_mul(2).min(CYCLE_GAP_MAX)
    } else {
        CYCLE_GAP
    }
}

fn via_node(c: &crate::clash_pull::ClashConn, group: &str, old: &str) -> bool {
    c.chains.first().is_some_and(|n| n == old)
        && c.chains.iter().any(|g| g == group)
        && c.inbound_type != "Inner"
}

fn stalled_on(
    group: &str,
    old: &str,
    before: &[crate::clash_pull::ClashConn],
    after: &[crate::clash_pull::ClashConn],
) -> (Vec<String>, Vec<String>) {
    let prev: HashMap<&str, (u64, u64)> = before
        .iter()
        .filter(|c| via_node(c, group, old))
        .map(|c| (c.id.as_str(), (c.upload, c.download)))
        .collect();
    let (mut stalled, mut moving) = (Vec::new(), Vec::new());
    for c in after.iter().filter(|c| via_node(c, group, old)) {
        match prev.get(c.id.as_str()) {
            Some(&bytes) if bytes == (c.upload, c.download) => stalled.push(c.id.clone()),
            Some(_) => moving.push(c.id.clone()),
            None => {}
        }
    }
    (stalled, moving)
}

#[derive(Debug, Clone, Copy)]
struct Backoff {
    streak: u32,
    until: Option<tokio::time::Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PassOutcome {
    settled: bool,
}

#[derive(Default)]
struct GroupState {
    hist: HashMap<String, NodeHist>,
    backoff: HashMap<String, Backoff>,

    anchor: Option<Member>,
}

impl GroupState {

    fn observe(
        &mut self,
        node: &str,
        sample: Option<u32>,
        now: tokio::time::Instant,
    ) -> Option<Duration> {
        self.push(node, sample);
        if sample.is_some() {
            self.backoff.remove(node);
            return None;
        }
        let b = self.backoff.entry(node.to_string()).or_insert(Backoff {
            streak: 0,
            until: None,
        });
        b.streak += 1;
        let d = backoff_delay(b.streak);
        b.until = d.map(|d| now + d);
        d
    }

    fn confirmed_down(&self, node: &str) -> bool {
        !self.latest_ok(node) && self.backoff.get(node).is_some_and(|b| b.streak >= 2)
    }

    fn in_backoff(&self, node: &str, now: tokio::time::Instant) -> bool {
        self.backoff
            .get(node)
            .and_then(|b| b.until)
            .is_some_and(|until| now < until)
    }

    fn score(&self, node: &str) -> f64 {
        self.hist
            .get(node)
            .map(NodeHist::score)
            .unwrap_or(f64::INFINITY)
    }

    fn push(&mut self, node: &str, sample: Option<u32>) {
        self.hist.entry(node.to_string()).or_default().push(sample);
    }

    fn latest_ok(&self, node: &str) -> bool {
        self.hist
            .get(node)
            .and_then(NodeHist::last)
            .is_some_and(|s| s.is_some())
    }
}

pub fn parse_smart_groups(json: &str) -> Vec<SmartGroup> {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.get("node-groups").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter(|g| g.get("smart").and_then(|s| s.as_bool()).unwrap_or(false))
        .filter_map(|g| {
            let name = g.get("name")?.as_str()?.trim();
            (!name.is_empty()).then(|| SmartGroup {
                name: name.to_string(),
                url: g
                    .get("speedtest_url")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,

    pub provider: Option<String>,
}

pub(crate) fn eligible_members(
    proxies: &RawProxies,
    providers: Option<&RawProviders>,
    group: &str,
) -> Option<(Vec<Member>, String)> {
    let g = proxies.proxies.get(group)?;
    let now = g.now.clone().unwrap_or_default();
    let all = g.all.as_ref()?;

    let mut prov_idx: HashMap<&str, (&str, &str)> = HashMap::new();
    if let Some(pv) = providers {
        for (pname, p) in &pv.providers {
            for node in &p.proxies {
                if let Some(n) = node.name.as_deref() {
                    prov_idx
                        .entry(n)
                        .or_insert((pname.as_str(), node.typ.as_deref().unwrap_or("")));
                }
            }
        }
    }
    let mut out = Vec::new();
    for m in all {

        if m == SMART_HIDE_NODE || m.contains("@@") {
            continue;
        }
        let (typ, provider) = match proxies.proxies.get(m) {
            Some(p) => (p.typ.as_deref().unwrap_or(""), None),
            None => match prov_idx.get(m.as_str()) {
                Some(&(pname, t)) => (t, Some(pname.to_string())),
                None => continue,
            },
        };
        if matches!(typ, "Reject" | "RejectDrop" | "Pass") {
            continue;
        }
        out.push(Member {
            name: m.clone(),
            provider,
        });
    }
    Some((out, now))
}

pub(crate) fn needs_providers(proxies: &RawProxies, group: &str) -> bool {
    let Some(all) = proxies.proxies.get(group).and_then(|g| g.all.as_ref()) else {
        return false;
    };
    all.iter()
        .any(|m| m != SMART_HIDE_NODE && !proxies.proxies.contains_key(m))
}

type SharedStates = Arc<Mutex<HashMap<String, GroupState>>>;

fn lock_states(states: &SharedStates) -> std::sync::MutexGuard<'_, HashMap<String, GroupState>> {
    states.lock().unwrap_or_else(|e| e.into_inner())
}

struct Runner {
    names: Vec<String>,
    cancel: watch::Sender<bool>,
}

pub fn spawn(
    clash_sock: PathBuf,
    stats: Arc<SmartStats>,
    fixed: Arc<crate::smart_fixed::SmartFixed>,
    shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(supervise(clash_sock, stats, fixed, shutdown));
}

async fn supervise(
    sock: PathBuf,
    stats: Arc<SmartStats>,
    fixed: Arc<crate::smart_fixed::SmartFixed>,
    mut shutdown: watch::Receiver<bool>,
) {
    let states: SharedStates = Arc::new(Mutex::new(HashMap::new()));
    let mut runners: HashMap<String, Runner> = HashMap::new();
    let mut last_names: Vec<String> = Vec::new();
    st_log!("scheduler started (sock={})", sock.display());
    loop {
        let groups = if crate::runtime::ppsub_active() {
            std::fs::read_to_string(crate::geo_cron::PPSUB_JSON)
                .map(|j| parse_smart_groups(&j))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        {
            let live: std::collections::HashSet<&str> =
                groups.iter().map(|g| g.name.as_str()).collect();
            lock_states(&states).retain(|k, _| live.contains(k.as_str()));
        }
        stats.retain_groups(&groups);
        let names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();

        fixed.retain_groups(&names);
        if names != last_names {
            if names.is_empty() {
                st_log!("no smart group configured (ppsub.json), idle");
            } else {
                st_log!(
                    "managing {} smart group(s): {}",
                    names.len(),
                    names.join(", ")
                );
            }
            last_names = names;
        }
        let default_url = crate::web_proxies::read_test_url(Path::new("/tmp/ppgw.ini"));
        let buckets = bucket_by_url(&groups, &default_url);

        runners.retain(|url, r| {
            let keep = buckets.get(url).map(|gs| group_names(gs)) == Some(r.names.clone());
            if !keep {
                let _ = r.cancel.send(true);
                st_log!("runner for `{url}` stopped (config changed)");
            }
            keep
        });

        for (url, gs) in &buckets {
            if runners.contains_key(url) {
                continue;
            }
            let (ctx, crx) = watch::channel(false);
            st_log!(
                "runner for `{url}` started, covering: {}",
                group_names(gs).join(", ")
            );
            tokio::spawn(runner(
                sock.clone(),
                url.clone(),
                gs.clone(),
                Arc::clone(&states),
                Arc::clone(&stats),
                Arc::clone(&fixed),
                crx,
            ));
            runners.insert(
                url.clone(),
                Runner {
                    names: group_names(gs),
                    cancel: ctx,
                },
            );
        }
        if sleep_or_shutdown(SUPERVISOR_TICK, &mut shutdown).await {
            for r in runners.values() {
                let _ = r.cancel.send(true);
            }
            break;
        }
    }
    st_log!("scheduler exited");
}

fn bucket_by_url(
    groups: &[SmartGroup],
    default_url: &str,
) -> std::collections::BTreeMap<String, Vec<SmartGroup>> {
    let mut buckets: std::collections::BTreeMap<String, Vec<SmartGroup>> = Default::default();
    let mut seen = std::collections::HashSet::new();
    for g in groups {
        if !seen.insert(g.name.clone()) {
            continue;
        }
        let url = if g.url.is_empty() {
            default_url.to_string()
        } else {
            g.url.clone()
        };
        buckets.entry(url).or_default().push(g.clone());
    }
    buckets
}

fn group_names(gs: &[SmartGroup]) -> Vec<String> {
    gs.iter().map(|g| g.name.clone()).collect()
}

async fn runner(
    sock: PathBuf,
    url: String,
    groups: Vec<SmartGroup>,
    states: SharedStates,
    stats: Arc<SmartStats>,
    fixed: Arc<crate::smart_fixed::SmartFixed>,
    mut cancel: watch::Receiver<bool>,
) {
    let mut gap = CYCLE_GAP;
    loop {

        if !sock.exists() {
            st_log!("clash api {} not up yet, idle", sock.display());
            if sleep_or_shutdown(WAIT_CLASH, &mut cancel).await {
                return;
            }
            continue;
        }
        let mut any_err = false;
        let mut settled = true;
        for g in &groups {
            if *cancel.borrow() {
                return;
            }
            let mut st = lock_states(&states).remove(&g.name).unwrap_or_default();
            let r = run_group_pass(&sock, &g.name, &url, &mut st, &stats, &fixed, &cancel).await;
            lock_states(&states).insert(g.name.clone(), st);
            match r {
                Ok(o) => settled &= o.settled,
                Err(e) => {
                    tracing::warn!(
                        "[PaoPaoGW Smart Test] {}: clash api error ({e}), retry in {}s",
                        g.name,
                        ERR_BACKOFF.as_secs()
                    );
                    any_err = true;
                    break;
                }
            }
        }
        if any_err {
            gap = CYCLE_GAP;
            if sleep_or_shutdown(ERR_BACKOFF, &mut cancel).await {
                return;
            }
            continue;
        }
        let prev = gap;
        gap = next_gap(gap, settled);
        if gap != prev {
            st_log!(
                "`{url}`: next full sweep in {}s, current node(s) checked every {}s meanwhile",
                gap.as_secs(),
                ANCHOR_CHECK.as_secs()
            );
        }
        let deadline = tokio::time::Instant::now() + gap;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            if sleep_or_shutdown(left.min(ANCHOR_CHECK), &mut cancel).await {
                return;
            }
            if tokio::time::Instant::now() >= deadline || *cancel.borrow() {
                break;
            }
            if check_anchors(&sock, &url, &groups, &states, &stats, &fixed).await {
                gap = CYCLE_GAP;
                break;
            }
        }
    }
}

async fn sleep_or_shutdown(d: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn observe_and_publish(
    group: &str,
    st: &mut GroupState,
    stats: &SmartStats,
    name: &str,
    d: Option<u32>,
) {
    let backoff = st.observe(name, d, tokio::time::Instant::now());
    log_result(group, name, d, st.score(name));
    if let Some(b) = backoff {
        st_log!(
            "{group}: {name} failed {} times in a row, retest in {}s",
            st.backoff.get(name).map_or(0, |b| b.streak),
            b.as_secs()
        );
    }
    if let Some(h) = st.hist.get(name) {
        stats.publish_node(group, name, h);
    }
}

async fn run_group_pass(
    sock: &Path,
    group: &str,
    url: &str,
    st: &mut GroupState,
    stats: &SmartStats,
    fixed: &crate::smart_fixed::SmartFixed,
    shutdown: &watch::Receiver<bool>,
) -> std::io::Result<PassOutcome> {
    let unsettled = PassOutcome { settled: false };
    let px: RawProxies = fetch_typed(sock, "/proxies").await?;
    let providers: Option<RawProviders> = if needs_providers(&px, group) {
        Some(fetch_typed(sock, "/providers/proxies").await?)
    } else {
        None
    };
    let Some((members, now)) = eligible_members(&px, providers.as_ref(), group) else {

        st_log!("{group}: group not present in clash yet, skip this cycle");
        return Ok(unsettled);
    };
    if members.is_empty() {
        st_log!("{group}: no testable member, skip this cycle");
        return Ok(unsettled);
    }

    let live: std::collections::HashSet<&str> = members.iter().map(|m| m.name.as_str()).collect();
    st.hist.retain(|k, _| live.contains(k.as_str()));
    st.backoff.retain(|k, _| live.contains(k.as_str()));

    let mut locked = fixed.get(group);
    if let Some(l) = &locked
        && !members.iter().any(|m| &m.name == l)
    {
        fixed.clear(group);
        st_info!("{group}: locked node `{l}` is gone from the group, lock released");
        locked = None;
    }

    let seeded = seed_from_clash(st, &members, &px, providers.as_ref(), url);
    if seeded > 0 {
        st_log!("{group}: seeded history for {seeded} node(s) from clash delay data");
    }

    stats.publish(group, &st.hist);

    let no_data: Vec<&Member> = members
        .iter()
        .filter(|m| st.hist.get(&m.name).is_none_or(NodeHist::is_empty))
        .collect();

    if no_data.len() == members.len() {
        let r = ladder_pass(sock, group, url, st, &members, &now, locked.as_deref()).await;
        stats.publish(group, &st.hist);
        return r.map(|()| unsettled);
    }

    if !no_data.is_empty() {
        st_log!(
            "{group}: testing {} node(s) without history (concurrent, {}ms timeout)",
            no_data.len(),
            REGULAR_TIMEOUT_MS
        );
        for (m, d) in test_many(sock, &no_data, url, REGULAR_TIMEOUT_MS).await {
            observe_and_publish(group, st, stats, &m.name, d);
        }
        stats.publish(group, &st.hist);
    }
    let mut switched = false;

    let mut current = now.clone();
    if !members.iter().any(|m| m.name == current) {
        let pick = locked.clone().or_else(|| {
            members
                .iter()
                .min_by(|a, b| st.score(&a.name).total_cmp(&st.score(&b.name)))
                .map(|m| m.name.clone())
        });
        if let Some(pick) = pick
            && select_node(sock, group, &pick).await?
        {
            st_info!(
                "{group}: current selection `{current}` invalid (clash reloaded?), reselected `{pick}`"
            );
            current = pick;
            switched = true;
        }
    }

    let anchor = locked.clone().unwrap_or_else(|| current.clone());
    st_log!(
        "{group}: sequential sweep over {} node(s), current `{current}`{}",
        members.len(),
        locked
            .as_deref()
            .map(|l| format!(", user-locked to `{l}`"))
            .unwrap_or_default()
    );
    if let Some(cur) = members.iter().find(|m| m.name == anchor) {
        let mut d = test_member(sock, cur, url, REGULAR_TIMEOUT_MS).await;

        if d.is_none() && !st.backoff.contains_key(&cur.name) {
            st_log!(
                "{group}: current node `{}` failed, retest in {}s to confirm",
                cur.name,
                CONFIRM_DELAY.as_secs()
            );
            if sleep_or_shutdown(CONFIRM_DELAY, &mut shutdown.clone()).await {
                return Ok(unsettled);
            }
            d = test_member(sock, cur, url, REGULAR_TIMEOUT_MS).await;
            if d.is_some() {
                st_log!(
                    "{group}: `{}` answered the retest, transient failure ignored",
                    cur.name
                );
            } else {
                observe_and_publish(group, st, stats, &cur.name, None);
            }
        }
        observe_and_publish(group, st, stats, &cur.name, d);
    }
    let anchor_ok = st.latest_ok(&anchor);

    if let Some(l) = locked.clone()
        && !st.latest_ok(&l)
    {
        fixed.clear(group);
        st_info!("{group}: locked node `{l}` is down, lock released, back to auto");
        locked = None;
    }

    if let Some(l) = locked.clone()
        && current != l
        && select_node(sock, group, &l).await?
    {
        st_info!("{group}: hold on user-locked `{l}` (was `{current}`)");
        current = l;
        switched = true;
    }
    let mut rest: Vec<&Member> = members.iter().filter(|m| m.name != anchor).collect();
    rest.sort_by(|a, b| st.score(&a.name).total_cmp(&st.score(&b.name)));
    let clock = tokio::time::Instant::now();
    let mut skipped = 0usize;
    for m in rest {
        if *shutdown.borrow() {
            break;
        }

        if st.in_backoff(&m.name, clock) {
            skipped += 1;
            continue;
        }
        let d = test_member(sock, m, url, REGULAR_TIMEOUT_MS).await;
        observe_and_publish(group, st, stats, &m.name, d);

        if locked.is_some() {
            continue;
        }

        let cur_down = st.confirmed_down(&current);
        let cand = st.score(&m.name);
        let cur = if cur_down {
            f64::INFINITY
        } else {
            st.score(&current)
        };

        if st.latest_ok(&m.name) && cand < cur && select_node(sock, group, &m.name).await? {
            if cur_down {
                st_info!(
                    "{group}: switch `{current}` -> `{}` (current node failed twice in a row)",
                    m.name
                );

                spawn_drain(sock.to_path_buf(), group.to_string(), current.clone());
            } else {
                st_info!(
                    "{group}: switch `{current}` -> `{}` (score {} < {})",
                    m.name,
                    cand.round() as u64,
                    cur.round() as u64
                );
            }
            current = m.name.clone();
            switched = true;
        }
    }
    st_log!(
        "{group}: sweep done, selected `{current}` (score {}){}{}",
        fmt_score(st.score(&current)),
        if locked.is_some() { " [locked]" } else { "" },
        if skipped > 0 {
            format!(", {skipped} node(s) in backoff skipped")
        } else {
            String::new()
        }
    );

    let cur_score = st.score(&current);
    let recovering = members.iter().any(|m| {
        m.name != current
            && st.latest_ok(&m.name)
            && st.hist.get(&m.name).is_some_and(|h| {
                h.has_failures() && h.mean_ok().is_some_and(|mean| mean < cur_score)
            })
    });
    let keep = locked.unwrap_or(current);
    st.anchor = members.iter().find(|m| m.name == keep).cloned();
    Ok(PassOutcome {
        settled: !switched && anchor_ok && !recovering,
    })
}

async fn check_anchors(
    sock: &Path,
    url: &str,
    groups: &[SmartGroup],
    states: &SharedStates,
    stats: &SmartStats,
    fixed: &crate::smart_fixed::SmartFixed,
) -> bool {
    let mut failed = false;
    for g in groups {
        let mut st = lock_states(states).remove(&g.name).unwrap_or_default();

        let target = match (fixed.get(&g.name), st.anchor.clone()) {
            (Some(l), Some(a)) if a.name != l => None,
            (_, a) => a,
        };
        if let Some(m) = target {

            match test_member(sock, &m, url, REGULAR_TIMEOUT_MS).await {
                Some(d) => observe_and_publish(&g.name, &mut st, stats, &m.name, Some(d)),
                None => {
                    st_info!(
                        "{}: current node `{}` failed its check, full sweep now",
                        g.name,
                        m.name
                    );
                    failed = true;
                }
            }
        }
        lock_states(states).insert(g.name.clone(), st);
        if failed {
            break;
        }
    }
    failed
}

fn log_result(group: &str, name: &str, delay: Option<u32>, score: f64) {
    match delay {
        Some(d) => st_log!("{group}: {name} -> {d}ms (score {})", fmt_score(score)),
        None => st_log!("{group}: {name} -> timeout (score {})", fmt_score(score)),
    }
}

fn fmt_score(s: f64) -> String {
    if s.is_finite() {
        format!("{}", s.round() as u64)
    } else {
        "∞".to_string()
    }
}

fn seed_from_clash(
    st: &mut GroupState,
    members: &[Member],
    px: &RawProxies,
    providers: Option<&RawProviders>,
    url: &str,
) -> usize {
    let mut seeded = 0;
    for m in members {
        if st.hist.get(&m.name).is_some_and(|h| !h.is_empty()) {
            continue;
        }

        let node: Option<&RawNode> = match px.proxies.get(&m.name) {
            Some(n) => Some(n),
            None => m.provider.as_ref().and_then(|pname| {
                providers?
                    .providers
                    .get(pname)?
                    .proxies
                    .iter()
                    .find(|n| n.name.as_deref() == Some(&m.name))
            }),
        };
        let Some(node) = node else { continue };
        let hist = node
            .extra
            .get(url)
            .map(|b| &b.history)
            .filter(|h| !h.is_empty())
            .or(Some(&node.history).filter(|h| !h.is_empty()));
        let Some(hist) = hist else { continue };
        let mut any = false;
        for e in hist.iter().rev().take(HIST_CAP).rev() {
            if let Some(d) = e.delay {
                st.push(&m.name, if d == 0 { None } else { Some(d as u32) });
                any = true;
            }
        }
        if any {
            seeded += 1;
        }
    }
    seeded
}

fn pick_ladder_best<'a>(
    results: &'a [(Member, Option<u32>)],
    locked: Option<&str>,
) -> Option<(&'a Member, u32)> {
    if let Some(l) = locked
        && let Some((m, Some(d))) = results.iter().find(|(m, d)| m.name == l && d.is_some())
    {
        return Some((m, *d));
    }
    results
        .iter()
        .filter_map(|(m, d)| d.map(|d| (m, d)))
        .min_by_key(|&(_, d)| d)
}

async fn ladder_pass(
    sock: &Path,
    group: &str,
    url: &str,
    st: &mut GroupState,
    members: &[Member],
    now: &str,
    locked: Option<&str>,
) -> std::io::Result<()> {
    let refs: Vec<&Member> = members.iter().collect();
    st_log!(
        "{group}: no history at all, laddered concurrent probe over {} node(s)",
        refs.len()
    );
    for t in LADDER_MS {
        let results = test_many(sock, &refs, url, t).await;
        let mut ok = 0;
        for (m, d) in &results {
            if let Some(d) = d {
                ok += 1;
                st.push(&m.name, Some(*d));
            }
        }
        let best = pick_ladder_best(&results, locked);
        st_log!("{group}: ladder timeout={t}ms -> {ok}/{} ok", refs.len());
        if let Some((m, d)) = best {

            if m.name == now || select_node(sock, group, &m.name).await? {
                st_info!("{group}: initial pick `{}` ({d}ms, lowest delay)", m.name);
            }
            return Ok(());
        }
    }
    tracing::warn!("[PaoPaoGW Smart Test] {group}: all nodes timed out at every ladder step");
    Ok(())
}

async fn test_many(
    sock: &Path,
    members: &[&Member],
    url: &str,
    timeout_ms: u64,
) -> Vec<(Member, Option<u32>)> {
    let mut out = Vec::with_capacity(members.len());
    for chunk in members.chunks(MAX_CONCURRENT) {
        let mut set = tokio::task::JoinSet::new();
        for m in chunk {
            let (sock, m, url) = (sock.to_path_buf(), (*m).clone(), url.to_string());
            set.spawn(async move {
                let d = test_member(&sock, &m, &url, timeout_ms).await;
                (m, d)
            });
        }
        while let Some(r) = set.join_next().await {
            if let Ok(v) = r {
                out.push(v);
            }
        }
    }
    out
}

async fn test_member(sock: &Path, m: &Member, url: &str, timeout_ms: u64) -> Option<u32> {
    let enc = crate::web_proxies::pct_encode_segment(&m.name);
    let query = format!(
        "?timeout={timeout_ms}&url={}",
        crate::web_proxies::pct_encode_segment(url)
    );
    let path = match &m.provider {
        Some(p) => format!(
            "/providers/proxies/{}/{enc}/healthcheck{query}",
            crate::web_proxies::pct_encode_segment(p)
        ),
        None => format!("/proxies/{enc}/delay{query}"),
    };

    let (status, body) = uds_request(
        sock,
        "GET",
        &path,
        None,
        Duration::from_millis(timeout_ms + 3000),
    )
    .await
    .ok()?;
    if status != 200 {
        return None;
    }
    serde_json::from_slice::<Value>(&body)
        .ok()?
        .get("delay")?
        .as_u64()
        .map(|d| d as u32)
}

async fn select_node(sock: &Path, group: &str, name: &str) -> std::io::Result<bool> {
    let path = format!("/proxies/{}", crate::web_proxies::pct_encode_segment(group));
    let body = serde_json::json!({ "name": name }).to_string();
    let (status, _) = uds_request(sock, "PUT", &path, Some(&body), SELECT_TIMEOUT).await?;
    if !(200..300).contains(&status) {
        tracing::warn!(
            group,
            name,
            status,
            "smart speedtest: select rejected by clash"
        );
        return Ok(false);
    }
    Ok(true)
}

async fn fetch_connections(sock: &Path) -> std::io::Result<Vec<crate::clash_pull::ClashConn>> {
    let (status, body) = uds_request(sock, "GET", "/connections", None, SNAPSHOT_TIMEOUT).await?;
    if status != 200 {
        return Err(std::io::Error::other(format!(
            "clash /connections -> {status}"
        )));
    }
    Ok(crate::clash_pull::parse_connections(
        &String::from_utf8_lossy(&body),
    ))
}

async fn close_connections(sock: &Path, ids: &[String]) -> usize {
    let mut n = 0;
    for id in ids {
        let path = format!(
            "/connections/{}",
            crate::web_proxies::pct_encode_segment(id)
        );
        if let Ok((status, _)) = uds_request(sock, "DELETE", &path, None, SELECT_TIMEOUT).await
            && (200..300).contains(&status)
        {
            n += 1;
        }
    }
    n
}

fn spawn_drain(sock: PathBuf, group: String, old: String) {
    tokio::spawn(async move {
        let Ok(first) = fetch_connections(&sock).await else {
            return;
        };
        if !first.iter().any(|c| via_node(c, &group, &old)) {
            return;
        }
        tokio::time::sleep(DRAIN_PROBE).await;
        let Ok(second) = fetch_connections(&sock).await else {
            return;
        };
        let (stalled, mut moving) = stalled_on(&group, &old, &first, &second);
        let mut closed = close_connections(&sock, &stalled).await;
        if !moving.is_empty() {
            tokio::time::sleep(DRAIN_RECHECK).await;
            if let Ok(third) = fetch_connections(&sock).await {
                let keep: std::collections::HashSet<&str> =
                    moving.iter().map(String::as_str).collect();
                let second: Vec<_> = second
                    .into_iter()
                    .filter(|c| keep.contains(c.id.as_str()))
                    .collect();
                let (later, still) = stalled_on(&group, &old, &second, &third);
                closed += close_connections(&sock, &later).await;
                moving = still;
            }
        }
        st_info!(
            "{group}: moved off `{old}`: closed {closed} stalled/idle connection(s), kept {} still moving data",
            moving.len()
        );
    });
}

async fn fetch_typed<T: serde::de::DeserializeOwned>(
    sock: &Path,
    path: &str,
) -> std::io::Result<T> {
    let (status, body) = uds_request(sock, "GET", path, None, SNAPSHOT_TIMEOUT).await?;
    if status != 200 {
        return Err(std::io::Error::other(format!("clash {path} -> {status}")));
    }
    serde_json::from_slice(&body).map_err(std::io::Error::other)
}

async fn uds_request(
    sock: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> std::io::Result<(u16, Vec<u8>)> {
    tokio::time::timeout(timeout, uds_request_inner(sock, method, path, body))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("clash {path} did not answer within {timeout:?}"),
            )
        })?
}

async fn uds_request_inner(
    sock: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> std::io::Result<(u16, Vec<u8>)> {
    let mut up = UnixStream::connect(sock).await?;
    let req = match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
            b.len()
        ),
        None => format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    };
    up.write_all(req.as_bytes()).await?;
    up.flush().await?;
    let mut buf = Vec::new();
    let hl = sb_web::http::read_head(&mut up, &mut buf).await?;
    let resp = sb_web::http::parse_response(&buf[..hl])?;
    let status = resp.status;
    let chunked = matches!(resp.framing(false), Ok(sb_web::http::Framing::Chunked));
    let mut data = buf.split_off(hl);
    let mut rest = Vec::new();
    tokio::io::AsyncReadExt::take(&mut up, MAX_RESP_BYTES)
        .read_to_end(&mut rest)
        .await?;
    data.extend_from_slice(&rest);
    if chunked {
        data = dechunk(&data);
    }
    Ok((status, data))
}

fn dechunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let Some(rel) = data[i..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let nl = i + rel;
        let hex = std::str::from_utf8(&data[i..nl]).unwrap_or("");
        let size =
            usize::from_str_radix(hex.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        i = nl + 2;
        if size == 0 || i + size > data.len() {
            break;
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rp(v: serde_json::Value) -> RawProxies {
        serde_json::from_value(v).unwrap()
    }
    fn rv(v: serde_json::Value) -> RawProviders {
        serde_json::from_value(v).unwrap()
    }
    fn hist(samples: &[Option<u32>]) -> NodeHist {
        let mut h = NodeHist::default();
        for s in samples {
            h.push(*s);
        }
        h
    }

    fn member(name: &str) -> Member {
        Member {
            name: name.to_string(),
            provider: None,
        }
    }

    #[test]
    fn latest_ok_looks_only_at_the_newest_sample() {
        let mut st = GroupState::default();

        st.hist.insert("A".into(), hist(&[None, None, Some(120)]));
        st.hist
            .insert("B".into(), hist(&[Some(80), Some(80), None]));
        assert!(st.latest_ok("A"), "recovered node counts as up");
        assert!(!st.latest_ok("B"), "latest failure counts as down");
        assert!(!st.latest_ok("never-tested"), "no sample is not up");
    }

    #[test]
    fn ladder_prefers_the_locked_node_over_the_fastest() {
        let results = vec![
            (member("A"), Some(300)),
            (member("B"), Some(50)),
            (member("C"), None),
        ];

        assert_eq!(pick_ladder_best(&results, None).unwrap().0.name, "B");

        assert_eq!(pick_ladder_best(&results, Some("A")).unwrap().0.name, "A");

        assert_eq!(pick_ladder_best(&results, Some("C")).unwrap().0.name, "B");

        assert_eq!(pick_ladder_best(&results, Some("Z")).unwrap().0.name, "B");

        let all_fail = vec![(member("A"), None)];
        assert!(pick_ladder_best(&all_fail, Some("A")).is_none());
    }

    #[test]
    fn score_prefers_stable_low_latency() {

        let stable = hist(&[Some(100), Some(100), Some(100), Some(100)]);
        let jittery = hist(&[Some(50), Some(300), Some(50), Some(300)]);
        assert!(stable.score() < jittery.score());

        let lossy = hist(&[Some(100), None, Some(100), None]);
        let slow_stable = hist(&[Some(200), Some(200), Some(200), Some(200)]);
        assert!(slow_stable.score() < lossy.score());

        assert_eq!(hist(&[None, None]).score(), f64::INFINITY);
        assert_eq!(NodeHist::default().score(), f64::INFINITY);
    }

    #[test]
    fn hist_caps_at_8_samples() {
        let mut h = NodeHist::default();
        for i in 0..20 {
            h.push(Some(i));
        }
        assert_eq!(h.samples.len(), HIST_CAP);
        assert_eq!(h.samples.front(), Some(&Some(12)), "old sample evicted");
    }

    #[test]
    fn parse_smart_groups_filters_and_trims() {
        let j = r#"{"node-groups":[
            {"name":"A","smart":true,"speedtest_url":" http://x "},
            {"name":"B","speedtest_url":"http://y","interval":300},
            {"name":"C","smart":true},
            {"name":"","smart":true},
            {"name":"D","smart":false}
        ]}"#;
        let g = parse_smart_groups(j);
        assert_eq!(
            g,
            vec![
                SmartGroup {
                    name: "A".into(),
                    url: "http://x".into()
                },
                SmartGroup {
                    name: "C".into(),
                    url: "".into()
                },
            ]
        );
        assert!(parse_smart_groups("not json").is_empty());
        assert!(parse_smart_groups("{}").is_empty());
    }

    #[test]
    fn eligible_members_skips_marker_and_reject_types() {
        let px = rp(json!({"proxies":{
            "Smart":{"type":"Selector","now":"N1","all":["N1","N2","DIRECT","REJECT",
                     "smartspeedtest@hide","Sub_Sub: 1.23G/2.00G@@2026-08-01"]},
            "N1":{"type":"Trojan"},
            "N2":{"type":"Vless"},
            "DIRECT":{"type":"Direct"},
            "REJECT":{"type":"Reject"},
            "smartspeedtest@hide":{"type":"Reject"},
            "Sub_Sub: 1.23G/2.00G@@2026-08-01":{"type":"Shadowsocks"}
        }}));
        let (m, now) = eligible_members(&px, None, "Smart").unwrap();
        let names: Vec<&str> = m.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["N1", "N2", "DIRECT"],
            "skip reject-type, tag nodes and traffic virtual nodes containing @@"
        );
        assert_eq!(now, "N1");
        assert!(m.iter().all(|m| m.provider.is_none()));

        assert!(eligible_members(&px, None, "Nope").is_none());
    }

    #[test]
    fn eligible_members_locates_provider_nodes() {

        let px = rp(json!({"proxies":{
            "Grp":{"type":"Selector","now":"P1","all":["P1","smartspeedtest@hide","Ghost"]}
        }}));
        let pv = rv(json!({"providers":{
            "Grp=(Pre🔗Grp)":{"proxies":[
                {"name":"P1","type":"Trojan"},
                {"name":"smartspeedtest@hide","type":"Reject"}
            ]}
        }}));
        assert!(needs_providers(&px, "Grp"));
        let (m, _) = eligible_members(&px, Some(&pv), "Grp").unwrap();
        assert_eq!(
            m.len(),
            1,
            "Ghost not found on either side → skip; tag nodes skipped"
        );
        assert_eq!(m[0].name, "P1");
        assert_eq!(m[0].provider.as_deref(), Some("Grp=(Pre🔗Grp)"));
    }

    #[test]
    fn needs_providers_false_when_all_toplevel() {
        let px = rp(json!({"proxies":{
            "Smart":{"all":["N1","smartspeedtest@hide"]},
            "N1":{"type":"Trojan"}
        }}));
        assert!(
            !needs_providers(&px, "Smart"),
            "tag nodes should not trigger provider pulls"
        );
        assert!(!needs_providers(&px, "Nope"));
    }

    #[test]
    fn bucket_groups_by_effective_url() {
        let gs = vec![
            SmartGroup {
                name: "A".into(),
                url: "http://x".into(),
            },
            SmartGroup {
                name: "B".into(),
                url: "".into(),
            },
            SmartGroup {
                name: "C".into(),
                url: "http://x".into(),
            },
            SmartGroup {
                name: "D".into(),
                url: "http://def".into(),
            },
            SmartGroup {
                name: "A".into(),
                url: "http://dup".into(),
            },
        ];
        let b = bucket_by_url(&gs, "http://def");
        assert_eq!(b.len(), 2, "{b:?}");

        assert_eq!(group_names(&b["http://x"]), vec!["A", "C"]);
        assert_eq!(group_names(&b["http://def"]), vec!["B", "D"]);
    }

    #[test]
    fn seed_from_clash_prefers_url_bucket_and_falls_back() {
        let px = rp(json!({"proxies":{

            "N1":{"type":"Trojan",
                  "history":[{"delay":999}],
                  "extra":{"http://t":{"history":[{"delay":100},{"delay":0},{"delay":120}]}}},

            "N2":{"type":"Vless","history":[{"delay":300}],
                  "extra":{"http://other":{"history":[{"delay":280}]}}},

            "N3":{"type":"Vless","history":[]}
        }}));
        let members = vec![
            Member {
                name: "N1".into(),
                provider: None,
            },
            Member {
                name: "N2".into(),
                provider: None,
            },
            Member {
                name: "N3".into(),
                provider: None,
            },
        ];
        let mut st = GroupState::default();
        let n = seed_from_clash(&mut st, &members, &px, None, "http://t");
        assert_eq!(n, 2);
        assert_eq!(
            st.hist["N1"].samples,
            vec![Some(100), None, Some(120)],
            "extra[url] bucket takes priority, delay=0 counted as failure"
        );
        assert_eq!(
            st.hist["N2"].samples,
            vec![Some(300)],
            "top-level history fallback"
        );
        assert!(!st.hist.contains_key("N3"));

        let n2 = seed_from_clash(&mut st, &members, &px, None, "http://t");
        assert_eq!(n2, 0);
    }

    #[test]
    fn stats_publish_snapshot() {
        let stats = SmartStats::default();
        let mut hist = HashMap::new();
        hist.insert("N1".to_string(), hist_of(&[Some(100), None]));
        hist.insert("Dead".to_string(), hist_of(&[None]));
        stats.publish("G", &hist);
        let v = stats.group_scores("G").unwrap();
        assert_eq!(v["N1"]["samples"], json!([100, null]));
        assert!(v["N1"]["score"].as_u64().unwrap() >= 100);
        assert_eq!(v["Dead"]["score"], Value::Null, "all failed → score null");
        assert!(stats.group_scores("X").is_none());
        stats.retain_groups(&[]);
        assert!(stats.group_scores("G").is_none());
    }

    fn hist_of(samples: &[Option<u32>]) -> NodeHist {
        let mut h = NodeHist::default();
        for s in samples {
            h.push(*s);
        }
        h
    }

    #[test]
    fn incremental_publish_matches_full_rebuild() {
        let mut st = GroupState::default();
        for (name, s) in [
            ("A", Some(120)),
            ("B", None),
            ("C", Some(80)),
            ("D", Some(300)),
        ] {
            st.push(name, s);
        }
        let incremental = SmartStats::default();
        incremental.publish("G", &st.hist);

        for (name, s) in [
            ("C", Some(75)),
            ("A", None),
            ("D", Some(250)),
            ("D", Some(260)),
            ("E", Some(90)),
            ("B", Some(500)),
        ] {
            st.push(name, s);
            incremental.publish_node("G", name, st.hist.get(name).unwrap());
        }

        let full = SmartStats::default();
        full.publish("G", &st.hist);
        assert_eq!(
            incremental.group_scores("G"),
            full.group_scores("G"),
            "incremental updates must converge to the full rebuild"
        );
        let v = incremental.group_scores("G").unwrap();
        assert_eq!(v["D"]["samples"], json!([300, 250, 260]));
        assert_eq!(v["E"]["samples"], json!([90]));
    }

    #[test]
    fn publish_node_creates_missing_group() {
        let stats = SmartStats::default();
        stats.publish_node("G", "N1", &hist_of(&[Some(100)]));
        let v = stats
            .group_scores("G")
            .expect("group must be created on first node");
        assert_eq!(v["N1"]["samples"], json!([100]));
        assert_eq!(v["N1"]["score"], 100);

        stats.publish_node("H", "N2", &hist_of(&[None]));
        assert_eq!(stats.group_scores("H").unwrap()["N2"]["score"], Value::Null);
        assert!(stats.group_scores("G").unwrap().get("N2").is_none());
    }

    fn mock_clash_uds(dir: &tempfile::TempDir, reply: Option<&'static str>) -> PathBuf {
        let sock = dir.path().join("clash.sock");
        let ul = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut s, _)) = ul.accept().await {
                let mut buf = vec![0u8; 8192];
                let _ = s.read(&mut buf).await;
                match reply {
                    Some(r) => {
                        let _ = s.write_all(r.as_bytes()).await;
                        let _ = s.flush().await;
                    }

                    None => held.push(s),
                }
            }
        });
        sock
    }

    #[tokio::test]
    async fn uds_request_gives_up_when_clash_never_answers() {
        let dir = tempfile::tempdir().unwrap();
        let sock = mock_clash_uds(&dir, None);
        let started = std::time::Instant::now();
        let e = uds_request(&sock, "GET", "/proxies", None, Duration::from_millis(200))
            .await
            .expect_err("must not hang");
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "should bail at the deadline, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn select_node_reports_whether_clash_accepted_it() {
        let ok_dir = tempfile::tempdir().unwrap();
        let ok = mock_clash_uds(
            &ok_dir,
            Some("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
        );
        assert!(
            select_node(&ok, "G", "N1").await.unwrap(),
            "2xx means the switch really happened"
        );

        let bad_dir = tempfile::tempdir().unwrap();
        let bad = mock_clash_uds(
            &bad_dir,
            Some("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"),
        );
        assert!(
            !select_node(&bad, "G", "ghost").await.unwrap(),
            "a rejected switch must not be reported as success"
        );
    }

    #[test]
    fn poisoned_stats_lock_still_serves_reads_and_writes() {
        let stats = Arc::new(SmartStats::default());
        let mut hist = HashMap::new();
        hist.insert("N1".to_string(), hist_of(&[Some(100)]));
        stats.publish("G", &hist);

        let poisoner = Arc::clone(&stats);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.0.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();

        assert!(
            stats.group_scores("G").is_some(),
            "reads must survive a poisoned lock"
        );
        stats.publish("G2", &hist);
        assert!(
            stats.group_scores("G2").is_some(),
            "writes must survive a poisoned lock"
        );
        stats.publish_node("G2", "N9", &hist_of(&[Some(5)]));
        assert!(
            stats.group_scores("G2").unwrap().get("N9").is_some(),
            "incremental writes must survive a poisoned lock"
        );
        stats.retain_groups(&[SmartGroup {
            name: "G2".into(),
            url: String::new(),
        }]);
        assert!(stats.group_scores("G").is_none(), "retain must still prune");
    }

    #[test]
    fn backoff_starts_at_the_third_failure_doubles_and_caps() {
        assert_eq!(backoff_delay(1), None);
        assert_eq!(backoff_delay(2), None);
        assert_eq!(backoff_delay(3), Some(Duration::from_secs(120)));
        assert_eq!(backoff_delay(4), Some(Duration::from_secs(240)));
        assert_eq!(backoff_delay(5), Some(Duration::from_secs(480)));
        assert_eq!(backoff_delay(6), Some(Duration::from_secs(960)));
        assert_eq!(backoff_delay(7), Some(BACKOFF_MAX));
        assert_eq!(backoff_delay(u32::MAX), Some(BACKOFF_MAX));
    }

    #[test]
    fn gap_doubles_while_settled_and_snaps_back_on_any_change() {
        let mut g = CYCLE_GAP;
        let mut seen = Vec::new();
        for _ in 0..6 {
            g = next_gap(g, true);
            seen.push(g.as_secs());
        }
        assert_eq!(seen, vec![60, 120, 240, 300, 300, 300]);
        assert_eq!(next_gap(CYCLE_GAP_MAX, false), CYCLE_GAP);
    }

    #[test]
    fn observe_counts_consecutive_failures_and_success_clears() {
        let mut st = GroupState::default();
        let t0 = tokio::time::Instant::now();
        assert_eq!(st.observe("N", None, t0), None);
        assert_eq!(st.observe("N", None, t0), None);
        assert!(!st.in_backoff("N", t0), "two misses are not enough");
        assert_eq!(st.observe("N", None, t0), Some(BACKOFF_BASE));
        assert!(st.in_backoff("N", t0 + Duration::from_secs(60)));
        assert!(!st.in_backoff("N", t0 + BACKOFF_BASE), "backoff expires");
        assert_eq!(st.observe("N", None, t0), Some(BACKOFF_BASE * 2));
        assert_eq!(st.observe("N", Some(80), t0), None);
        assert!(st.backoff.is_empty(), "one success resets the streak");
        assert_eq!(
            st.hist["N"].samples.len(),
            5,
            "every result still feeds the score"
        );
    }

    struct FakeClash {
        _dir: tempfile::TempDir,
        sock: PathBuf,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl FakeClash {
        fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    fn fake_clash(proxies: Value, delays: &[(&str, &[Option<u32>])]) -> FakeClash {
        fake_clash_with_conns(proxies, delays, Vec::new())
    }

    fn fake_clash_with_conns(
        proxies: Value,
        delays: &[(&str, &[Option<u32>])],
        conns: Vec<Value>,
    ) -> FakeClash {
        let mut conns: VecDeque<String> = conns.iter().map(Value::to_string).collect();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("clash.sock");
        let ul = tokio::net::UnixListener::bind(&sock).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut delays: HashMap<String, VecDeque<Option<u32>>> = delays
            .iter()
            .map(|(n, d)| (n.to_string(), d.iter().copied().collect()))
            .collect();
        let body = proxies.to_string();
        let lg = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = ul.accept().await {
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let mut first = head.lines().next().unwrap_or("").split_whitespace();
                let method = first.next().unwrap_or("").to_string();
                let path = first
                    .next()
                    .unwrap_or("")
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .to_string();
                lg.lock().unwrap().push(format!("{method} {path}"));
                let delay_of = path
                    .strip_prefix("/proxies/")
                    .and_then(|p| p.strip_suffix("/delay"));
                let (status, resp) = match (method.as_str(), delay_of) {
                    ("GET", _) if path == "/proxies" => ("200 OK", body.clone()),
                    ("GET", _) if path == "/connections" => {
                        let snap = if conns.len() > 1 {
                            conns.pop_front()
                        } else {
                            conns.front().cloned()
                        };
                        (
                            "200 OK",
                            snap.unwrap_or_else(|| "{\"connections\":[]}".into()),
                        )
                    }
                    ("PUT", _) | ("DELETE", _) => ("204 No Content", String::new()),
                    ("GET", Some(name)) => match delays.get_mut(name).and_then(|q| {
                        if q.len() > 1 {
                            q.pop_front().flatten()
                        } else {
                            q.front().copied().flatten()
                        }
                    }) {
                        Some(d) => ("200 OK", format!("{{\"delay\":{d}}}")),
                        None => (
                            "503 Service Unavailable",
                            "{\"message\":\"Timeout\"}".to_string(),
                        ),
                    },
                    _ => ("404 Not Found", String::new()),
                };
                let msg = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                    resp.len()
                );
                let _ = s.write_all(msg.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        FakeClash {
            _dir: dir,
            sock,
            log,
        }
    }

    fn three_node_group(now: &str) -> Value {
        json!({"proxies": {
            "G": {"type": "Selector", "now": now, "all": ["N1", "N2", "N3", SMART_HIDE_NODE]},
            "N1": {"type": "Socks5"}, "N2": {"type": "Socks5"}, "N3": {"type": "Socks5"}
        }})
    }

    fn state_with_history() -> GroupState {
        let mut st = GroupState::default();
        for n in ["N1", "N2", "N3"] {
            st.push(n, Some(100));
        }
        st
    }

    #[tokio::test]
    async fn sweep_skips_backed_off_nodes_but_always_tests_the_anchor() {
        let fc = fake_clash(
            three_node_group("N1"),
            &[("N1", &[Some(100)]), ("N2", &[None]), ("N3", &[Some(300)])],
        );
        let mut st = state_with_history();
        let later = tokio::time::Instant::now() + Duration::from_secs(600);
        for n in ["N1", "N2"] {
            st.backoff.insert(
                n.into(),
                Backoff {
                    streak: 5,
                    until: Some(later),
                },
            );
        }
        let (stats, fixed) = (
            SmartStats::default(),
            crate::smart_fixed::SmartFixed::in_memory(),
        );
        let (_tx, rx) = watch::channel(false);
        let out = run_group_pass(&fc.sock, "G", "http://t/", &mut st, &stats, &fixed, &rx)
            .await
            .unwrap();
        let req = fc.requests();
        assert!(
            req.contains(&"GET /proxies/N1/delay".to_string()),
            "anchor must be tested even when backed off: {req:?}"
        );
        assert!(
            !req.contains(&"GET /proxies/N2/delay".to_string()),
            "backed-off node must be skipped: {req:?}"
        );
        assert!(
            req.contains(&"GET /proxies/N3/delay".to_string()),
            "{req:?}"
        );
        assert!(out.settled, "no switch and the anchor answered");
        assert!(
            !st.backoff.contains_key("N1"),
            "a success clears the anchor's streak"
        );
        assert_eq!(st.anchor.as_ref().map(|m| m.name.as_str()), Some("N1"));
    }

    #[tokio::test]
    async fn a_switch_makes_the_pass_unsettled_and_moves_the_anchor() {
        let fc = fake_clash(
            three_node_group("N1"),
            &[("N1", &[None]), ("N2", &[Some(400)]), ("N3", &[Some(50)])],
        );
        let mut st = state_with_history();
        let (stats, fixed) = (
            SmartStats::default(),
            crate::smart_fixed::SmartFixed::in_memory(),
        );
        let (_tx, rx) = watch::channel(false);
        let out = run_group_pass(&fc.sock, "G", "http://t/", &mut st, &stats, &fixed, &rx)
            .await
            .unwrap();
        assert!(!out.settled, "a switch must reset the cadence");
        assert!(fc.requests().contains(&"PUT /proxies/G".to_string()));
        assert_eq!(st.anchor.as_ref().map(|m| m.name.as_str()), Some("N3"));
    }

    #[tokio::test]
    async fn a_confirmed_dead_current_node_fails_over_despite_its_history() {
        for missed_before in [true, false] {

            let fc = fake_clash(
                three_node_group("N1"),
                &[("N1", &[None]), ("N2", &[Some(120)]), ("N3", &[None])],
            );
            let mut st = GroupState::default();
            for _ in 0..7 {
                st.push("N1", Some(100));
            }
            for d in [Some(100), None, None, None] {
                st.push("N2", d);
            }
            for _ in 0..4 {
                st.push("N3", None);
            }
            if missed_before {
                st.backoff.insert(
                    "N1".into(),
                    Backoff {
                        streak: 1,
                        until: None,
                    },
                );
            }
            let (stats, fixed) = (
                SmartStats::default(),
                crate::smart_fixed::SmartFixed::in_memory(),
            );
            let (_tx, rx) = watch::channel(false);
            let out = run_group_pass(&fc.sock, "G", "http://t/", &mut st, &stats, &fixed, &rx)
                .await
                .unwrap();
            let req = fc.requests();
            let n1_tests = req.iter().filter(|r| *r == "GET /proxies/N1/delay").count();
            assert_eq!(
                n1_tests,
                if missed_before { 1 } else { 2 },
                "a first failure is retested once, a repeat failure is not: {req:?}"
            );
            assert!(
                req.contains(&"PUT /proxies/G".to_string()),
                "missed before={missed_before}"
            );
            assert_eq!(st.anchor.as_ref().map(|m| m.name.as_str()), Some("N2"));
            assert!(!out.settled);
        }
    }

    #[tokio::test]
    async fn a_transient_failure_of_the_current_node_is_ignored() {
        let fc = fake_clash(
            three_node_group("N1"),
            &[
                ("N1", &[None, Some(100)]),
                ("N2", &[Some(300)]),
                ("N3", &[Some(300)]),
            ],
        );
        let mut st = state_with_history();
        let (stats, fixed) = (
            SmartStats::default(),
            crate::smart_fixed::SmartFixed::in_memory(),
        );
        let (_tx, rx) = watch::channel(false);
        let out = run_group_pass(&fc.sock, "G", "http://t/", &mut st, &stats, &fixed, &rx)
            .await
            .unwrap();
        assert!(!fc.requests().contains(&"PUT /proxies/G".to_string()));
        assert!(!st.hist["N1"].has_failures(), "the blip must not be scored");
        assert!(!st.backoff.contains_key("N1"));
        assert!(out.settled, "nothing changed in the end");
    }

    #[tokio::test]
    async fn a_recovering_faster_node_keeps_the_cadence_fast() {
        for (n2_delay, want_settled) in [(5, false), (500, true)] {
            let fc = fake_clash(
                three_node_group("N1"),
                &[
                    ("N1", &[Some(150)]),
                    ("N2", &[Some(n2_delay)]),
                    ("N3", &[None]),
                ],
            );
            let mut st = GroupState::default();
            for _ in 0..7 {
                st.push("N1", Some(150));
            }
            for d in [Some(n2_delay), None, None, Some(n2_delay)] {
                st.push("N2", d);
            }
            let later = tokio::time::Instant::now() + Duration::from_secs(600);
            st.backoff.insert(
                "N3".into(),
                Backoff {
                    streak: 9,
                    until: Some(later),
                },
            );
            let (stats, fixed) = (
                SmartStats::default(),
                crate::smart_fixed::SmartFixed::in_memory(),
            );
            let (_tx, rx) = watch::channel(false);
            let out = run_group_pass(&fc.sock, "G", "http://t/", &mut st, &stats, &fixed, &rx)
                .await
                .unwrap();
            assert!(
                !fc.requests().contains(&"PUT /proxies/G".to_string()),
                "N2 is still penalised for its misses"
            );
            assert_eq!(out.settled, want_settled, "N2 at {n2_delay}ms");
        }
    }

    fn cc(
        id: &str,
        chains: &[&str],
        up: u64,
        down: u64,
        typ: &str,
    ) -> crate::clash_pull::ClashConn {
        crate::clash_pull::ClashConn {
            id: id.into(),
            chains: chains.iter().map(|s| s.to_string()).collect(),
            upload: up,
            download: down,
            inbound_type: typ.into(),
            ..Default::default()
        }
    }

    fn conn_json(id: &str, chains: &[&str], up: u64, down: u64) -> Value {
        json!({"id": id, "chains": chains, "upload": up, "download": down, "metadata": {"type": "Socks5"}})
    }

    #[test]
    fn only_this_groups_idle_or_stuck_connections_on_the_old_node_are_picked() {
        let before = vec![
            cc("idle", &["N1", "G"], 10, 20, "Socks5"),
            cc("moving", &["N1", "G"], 10, 20, "Socks5"),
            cc("nested", &["N1", "G", "OUTER"], 3, 3, "Socks5"),
            cc("other-group", &["N1", "H"], 1, 1, "Socks5"),
            cc("inner", &["N1", "G"], 1, 1, "Inner"),
            cc("new-node", &["N2", "G"], 1, 1, "Socks5"),
            cc("gone", &["N1", "G"], 5, 5, "Socks5"),
        ];
        let mut after = before.clone();
        after.retain(|c| c.id != "gone");
        after
            .iter_mut()
            .find(|c| c.id == "moving")
            .unwrap()
            .download = 25;
        after.push(cc("fresh", &["N1", "G"], 0, 0, "Socks5"));
        let (stalled, moving) = stalled_on("G", "N1", &before, &after);
        assert_eq!(stalled, vec!["idle".to_string(), "nested".to_string()]);
        assert_eq!(moving, vec!["moving".to_string()]);
    }

    #[tokio::test]
    async fn failover_closes_stalled_connections_and_keeps_moving_ones() {
        let snaps = vec![
            json!({"connections": [conn_json("A", &["N1", "G"], 100, 100), conn_json("B", &["N1", "G"], 100, 100), conn_json("C", &["N2", "G"], 1, 1)]}),
            json!({"connections": [conn_json("A", &["N1", "G"], 100, 100), conn_json("B", &["N1", "G"], 100, 500), conn_json("C", &["N2", "G"], 1, 1)]}),
            json!({"connections": [conn_json("B", &["N1", "G"], 100, 900), conn_json("C", &["N2", "G"], 1, 1)]}),
        ];
        let fc = fake_clash_with_conns(
            three_node_group("N1"),
            &[("N1", &[None]), ("N2", &[Some(120)]), ("N3", &[None])],
            snaps,
        );
        let mut st = GroupState::default();
        for _ in 0..7 {
            st.push("N1", Some(100));
        }
        st.backoff.insert(
            "N1".into(),
            Backoff {
                streak: 1,
                until: None,
            },
        );
        st.push("N2", Some(100));
        let (stats, fixed) = (
            SmartStats::default(),
            crate::smart_fixed::SmartFixed::in_memory(),
        );
        let (_tx, rx) = watch::channel(false);
        run_group_pass(&fc.sock, "G", "http://t/", &mut st, &stats, &fixed, &rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let req = fc.requests();
        assert!(req.contains(&"PUT /proxies/G".to_string()), "{req:?}");
        assert_eq!(
            req.iter()
                .filter(|r| r.starts_with("GET /connections"))
                .count(),
            3,
            "first look, then the stall check, then the recheck of the moving one: {req:?}"
        );
        assert!(
            req.contains(&"DELETE /connections/A".to_string()),
            "{req:?}"
        );
        assert!(
            !req.iter()
                .any(|r| r == "DELETE /connections/B" || r == "DELETE /connections/C"),
            "{req:?}"
        );
    }

    #[tokio::test]
    async fn an_upgrade_switch_leaves_old_connections_alone() {
        let fc = fake_clash_with_conns(
            three_node_group("N1"),
            &[
                ("N1", &[Some(300)]),
                ("N2", &[Some(400)]),
                ("N3", &[Some(50)]),
            ],
            vec![json!({"connections": [conn_json("A", &["N1", "G"], 1, 1)]})],
        );
        let mut st = state_with_history();
        let (stats, fixed) = (
            SmartStats::default(),
            crate::smart_fixed::SmartFixed::in_memory(),
        );
        let (_tx, rx) = watch::channel(false);
        run_group_pass(&fc.sock, "G", "http://t/", &mut st, &stats, &fixed, &rx)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let req = fc.requests();
        assert!(req.contains(&"PUT /proxies/G".to_string()), "{req:?}");
        assert!(!req.iter().any(|r| r.contains("/connections")), "{req:?}");
    }

    #[tokio::test]
    async fn anchor_check_tests_only_the_anchor_and_flags_a_failure() {
        let group = vec![SmartGroup {
            name: "G".into(),
            url: String::new(),
        }];
        for (anchor_up, want) in [(true, false), (false, true)] {
            let n1 = [anchor_up.then_some(90)];
            let fc = fake_clash(
                three_node_group("N1"),
                &[("N1", &n1), ("N2", &[Some(10)]), ("N3", &[Some(10)])],
            );
            let states: SharedStates = Arc::new(Mutex::new(HashMap::new()));
            let mut st = state_with_history();
            st.anchor = Some(Member {
                name: "N1".into(),
                provider: None,
            });
            lock_states(&states).insert("G".into(), st);
            let (stats, fixed) = (
                SmartStats::default(),
                crate::smart_fixed::SmartFixed::in_memory(),
            );
            let failed =
                check_anchors(&fc.sock, "http://t/", &group, &states, &stats, &fixed).await;
            assert_eq!(failed, want, "anchor up={anchor_up}");
            assert_eq!(fc.requests(), vec!["GET /proxies/N1/delay".to_string()]);
            let g = lock_states(&states);
            let st = g.get("G").expect("state must be put back");
            assert!(
                !st.hist["N1"].has_failures(),
                "a failed check is not scored; the full sweep re-measures"
            );
            assert_eq!(st.hist["N1"].samples.len(), if anchor_up { 2 } else { 1 });
        }
    }

    #[test]
    fn dechunk_roundtrip() {
        assert_eq!(
            dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"),
            b"Wikipedia"
        );
    }
}
