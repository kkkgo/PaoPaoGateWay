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

const SUPERVISOR_TICK: Duration = Duration::from_secs(30);

const ERR_BACKOFF: Duration = Duration::from_secs(15);

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
}

#[derive(Default)]
pub struct SmartStats(Mutex<HashMap<String, Value>>);

impl SmartStats {

    pub fn group_scores(&self, group: &str) -> Option<Value> {
        self.0.lock().unwrap().get(group).cloned()
    }

    fn publish(&self, group: &str, hist: &HashMap<String, NodeHist>) {
        let mut obj = serde_json::Map::new();
        for (name, h) in hist {
            let score = h.score();
            let samples: Vec<Value> = h
                .samples
                .iter()
                .map(|s| s.map(Value::from).unwrap_or(Value::Null))
                .collect();
            obj.insert(
                name.clone(),
                serde_json::json!({
                    "score": if score.is_finite() { Value::from(score.round() as u64) } else { Value::Null },
                    "samples": samples,
                }),
            );
        }
        self.0
            .lock()
            .unwrap()
            .insert(group.to_string(), Value::Object(obj));
    }

    fn retain_groups(&self, keep: &[SmartGroup]) {
        self.0
            .lock()
            .unwrap()
            .retain(|k, _| keep.iter().any(|g| g.name == *k));
    }
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

#[derive(Default)]
struct GroupState {
    hist: HashMap<String, NodeHist>,
}

impl GroupState {
    fn score(&self, node: &str) -> f64 {
        self.hist.get(node).map(NodeHist::score).unwrap_or(f64::INFINITY)
    }

    fn push(&mut self, node: &str, sample: Option<u32>) {
        self.hist.entry(node.to_string()).or_default().push(sample);
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

struct Runner {
    names: Vec<String>,
    cancel: watch::Sender<bool>,
}

pub fn spawn(clash_sock: PathBuf, stats: Arc<SmartStats>, shutdown: watch::Receiver<bool>) {
    tokio::spawn(supervise(clash_sock, stats, shutdown));
}

async fn supervise(sock: PathBuf, stats: Arc<SmartStats>, mut shutdown: watch::Receiver<bool>) {
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
        states
            .lock()
            .unwrap()
            .retain(|k, _| groups.iter().any(|g| g.name == *k));
        stats.retain_groups(&groups);
        let names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();
        if names != last_names {
            if names.is_empty() {
                st_log!("no smart group configured (ppsub.json), idle");
            } else {
                st_log!("managing {} smart group(s): {}", names.len(), names.join(", "));
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
            st_log!("runner for `{url}` started, covering: {}", group_names(gs).join(", "));
            tokio::spawn(runner(
                sock.clone(),
                url.clone(),
                gs.clone(),
                Arc::clone(&states),
                Arc::clone(&stats),
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

fn bucket_by_url(groups: &[SmartGroup], default_url: &str) -> std::collections::BTreeMap<String, Vec<SmartGroup>> {
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
    mut cancel: watch::Receiver<bool>,
) {
    loop {
        let mut any_err = false;
        for g in &groups {
            if *cancel.borrow() {
                return;
            }
            let mut st = states.lock().unwrap().remove(&g.name).unwrap_or_default();
            let r = run_group_pass(&sock, &g.name, &url, &mut st, &stats, &cancel).await;
            states.lock().unwrap().insert(g.name.clone(), st);
            if let Err(e) = r {
                tracing::warn!("[PaoPaoGW Smart Test] {}: clash api error ({e}), retry in {}s", g.name, ERR_BACKOFF.as_secs());
                any_err = true;
                break;
            }
        }
        let gap = if any_err { ERR_BACKOFF } else { CYCLE_GAP };
        if sleep_or_shutdown(gap, &mut cancel).await {
            return;
        }
    }
}

async fn sleep_or_shutdown(d: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

async fn run_group_pass(
    sock: &Path,
    group: &str,
    url: &str,
    st: &mut GroupState,
    stats: &SmartStats,
    shutdown: &watch::Receiver<bool>,
) -> std::io::Result<()> {
    let px: RawProxies = fetch_typed(sock, "/proxies").await?;
    let providers: Option<RawProviders> = if needs_providers(&px, group) {
        Some(fetch_typed(sock, "/providers/proxies").await?)
    } else {
        None
    };
    let Some((members, now)) = eligible_members(&px, providers.as_ref(), group) else {

        st_log!("{group}: group not present in clash yet, skip this cycle");
        return Ok(());
    };
    if members.is_empty() {
        st_log!("{group}: no testable member, skip this cycle");
        return Ok(());
    }
    st.hist.retain(|k, _| members.iter().any(|m| m.name == *k));

    let seeded = seed_from_clash(st, &members, &px, providers.as_ref(), url);
    if seeded > 0 {
        st_log!("{group}: seeded history for {seeded} node(s) from clash delay data");
    }

    let no_data: Vec<&Member> = members
        .iter()
        .filter(|m| st.hist.get(&m.name).is_none_or(NodeHist::is_empty))
        .collect();

    if no_data.len() == members.len() {
        let r = ladder_pass(sock, group, url, st, &members, &now).await;
        stats.publish(group, &st.hist);
        return r;
    }

    if !no_data.is_empty() {
        st_log!("{group}: testing {} node(s) without history (concurrent, {}ms timeout)",
            no_data.len(), REGULAR_TIMEOUT_MS);
        for (m, d) in test_many(sock, &no_data, url, REGULAR_TIMEOUT_MS).await {
            st.push(&m.name, d);
            log_result(group, &m.name, d, st.score(&m.name));
        }
        stats.publish(group, &st.hist);
    }

    let mut current = now.clone();
    if !members.iter().any(|m| m.name == current) {
        if let Some(best) = members
            .iter()
            .min_by(|a, b| st.score(&a.name).total_cmp(&st.score(&b.name)))
        {
            select_node(sock, group, &best.name).await?;
            st_info!("{group}: current selection `{current}` invalid (clash reloaded?), reselected `{}`",
                best.name);
            current = best.name.clone();
        }
    }

    st_log!("{group}: sequential sweep over {} node(s), current `{current}`", members.len());
    if let Some(cur) = members.iter().find(|m| m.name == current) {
        let d = test_member(sock, cur, url, REGULAR_TIMEOUT_MS).await;
        st.push(&cur.name, d);
        log_result(group, &cur.name, d, st.score(&cur.name));
        stats.publish(group, &st.hist);
    }
    let mut rest: Vec<&Member> = members.iter().filter(|m| m.name != current).collect();
    rest.sort_by(|a, b| st.score(&a.name).total_cmp(&st.score(&b.name)));
    for m in rest {
        if *shutdown.borrow() {
            break;
        }
        let d = test_member(sock, m, url, REGULAR_TIMEOUT_MS).await;
        st.push(&m.name, d);
        log_result(group, &m.name, d, st.score(&m.name));
        stats.publish(group, &st.hist);
        let (cand, cur) = (st.score(&m.name), st.score(&current));
        if cand < cur {
            select_node(sock, group, &m.name).await?;
            st_info!("{group}: switch `{current}` -> `{}` (score {} < {})",
                m.name, cand.round() as u64, cur.round() as u64);
            current = m.name.clone();
        }
    }
    st_log!("{group}: sweep done, selected `{current}` (score {})",
        fmt_score(st.score(&current)));
    Ok(())
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

async fn ladder_pass(
    sock: &Path,
    group: &str,
    url: &str,
    st: &mut GroupState,
    members: &[Member],
    now: &str,
) -> std::io::Result<()> {
    let refs: Vec<&Member> = members.iter().collect();
    st_log!("{group}: no history at all, laddered concurrent probe over {} node(s)", refs.len());
    for t in LADDER_MS {
        let results = test_many(sock, &refs, url, t).await;
        let mut best: Option<(&Member, u32)> = None;
        let mut ok = 0;
        for (m, d) in &results {
            if let Some(d) = d {
                ok += 1;
                st.push(&m.name, Some(*d));
                if best.is_none_or(|(_, bd)| *d < bd) {
                    best = Some((m, *d));
                }
            }
        }
        st_log!("{group}: ladder timeout={t}ms -> {ok}/{} ok", refs.len());
        if let Some((m, d)) = best {
            if m.name != now {
                select_node(sock, group, &m.name).await?;
            }
            st_info!("{group}: initial pick `{}` ({d}ms, lowest delay)", m.name);
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

    let fut = uds_request(sock, "GET", &path, None);
    let (status, body) = tokio::time::timeout(Duration::from_millis(timeout_ms + 3000), fut)
        .await
        .ok()?
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

async fn select_node(sock: &Path, group: &str, name: &str) -> std::io::Result<()> {
    let path = format!(
        "/proxies/{}",
        crate::web_proxies::pct_encode_segment(group)
    );
    let body = serde_json::json!({ "name": name }).to_string();
    let (status, _) = uds_request(sock, "PUT", &path, Some(&body)).await?;
    if !(200..300).contains(&status) {
        tracing::warn!(group, name, status, "smart speedtest: select rejected by clash");
    }
    Ok(())
}

async fn fetch_typed<T: serde::de::DeserializeOwned>(
    sock: &Path,
    path: &str,
) -> std::io::Result<T> {
    let (status, body) = uds_request(sock, "GET", path, None).await?;
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
    up.read_to_end(&mut rest).await?;
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
                SmartGroup { name: "A".into(), url: "http://x".into() },
                SmartGroup { name: "C".into(), url: "".into() },
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
        assert_eq!(m.len(), 1, "Ghost not found on either side → skip; tag nodes skipped");
        assert_eq!(m[0].name, "P1");
        assert_eq!(m[0].provider.as_deref(), Some("Grp=(Pre🔗Grp)"));
    }

    #[test]
    fn needs_providers_false_when_all_toplevel() {
        let px = rp(json!({"proxies":{
            "Smart":{"all":["N1","smartspeedtest@hide"]},
            "N1":{"type":"Trojan"}
        }}));
        assert!(!needs_providers(&px, "Smart"), "tag nodes should not trigger provider pulls");
        assert!(!needs_providers(&px, "Nope"));
    }

    #[test]
    fn bucket_groups_by_effective_url() {
        let gs = vec![
            SmartGroup { name: "A".into(), url: "http://x".into() },
            SmartGroup { name: "B".into(), url: "".into() },
            SmartGroup { name: "C".into(), url: "http://x".into() },
            SmartGroup { name: "D".into(), url: "http://def".into() },
            SmartGroup { name: "A".into(), url: "http://dup".into() },
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
            Member { name: "N1".into(), provider: None },
            Member { name: "N2".into(), provider: None },
            Member { name: "N3".into(), provider: None },
        ];
        let mut st = GroupState::default();
        let n = seed_from_clash(&mut st, &members, &px, None, "http://t");
        assert_eq!(n, 2);
        assert_eq!(
            st.hist["N1"].samples,
            vec![Some(100), None, Some(120)],
            "extra[url] bucket takes priority, delay=0 counted as failure"
        );
        assert_eq!(st.hist["N2"].samples, vec![Some(300)], "top-level history fallback");
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
    fn dechunk_roundtrip() {
        assert_eq!(
            dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"),
            b"Wikipedia"
        );
    }
}
