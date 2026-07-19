// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_TEST_URL: &str = "http://cp.cloudflare.com/generate_204";

const FRESH_MIN_INTERVAL: Duration = Duration::from_secs(3);

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawProxies {
    pub proxies: HashMap<String, RawNode>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawNode {

    pub name: Option<String>,
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub udp: Option<bool>,
    pub alive: Option<bool>,
    pub history: Vec<RawDelay>,
    pub extra: HashMap<String, RawBucket>,

    pub all: Option<Vec<String>>,
    pub now: Option<String>,
    #[serde(rename = "testUrl")]
    pub test_url: Option<String>,
    pub fixed: Option<String>,
    pub hidden: Option<bool>,
    pub icon: Option<String>,
}

#[derive(serde::Deserialize, Default, Clone, Copy)]
#[serde(default)]
pub(crate) struct RawDelay {
    pub delay: Option<u64>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawBucket {
    pub history: Vec<RawDelay>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawProviders {
    pub providers: HashMap<String, RawProvider>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub(crate) struct RawProvider {
    #[serde(rename = "vehicleType")]
    pub vehicle_type: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    #[serde(rename = "subscriptionInfo")]
    pub subscription_info: Option<Value>,
    pub proxies: Vec<RawNode>,
}

pub struct WebProxies {
    clash_sock: PathBuf,
    ppgw_ini: PathBuf,
    cache: Mutex<Option<String>>,

    last_fetch: Mutex<Option<std::time::Instant>>,

    warm: Arc<tokio::sync::Notify>,

    smart_stats: Arc<crate::smart_speed::SmartStats>,
}

impl WebProxies {
    pub fn new(clash_sock: PathBuf, smart_stats: Arc<crate::smart_speed::SmartStats>) -> Arc<Self> {
        Arc::new(Self {
            clash_sock,
            ppgw_ini: PathBuf::from("/tmp/ppgw.ini"),
            cache: Mutex::new(None),
            last_fetch: Mutex::new(None),
            warm: Arc::new(tokio::sync::Notify::new()),
            smart_stats,
        })
    }

    pub fn warm_signal(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.warm)
    }

    fn fetch(&self) -> Option<String> {
        let sock = &self.clash_sock;
        let px: RawProxies = clash_get(sock, "/proxies")
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())?;

        if px.proxies.is_empty() {
            return None;
        }
        let pv: RawProviders = clash_get(sock, "/providers/proxies")
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mode = fetch_mode(sock);
        let test_url = read_test_url(&self.ppgw_ini);

        let smart_urls: HashMap<String, String> =
            std::fs::read_to_string(crate::geo_cron::PPSUB_JSON)
                .map(|j| {
                    crate::smart_speed::parse_smart_groups(&j)
                        .into_iter()
                        .map(|g| (g.name, g.url))
                        .collect()
                })
                .unwrap_or_default();
        Some(build_trimmed(
            &px,
            &pv,
            &mode,
            &test_url,
            &smart_urls,
            &|g| self.smart_stats.group_scores(g),
        ))
    }

    pub fn refresh(&self) -> bool {
        if let Some(json) = self.fetch() {
            *self.cache.lock().unwrap() = Some(json);
            *self.last_fetch.lock().unwrap() = Some(std::time::Instant::now());
            true
        } else {
            false
        }
    }

    fn refresh_rate_limited(&self) {
        let recent = self
            .last_fetch
            .lock()
            .unwrap()
            .is_some_and(|t| t.elapsed() < FRESH_MIN_INTERVAL);
        if !recent {
            self.refresh();
        }
    }
}

impl sb_web::ProxiesSource for WebProxies {
    fn proxies_json(&self) -> String {

        if let Some(j) = self.cache.lock().unwrap().clone() {
            return j;
        }

        self.refresh();
        self.cache
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "{}".to_string())
    }

    fn proxies_json_fresh(&self) -> String {
        self.refresh_rate_limited();
        self.cache
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "{}".to_string())
    }

    fn mode_json(&self) -> String {
        format!(r#"{{"mode":"{}"}}"#, fetch_mode(&self.clash_sock))
    }

    fn warm(&self) {
        self.warm.notify_one();
    }

    fn proxy_detail(&self, name: &str) -> (u16, String) {
        proxy_detail_lookup(&self.clash_sock, name)
    }
}

fn proxy_detail_lookup(sock: &Path, name: &str) -> (u16, String) {

    let enc = pct_encode_segment(name);
    if let Ok((200, body)) = clash_get_status(sock, &format!("/proxies/{enc}"))
        && let Ok(s) = String::from_utf8(body)
    {
        return (200, s);
    }

    if let Ok((200, body)) = clash_get_status(sock, "/providers/proxies")
        && let Some(node) = find_provider_node(&body, name)
    {
        return (200, node);
    }
    (404, r#"{"message":"Resource not found"}"#.to_string())
}

fn find_provider_node(providers_body: &[u8], name: &str) -> Option<String> {
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Wrap<'a> {
        #[serde(borrow)]
        providers: HashMap<String, One<'a>>,
    }
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct One<'a> {
        #[serde(borrow)]
        proxies: Vec<&'a serde_json::value::RawValue>,
    }
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct NameOnly {
        name: Option<String>,
    }
    let body = std::str::from_utf8(providers_body).ok()?;
    let w: Wrap = serde_json::from_str(body).ok()?;
    for one in w.providers.values() {
        for raw in &one.proxies {
            let n = serde_json::from_str::<NameOnly>(raw.get())
                .ok()
                .and_then(|x| x.name);
            if n.as_deref() == Some(name) {
                return Some(raw.get().to_string());
            }
        }
    }
    None
}

pub(crate) fn pct_encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub(crate) fn build_trimmed(
    proxies_raw: &RawProxies,
    providers_raw: &RawProviders,
    mode: &str,
    test_url: &str,
    smart_urls: &HashMap<String, String>,
    smart_scores: &dyn Fn(&str) -> Option<Value>,
) -> String {
    let mut proxies = Map::new();
    for (name, p) in &proxies_raw.proxies {

        if name == sb_ppgw::ppsub::SMART_HIDE_NODE {
            continue;
        }
        let mut t = trim_one(name, p);

        if t.get("smart").is_some() {
            let url = smart_urls
                .get(name)
                .filter(|u| !u.is_empty())
                .map(String::as_str)
                .unwrap_or(test_url);
            if let Some(o) = t.as_object_mut() {
                o.insert("testUrl".into(), Value::String(url.to_string()));

                if let Some(sc) = smart_scores(name) {
                    o.insert("scores".into(), sc);
                }
            }
        }
        proxies.insert(name.clone(), t);
    }
    let mut providers = Map::new();
    for (name, pv) in &providers_raw.providers {
        let mut names = Vec::new();
        for node in &pv.proxies {
            let Some(n) = node.name.as_deref() else { continue };

            if n == sb_ppgw::ppsub::SMART_HIDE_NODE {
                continue;
            }
            names.push(Value::String(n.to_string()));

            proxies
                .entry(n.to_string())
                .or_insert_with(|| trim_one(n, node));
        }
        let mut m = Map::new();
        if let Some(v) = &pv.vehicle_type {
            m.insert("vehicleType".into(), Value::String(v.clone()));
        }
        if let Some(v) = &pv.updated_at {
            m.insert("updatedAt".into(), Value::String(v.clone()));
        }
        if let Some(v) = pv.subscription_info.as_ref().filter(|v| !v.is_null()) {
            m.insert("subscriptionInfo".into(), v.clone());
        }
        m.insert("proxies".into(), Value::Array(names));
        providers.insert(name.clone(), Value::Object(m));
    }

    let mut root = Map::new();
    root.insert("mode".into(), Value::String(mode.to_string()));
    root.insert("testUrl".into(), Value::String(test_url.to_string()));
    root.insert("proxies".into(), Value::Object(proxies));
    root.insert("providers".into(), Value::Object(providers));
    Value::Object(root).to_string()
}

fn trim_one(name: &str, p: &RawNode) -> Value {
    let mut m = Map::new();
    if let Some(v) = &p.typ {
        m.insert("type".into(), Value::String(v.clone()));
    }
    if let Some(v) = p.udp {
        m.insert("udp".into(), Value::Bool(v));
    }
    if let Some(v) = p.alive {
        m.insert("alive".into(), Value::Bool(v));
    }

    if let Some(d) = p.history.last().and_then(|e| e.delay) {
        m.insert("delay".into(), Value::from(d));
    }

    let hist: Vec<Value> = p
        .history
        .iter()
        .rev()
        .take(8)
        .rev()
        .filter_map(|e| e.delay.map(Value::from))
        .collect();
    if hist.len() >= 2 {
        m.insert("hist".into(), Value::Array(hist));
    }

    let mut ex = Map::new();
    for (url, v) in &p.extra {
        if let Some(d) = v.history.last().and_then(|e| e.delay) {
            ex.insert(url.clone(), Value::from(d));
        }
    }
    if !ex.is_empty() {
        m.insert("extra".into(), Value::Object(ex));
    }

    if let Some(all) = &p.all {
        let before = all.len();
        let kept: Vec<Value> = all
            .iter()
            .filter(|n| n.as_str() != sb_ppgw::ppsub::SMART_HIDE_NODE)
            .map(|n| Value::String(n.clone()))
            .collect();
        if kept.len() != before && name != "GLOBAL" {
            m.insert("smart".into(), Value::Bool(true));
        }
        m.insert("all".into(), Value::Array(kept));
        if let Some(v) = &p.now {
            m.insert("now".into(), Value::String(v.clone()));
        }
        if let Some(v) = p.test_url.as_ref().filter(|v| !v.is_empty()) {
            m.insert("testUrl".into(), Value::String(v.clone()));
        }
        if let Some(v) = p.fixed.as_ref().filter(|v| !v.is_empty()) {
            m.insert("fixed".into(), Value::String(v.clone()));
        }
        if p.hidden == Some(true) {
            m.insert("hidden".into(), Value::Bool(true));
        }
        if let Some(v) = p.icon.as_ref().filter(|v| !v.is_empty()) {
            m.insert("icon".into(), Value::String(v.clone()));
        }
    }
    Value::Object(m)
}

fn fetch_mode(sock: &Path) -> String {
    clash_get(sock, "/configs")
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| {
            v.get("mode")
                .and_then(|m| m.as_str())
                .map(|s| s.to_lowercase())
        })
        .unwrap_or_else(|| "rule".to_string())
}

pub(crate) fn read_test_url(ini: &Path) -> String {
    let Ok(txt) = std::fs::read_to_string(ini) else {
        return DEFAULT_TEST_URL.to_string();
    };
    parse_test_url(&txt)
}

fn parse_test_url(txt: &str) -> String {

    let mut found: Option<String> = None;
    for line in txt.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("test_node_url") else {
            continue;
        };
        let Some(val) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let v = val.trim().trim_matches('"').trim();
        if !v.is_empty() {
            found = Some(v.to_string());
        }
    }
    found.unwrap_or_else(|| DEFAULT_TEST_URL.to_string())
}

fn clash_get(sock: &Path, path: &str) -> std::io::Result<Vec<u8>> {
    let mut s = std::os::unix::net::UnixStream::connect(sock)?;
    s.set_read_timeout(Some(Duration::from_secs(8)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes())?;
    s.flush()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let Some(sep) = sep else {
        return Ok(Vec::new());
    };
    let head = &buf[..sep];
    let body = &buf[sep + 4..];
    if head_is_chunked(head) {
        Ok(dechunk_buffered(body))
    } else {
        Ok(body.to_vec())
    }
}

fn clash_get_status(sock: &Path, path: &str) -> std::io::Result<(u16, Vec<u8>)> {
    let mut s = std::os::unix::net::UnixStream::connect(sock)?;
    s.set_read_timeout(Some(Duration::from_secs(8)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes())?;
    s.flush()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    let Some(sep) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok((0, Vec::new()));
    };
    let head = &buf[..sep];
    let status = parse_status(head);
    let body = &buf[sep + 4..];
    let body = if head_is_chunked(head) {
        dechunk_buffered(body)
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn parse_status(head: &[u8]) -> u16 {
    let line = head
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(head);
    let s = String::from_utf8_lossy(line);
    s.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn head_is_chunked(head: &[u8]) -> bool {
    let s = String::from_utf8_lossy(head).to_ascii_lowercase();
    s.lines()
        .any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"))
}

fn dechunk_buffered(data: &[u8]) -> Vec<u8> {
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
    fn px(v: Value) -> RawProxies {
        serde_json::from_value(v).unwrap()
    }
    fn pv(v: Value) -> RawProviders {
        if v.is_null() { RawProviders::default() } else { serde_json::from_value(v).unwrap() }
    }

    #[test]
    fn trims_node_and_group_fields() {
        let proxies = json!({
            "proxies": {
                "N1": {
                    "name": "N1", "type": "Trojan", "udp": true, "alive": true,
                    "smux": {}, "tfo": false, "xudp": true, "dialer-proxy": "", "id": "abc",
                    "extra": {"http://x": {"history": [{"delay": 999}]}},
                    "history": [{"time": "t1", "delay": 100}, {"time": "t2", "delay": 200}]
                },
                "G1": {
                    "name": "G1", "type": "Selector", "udp": true, "now": "N1",
                    "all": ["N1", "N2"], "testUrl": "http://cp/204", "fixed": "", "hidden": false,
                    "history": []
                }
            }
        });
        let providers = json!({
            "providers": {
                "AirA": {
                    "name": "AirA", "vehicleType": "HTTP", "updatedAt": "2026",
                    "subscriptionInfo": {"Total": 100, "Download": 40, "Upload": 10, "Expire": 123},
                    "proxies": [{"name": "N2", "type": "Vless", "udp": false, "alive": true,
                                 "history": [{"delay": 300}], "smux": {}}]
                },
                "default": {"name": "default", "vehicleType": "Compatible", "proxies": []}
            }
        });
        let out: Value =
            serde_json::from_str(&build_trimmed(
                &px(proxies),
                &pv(providers),
                "Rule",
                "http://t",
                &HashMap::new(),
                &|_| None
            ))
            .unwrap();
        assert_eq!(out["mode"], "Rule");
        assert_eq!(out["testUrl"], "http://t");

        let n1 = &out["proxies"]["N1"];
        assert_eq!(n1["type"], "Trojan");
        assert_eq!(n1["delay"], 200);
        assert!(n1.get("smux").is_none() && n1.get("history").is_none());

        assert_eq!(n1["extra"]["http://x"], 999);

        assert_eq!(n1["hist"], json!([100, 200]));

        let g1 = &out["proxies"]["G1"];
        assert_eq!(g1["now"], "N1");
        assert_eq!(g1["all"], json!(["N1", "N2"]));
        assert_eq!(g1["testUrl"], "http://cp/204");
        assert!(g1.get("fixed").is_none() && g1.get("hidden").is_none());

        assert_eq!(out["proxies"]["N2"]["type"], "Vless");
        assert_eq!(out["proxies"]["N2"]["delay"], 300);

        assert_eq!(out["providers"]["AirA"]["proxies"], json!(["N2"]));
        assert_eq!(out["providers"]["AirA"]["subscriptionInfo"]["Total"], 100);
    }

    #[test]
    fn smart_marker_hidden_and_group_flagged() {
        let proxies = json!({
            "proxies": {
                "N1": {"name": "N1", "type": "Trojan"},
                "Smart": {"name": "Smart", "type": "Selector", "now": "N1",
                          "all": ["N1", "smartspeedtest@hide"]},
                "Plain": {"name": "Plain", "type": "Selector", "now": "N1", "all": ["N1"]},
                "GLOBAL": {"name": "GLOBAL", "type": "Selector", "now": "Smart",
                           "all": ["Smart", "Plain", "N1", "smartspeedtest@hide"]},
                "smartspeedtest@hide": {"name": "smartspeedtest@hide", "type": "Reject"}
            }
        });
        let providers = json!({
            "providers": {
                "Grp=(Pre🔗Grp)": {"vehicleType": "Inline", "proxies": [
                    {"name": "P1", "type": "Vless"},
                    {"name": "smartspeedtest@hide", "type": "Reject"}
                ]}
            }
        });
        let smart_urls =
            HashMap::from([("Smart".to_string(), "http://smart/204".to_string())]);
        let out: Value =
            serde_json::from_str(&build_trimmed(
                &px(proxies),
                &pv(providers),
                "rule",
                "u",
                &smart_urls,
                &|g| (g == "Smart").then(|| json!({"N1": {"score": 123, "samples": [100, null]}})),
            ))
            .unwrap();

        assert!(out["proxies"].get("smartspeedtest@hide").is_none());
        assert_eq!(out["proxies"]["Smart"]["all"], json!(["N1"]));
        assert_eq!(out["proxies"]["GLOBAL"]["all"], json!(["Smart", "Plain", "N1"]));
        assert_eq!(
            out["providers"]["Grp=(Pre🔗Grp)"]["proxies"],
            json!(["P1"])
        );

        assert_eq!(out["proxies"]["Smart"]["smart"], true);
        assert!(out["proxies"]["Plain"].get("smart").is_none());
        assert!(out["proxies"]["GLOBAL"].get("smart").is_none());

        assert_eq!(out["proxies"]["Smart"]["testUrl"], "http://smart/204");
        assert!(out["proxies"]["Plain"].get("testUrl").is_none());

        assert_eq!(out["proxies"]["Smart"]["scores"]["N1"]["score"], 123);
        assert_eq!(out["proxies"]["Smart"]["scores"]["N1"]["samples"], json!([100, null]));
        assert!(out["proxies"]["Plain"].get("scores").is_none());
        assert!(out["proxies"]["GLOBAL"].get("scores").is_none());
    }

    #[test]
    fn smart_test_url_falls_back_to_default() {
        let proxies = json!({"proxies": {
            "N1": {"name": "N1", "type": "Trojan"},
            "Smart": {"name": "Smart", "type": "Selector", "now": "N1",
                      "all": ["N1", "smartspeedtest@hide"]}
        }});

        let smart_urls = HashMap::from([("Smart".to_string(), String::new())]);
        let out: Value = serde_json::from_str(&build_trimmed(
            &px(proxies),
            &RawProviders::default(),
            "rule",
            "http://fallback/204",
            &smart_urls,
            &|_| None,
        ))
        .unwrap();
        assert_eq!(out["proxies"]["Smart"]["testUrl"], "http://fallback/204");
    }

    #[test]
    fn parse_test_url_variants() {
        assert_eq!(
            parse_test_url("test_node_url=\"http://a/204\"\nfoo=1"),
            "http://a/204"
        );
        assert_eq!(parse_test_url("test_node_url=http://b/204"), "http://b/204");
        assert_eq!(
            parse_test_url("  test_node_url = \"http://c\" "),
            "http://c"
        );
        assert_eq!(parse_test_url("other=1"), DEFAULT_TEST_URL);
        assert_eq!(parse_test_url("test_node_url="), DEFAULT_TEST_URL);

        assert_eq!(
            parse_test_url(
                "test_node_url=\"http://google.com\"\ntest_node_url=\"http://youtube.com\""
            ),
            "http://youtube.com"
        );

        assert_eq!(
            parse_test_url("test_node_url=\"http://a\"\ntest_node_url="),
            "http://a"
        );
    }

    #[test]
    fn dechunk_basic() {
        assert_eq!(
            dechunk_buffered(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"),
            b"Wikipedia"
        );
    }

    #[test]
    fn parse_status_line() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\nX: y"), 200);
        assert_eq!(parse_status(b"HTTP/1.1 404 Not Found"), 404);
        assert_eq!(parse_status(b"garbage"), 0);
    }

    #[test]
    fn pct_encode_segment_unicode() {
        assert_eq!(pct_encode_segment("ab-1_2.3~"), "ab-1_2.3~");
        assert_eq!(pct_encode_segment("a b"), "a%20b");

        assert_eq!(pct_encode_segment("café"), "caf%C3%A9");
    }

    #[test]
    fn find_provider_node_by_name() {
        let body = json!({
            "providers": {
                "subhuayi": { "vehicleType": "HTTP", "proxies": [
                    {"name": "US🇺🇸-SJC-direct-backup", "type": "Trojan", "server": "1.2.3.4", "port": 443,
                     "history": [{"time":"t","delay": 88}]},
                    {"name": "Hong Kong-IX", "type": "Vless", "server": "5.6.7.8", "port": 8443}
                ]},
                "default": { "vehicleType": "Compatible", "proxies": [] }
            }
        })
        .to_string();
        let node: Value =
            serde_json::from_str(&find_provider_node(body.as_bytes(), "US🇺🇸-SJC-direct-backup").unwrap())
                .unwrap();
        assert_eq!(node["type"], "Trojan");
        assert_eq!(node["server"], "1.2.3.4");
        assert_eq!(node["port"], 443);
        assert_eq!(node["history"][0]["delay"], 88);

        assert!(find_provider_node(body.as_bytes(), "nonexistent").is_none());

        assert!(find_provider_node(b"not json", "x").is_none());
    }

    #[test]
    fn missing_proxies_key_yields_empty_map() {
        let out: Value =
            serde_json::from_str(&build_trimmed(
                &px(json!({})),
                &RawProviders::default(),
                "rule",
                "u",
                &HashMap::new(),
                &|_| None
            ))
            .unwrap();
        assert_eq!(out["proxies"], json!({}));
        assert_eq!(out["providers"], json!({}));
    }
}
