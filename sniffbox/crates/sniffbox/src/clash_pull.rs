// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::runtime::{SharedState, SocksSrc};
use dashmap::DashMap;
use sb_stats::NodeDist;
use sb_stats::types::{ConnRecord, InboundKind, SniffedProto, Transport};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

const PPLOG_NODE_INTERVAL: Duration = Duration::from_secs(600);

const CONNS_DEMAND_WINDOW_MS: u64 = 30_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClashConn {
    pub id: String,
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub inbound_type: String,
    pub network: String,
    pub host: String,
    pub src_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
}

impl ClashConn {

    fn endpoint(&self) -> &str {
        self.chains.first().map(String::as_str).unwrap_or("")
    }
}

pub fn spawn(
    shared: Arc<SharedState>,
    clash_sock: PathBuf,
    interval: Duration,
    nodes_enabled: bool,
    shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(run(shared, clash_sock, interval, nodes_enabled, shutdown));
}

async fn run(
    shared: Arc<SharedState>,
    clash_sock: PathBuf,
    interval: Duration,
    nodes_enabled: bool,
    mut shutdown: watch::Receiver<bool>,
) {

    let mut last: HashMap<String, (u64, u64)> = HashMap::new();

    let mut mirror: HashMap<String, Arc<ConnRecord>> = HashMap::new();

    let mut gate = ListenersGate::new(PathBuf::from(crate::clash_ctl::CLASH_YAML));
    let mut last_pplog = tokio::time::Instant::now();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::info!(sock = %clash_sock.display(), ?interval, nodes_enabled, "clash /connections poll started");
    loop {
        tokio::select! {
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
            _ = ticker.tick() => {

                let need_conns = conns_in_demand(&shared);
                if !nodes_enabled && !need_conns {
                    continue;
                }
                match fetch_connections(&clash_sock).await {
                    Ok(json) => {
                        if nodes_enabled {
                            let conns = parse_connections(&json);
                            accumulate(&shared.node_dist, &mut last, &conns);
                            shared.node_dist.rebuild();
                            let active = gate.check();
                            if !active.is_empty() {
                                mirror_direct_inbounds(&shared, &mut mirror, &conns, &active);
                            } else if !mirror.is_empty() {

                                mirror_direct_inbounds(&shared, &mut mirror, &[], &active);
                            }
                        }

                        if need_conns {
                            let restored = restore_sources(&shared, &json);
                            shared.clash_conns_cache.store(Some(Arc::new(restored)));
                        }
                    }
                    Err(e) => tracing::debug!(?e, "clash /connections poll failed"),
                }
                if nodes_enabled
                    && let Some(p) = &shared.pplog
                    && last_pplog.elapsed() >= PPLOG_NODE_INTERVAL
                {
                    p.node_dist(shared.node_dist.snapshot());
                    last_pplog = tokio::time::Instant::now();
                }
            }
        }
    }
    tracing::info!("clash /connections poll exited");
}

fn conns_in_demand(shared: &SharedState) -> bool {
    let last = shared
        .clash_conns_last_access
        .load(std::sync::atomic::Ordering::Relaxed);
    in_demand_window(last, sb_stats::now_epoch_ms())
}

fn in_demand_window(last: u64, now: u64) -> bool {
    last != 0 && now.saturating_sub(last) <= CONNS_DEMAND_WINDOW_MS
}

pub fn accumulate(
    node_dist: &NodeDist,
    last: &mut HashMap<String, (u64, u64)>,
    conns: &[ClashConn],
) {
    let mut seen: HashSet<&str> = HashSet::with_capacity(conns.len());
    for c in conns {
        seen.insert(c.id.as_str());
        let (pu, pd) = last.get(&c.id).copied().unwrap_or((0, 0));

        let dup = c.upload.saturating_sub(pu);
        let ddown = c.download.saturating_sub(pd);
        node_dist.add(c.endpoint(), dup, ddown);
        last.insert(c.id.clone(), (c.upload, c.download));
    }
    last.retain(|id, _| seen.contains(id.as_str()));
}

fn clash_inbound_label(t: &str) -> Option<&'static str> {
    const SKIP: &[&str] = &[
        "https", "http", "redir", "socks4", "socks5", "tproxy", "tun", "inner",
    ];

    const KNOWN: &[&str] = &[
        "anytls",
        "hysteria2",
        "mieru",
        "shadowsocks",
        "snell",
        "sudoku",
        "trojan",
        "trusttunnel",
        "tuic",
        "tunnel",
        "vless",
        "vmess",
    ];
    if t.is_empty() || SKIP.iter().any(|s| t.eq_ignore_ascii_case(s)) {
        return None;
    }
    Some(
        KNOWN
            .iter()
            .find(|k| t.eq_ignore_ascii_case(k))
            .copied()
            .unwrap_or("clash"),
    )
}

pub fn config_listener_types(yaml: &str) -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    let mut in_block = false;
    for line in yaml.lines() {
        let is_top = !line.starts_with([' ', '\t']) && !line.trim().is_empty();
        if is_top {
            if let Some(rest) = line.strip_prefix("listeners:") {
                let rest = rest.split('#').next().unwrap_or("").trim();
                if rest.is_empty() {
                    in_block = true;
                } else {
                    collect_types(rest, &mut types);
                    in_block = false;
                }
                continue;
            }
            in_block = false;
            continue;
        }
        if in_block {
            collect_types(line, &mut types);
        }
    }
    types
}

fn collect_types(s: &str, out: &mut BTreeSet<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while let Some(rel) = s[i..].find("type:") {
        let start = i + rel;
        i = start + 5;
        let boundary_ok =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'-');
        if !boundary_ok {
            continue;
        }
        let val: String = s[i..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if !val.is_empty() {
            out.insert(val.to_ascii_lowercase());
        }
    }
}

struct ListenersGate {
    path: PathBuf,
    mtime: Option<std::time::SystemTime>,
    checked: bool,
    types: Arc<BTreeSet<String>>,
}

impl ListenersGate {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            mtime: None,
            checked: false,
            types: Arc::new(BTreeSet::new()),
        }
    }

    fn check(&mut self) -> Arc<BTreeSet<String>> {
        let mt = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if !self.checked || mt != self.mtime {
            self.checked = true;
            self.mtime = mt;
            let types = mt
                .map(|_| {
                    config_listener_types(&std::fs::read_to_string(&self.path).unwrap_or_default())
                })
                .unwrap_or_default();
            if types != *self.types {
                tracing::info!(?types, "clash listeners mirror gate changed");
                self.types = Arc::new(types);
            }
        }
        Arc::clone(&self.types)
    }
}

pub fn mirror_direct_inbounds(
    shared: &SharedState,
    mirror: &mut HashMap<String, Arc<ConnRecord>>,
    conns: &[ClashConn],
    active: &BTreeSet<String>,
) {
    let mut seen: HashSet<&str> = HashSet::with_capacity(conns.len());
    for c in conns {
        let Some(label) = clash_inbound_label(&c.inbound_type) else {
            continue;
        };

        if !active.contains(&c.inbound_type.to_ascii_lowercase()) {
            continue;
        }
        let Some(src_ip) = c.src_ip else { continue };
        if src_ip.is_loopback() {
            continue;
        }
        seen.insert(c.id.as_str());
        let rec = mirror.entry(c.id.clone()).or_insert_with(|| {
            let transport = if c.network.eq_ignore_ascii_case("udp") {
                Transport::Udp
            } else {
                Transport::Tcp
            };
            let domain = (!c.host.is_empty()).then(|| c.host.clone());
            let dst = (c.dst_ip.unwrap_or(IpAddr::from([0, 0, 0, 0])), c.dst_port);
            let r = Arc::new(
                ConnRecord::new(
                    shared.id_gen.next_id(),
                    (src_ip, c.src_port),
                    dst,
                    SniffedProto::Unknown,
                    domain,
                )
                .with_inbound(InboundKind::Clash(label), transport),
            );
            shared.conn_table.insert(Arc::clone(&r));
            if let Some(p) = &shared.pplog {
                p.open(&r);
            }
            r
        });

        if shared.conn_table.get(rec.id).is_none() {
            shared.conn_table.insert(Arc::clone(rec));
        }
        rec.upload.store(c.upload, Ordering::Relaxed);
        rec.download.store(c.download, Ordering::Relaxed);
    }
    mirror.retain(|id, rec| {
        if seen.contains(id.as_str()) {
            return true;
        }
        shared.conn_table.close(rec.id);
        if let Some(p) = &shared.pplog {
            p.close(rec);
        }
        false
    });
}

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_RESP_BYTES: u64 = 64 * 1024 * 1024;

async fn fetch_connections(sock: &Path) -> std::io::Result<String> {
    tokio::time::timeout(FETCH_TIMEOUT, fetch_connections_inner(sock))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "clash /connections did not answer in time",
            )
        })?
}

async fn fetch_connections_inner(sock: &Path) -> std::io::Result<String> {
    let mut up = UnixStream::connect(sock).await?;
    up.write_all(b"GET /connections HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    up.flush().await?;
    let mut buf = Vec::new();
    let hl = sb_web::http::read_head(&mut up, &mut buf).await?;
    let resp = sb_web::http::parse_response(&buf[..hl])?;
    let mut body = buf.split_off(hl);
    let mut rest = Vec::new();
    AsyncReadExt::take(&mut up, MAX_RESP_BYTES)
        .read_to_end(&mut rest)
        .await?;
    body.extend_from_slice(&rest);
    if matches!(resp.framing(false), Ok(sb_web::http::Framing::Chunked)) {
        body = dechunk_buffered(&body);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
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

pub fn restore_sources(shared: &SharedState, json: &str) -> String {
    restore_with_index(&shared.socks_src_index, json)
}

pub fn restore_with_index(index: &DashMap<u16, SocksSrc>, json: &str) -> String {
    restore_fast(index, json).unwrap_or_else(|| restore_via_value(index, json))
}

fn restore_via_value(index: &DashMap<u16, SocksSrc>, json: &str) -> String {
    let mut v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#.to_string(),
    };
    if let Some(arr) = v.get_mut("connections").and_then(|c| c.as_array_mut()) {
        arr.retain_mut(|c| restore_one(index, c));
    }
    v.to_string()
}

fn restore_one(index: &DashMap<u16, SocksSrc>, c: &mut serde_json::Value) -> bool {
    let Some(meta) = c.get_mut("metadata").and_then(|m| m.as_object_mut()) else {
        return true;
    };
    let src_ip = meta.get("sourceIP").and_then(|x| x.as_str()).unwrap_or("");

    let is_loopback = src_ip
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);
    if !is_loopback {
        return true;
    }

    let port = meta
        .get("sourcePort")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<u16>().ok());
    let Some(src) = port.and_then(|p| index.get(&p).map(|e| *e.value())) else {
        return false;
    };
    meta.insert(
        "sourceIP".into(),
        serde_json::Value::String(src.ip.to_string()),
    );
    meta.insert(
        "sourcePort".into(),
        serde_json::Value::String(src.port.to_string()),
    );
    meta.insert(
        "type".into(),
        serde_json::Value::String(crate::runtime::inbound_type_str(src.inbound).to_string()),
    );
    true
}

fn restore_fast(index: &DashMap<u16, SocksSrc>, json: &str) -> Option<String> {
    let top: TopDoc<'_> = serde_json::from_str(json).ok()?;
    let mut out = String::with_capacity(json.len());
    out.push('{');
    for (i, (k, v)) in top.0.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_str(&mut out, k);
        out.push(':');
        match v {
            TopField::Raw(r) => out.push_str(r.get()),
            TopField::Null => out.push_str("null"),
            TopField::Conns(conns) => {
                out.push('[');
                let mut kept = 0usize;
                for c in conns {
                    let rewrite = match classify_conn(index, c) {
                        ConnAction::Drop => continue,
                        ConnAction::Keep => None,
                        ConnAction::Rewrite(src) => Some(src),
                    };
                    if kept > 0 {
                        out.push(',');
                    }
                    kept += 1;
                    write_conn(&mut out, c, rewrite.as_ref());
                }
                out.push(']');
            }
        }
    }
    out.push('}');
    Some(out)
}

enum ConnAction {

    Keep,

    Drop,

    Rewrite(SocksSrc),
}

fn classify_conn(index: &DashMap<u16, SocksSrc>, c: &ConnObj<'_>) -> ConnAction {
    let meta = c.0.iter().rev().find_map(|(k, v)| match v {
        _ if k.as_ref() != "metadata" => None,
        ConnField::Meta(m) => Some(Some(m)),
        _ => Some(None),
    });
    let Some(Some(meta)) = meta else {
        return ConnAction::Keep;
    };
    let is_loopback = meta
        .last("sourceIP")
        .and_then(json_str)
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if !is_loopback {
        return ConnAction::Keep;
    }
    let port = meta
        .last("sourcePort")
        .and_then(json_str)
        .and_then(|s| s.parse::<u16>().ok());
    match port.and_then(|p| index.get(&p).map(|e| *e.value())) {
        Some(src) => ConnAction::Rewrite(src),
        None => ConnAction::Drop,
    }
}

fn write_conn(out: &mut String, c: &ConnObj<'_>, rewrite: Option<&SocksSrc>) {
    out.push('{');
    for (i, (k, v)) in c.0.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_str(out, k);
        out.push(':');
        match v {
            ConnField::Raw(r) => out.push_str(r.get()),
            ConnField::Null => out.push_str("null"),
            ConnField::Meta(m) => write_meta(out, m, rewrite),
        }
    }
    out.push('}');
}

fn write_meta(out: &mut String, meta: &RawObj<'_>, rewrite: Option<&SocksSrc>) {
    use std::fmt::Write as _;
    out.push('{');
    let mut has_type = false;
    for (i, (k, v)) in meta.0.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_str(out, k);
        out.push(':');
        match (rewrite, k.as_ref()) {

            (Some(src), "sourceIP") => {
                let _ = write!(out, "\"{}\"", src.ip);
            }
            (Some(src), "sourcePort") => {
                let _ = write!(out, "\"{}\"", src.port);
            }
            (Some(src), "type") => {
                has_type = true;
                push_json_str(out, crate::runtime::inbound_type_str(src.inbound));
            }
            _ => out.push_str(v.get()),
        }
    }
    if let Some(src) = rewrite
        && !has_type
    {

        if !meta.0.is_empty() {
            out.push(',');
        }
        out.push_str("\"type\":");
        push_json_str(out, crate::runtime::inbound_type_str(src.inbound));
    }
    out.push('}');
}

fn push_json_str(out: &mut String, s: &str) {
    if s.bytes().all(|b| b >= 0x20 && b != b'"' && b != b'\\') {
        out.push('"');
        out.push_str(s);
        out.push('"');
    } else {
        out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()));
    }
}

fn json_str(v: &RawValue) -> Option<Cow<'_, str>> {
    serde_json::from_str::<JsonStr<'_>>(v.get())
        .ok()
        .map(|s| s.0)
}

struct JsonStr<'a>(Cow<'a, str>);

impl<'de> serde::Deserialize<'de> for JsonStr<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = JsonStr<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                s: &'de str,
            ) -> Result<Self::Value, E> {
                Ok(JsonStr(Cow::Borrowed(s)))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(JsonStr(Cow::Owned(s.to_owned())))
            }
        }
        d.deserialize_str(V)
    }
}

fn visit_fields<'de, A, F>(
    mut m: A,
    mut field: impl FnMut(&str, &mut A) -> Result<F, A::Error>,
) -> Result<Vec<(Cow<'de, str>, F)>, A::Error>
where
    A: serde::de::MapAccess<'de>,
{
    let mut fields = Vec::with_capacity(m.size_hint().unwrap_or(0));
    while let Some(JsonStr(k)) = m.next_key()? {
        let v = field(&k, &mut m)?;
        fields.push((k, v));
    }
    Ok(fields)
}

struct RawObj<'a>(Vec<(Cow<'a, str>, &'a RawValue)>);

impl<'de> serde::Deserialize<'de> for RawObj<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = RawObj<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                m: A,
            ) -> Result<Self::Value, A::Error> {
                visit_fields(m, |_, m| m.next_value::<&'de RawValue>()).map(RawObj)
            }
        }
        d.deserialize_map(V)
    }
}

impl<'a> RawObj<'a> {

    fn last(&self, key: &str) -> Option<&'a RawValue> {
        self.0
            .iter()
            .rev()
            .find(|(k, _)| k.as_ref() == key)
            .map(|(_, v)| *v)
    }
}

struct ConnObj<'a>(Vec<(Cow<'a, str>, ConnField<'a>)>);

enum ConnField<'a> {
    Raw(&'a RawValue),
    Null,
    Meta(RawObj<'a>),
}

impl<'de> serde::Deserialize<'de> for ConnObj<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = ConnObj<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a connection object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                m: A,
            ) -> Result<Self::Value, A::Error> {
                visit_fields(m, |k, m| {
                    Ok(if k == "metadata" {
                        match m.next_value::<Option<RawObj<'de>>>()? {
                            Some(o) => ConnField::Meta(o),
                            None => ConnField::Null,
                        }
                    } else {
                        ConnField::Raw(m.next_value()?)
                    })
                })
                .map(ConnObj)
            }
        }
        d.deserialize_map(V)
    }
}

struct TopDoc<'a>(Vec<(Cow<'a, str>, TopField<'a>)>);

enum TopField<'a> {
    Raw(&'a RawValue),

    Null,
    Conns(Vec<ConnObj<'a>>),
}

impl<'de> serde::Deserialize<'de> for TopDoc<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = TopDoc<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a connections snapshot object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                m: A,
            ) -> Result<Self::Value, A::Error> {
                visit_fields(m, |k, m| {
                    Ok(if k == "connections" {
                        match m.next_value::<Option<Vec<ConnObj<'de>>>>()? {
                            Some(c) => TopField::Conns(c),
                            None => TopField::Null,
                        }
                    } else {
                        TopField::Raw(m.next_value()?)
                    })
                })
                .map(TopDoc)
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct WireConns {
    #[serde(deserialize_with = "null_as_empty_vec")]
    connections: Vec<WireConn>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct WireConn {
    id: String,
    #[serde(deserialize_with = "null_as_empty_vec")]
    chains: Vec<String>,
    upload: u64,
    download: u64,
    metadata: WireMeta,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct WireMeta {
    #[serde(rename = "type")]
    typ: String,
    network: String,
    host: String,
    #[serde(rename = "sourceIP")]
    source_ip: String,
    #[serde(rename = "sourcePort", deserialize_with = "port_of")]
    source_port: u16,
    #[serde(rename = "destinationIP")]
    destination_ip: String,
    #[serde(rename = "destinationPort", deserialize_with = "port_of")]
    destination_port: u16,
}

fn null_as_empty_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(<Option<Vec<T>> as serde::Deserialize>::deserialize(d)?.unwrap_or_default())
}

fn port_of<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
    Ok(
        match <Option<serde_json::Value> as serde::Deserialize>::deserialize(d)? {
            Some(serde_json::Value::String(s)) => s.parse().unwrap_or(0),
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0).try_into().unwrap_or(0),
            _ => 0,
        },
    )
}

pub fn parse_connections(json: &str) -> Vec<ClashConn> {
    let Ok(w) = serde_json::from_str::<WireConns>(json) else {
        return Vec::new();
    };
    w.connections
        .into_iter()
        .map(|c| ClashConn {
            id: c.id,
            chains: c.chains,
            upload: c.upload,
            download: c.download,
            src_ip: c.metadata.source_ip.parse().ok(),
            src_port: c.metadata.source_port,
            dst_ip: c.metadata.destination_ip.parse().ok(),
            dst_port: c.metadata.destination_port,
            inbound_type: c.metadata.typ,
            network: c.metadata.network,
            host: c.metadata.host,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "downloadTotal": 100, "uploadTotal": 50,
        "connections": [
            {"id":"a","metadata":{"host":"example.com"},"chains":["HKG 01","Asia-Pacific"],"upload":10,"download":20},
            {"id":"b","metadata":{"host":"x"},"chains":["JP 02","Asia-Pacific"],"upload":7,"download":9}
        ]
    }"#;

    #[test]
    fn parse_extracts_id_chains_bytes() {
        let conns = parse_connections(SAMPLE);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].id, "a");
        assert_eq!(conns[0].endpoint(), "HKG 01");
        assert_eq!(conns[0].upload, 10);
        assert_eq!(conns[1].endpoint(), "JP 02");
    }

    #[test]
    fn parse_bad_json_is_empty() {
        assert!(parse_connections("not json").is_empty());
        assert!(parse_connections("{}").is_empty());
    }

    fn parse_connections_via_value(json: &str) -> Vec<ClashConn> {
        let v: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let Some(arr) = v.get("connections").and_then(|c| c.as_array()) else {
            return Vec::new();
        };
        arr.iter()
            .map(|c| {
                let chains = c
                    .get("chains")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let meta = c.get("metadata");
                let ms = |k: &str| {
                    meta.and_then(|m| m.get(k))
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                };
                ClashConn {
                    id: c
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    chains,
                    upload: c.get("upload").and_then(|x| x.as_u64()).unwrap_or(0),
                    download: c.get("download").and_then(|x| x.as_u64()).unwrap_or(0),
                    inbound_type: ms("type").to_string(),
                    network: ms("network").to_string(),
                    host: ms("host").to_string(),
                    src_ip: ms("sourceIP").parse().ok(),
                    src_port: ms("sourcePort").parse().unwrap_or(0),
                    dst_ip: ms("destinationIP").parse().ok(),
                    dst_port: ms("destinationPort").parse().unwrap_or(0),
                }
            })
            .collect()
    }

    #[test]
    fn typed_parse_matches_the_value_based_reference() {
        let cases: &[&str] = &[
            SAMPLE,

            r#"{"downloadTotal":0,"uploadTotal":0,"connections":null}"#,
            r#"{"connections":[]}"#,

            r#"{"connections":[{"id":"a","chains":null,"upload":1,"download":2}]}"#,

            r#"{"connections":[{"id":"a","chains":["N"],"upload":1,"download":2}]}"#,

            r#"{"connections":[{"id":"a","chains":["N","G"],"upload":1,"download":2,
                "metadata":{"type":"Shadowsocks","network":"tcp","host":"x.com",
                "sourceIP":"10.0.0.5","sourcePort":"40001",
                "destinationIP":"1.2.3.4","destinationPort":"443"}}]}"#,

            r#"{"connections":[{"id":"a","metadata":{"sourceIP":"not-an-ip","sourcePort":"99999",
                "destinationIP":"","destinationPort":"abc"}}]}"#,

            r#"{"connections":[{"metadata":{}}]}"#,

            "not json",
            "{}",
            "[]",
        ];
        for j in cases {
            assert_eq!(
                parse_connections(j),
                parse_connections_via_value(j),
                "typed parse diverged from the Value reference on: {j}"
            );
        }
    }

    #[test]
    fn numeric_ports_do_not_void_the_whole_snapshot() {
        let j = r#"{"connections":[{"id":"a","chains":["N"],
            "metadata":{"sourcePort":40001,"destinationPort":443}}]}"#;
        let got = parse_connections(j);
        assert_eq!(got.len(), 1, "one malformed field must not drop the record");
        assert_eq!(got[0].id, "a");
        assert_eq!(got[0].src_port, 40001);
        assert_eq!(got[0].dst_port, 443);

        assert_eq!(parse_connections_via_value(j).len(), 1);
    }

    #[test]
    fn dechunk_roundtrip() {
        let chunked = b"18\r\n{\"connections\":[],\"x\":1}\r\n0\r\n\r\n";
        let out = dechunk_buffered(chunked);
        assert_eq!(out, br#"{"connections":[],"x":1}"#);
    }

    #[test]
    fn accumulate_deltas_by_endpoint_node() {
        let nd = NodeDist::new();
        let mut last = HashMap::new();

        accumulate(&nd, &mut last, &parse_connections(SAMPLE));

        let p2 = r#"{"connections":[
            {"id":"a","chains":["HKG 01"],"upload":100,"download":200},
            {"id":"b","chains":["JP 02"],"upload":7,"download":9},
            {"id":"c","chains":["HKG 01"],"upload":5,"download":5}
        ]}"#;
        accumulate(&nd, &mut last, &parse_connections(p2));
        nd.rebuild();
        let v: serde_json::Value = serde_json::from_str(&nd.snapshot_json()).unwrap();
        let nodes = v["nodes"].as_array().unwrap();

        let hkg = nodes.iter().find(|n| n["node"] == "HKG 01").unwrap();
        assert_eq!(hkg["total"], 310);
        let jp = nodes.iter().find(|n| n["node"] == "JP 02").unwrap();
        assert_eq!(jp["total"], 16);
    }

    #[test]
    fn restore_rewrites_loopback_drops_unmatched_keeps_nonloopback() {
        use sb_stats::InboundKind;
        use std::net::IpAddr;
        let index: DashMap<u16, SocksSrc> = DashMap::new();

        index.insert(
            40001,
            SocksSrc {
                ip: "10.0.0.5".parse::<IpAddr>().unwrap(),
                port: 1234,
                inbound: InboundKind::TProxy,
            },
        );
        let raw = r#"{
            "downloadTotal": 100, "uploadTotal": 50,
            "connections": [
                {"id":"a","metadata":{"type":"Socks5","sourceIP":"127.0.0.1","sourcePort":"40001","host":"x.com"},"chains":["N"],"upload":1,"download":2},
                {"id":"b","metadata":{"type":"Socks5","sourceIP":"127.0.0.1","sourcePort":"55555","host":"speedtest"},"chains":["N"],"upload":3,"download":4},
                {"id":"c","metadata":{"type":"TProxy","sourceIP":"192.168.1.9","sourcePort":"6000","host":"y.com"},"chains":["N"],"upload":5,"download":6}
            ]
        }"#;
        let out = restore_with_index(&index, raw);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["downloadTotal"], 100);
        assert_eq!(v["uploadTotal"], 50);
        let conns = v["connections"].as_array().unwrap();

        assert_eq!(conns.len(), 2);
        let a = conns.iter().find(|c| c["id"] == "a").unwrap();

        assert_eq!(a["metadata"]["sourceIP"], "10.0.0.5");
        assert_eq!(a["metadata"]["sourcePort"], "1234");
        assert_eq!(a["metadata"]["type"], "TProxy");
        let c = conns.iter().find(|c| c["id"] == "c").unwrap();

        assert_eq!(c["metadata"]["sourceIP"], "192.168.1.9");
        assert_eq!(c["metadata"]["sourcePort"], "6000");
        assert!(
            conns.iter().all(|c| c["id"] != "b"),
            "unmatched loopback b must be dropped"
        );
    }

    #[test]
    fn demand_window_gates_on_recent_access() {

        assert!(!in_demand_window(0, 1_000_000));

        assert!(in_demand_window(1_000_000, 1_000_000));

        assert!(in_demand_window(1_000_000, 1_000_000 + 29_000));

        assert!(in_demand_window(1_000_000, 1_000_000 + 30_000));

        assert!(!in_demand_window(1_000_000, 1_000_000 + 31_000));
    }

    #[test]
    fn restore_bad_json_is_empty_snapshot() {
        let index: DashMap<u16, SocksSrc> = DashMap::new();
        let out = restore_with_index(&index, "not json");
        assert_eq!(
            out,
            r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#
        );
    }

    fn restore_index() -> DashMap<u16, SocksSrc> {
        use std::net::IpAddr;
        let index = DashMap::new();
        index.insert(
            40001,
            SocksSrc {
                ip: "10.0.0.5".parse::<IpAddr>().unwrap(),
                port: 1234,
                inbound: InboundKind::TProxy,
            },
        );
        index.insert(
            40002,
            SocksSrc {
                ip: "fd00::9".parse::<IpAddr>().unwrap(),
                port: 5353,
                inbound: InboundKind::Socks5,
            },
        );
        index
    }

    fn synthetic_connections(n: usize) -> String {
        use std::fmt::Write as _;
        let mut s = String::from(
            r#"{"downloadTotal":123456789,"uploadTotal":98765,"memory":52428800,"connections":["#,
        );
        for i in 0..n {
            if i > 0 {
                s.push(',');
            }
            let (ip, port) = match i % 4 {
                0 => ("127.0.0.1", 40001),
                1 => ("127.0.0.1", 50_000 + (i % 1000) as u16),
                2 => ("192.0.2.20", 6000),
                _ => ("::1", 40002),
            };
            write!(
                s,
                r#"{{"id":"{i:08x}-0000-4000-8000-{i:012x}","metadata":{{"network":"tcp","type":"Socks5","sourceIP":"{ip}","destinationIP":"203.0.113.{d}","sourcePort":"{port}","destinationPort":"443","inboundIP":"127.0.0.1","inboundPort":"1080","inboundName":"DEFAULT-SOCKS","inboundUser":"","host":"host{i}.example.net","dnsMode":"normal","uid":0,"process":"","processPath":"","specialProxy":"","specialRules":"","remoteDestination":"203.0.113.{d}","dscp":0,"sniffHost":""}},"upload":{up},"download":{down},"start":"2026-01-01T00:00:00.{ms:03}Z","chains":["Node {c}","Proxy"],"rule":"DomainSuffix","rulePayload":"example.net"}}"#,
                d = i % 250,
                up = i * 1311,
                down = i * 7919,
                ms = i % 1000,
                c = i % 40,
            )
            .unwrap();
        }
        s.push_str("]}");
        s
    }

    const DUP_CONNECTIONS: &str = r#"{"connections":[],"connections":[{"id":"x","metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"}}]}"#;

    #[test]
    fn fast_restore_matches_the_value_reference() {
        let index = restore_index();
        let synthetic = synthetic_connections(64);
        let cases: Vec<&str> = vec![
            SAMPLE,
            r#"{
                "downloadTotal": 100, "uploadTotal": 50,
                "connections": [
                    {"id":"a","metadata":{"type":"Socks5","sourceIP":"127.0.0.1","sourcePort":"40001","host":"x.com"},"chains":["N"],"upload":1,"download":2},
                    {"id":"b","metadata":{"type":"Socks5","sourceIP":"127.0.0.1","sourcePort":"55555","host":"speedtest"},"chains":["N"],"upload":3,"download":4},
                    {"id":"c","metadata":{"type":"TProxy","sourceIP":"192.168.1.9","sourcePort":"6000","host":"y.com"},"chains":["N"],"upload":5,"download":6}
                ]
            }"#,
            r#"{"downloadTotal":0,"uploadTotal":0,"connections":null}"#,
            r#"{"connections":[]}"#,
            r#"{"connections":{"not":"an array"}}"#,
            r#"{"connections":[1,"x",null,[],{},true]}"#,

            r#"{"connections":[{"id":"a"},{"id":"b","metadata":null},{"id":"c","metadata":[1]}]}"#,

            r#"{"connections":[{"id":"a","metadata":{"sourceIP":2130706433,"sourcePort":"40001"}}]}"#,

            r#"{"connections":[{"id":"a","metadata":{"sourceIP":"127.0.0.1","sourcePort":40001}},{"id":"b","metadata":{"sourceIP":"127.0.0.1","sourcePort":"99999"}},{"id":"c","metadata":{"sourceIP":"127.0.0.1"}},{"id":"d","metadata":{"sourceIP":"127.0.0.1","sourcePort":""}}]}"#,

            r#"{"connections":[{"id":"v6","metadata":{"type":"Socks5","sourceIP":"::1","sourcePort":"40002","host":"h"}},{"id":"m","metadata":{"sourceIP":"::ffff:127.0.0.1","sourcePort":"40001"}}]}"#,

            r#"{"connections":[{"id":"nt","metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"}}]}"#,

            r#"{"connections":[{"id":"e\u0073c","metadata":{"source\u0049P":"127.0.0.1","sourcePort":"4000\u0031","host":"例子.test","path":"a\"b\\c\n\t"},"rule":"DOMAIN","chains":["节点 🌐","Gé"]}],"we\"ird":"v"}"#,

            r#"{"downloadTotal":18446744073709551615,"uploadTotal":1.5e3,"memory":-0,"connections":[{"id":"n","upload":123456789012,"download":0.25,"metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001","big":1e300}}]}"#,

            r#"{"connections":[{"id":"x","id":"y","metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001","host":"a","host":"b"}}]}"#,
            DUP_CONNECTIONS,
            r#"{"connections":[{"id":"x","metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"}}],"connections":null}"#,
            r#"{"connections":[{"id":"d","metadata":{"sourceIP":"10.0.0.1"},"metadata":{"sourceIP":"127.0.0.1","sourcePort":"55555"}}]}"#,
            r#"{"connections":[{"id":"d2","metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"},"metadata":{"sourceIP":"10.0.0.1"}}]}"#,
            r#"{"connections":[{"id":"d3","metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"},"metadata":null}]}"#,
            r#"{"connections":[{"id":"d4","metadata":null,"metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"}}]}"#,
            r#"{"connections":[{"id":"d5","metadata":{},"metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"}}]}"#,
            r#"{"connections":[{"metadata":{"sourceIP":"127.0.0.1","sourceIP":"192.168.1.2","sourcePort":"40001"}}]}"#,
            r#"{"connections":[{"metadata":{"sourceIP":"192.168.1.2","sourceIP":"127.0.0.1","sourcePort":"40001"}}]}"#,
            r#"{"connections":[{"metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001","sourcePort":"55555"}}]}"#,
            r#"{"connections":[{"metadata":{"sourceIP":"127.0.0.1","sourcePort":"55555","sourcePort":"40002"}}]}"#,
            r#"{"connections":[{"metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001","type":"A","type":"B"}}]}"#,

            "{}",
            "[]",
            "null",
            r#""s""#,
            "not json",
            r#"{"connections":["#,
            r#"{"connections":[]} trailing"#,
            &synthetic,
        ];
        for j in cases {
            let fast = restore_with_index(&index, j);
            let reference = restore_via_value(&index, j);
            let a: serde_json::Value = serde_json::from_str(&fast)
                .unwrap_or_else(|e| panic!("fast output is not valid JSON ({e}) for: {j}"));
            let b: serde_json::Value = serde_json::from_str(&reference).unwrap();
            assert_eq!(
                a, b,
                "fast restore diverged from the Value reference on: {j}"
            );
        }
    }

    #[test]
    fn fast_restore_matches_reference_on_generated_shapes() {
        const SRC_IP: &[&str] = &[
            r#""127.0.0.1""#,
            r#""::1""#,
            r#""192.0.2.7""#,
            r#""127.0.0.\u0031""#,
            "2130706433",
            "null",
            r#""""#,
        ];
        const SRC_PORT: &[&str] = &[
            r#""40001""#,
            r#""40002""#,
            r#""55555""#,
            "40001",
            r#""""#,
            r#""4000\u0031""#,
            "null",
        ];
        const TYPE: &[&str] = &[r#""Socks5""#, r#""HTTP""#, "null", "7"];
        const OTHER: &[&str] = &[
            r#""host":"a.example""#,
            r#""uid":0"#,
            r#""path":"a\"b\\c""#,
            r#""big":1e300"#,
        ];
        let index = restore_index();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut pick = move |n: usize| -> usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        for _ in 0..4000 {
            let mut doc = String::from("{");
            for t in 0..1 + pick(3) {
                if t > 0 {
                    doc.push(',');
                }
                match pick(5) {
                    0 => doc.push_str(r#""downloadTotal":123"#),
                    1 => doc.push_str(r#""connections":null"#),
                    _ => {
                        doc.push_str(r#""connections":["#);
                        for c in 0..pick(4) {
                            if c > 0 {
                                doc.push(',');
                            }
                            doc.push('{');
                            for f in 0..pick(4) {
                                if f > 0 {
                                    doc.push(',');
                                }
                                let meta_key = [r#""metadata""#, r#""meta\u0064ata""#][pick(2)];
                                match pick(4) {
                                    0 => doc.push_str(r#""id":"x""#),
                                    1 => {
                                        doc.push_str(meta_key);
                                        doc.push_str(":null");
                                    }
                                    _ => {
                                        doc.push_str(meta_key);
                                        doc.push_str(":{");
                                        for m in 0..pick(5) {
                                            if m > 0 {
                                                doc.push(',');
                                            }
                                            match pick(4) {
                                                0 => {
                                                    doc.push_str(
                                                        [r#""sourceIP":"#, r#""source\u0049P":"#]
                                                            [pick(2)],
                                                    );
                                                    doc.push_str(SRC_IP[pick(SRC_IP.len())]);
                                                }
                                                1 => {
                                                    doc.push_str(r#""sourcePort":"#);
                                                    doc.push_str(SRC_PORT[pick(SRC_PORT.len())]);
                                                }
                                                2 => {
                                                    doc.push_str(r#""type":"#);
                                                    doc.push_str(TYPE[pick(TYPE.len())]);
                                                }
                                                _ => doc.push_str(OTHER[pick(OTHER.len())]),
                                            }
                                        }
                                        doc.push('}');
                                    }
                                }
                            }
                            doc.push('}');
                        }
                        doc.push(']');
                    }
                }
            }
            doc.push('}');
            let fast = restore_with_index(&index, &doc);
            let a: serde_json::Value = serde_json::from_str(&fast)
                .unwrap_or_else(|e| panic!("fast output is not valid JSON ({e}) for: {doc}"));
            let b: serde_json::Value =
                serde_json::from_str(&restore_via_value(&index, &doc)).unwrap();
            assert_eq!(
                a, b,
                "fast restore diverged from the Value reference on: {doc}"
            );
        }
    }

    #[test]
    fn fast_restore_takes_the_fast_path_on_mihomo_shaped_input() {
        let index = restore_index();
        let doc = synthetic_connections(2000);
        let fast =
            restore_fast(&index, &doc).expect("mihomo-shaped snapshot must take the fast path");
        let v: serde_json::Value = serde_json::from_str(&fast).unwrap();
        let conns = v["connections"].as_array().unwrap();
        assert_eq!(
            conns.len(),
            1500,
            "only the unmatched loopback quarter is dropped"
        );
        assert_eq!(v["memory"], 52428800);
        let first = &conns[0]["metadata"];
        assert_eq!(first["sourceIP"], "10.0.0.5");
        assert_eq!(first["sourcePort"], "1234");
        assert_eq!(first["type"], "TProxy");
        let v6 = conns
            .iter()
            .find(|c| c["metadata"]["sourceIP"] == "fd00::9")
            .expect("IPv6 loopback source restored");
        assert_eq!(v6["metadata"]["type"], "Socks5");
        assert_eq!(v6["metadata"]["sourcePort"], "5353");
        assert!(
            conns
                .iter()
                .any(|c| c["metadata"]["sourceIP"] == "192.0.2.20"),
            "non-loopback connection kept as-is"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&restore_via_value(&index, &doc)).unwrap(),
            v,
            "large snapshot must match the Value reference too"
        );

        assert!(restore_fast(&index, r#"{"connections":null}"#).is_some());
        assert!(restore_fast(&index, DUP_CONNECTIONS).is_some());
        let escaped = r#"{"connections":[{"meta\u0064ata":{"source\u0049P":"127.0.0.1","sourcePort":"4000\u0031"}}]}"#;
        let out =
            restore_fast(&index, escaped).expect("escaped key spellings stay on the fast path");
        assert!(
            out.contains(r#""sourceIP":"10.0.0.5""#),
            "escaped keys are still recognised and rewritten: {out}"
        );
        assert!(restore_fast(&index, r#"{"connections":[1]}"#).is_none());
        assert!(restore_fast(&index, r#"{"connections":{"a":1}}"#).is_none());
        assert!(restore_fast(&index, r#"{"connections":[{"metadata":[1]}]}"#).is_none());
        assert!(restore_fast(&index, "not json").is_none());
        assert!(restore_fast(&index, "[]").is_none());
    }

    #[test]
    fn out_of_range_number_does_not_blank_the_snapshot() {
        let index = restore_index();
        let j = r#"{"connections":[{"id":"a","metadata":{"sourceIP":"127.0.0.1","sourcePort":"40001"},"weird":1e400}]}"#;
        let out = restore_with_index(&index, j);
        assert!(
            out.contains("1e400"),
            "raw number must be passed through: {out}"
        );
        assert!(
            out.contains(r#""sourceIP":"10.0.0.5""#),
            "the connection is still restored: {out}"
        );
        assert_eq!(
            restore_via_value(&index, j),
            r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#,
            "the Value reference blanks the whole snapshot on such input"
        );
    }

    #[test]
    fn parse_extracts_metadata_for_mirror() {
        let raw = r#"{"connections":[
            {"id":"m1","metadata":{"type":"Shadowsocks","network":"tcp","host":"ex.com",
             "sourceIP":"10.0.0.8","sourcePort":"5555","destinationIP":"1.2.3.4","destinationPort":"443"},
             "chains":["N"],"upload":11,"download":22}
        ]}"#;
        let c = &parse_connections(raw)[0];
        assert_eq!(c.inbound_type, "Shadowsocks");
        assert_eq!(c.network, "tcp");
        assert_eq!(c.host, "ex.com");
        assert_eq!(c.src_ip.unwrap().to_string(), "10.0.0.8");
        assert_eq!(c.src_port, 5555);
        assert_eq!(c.dst_ip.unwrap().to_string(), "1.2.3.4");
        assert_eq!(c.dst_port, 443);
    }

    #[test]
    fn inbound_label_skips_regular_and_inner_maps_listeners() {

        for t in [
            "HTTPS", "HTTP", "Redir", "Socks4", "Socks5", "TProxy", "Tun", "Inner",
        ] {
            assert_eq!(clash_inbound_label(t), None, "{t} should not be mirrored");
            assert_eq!(clash_inbound_label(&t.to_lowercase()), None);
            assert_eq!(clash_inbound_label(&t.to_uppercase()), None);
        }
        assert_eq!(clash_inbound_label(""), None);

        for (t, want) in [
            ("AnyTLS", "anytls"),
            ("Hysteria2", "hysteria2"),
            ("Mieru", "mieru"),
            ("ShadowSocks", "shadowsocks"),
            ("Snell", "snell"),
            ("Sudoku", "sudoku"),
            ("Trojan", "trojan"),
            ("TrustTunnel", "trusttunnel"),
            ("Tuic", "tuic"),
            ("Tunnel", "tunnel"),
            ("Vless", "vless"),
            ("VMESS", "vmess"),
        ] {
            assert_eq!(clash_inbound_label(t), Some(want));
        }

        assert_eq!(clash_inbound_label("FutureProto"), Some("clash"));
    }

    fn types_of(yaml: &str) -> Vec<String> {
        config_listener_types(yaml).into_iter().collect()
    }

    #[test]
    fn config_listener_types_detection() {

        assert_eq!(
            types_of(
                "port: 7890\nlisteners:\n  - name: ss-in-1\n    type: shadowsocks\n    port: 8080\n    listen: 0.0.0.0\nrules:\n  - MATCH,DIRECT\n"
            ),
            vec!["shadowsocks"]
        );

        assert_eq!(
            types_of(
                "listeners:\n  - name: a\n    type: shadowsocks\n  - name: b\n    type: Vless\n  - name: c\n    type: shadowsocks\n"
            ),
            vec!["shadowsocks", "vless"]
        );

        for y in [
            "port: 7890\nrules:\n  - MATCH,DIRECT\n",
            "listeners:\nrules:\n  - MATCH,DIRECT\n",
            "listeners: []\n",
            "listeners: null\n",
            "listeners: # comment\nrules: []\n",
            "",
        ] {
            assert!(
                config_listener_types(y).is_empty(),
                "should be empty: {y:?}"
            );
        }

        assert_eq!(
            types_of("listeners: [{name: a, type: mixed, port: 1}]\n"),
            vec!["mixed"]
        );

        assert!(
            config_listener_types("x:\n  listeners:\n    - name: a\n    type: shadowsocks\n")
                .is_empty()
        );
    }

    #[test]
    fn collect_types_ignores_key_suffix_and_takes_value() {
        let mut s = BTreeSet::new();
        collect_types("    type: shadowsocks", &mut s);
        assert!(s.contains("shadowsocks"));

        let mut s2 = BTreeSet::new();
        collect_types("    proxy-type: foo", &mut s2);
        assert!(s2.is_empty());
    }

    #[test]
    fn mirror_records_direct_inbound_updates_and_closes() {
        let shared = SharedState::new(&crate::config::Config::default());
        let mut mirror = HashMap::new();
        let raw = r#"{"connections":[
            {"id":"ss1","metadata":{"type":"Shadowsocks","network":"tcp","host":"ex.com",
             "sourceIP":"10.0.0.8","sourcePort":"5555","destinationIP":"1.2.3.4","destinationPort":"443"},
             "chains":["N"],"upload":100,"download":200},
            {"id":"lo","metadata":{"type":"Socks5","network":"tcp","host":"x",
             "sourceIP":"127.0.0.1","sourcePort":"40001"},"chains":["N"],"upload":1,"download":1},
            {"id":"inner","metadata":{"type":"Inner","network":"tcp","host":"speedtest",
             "sourceIP":"10.0.0.9","sourcePort":"1"},"chains":["N"],"upload":1,"download":1},
            {"id":"vmess-lo","metadata":{"type":"Vmess","network":"udp","host":"",
             "sourceIP":"127.0.0.1","sourcePort":"2"},"chains":["N"],"upload":1,"download":1}
        ]}"#;

        let active: BTreeSet<String> = ["shadowsocks".to_string()].into_iter().collect();
        mirror_direct_inbounds(&shared, &mut mirror, &parse_connections(raw), &active);

        assert_eq!(mirror.len(), 1);
        assert_eq!(shared.conn_table.len(), 1);
        let rec = Arc::clone(mirror.get("ss1").unwrap());
        assert_eq!(rec.src.0.to_string(), "10.0.0.8");
        assert_eq!(rec.src.1, 5555);
        assert_eq!(rec.dst.1, 443);
        assert_eq!(rec.inbound.as_str(), "shadowsocks");
        assert_eq!(rec.domain.as_deref(), Some("ex.com"));
        assert_eq!(rec.upload.load(std::sync::atomic::Ordering::Relaxed), 100);
        assert_eq!(rec.download.load(std::sync::atomic::Ordering::Relaxed), 200);

        assert_eq!(rec.drain_delta(), (100, 200));

        let raw2 = r#"{"connections":[
            {"id":"ss1","metadata":{"type":"Shadowsocks","network":"tcp","host":"ex.com",
             "sourceIP":"10.0.0.8","sourcePort":"5555","destinationIP":"1.2.3.4","destinationPort":"443"},
             "chains":["N"],"upload":150,"download":260}
        ]}"#;
        mirror_direct_inbounds(&shared, &mut mirror, &parse_connections(raw2), &active);
        assert_eq!(mirror.len(), 1);
        assert!(
            Arc::ptr_eq(&rec, mirror.get("ss1").unwrap()),
            "reuse record with same id"
        );
        assert_eq!(rec.drain_delta(), (50, 60));

        mirror_direct_inbounds(&shared, &mut mirror, &[], &active);
        assert!(mirror.is_empty());
        assert_ne!(
            rec.closed_ms.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "disappearance marks as closed"
        );
    }

    #[test]
    fn mirror_reinserts_after_table_clear() {
        let shared = SharedState::new(&crate::config::Config::default());
        let mut mirror = HashMap::new();
        let raw = r#"{"connections":[
            {"id":"ss1","metadata":{"type":"Shadowsocks","network":"tcp","host":"ex.com",
             "sourceIP":"10.0.0.8","sourcePort":"5555","destinationIP":"1.2.3.4","destinationPort":"443"},
             "chains":["N"],"upload":100,"download":200}
        ]}"#;
        let conns = parse_connections(raw);
        let active: BTreeSet<String> = ["shadowsocks".to_string()].into_iter().collect();
        mirror_direct_inbounds(&shared, &mut mirror, &conns, &active);
        assert_eq!(shared.conn_table.len(), 1);
        shared.conn_table.clear();
        mirror_direct_inbounds(&shared, &mut mirror, &conns, &active);
        assert_eq!(
            shared.conn_table.len(),
            1,
            "still-active mirrored connection added back to table"
        );
    }

    #[test]
    fn mirror_skips_undeclared_type() {

        let shared = SharedState::new(&crate::config::Config::default());
        let mut mirror = HashMap::new();
        let raw = r#"{"connections":[
            {"id":"v1","metadata":{"type":"Vmess","network":"tcp","host":"ex.com",
             "sourceIP":"10.0.0.8","sourcePort":"5555","destinationIP":"1.2.3.4","destinationPort":"443"},
             "chains":["N"],"upload":100,"download":200}
        ]}"#;
        mirror_direct_inbounds(
            &shared,
            &mut mirror,
            &parse_connections(raw),
            &BTreeSet::new(),
        );
        assert!(mirror.is_empty());
        assert_eq!(shared.conn_table.len(), 0);
    }

    #[test]
    fn accumulate_prunes_closed_conns() {
        let nd = NodeDist::new();
        let mut last = HashMap::new();
        accumulate(&nd, &mut last, &parse_connections(SAMPLE));
        assert_eq!(last.len(), 2);

        accumulate(
            &nd,
            &mut last,
            &parse_connections(
                r#"{"connections":[{"id":"a","chains":["HKG 01"],"upload":10,"download":20}]}"#,
            ),
        );
        assert_eq!(last.len(), 1);
        assert!(last.contains_key("a"));
    }
}
