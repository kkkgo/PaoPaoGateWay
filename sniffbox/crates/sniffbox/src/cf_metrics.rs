// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use crate::config::Protocol;

const TIMEOUT: Duration = Duration::from_millis(800);

const MAX_BODY: usize = 256 * 1024;

struct Series {
    labels: BTreeMap<String, String>,
    value: f64,
}

pub fn scrape(addr: SocketAddr, acc: &ByteAccum) -> Option<serde_json::Value> {
    let body = http_get(addr, "/metrics")?.1;
    let fams = parse_prometheus(&body);
    acc.fold(&conn_bytes(&fams));
    let ready = ready_connections(addr);

    let diag = diag_tunnel(addr);
    Some(summarize(&fams, ready, diag.as_ref()))
}

#[derive(Default)]
pub struct ByteAccum {
    inner: Mutex<AccumInner>,
}

#[derive(Default)]
struct AccumInner {

    prev: BTreeMap<String, (u64, u64)>,
    up: u64,
    down: u64,
}

impl ByteAccum {

    fn fold(&self, cur: &BTreeMap<String, (u64, u64)>) -> (u64, u64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for (idx, &(sent, recv)) in cur {
            let (psent, precv) = g.prev.get(idx).copied().unwrap_or((0, 0));

            g.up += if sent >= psent { sent - psent } else { sent };
            g.down += if recv >= precv { recv - precv } else { recv };
        }

        g.prev = cur.clone();
        (g.up, g.down)
    }

    pub fn totals(&self) -> (u64, u64) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.up, g.down)
    }
}

fn conn_bytes(fams: &BTreeMap<String, Vec<Series>>) -> BTreeMap<String, (u64, u64)> {
    let sent = per_conn(fams, "quic_client_sent_bytes");
    let recv = per_conn(fams, "quic_client_receive_bytes");
    let mut out: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for (idx, v) in sent {
        out.entry(idx).or_default().0 = v.max(0.0) as u64;
    }
    for (idx, v) in recv {
        out.entry(idx).or_default().1 = v.max(0.0) as u64;
    }
    out
}

fn ready_connections(addr: SocketAddr) -> Option<u64> {
    let (_, body) = http_get(addr, "/ready")?;
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    v.get("readyConnections")?.as_u64()
}

fn http_get(addr: SocketAddr, path: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect_timeout(&addr, TIMEOUT).ok()?;
    s.set_read_timeout(Some(TIMEOUT)).ok()?;
    s.set_write_timeout(Some(TIMEOUT)).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_BODY {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, body.to_string()))
}

fn parse_prometheus(text: &str) -> BTreeMap<String, Vec<Series>> {
    let mut out: BTreeMap<String, Vec<Series>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, labels, value)) = parse_line(line) else {
            continue;
        };
        out.entry(name).or_default().push(Series { labels, value });
    }
    out
}

fn parse_line(line: &str) -> Option<(String, BTreeMap<String, String>, f64)> {
    let (head, rest) = match line.split_once('{') {
        Some((name, tail)) => {
            let (labels, tail) = tail.split_once('}')?;
            (name.trim().to_string(), (Some(labels), tail))
        }
        None => {
            let (name, tail) = line.split_once(char::is_whitespace)?;
            (name.trim().to_string(), (None, tail))
        }
    };
    let (labels_raw, value_raw) = rest;

    let value: f64 = value_raw.split_whitespace().next()?.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    Some((head, parse_labels(labels_raw.unwrap_or("")), value))
}

fn parse_labels(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {

        let Some(eq) = raw[i..].find('=').map(|p| p + i) else {
            break;
        };
        let key = raw[i..eq].trim_start_matches(',').trim().to_string();

        let mut j = eq + 1;
        if b.get(j) != Some(&b'"') {
            break;
        }
        j += 1;
        let mut val = String::new();
        while j < b.len() {
            match b[j] {
                b'\\' if j + 1 < b.len() => {
                    val.push(match b[j + 1] {
                        b'n' => '\n',
                        c => c as char,
                    });
                    j += 2;
                }
                b'"' => break,
                c => {
                    val.push(c as char);
                    j += 1;
                }
            }
        }
        if key.is_empty() {
            break;
        }
        out.insert(key, val);
        i = j + 1;
    }
    out
}

fn sum(fams: &BTreeMap<String, Vec<Series>>, name: &str) -> Option<f64> {
    let v = fams.get(name)?;
    (!v.is_empty()).then(|| v.iter().map(|s| s.value).sum())
}

fn max(fams: &BTreeMap<String, Vec<Series>>, name: &str) -> Option<f64> {
    fams.get(name)?
        .iter()
        .map(|s| s.value)
        .fold(None, |acc: Option<f64>, v| {
            Some(acc.map_or(v, |a| a.max(v)))
        })
}

fn as_u64(v: Option<f64>) -> Option<u64> {
    v.filter(|x| *x >= 0.0).map(|x| x as u64)
}

fn label<'a>(s: &'a Series, key: &str) -> &'a str {
    s.labels.get(key).map(String::as_str).unwrap_or("")
}

fn per_conn(fams: &BTreeMap<String, Vec<Series>>, name: &str) -> BTreeMap<String, f64> {
    fams.get(name)
        .map(|v| {
            v.iter()
                .map(|s| (label(s, "conn_index").to_string(), s.value))
                .collect()
        })
        .unwrap_or_default()
}

fn summarize(
    fams: &BTreeMap<String, Vec<Series>>,
    ready: Option<u64>,
    diag: Option<&DiagTunnel>,
) -> serde_json::Value {

    let mut colo: BTreeMap<String, String> = BTreeMap::new();
    if let Some(v) = fams.get("cloudflared_tunnel_server_locations") {
        for s in v.iter().filter(|s| s.value >= 1.0) {
            colo.insert(
                label(s, "connection_id").to_string(),
                label(s, "edge_location").to_string(),
            );
        }
    }

    let latest_rtt = per_conn(fams, "quic_client_latest_rtt");
    let min_rtt = per_conn(fams, "quic_client_min_rtt");
    let smoothed_rtt = per_conn(fams, "quic_client_smoothed_rtt");
    let cwnd = per_conn(fams, "quic_client_congestion_window");
    let mtu = per_conn(fams, "quic_client_mtu");
    let sent = per_conn(fams, "quic_client_sent_bytes");
    let recv = per_conn(fams, "quic_client_receive_bytes");
    let lost = per_conn(fams, "quic_client_lost_packets");

    let indices: Vec<String> = match diag {
        Some(d) if !d.connections.is_empty() => {
            d.connections.iter().map(|c| c.index.to_string()).collect()
        }
        _ => {
            let mut k: Vec<String> = colo.keys().cloned().collect();
            k.sort();
            k
        }
    };
    let conns: Vec<serde_json::Value> = indices
        .iter()
        .map(|idx| {
            let d = diag.and_then(|d| d.connections.iter().find(|c| c.index.to_string() == *idx));
            serde_json::json!({
                "index": idx.parse::<u64>().ok(),
                "edge": d.map(|c| c.edge_address.clone()),
                "protocol": d.map(|c| c.protocol_name()),
                "connected": d.map(|c| c.is_connected),
                "colo": colo.get(idx).cloned(),
                "rttMs": latest_rtt.get(idx).copied(),
                "minRttMs": min_rtt.get(idx).copied(),
                "smoothedRttMs": smoothed_rtt.get(idx).copied(),
                "cwnd": cwnd.get(idx).copied().map(|v| v as u64),
                "mtu": mtu.get(idx).copied().map(|v| v as u64),
                "sentBytes": sent.get(idx).copied().map(|v| v as u64),
                "recvBytes": recv.get(idx).copied().map(|v| v as u64),
                "lostPackets": lost.get(idx).copied().map(|v| v as u64),
            })
        })
        .collect();

    let codes: serde_json::Map<String, serde_json::Value> = fams
        .get("cloudflared_tunnel_response_by_code")
        .map(|v| {
            let mut m = serde_json::Map::new();
            for s in v {
                let Some(code) = s.labels.get("status_code") else {
                    continue;
                };
                let slot = m.entry(code.clone()).or_insert(serde_json::json!(0));
                let cur = slot.as_u64().unwrap_or(0);
                *slot = serde_json::json!(cur + s.value.max(0.0) as u64);
            }
            m
        })
        .unwrap_or_default();

    let lat_sum = sum(fams, "cloudflared_proxy_connect_latency_sum");
    let lat_count = sum(fams, "cloudflared_proxy_connect_latency_count");
    let lat_avg = match (lat_sum, lat_count) {
        (Some(s), Some(c)) if c > 0.0 => Some((s / c * 100.0).round() / 100.0),
        _ => None,
    };

    let build = fams
        .get("build_info")
        .and_then(|v| v.first())
        .map(|s| {
            serde_json::json!({
                "version": label(s, "version"),
                "goVersion": label(s, "goversion"),
                "revision": label(s, "revision"),
            })
        })
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "ready": ready,

        "connectorId": diag.map(|d| d.connector_id.clone()),
        "tunnelId": diag.map(|d| d.tunnel_id.clone()),

        "haConnections": as_u64(sum(fams, "cloudflared_tunnel_ha_connections")),
        "build": build,
        "conns": conns,
        "requests": {
            "total": as_u64(sum(fams, "cloudflared_tunnel_total_requests")),
            "concurrent": as_u64(sum(fams, "cloudflared_tunnel_concurrent_requests_per_tunnel")),
            "maxConcurrent": as_u64(max(fams, "cloudflared_tunnel_max_concurrent_requests_per_tunnel")),
            "errors": as_u64(sum(fams, "cloudflared_tunnel_request_errors")),
        },
        "codes": codes,
        "tcp": {
            "active": as_u64(sum(fams, "cloudflared_tcp_active_sessions")),
            "total": as_u64(sum(fams, "cloudflared_tcp_total_sessions")),
        },
        "udp": {
            "active": as_u64(sum(fams, "cloudflared_udp_active_sessions")),
            "total": as_u64(sum(fams, "cloudflared_udp_total_sessions")),
        },

        "register": {
            "success": as_u64(sum(fams, "cloudflared_tunnel_tunnel_register_success")),
            "fail": as_u64(sum(fams, "cloudflared_tunnel_tunnel_register_fail")),
            "rpcFail": as_u64(sum(fams, "cloudflared_tunnel_tunnel_rpc_fail")),
        },
        "latency": {
            "avgMs": lat_avg,
            "count": as_u64(lat_count),
            "streamErrors": as_u64(sum(fams, "cloudflared_proxy_connect_streams_errors")),
        },
        "config": {
            "pushes": as_u64(sum(fams, "cloudflared_config_local_config_pushes")),
            "pushErrors": as_u64(sum(fams, "cloudflared_config_local_config_pushes_errors")),
            "version": as_u64(sum(fams, "cloudflared_orchestration_config_version")),
        },

        "proc": {
            "rssBytes": as_u64(sum(fams, "process_resident_memory_bytes")),
            "cpuSeconds": sum(fams, "process_cpu_seconds_total").map(|v| (v * 100.0).round() / 100.0),
            "openFds": as_u64(sum(fams, "process_open_fds")),
            "startedAt": as_u64(sum(fams, "process_start_time_seconds")),
            "netRxBytes": as_u64(sum(fams, "process_network_receive_bytes_total")),
            "netTxBytes": as_u64(sum(fams, "process_network_transmit_bytes_total")),
        },
        "runtime": {
            "goroutines": as_u64(sum(fams, "go_goroutines")),
            "heapBytes": as_u64(sum(fams, "go_memstats_heap_alloc_bytes")),
            "threads": as_u64(sum(fams, "go_threads")),
        },
    })
}

pub fn metrics_text(addr: SocketAddr) -> Option<String> {
    http_get(addr, "/metrics").map(|(_, body)| body)
}

pub fn ready(addr: SocketAddr) -> Option<u64> {
    ready_connections(addr)
}

pub fn running_protocol(addr: SocketAddr) -> Option<Protocol> {
    protocol_of(&diag_tunnel(addr)?)
}

fn protocol_of(d: &DiagTunnel) -> Option<Protocol> {
    let c = d.connections.iter().find(|c| c.is_connected)?;
    Some(match c.protocol {
        1 => Protocol::Quic,
        _ => Protocol::Http2,
    })
}

pub struct DiagTunnel {
    pub tunnel_id: String,
    pub connector_id: String,
    pub connections: Vec<DiagConn>,
}
pub struct DiagConn {
    pub index: u64,
    pub edge_address: String,

    pub protocol: u64,
    pub is_connected: bool,
}
impl DiagConn {
    fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1 => "quic",
            _ => "http2",
        }
    }
}

fn diag_tunnel(addr: SocketAddr) -> Option<DiagTunnel> {
    let (_, body) = http_get(addr, "/diag/tunnel")?;
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let conns = v
        .get("connections")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .map(|c| DiagConn {
                    index: c.get("index").and_then(|x| x.as_u64()).unwrap_or(0),
                    edge_address: c
                        .get("edgeAddress")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    protocol: c.get("protocol").and_then(|x| x.as_u64()).unwrap_or(0),
                    is_connected: c
                        .get("isConnected")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();
    Some(DiagTunnel {
        tunnel_id: v
            .get("tunnelID")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        connector_id: v
            .get("connectorID")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        connections: conns,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# HELP cloudflared_tunnel_server_locations Where each tunnel is connected to
# TYPE cloudflared_tunnel_server_locations gauge
cloudflared_tunnel_server_locations{connection_id="1",edge_location="LAX"} 1
cloudflared_tunnel_server_locations{connection_id="0",edge_location="SJC"} 1
cloudflared_tunnel_server_locations{connection_id="0",edge_location="NRT"} 0
cloudflared_tunnel_total_requests 42
cloudflared_tunnel_concurrent_requests_per_tunnel 3
cloudflared_tunnel_max_concurrent_requests_per_tunnel{connection_id="0"} 7
cloudflared_tunnel_max_concurrent_requests_per_tunnel{connection_id="1"} 11
cloudflared_tunnel_response_by_code{status_code="200"} 30
cloudflared_tunnel_response_by_code{status_code="502"} 2
cloudflared_tunnel_request_errors 1
cloudflared_tcp_active_sessions 2
cloudflared_tcp_total_sessions 19
cloudflared_tunnel_tunnel_register_success{rpcName="registerConnection"} 4
cloudflared_tunnel_tunnel_rpc_fail{error="dial",rpcName="registerConnection"} 1
cloudflared_tunnel_ha_connections 2
cloudflared_udp_active_sessions 3
cloudflared_udp_total_sessions 9
cloudflared_proxy_connect_latency_sum 250
cloudflared_proxy_connect_latency_count 5
build_info{goversion="go1.26.4",revision="2026-07-23-09:58 UTC",type="",version="2026.7.3"} 1
process_resident_memory_bytes 3.9206912e+07
process_cpu_seconds_total 4.51
process_open_fds 12
process_start_time_seconds 1.78540922511e+09
process_network_receive_bytes_total 103290
process_network_transmit_bytes_total 204343
quic_client_latest_rtt{conn_index="0"} 11
quic_client_latest_rtt{conn_index="1"} 35
quic_client_min_rtt{conn_index="0"} 10
quic_client_congestion_window{conn_index="0"} 39424
quic_client_sent_bytes{conn_index="0"} 204343
quic_client_receive_bytes{conn_index="0"} 103290
go_goroutines 38
go_threads 9
"#;

    const DIAG: &str = r#"{"tunnelID":"dcdb67dc-cd58-46e5-9d95-90c0221085f3","connectorID":"24adc1cc-4732-4c4d-a4bf-541bc5d33aec","connections":[{"isConnected":true,"protocol":1,"edgeAddress":"198.41.192.227","index":1},{"isConnected":true,"protocol":1,"edgeAddress":"198.41.200.43"}],"icmp_sources":["10.10.10.235","::"]}"#;
    fn diag() -> DiagTunnel {
        let v: serde_json::Value = serde_json::from_str(DIAG).unwrap();
        DiagTunnel {
            tunnel_id: v["tunnelID"].as_str().unwrap().to_string(),
            connector_id: v["connectorID"].as_str().unwrap().to_string(),
            connections: v["connections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| DiagConn {
                    index: c.get("index").and_then(|x| x.as_u64()).unwrap_or(0),
                    edge_address: c["edgeAddress"].as_str().unwrap().to_string(),
                    protocol: c["protocol"].as_u64().unwrap(),
                    is_connected: c["isConnected"].as_bool().unwrap(),
                })
                .collect(),
        }
    }

    #[test]
    fn parses_labels_and_values() {
        let fams = parse_prometheus(SAMPLE);
        assert_eq!(sum(&fams, "cloudflared_tunnel_total_requests"), Some(42.0));

        assert_eq!(
            sum(&fams, "cloudflared_tunnel_response_by_code"),
            Some(32.0)
        );
        assert_eq!(
            max(
                &fams,
                "cloudflared_tunnel_max_concurrent_requests_per_tunnel"
            ),
            Some(11.0)
        );
        assert_eq!(sum(&fams, "no_such_metric"), None);
    }

    #[test]
    fn summarize_shapes_frontend_json() {
        let v = summarize(&parse_prometheus(SAMPLE), Some(2), None);
        assert_eq!(v["ready"], 2);
        assert_eq!(v["haConnections"], 2);
        assert_eq!(v["requests"]["total"], 42);
        assert_eq!(v["requests"]["maxConcurrent"], 11);
        assert_eq!(v["codes"]["200"], 30);
        assert_eq!(v["codes"]["502"], 2);
        assert_eq!(v["tcp"]["total"], 19);
        assert_eq!(v["udp"]["active"], 3);
        assert_eq!(v["latency"]["avgMs"], 50.0);
        assert_eq!(v["runtime"]["goroutines"], 38);
        assert_eq!(v["runtime"]["threads"], 9);

        assert_eq!(v["build"]["version"], "2026.7.3");
        assert_eq!(v["build"]["goVersion"], "go1.26.4");

        assert_eq!(v["proc"]["rssBytes"], 39206912u64);
        assert_eq!(v["proc"]["netTxBytes"], 204343u64);
        assert_eq!(v["proc"]["openFds"], 12);
    }

    #[test]
    fn byte_accum_is_monotonic_across_connection_resets() {
        let acc = ByteAccum::default();

        assert_eq!(
            acc.fold(&conn_bytes(&parse_prometheus(SAMPLE))),
            (204343, 103290)
        );

        let grown = "quic_client_sent_bytes{conn_index=\"0\"} 300000\n\
                     quic_client_receive_bytes{conn_index=\"0\"} 200000\n";
        assert_eq!(
            acc.fold(&conn_bytes(&parse_prometheus(grown))),
            (300000, 200000)
        );

        let reset = "quic_client_sent_bytes{conn_index=\"0\"} 500\n\
                     quic_client_receive_bytes{conn_index=\"0\"} 400\n\
                     quic_client_sent_bytes{conn_index=\"1\"} 70\n\
                     quic_client_receive_bytes{conn_index=\"1\"} 30\n";
        assert_eq!(
            acc.fold(&conn_bytes(&parse_prometheus(reset))),
            (300570, 200430)
        );

        assert_eq!(acc.fold(&BTreeMap::new()), (300570, 200430));
        assert_eq!(acc.totals(), (300570, 200430));
        assert_eq!(
            acc.fold(&conn_bytes(&parse_prometheus(reset))),
            (301140, 200860)
        );
    }

    #[test]
    fn byte_accum_starts_at_zero() {
        let acc = ByteAccum::default();
        assert_eq!(acc.totals(), (0, 0));
        assert_eq!(acc.fold(&conn_bytes(&parse_prometheus(""))), (0, 0));
    }

    #[test]
    fn register_metrics_use_the_doubled_tunnel_prefix() {
        let v = summarize(&parse_prometheus(SAMPLE), None, None);
        assert_eq!(
            v["register"]["success"], 4,
            "must read cloudflared_tunnel_tunnel_register_success"
        );
        assert_eq!(v["register"]["rpcFail"], 1);

        assert_eq!(v["register"]["fail"], serde_json::Value::Null);

        let wrong = parse_prometheus("cloudflared_tunnel_register_success 7\n");
        assert_eq!(
            summarize(&wrong, None, None)["register"]["success"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn running_protocol_reads_the_omitempty_field() {
        assert_eq!(protocol_of(&diag()), Some(Protocol::Quic));

        let http2: serde_json::Value = serde_json::from_str(
            r#"{"connections":[{"isConnected":true,"edgeAddress":"198.41.192.7"}]}"#,
        )
        .unwrap();
        let d = DiagTunnel {
            tunnel_id: String::new(),
            connector_id: String::new(),
            connections: http2["connections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| DiagConn {
                    index: 0,
                    edge_address: c["edgeAddress"].as_str().unwrap().to_string(),
                    protocol: c.get("protocol").and_then(|x| x.as_u64()).unwrap_or(0),
                    is_connected: c["isConnected"].as_bool().unwrap(),
                })
                .collect(),
        };
        assert_eq!(protocol_of(&d), Some(Protocol::Http2));

        let empty = DiagTunnel {
            tunnel_id: String::new(),
            connector_id: String::new(),
            connections: Vec::new(),
        };
        assert_eq!(protocol_of(&empty), None);
    }

    #[test]
    fn conns_join_diag_colo_and_quic_quality() {
        let v = summarize(&parse_prometheus(SAMPLE), Some(2), Some(&diag()));
        assert_eq!(v["tunnelId"], "dcdb67dc-cd58-46e5-9d95-90c0221085f3");
        assert_eq!(v["connectorId"], "24adc1cc-4732-4c4d-a4bf-541bc5d33aec");
        let conns = v["conns"].as_array().unwrap();
        assert_eq!(conns.len(), 2);

        assert_eq!(conns[0]["index"], 1);
        assert_eq!(conns[0]["edge"], "198.41.192.227");
        assert_eq!(conns[0]["protocol"], "quic");
        assert_eq!(conns[0]["colo"], "LAX");
        assert_eq!(conns[0]["rttMs"], 35.0);

        assert_eq!(conns[1]["index"], 0);
        assert_eq!(conns[1]["edge"], "198.41.200.43");
        assert_eq!(conns[1]["colo"], "SJC");
        assert_eq!(conns[1]["rttMs"], 11.0);
        assert_eq!(conns[1]["minRttMs"], 10.0);
        assert_eq!(conns[1]["cwnd"], 39424u64);
        assert_eq!(conns[1]["sentBytes"], 204343u64);
        assert_eq!(conns[1]["connected"], true);
    }

    #[test]
    fn conns_fall_back_to_server_locations_without_diag() {
        let v = summarize(&parse_prometheus(SAMPLE), None, None);
        let conns = v["conns"].as_array().unwrap();
        assert_eq!(conns.len(), 2, "two currently-connected colos");
        assert_eq!(conns[0]["index"], 0);
        assert_eq!(conns[0]["colo"], "SJC");
        assert_eq!(conns[0]["edge"], serde_json::Value::Null);
        assert_eq!(conns[1]["colo"], "LAX");
    }

    #[test]
    fn missing_metrics_become_null_not_zero() {

        let v = summarize(&parse_prometheus(""), None, None);
        assert_eq!(v["ready"], serde_json::Value::Null);
        assert_eq!(v["requests"]["total"], serde_json::Value::Null);
        assert_eq!(v["tcp"]["active"], serde_json::Value::Null);
        assert_eq!(v["haConnections"], serde_json::Value::Null);
        assert_eq!(v["build"], serde_json::Value::Null);
        assert_eq!(v["proc"]["rssBytes"], serde_json::Value::Null);
        assert!(v["conns"].as_array().unwrap().is_empty());
    }

    #[test]
    fn tolerates_garbage_lines() {
        let text = "# comment\n\nbroken line without value\nname{unterminated 1\nok_metric 5\nnan_metric NaN\ninf_metric +Inf\n";
        let fams = parse_prometheus(text);
        assert_eq!(sum(&fams, "ok_metric"), Some(5.0));
        assert!(!fams.contains_key("nan_metric"));
        assert!(!fams.contains_key("inf_metric"));
    }

    #[test]
    fn parses_escaped_label_values() {
        let fams = parse_prometheus(r#"m{error="dial \"tcp\"",rpcName="X"} 3"#);
        let s = &fams["m"][0];
        assert_eq!(s.labels["error"], "dial \"tcp\"");
        assert_eq!(s.labels["rpcName"], "X");
        assert_eq!(s.value, 3.0);
    }

    #[test]
    fn scrape_of_dead_port_is_none() {

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let acc = ByteAccum::default();
        assert!(scrape(addr, &acc).is_none());
        assert_eq!(acc.totals(), (0, 0));
    }
}
