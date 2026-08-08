// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::clash_logs::ChunkDecoder;
use crate::http;
use crate::probe::{Busy, ProbeSource};
use crate::server::ServerConfig;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::Instant;

const HARD_DEADLINE: Duration = Duration::from_secs(20);

const GRACE: Duration = Duration::from_millis(800);

const MAX_LINES: usize = 2000;

const MAX_LINE_LEN: usize = 16 * 1024;
const MAX_URL_LEN: usize = 2048;

const PROBE_TIMEOUT_MS: u64 = 8_000;
const PROBE_MAX_BODY: u64 = 2048;

pub async fn run(
    cfg: &ServerConfig,
    probe: Arc<dyn ProbeSource>,
    body: &[u8],
) -> Result<String, Busy> {
    let url = match parse_req(body) {
        Ok(u) => u,
        Err(e) => return Ok(json!({ "ok": false, "denied": true, "error": e }).to_string()),
    };
    let (host, port) = split_host_port(&url);

    let (mut tail, logs_err) = match LogTail::connect(&cfg.clash_sock).await {
        Ok(t) => (Some(t), None),
        Err(e) => (None, Some(e.to_string())),
    };

    let req_json = json!({
        "url": url,
        "method": "GET",
        "follow": false,
        "timeoutMs": PROBE_TIMEOUT_MS,
        "maxBody": PROBE_MAX_BODY,
    })
    .to_string();

    let fut = probe.probe_relaxed(&req_json);
    tokio::pin!(fut);

    let hard = Instant::now() + HARD_DEADLINE;
    let mut soft: Option<Instant> = None;
    let mut probe_out: Option<Result<String, Busy>> = None;
    loop {
        let until = soft.map_or(hard, |s| s.min(hard));
        if Instant::now() >= until {
            break;
        }
        let can_read = tail.as_ref().is_some_and(|t| !t.eof);
        tokio::select! {
            r = &mut fut, if probe_out.is_none() => {
                probe_out = Some(r);
                soft = Some(Instant::now() + GRACE);
            }

            () = async { tail.as_mut().unwrap().read_more().await }, if can_read => {}
            _ = tokio::time::sleep_until(until) => break,
        }
    }
    let probe_out = match probe_out {
        Some(v) => v,
        None => Ok(json!({ "ok": false, "error": "rule test timed out" }).to_string()),
    };

    let probe_out = probe_out?;

    let lines = tail.map(|t| t.lines).unwrap_or_default();
    let (picked, ports) = select_lines(&lines, &host);
    Ok(json!({
        "ok": true,
        "url": url,
        "host": host,
        "port": port,
        "probe": probe_summary(&probe_out),
        "logs": picked,
        "srcPorts": ports.iter().copied().collect::<Vec<u16>>(),
        "captured": lines.len(),
        "logsError": logs_err,
    })
    .to_string())
}

fn probe_summary(out: &str) -> Value {
    let Ok(v) = serde_json::from_str::<Value>(out) else {
        return Value::Null;
    };
    let mut o = serde_json::Map::new();
    for k in ["ok", "status", "ms", "error", "denied", "url"] {
        if let Some(x) = v.get(k) {
            o.insert(k.to_string(), x.clone());
        }
    }
    Value::Object(o)
}

fn parse_req(body: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(body).map_err(|_| "body must be utf-8".to_string())?;
    let v: Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
    let raw = v
        .get("url")
        .and_then(Value::as_str)
        .ok_or("missing url")?
        .trim();
    normalize_url(raw)
}

fn normalize_url(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("url is empty".into());
    }
    if raw.len() > MAX_URL_LEN {
        return Err("url too long".into());
    }
    let has_scheme = raw.split_once("://").is_some_and(|(s, _)| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    });
    Ok(if has_scheme {
        raw.to_string()
    } else {
        format!("http://{raw}")
    })
}

fn split_host_port(url: &str) -> (String, u16) {
    let https = url.starts_with("https://");
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = match authority.strip_prefix('[') {

        Some(v6) => match v6.split_once(']') {
            Some((h, tail)) => (h, tail.strip_prefix(':').and_then(|p| p.parse().ok())),
            None => (v6, None),
        },
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()),
            None => (authority, None),
        },
    };
    (
        host.to_ascii_lowercase(),
        port.unwrap_or(if https { 443 } else { 80 }),
    )
}

fn select_lines(lines: &[(String, String)], host: &str) -> (Vec<Value>, BTreeSet<u16>) {
    let hostl = host.to_ascii_lowercase();
    let mut ports = BTreeSet::new();
    let mut hit = vec![false; lines.len()];
    if !hostl.is_empty() {
        for (i, (_, msg)) in lines.iter().enumerate() {
            if msg.to_ascii_lowercase().contains(&hostl) {
                hit[i] = true;
                ports.extend(loopback_ports(msg));
            }
        }
    }

    if !ports.is_empty() {
        for (i, (_, msg)) in lines.iter().enumerate() {
            if !hit[i] && loopback_ports(msg).iter().any(|p| ports.contains(p)) {
                hit[i] = true;
            }
        }
    }
    let picked = lines
        .iter()
        .zip(&hit)
        .filter(|(_, h)| **h)
        .map(|((level, msg), _)| json!({ "type": level, "payload": msg }))
        .collect();
    (picked, ports)
}

fn loopback_ports(s: &str) -> Vec<u16> {
    const PAT: &[u8] = b"127.0.0.1:";
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + PAT.len() <= b.len() {
        if &b[i..i + PAT.len()] != PAT {
            i += 1;
            continue;
        }
        let start = i + PAT.len();
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > start
            && let Ok(p) = s[start..j].parse::<u16>()
        {
            out.push(p);
        }
        i = j.max(start);
    }
    out
}

struct LogTail {
    up: UnixStream,
    dec: ChunkDecoder,
    chunked: bool,
    line: Vec<u8>,
    lines: Vec<(String, String)>,
    eof: bool,
}

impl LogTail {
    async fn connect(sock: &Path) -> io::Result<Self> {
        let mut up = UnixStream::connect(sock).await?;
        up.write_all(
            b"GET /logs?level=debug HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n",
        )
        .await?;
        up.flush().await?;
        let mut buf = Vec::new();
        let hl = http::read_head(&mut up, &mut buf).await?;
        let resp = http::parse_response(&buf[..hl])?;
        if resp.status != 200 {
            return Err(io::Error::other(format!(
                "clash /logs returned {}",
                resp.status
            )));
        }
        let chunked = matches!(resp.framing(false)?, http::Framing::Chunked);
        let overflow = buf.split_off(hl);
        let mut t = Self {
            up,
            dec: ChunkDecoder::new(),
            chunked,
            line: Vec::new(),
            lines: Vec::new(),
            eof: false,
        };
        t.absorb(&overflow);
        Ok(t)
    }

    async fn read_more(&mut self) {
        let mut buf = [0u8; 8192];
        match self.up.read(&mut buf).await {
            Ok(0) | Err(_) => self.eof = true,
            Ok(n) => {
                let chunk = buf[..n].to_vec();
                self.absorb(&chunk);
            }
        }
    }

    fn absorb(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }
        let mut decoded = Vec::new();
        if self.chunked {
            if self.dec.feed(input, &mut decoded).is_err() {
                self.eof = true;
                return;
            }
            if self.dec.done {
                self.eof = true;
            }
        } else {
            decoded.extend_from_slice(input);
        }
        for &b in &decoded {
            if b == b'\n' {
                self.push_line();
            } else if self.line.len() < MAX_LINE_LEN {
                self.line.push(b);
            }
        }
    }

    fn push_line(&mut self) {
        let raw = std::mem::take(&mut self.line);
        if self.lines.len() >= MAX_LINES {
            return;
        }
        let Ok(s) = std::str::from_utf8(&raw) else {
            return;
        };
        let Ok(v) = serde_json::from_str::<Value>(s.trim()) else {
            return;
        };
        let msg = v.get("payload").and_then(Value::as_str).unwrap_or("");
        if msg.is_empty() {
            return;
        }
        let level = v.get("type").and_then(Value::as_str).unwrap_or("info");
        self.lines.push((level.to_string(), msg.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_domain_gets_http_scheme() {
        assert_eq!(normalize_url("a.com").unwrap(), "http://a.com");
        assert_eq!(normalize_url("a.com/p?q=1").unwrap(), "http://a.com/p?q=1");
        assert_eq!(normalize_url("https://a.com").unwrap(), "https://a.com");
        assert_eq!(normalize_url("HTTP://a.com").unwrap(), "HTTP://a.com");

        assert_eq!(normalize_url("a.com/x://y").unwrap(), "http://a.com/x://y");
        assert!(normalize_url("").is_err());
        assert!(normalize_url(&"a".repeat(MAX_URL_LEN + 1)).is_err());
    }

    #[test]
    fn host_and_default_port() {
        assert_eq!(split_host_port("http://a.com/x"), ("a.com".into(), 80));
        assert_eq!(split_host_port("https://A.com"), ("a.com".into(), 443));
        assert_eq!(
            split_host_port("http://a.com:8080/x"),
            ("a.com".into(), 8080)
        );
        assert_eq!(split_host_port("http://u:p@a.com/x"), ("a.com".into(), 80));
        assert_eq!(split_host_port("http://[::1]:81/x"), ("::1".into(), 81));
        assert_eq!(split_host_port("http://[::1]/x"), ("::1".into(), 80));
        assert_eq!(split_host_port("http://a.com?q=1"), ("a.com".into(), 80));
    }

    #[test]
    fn loopback_port_extraction_is_exact() {
        assert_eq!(
            loopback_ports("[TCP] 127.0.0.1:41234 --> a.com:80"),
            vec![41234]
        );
        assert_eq!(
            loopback_ports("127.0.0.1:1 x 127.0.0.1:65535"),
            vec![1, 65535]
        );

        assert!(loopback_ports("127.0.0.1:70000").is_empty());
        assert!(loopback_ports("10.0.0.1:80").is_empty());
        assert!(loopback_ports("127.0.0.1:").is_empty());
    }

    fn l(msg: &str) -> (String, String) {
        ("info".to_string(), msg.to_string())
    }

    #[test]
    fn picks_the_matching_line_and_its_siblings_by_source_port() {
        let lines = vec![
            l("[TCP] 127.0.0.1:5555 --> other.com:443 match GeoIP(CN) using DIRECT"),
            l("[TCP] 127.0.0.1:41234 --> a.com:80 match DomainSuffix(a.com) using PROXY"),
            l("[DNS] failed to lookup 127.0.0.1:41234 timeout"),
            l("noise without any address"),
        ];
        let (picked, ports) = select_lines(&lines, "a.com");
        assert_eq!(picked.len(), 2, "target line + same-source-port sibling");
        assert!(
            picked[0]["payload"]
                .as_str()
                .unwrap()
                .contains("DomainSuffix")
        );
        assert!(picked[1]["payload"].as_str().unwrap().contains("[DNS]"));
        assert_eq!(ports.into_iter().collect::<Vec<_>>(), vec![41234]);
    }

    #[test]
    fn unrelated_host_lines_are_dropped() {
        let lines = vec![l(
            "[TCP] 127.0.0.1:5555 --> other.com:443 match Match using DIRECT",
        )];
        let (picked, ports) = select_lines(&lines, "a.com");
        assert!(picked.is_empty());
        assert!(ports.is_empty());
    }

    #[test]
    fn probe_summary_drops_body_and_headers() {
        let v = probe_summary(
            r#"{"ok":true,"status":302,"ms":419,"url":"http://a.com/","body":"<html>","headers":{"server":"gws"},"setCookie":["x=1"]}"#,
        );
        assert_eq!(v["ok"], true);
        assert_eq!(v["status"], 302);
        assert_eq!(v["ms"], 419);
        assert_eq!(v["url"], "http://a.com/");
        assert!(v.get("body").is_none(), "body must not be echoed: {v}");
        assert!(
            v.get("headers").is_none(),
            "headers must not be echoed: {v}"
        );
        assert!(
            v.get("setCookie").is_none(),
            "cookies must not be echoed: {v}"
        );
        assert_eq!(probe_summary("not json"), serde_json::Value::Null);
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let lines = vec![l(
            "[TCP] 127.0.0.1:1 --> API.Example.COM:443 match Domain(x) using P",
        )];
        let (picked, _) = select_lines(&lines, "api.example.com");
        assert_eq!(picked.len(), 1);
    }
}
