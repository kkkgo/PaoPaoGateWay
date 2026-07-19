// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum ClashErr {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad http response")]
    BadResponse,
    #[error("http status {0}")]
    Status(u16),
    #[error("json parse: {0}")]
    Json(String),
    #[error("ping: {0}")]
    Ping(String),
}

enum Target {
    Unix(String),
    Tcp(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClashNode {
    pub name: String,
    pub typ: String,
}

#[derive(Debug, Clone, Default)]
pub struct GroupInfo {
    pub typ: String,
    pub now: String,
    pub all: Vec<String>,
}

pub struct ClashClient {
    target: Target,
    secret: String,
    requires_secret: bool,
    timeout: Duration,
}

impl ClashClient {

    pub fn from_api_url(api_url: &str, secret: &str) -> Self {
        let (target, requires_secret) = if let Some(p) = api_url.strip_prefix("unix://") {
            (Target::Unix(p.to_string()), false)
        } else {
            let hp = api_url
                .strip_prefix("http://")
                .or_else(|| api_url.strip_prefix("https://"))
                .unwrap_or(api_url)
                .trim_end_matches('/')
                .to_string();
            (Target::Tcp(hp), true)
        };
        Self {
            target,
            secret: secret.to_string(),
            requires_secret,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn requires_secret(&self) -> bool {
        self.requires_secret
    }

    pub fn set_timeout(&mut self, d: Duration) {
        self.timeout = d;
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), ClashErr> {
        let mut req: Vec<u8> = Vec::new();
        let _ = write!(req, "{method} {path} HTTP/1.1\r\nHost: localhost\r\n");

        if !self.secret.is_empty() {
            let _ = write!(req, "Authorization: Bearer {}\r\n", self.secret);
        }
        if let Some(b) = body {
            let _ = write!(
                req,
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            );
        }
        req.extend_from_slice(b"Connection: close\r\n\r\n");
        if let Some(b) = body {
            req.extend_from_slice(b);
        }

        let raw = match &self.target {
            Target::Unix(p) => {
                let mut s = UnixStream::connect(p)?;
                s.set_read_timeout(Some(self.timeout))?;
                s.set_write_timeout(Some(self.timeout))?;
                s.write_all(&req)?;
                s.flush()?;
                let mut buf = Vec::new();
                s.read_to_end(&mut buf)?;
                buf
            }
            Target::Tcp(hp) => {
                let mut s = TcpStream::connect(hp)?;
                s.set_read_timeout(Some(self.timeout))?;
                s.set_write_timeout(Some(self.timeout))?;
                s.write_all(&req)?;
                s.flush()?;
                let mut buf = Vec::new();
                s.read_to_end(&mut buf)?;
                buf
            }
        };
        parse_http_response(&raw)
    }

    pub fn get_mode(&self) -> Result<String, ClashErr> {
        let (code, body) = self.send("GET", "/configs", None)?;
        ok(code)?;
        let v = json(&body)?;
        Ok(v.get("mode")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string())
    }

    pub fn get_nodes(&self) -> Result<(Vec<ClashNode>, String), ClashErr> {
        let (code, body) = self.send("GET", "/proxies", None)?;
        ok(code)?;
        Ok(parse_proxies(&json(&body)?))
    }

    pub fn set_global_mode(&self) -> Result<(), ClashErr> {
        let (code, _) = self.send("PATCH", "/configs", Some(br#"{"mode":"Global"}"#))?;
        ok(code)
    }

    pub fn select_node(&self, name: &str) -> Result<(), ClashErr> {
        self.set_global_mode()?;
        let body = serde_json::json!({ "name": name }).to_string();
        let (code, _) = self.send("PUT", "/proxies/GLOBAL", Some(body.as_bytes()))?;
        ok(code)
    }

    pub fn reload_yaml(&self) -> Result<(), ClashErr> {
        let (code, _) = self.send("PUT", "/configs", Some(br#"{"path":"/tmp/clash.yaml"}"#))?;
        ok(code)
    }

    pub fn delete_connections(&self) -> Result<(), ClashErr> {
        let (code, _) = self.send("DELETE", "/connections", None)?;
        ok(code)
    }

    pub fn ping_node(
        &self,
        name: &str,
        test_url: &str,
        timeout: &str,
        cpudelay: i64,
    ) -> Result<u32, ClashErr> {
        if cpudelay > 0 && system_load_delay_ms() > cpudelay as u128 {
            return Err(ClashErr::Ping("high cpu load".into()));
        }
        let path = format!(
            "/proxies/{}/delay?timeout={}&url={}",
            percent_encode(name),
            timeout,
            percent_encode(test_url)
        );
        let (code, body) = self.send("GET", &path, None)?;
        if !(200..300).contains(&code) {
            return Err(ClashErr::Ping(format!("status {code}")));
        }
        let v = json(&body)?;
        let delay = v.get("delay").and_then(|d| d.as_u64()).unwrap_or(0);
        if delay > 0 {
            Ok(delay as u32)
        } else {
            Err(ClashErr::Ping("no delay".into()))
        }
    }

    pub fn get_group_info(&self, name: &str) -> Result<GroupInfo, ClashErr> {
        let (code, body) = self.send("GET", &format!("/group/{}", percent_encode(name)), None)?;
        ok(code)?;
        let v = json(&body)?;
        Ok(GroupInfo {
            typ: v
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            now: v
                .get("now")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            all: v
                .get("all")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    pub fn test_node_delay(
        &self,
        name: &str,
        url: &str,
        expected: &str,
        timeout_ms: u32,
    ) -> Result<u32, ClashErr> {
        let path = format!(
            "/proxies/{}/delay?timeout={}&url={}&expected={}",
            percent_encode(name),
            timeout_ms,
            percent_encode(url),
            percent_encode(&normalize_expected_status(expected))
        );
        let (code, body) = self.send("GET", &path, None)?;
        if !(200..300).contains(&code) {
            return Err(ClashErr::Ping(format!("status {code}")));
        }
        let v = json(&body)?;
        let delay = v.get("delay").and_then(|d| d.as_u64()).unwrap_or(0);
        if delay > 0 {
            Ok(delay as u32)
        } else {
            Err(ClashErr::Ping("no delay".into()))
        }
    }

    pub fn test_group_delay(
        &self,
        group: &str,
        url: &str,
        expected: &str,
        timeout_ms: u32,
    ) -> Result<HashMap<String, u32>, ClashErr> {
        let path = format!(
            "/group/{}/delay?timeout={}&url={}&expected={}",
            percent_encode(group),
            timeout_ms,
            percent_encode(url),
            percent_encode(&normalize_expected_status(expected))
        );
        let (code, body) = self.send("GET", &path, None)?;
        if code == 504 {
            return Ok(HashMap::new());
        }
        ok(code)?;
        let v = json(&body)?;
        let mut out = HashMap::new();
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                if let Some(d) = val.as_u64() {
                    out.insert(k.clone(), d as u32);
                }
            }
        }
        Ok(out)
    }

    pub fn set_group_selected(&self, group: &str, node: &str) -> Result<(), ClashErr> {
        let body = serde_json::json!({ "name": node }).to_string();
        let (code, _) = self.send(
            "PUT",
            &format!("/proxies/{}", percent_encode(group)),
            Some(body.as_bytes()),
        )?;
        ok(code)
    }
}

pub fn normalize_expected_status(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        "100-599".to_string()
    } else {
        s.to_string()
    }
}

fn ok(code: u16) -> Result<(), ClashErr> {
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(ClashErr::Status(code))
    }
}

fn json(body: &[u8]) -> Result<serde_json::Value, ClashErr> {
    serde_json::from_slice(body).map_err(|e| ClashErr::Json(e.to_string()))
}

fn parse_proxies(v: &serde_json::Value) -> (Vec<ClashNode>, String) {
    let mut nodes = Vec::new();
    if let Some(obj) = v.get("proxies").and_then(|p| p.as_object()) {
        for (name, node) in obj {
            let typ = node
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if !crate::nodes::is_system_node(&typ) {
                nodes.push(ClashNode {
                    name: name.clone(),
                    typ,
                });
            }
        }
    }
    let now = v
        .get("proxies")
        .and_then(|p| p.get("GLOBAL"))
        .and_then(|g| g.get("now"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    (nodes, now)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), ClashErr> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(raw).map_err(|_| ClashErr::BadResponse)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err(ClashErr::BadResponse),
    };
    let code = resp.code.ok_or(ClashErr::BadResponse)?;
    let chunked = resp.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value)
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false)
    });
    let body = &raw[head_len..];
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_vec()
    };
    Ok((code, body))
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

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0xf));
            }
        }
    }
    out
}

fn hex_upper(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

fn system_load_delay_ms() -> u128 {
    let start = Instant::now();
    match std::process::Command::new("ps").output() {
        Ok(_) => start.elapsed().as_millis(),
        Err(_) => 10000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_api_url_unix_vs_tcp() {
        let u = ClashClient::from_api_url("unix:///tmp/clash.sock", "");
        assert!(!u.requires_secret());
        assert!(matches!(u.target, Target::Unix(ref p) if p == "/tmp/clash.sock"));

        let t = ClashClient::from_api_url("http://127.0.0.1:9090", "sek");
        assert!(t.requires_secret());
        assert!(matches!(t.target, Target::Tcp(ref hp) if hp == "127.0.0.1:9090"));
    }

    #[test]
    fn percent_encode_escapes() {
        assert_eq!(percent_encode("NodeA"), "NodeA");
        assert_eq!(percent_encode("a b/c"), "a%20b%2Fc");
        assert_eq!(
            percent_encode("http://x/y?z=1"),
            "http%3A%2F%2Fx%2Fy%3Fz%3D1"
        );
    }

    #[test]
    fn parse_response_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"mode\":\"rule\"}\n\n";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 200);
        assert!(String::from_utf8_lossy(&body).contains("rule"));
    }

    #[test]
    fn parse_response_204_no_body() {
        let raw = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 204);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn ok_status_ranges() {
        assert!(ok(200).is_ok());
        assert!(ok(204).is_ok());
        assert!(ok(404).is_err());
        assert!(ok(500).is_err());
    }

    #[test]
    fn normalize_expected() {
        assert_eq!(normalize_expected_status(""), "100-599");
        assert_eq!(normalize_expected_status("0"), "100-599");
        assert_eq!(normalize_expected_status(" 0 "), "100-599");
        assert_eq!(normalize_expected_status("200"), "200");
        assert_eq!(normalize_expected_status("200-299"), "200-299");
    }

    #[test]
    fn parse_proxies_filters_system_types_and_takes_now() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"proxies":{
                "GLOBAL":{"name":"GLOBAL","type":"Selector","now":"NodeA"},
                "NodeA":{"name":"NodeA","type":"Shadowsocks"},
                "NodeB":{"name":"NodeB","type":"Vmess"},
                "DIRECT":{"name":"DIRECT","type":"Direct"},
                "REJECT":{"name":"REJECT","type":"Reject"}
            }}"#,
        )
        .unwrap();
        let (nodes, now) = parse_proxies(&v);
        let mut names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
        names.sort();

        assert_eq!(names, vec!["GLOBAL", "NodeA", "NodeB"]);
        assert_eq!(now, "NodeA");
    }
}
