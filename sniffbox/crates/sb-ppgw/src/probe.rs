// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use ureq::config::Config;
use ureq::http::Uri;
use ureq::{Agent, ResponseExt};

pub const UA_BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                              (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const DEFAULT_HEADERS: &[(&str, &str)] = &[
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    ("accept-language", "en-US,en;q=0.9"),
    ("upgrade-insecure-requests", "1"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-user", "?1"),
    ("priority", "u=0, i"),
];

const MAX_HEADERS: usize = 24;
const MAX_HEADER_LEN: usize = 8192;
const MAX_UA_LEN: usize = 256;
const MAX_URL_LEN: usize = 2048;
const MAX_REQ_BODY: usize = 8 * 1024;

const MAX_RESP_BODY: u64 = 5 * 1024 * 1024;
const DEFAULT_RESP_BODY: u64 = 256 * 1024;

const MAX_REDIRECTS: u32 = 5;
const MIN_TIMEOUT_MS: u64 = 1_000;
const MAX_TIMEOUT_MS: u64 = 20_000;
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

const DENY_HEADERS: &[&str] = &[
    "accept-encoding",
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

struct Req {
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    ua: String,
    follow: bool,
    timeout: Duration,
    max_body: u64,

    binary: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Head,
    Post,
}

pub fn run_json(req_json: &str, proxy: &str) -> String {
    let req = match serde_json::from_str::<Value>(req_json)
        .map_err(|e| e.to_string())
        .and_then(|v| validate(&v))
    {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "denied": true, "error": e }).to_string(),
    };
    let started = Instant::now();
    match execute(&req, proxy) {
        Ok(mut v) => {
            v["ms"] = json!(started.elapsed().as_millis() as u64);
            v.to_string()
        }
        Err(e) => json!({ "ok": false, "error": e, "ms": started.elapsed().as_millis() as u64 })
            .to_string(),
    }
}

fn validate(v: &Value) -> Result<Req, String> {
    let obj = v.as_object().ok_or("request must be a JSON object")?;

    let method = match obj
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_ascii_uppercase()
        .as_str()
    {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        m => return Err(format!("method not allowed: {m}")),
    };

    let url = obj
        .get("url")
        .and_then(Value::as_str)
        .ok_or("missing url")?;
    if url.len() > MAX_URL_LEN {
        return Err("url too long".into());
    }
    check_url(url)?;

    let headers = parse_headers(obj.get("headers"))?;

    let body = match obj.get("body") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            if method != Method::Post {
                return Err("body only allowed on POST".into());
            }
            if s.len() > MAX_REQ_BODY {
                return Err("body too large".into());
            }
            Some(s.clone())
        }
        Some(_) => return Err("body must be a string".into()),
    };

    let ua = obj.get("ua").and_then(Value::as_str).unwrap_or(UA_BROWSER);
    if ua.len() > MAX_UA_LEN || !is_header_value(ua) {
        return Err("bad ua".into());
    }

    let timeout_ms = obj
        .get("timeoutMs")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
    let max_body = obj
        .get("maxBody")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_RESP_BODY)
        .clamp(1, MAX_RESP_BODY);

    Ok(Req {
        method,
        url: url.to_string(),
        headers,
        body,
        ua: ua.to_string(),
        follow: obj.get("follow").and_then(Value::as_bool).unwrap_or(true),
        timeout: Duration::from_millis(timeout_ms),
        max_body,
        binary: obj.get("binary").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn parse_headers(v: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(v) = v else { return Ok(Vec::new()) };
    if v.is_null() {
        return Ok(Vec::new());
    }
    let map = v.as_object().ok_or("headers must be an object")?;
    if map.len() > MAX_HEADERS {
        return Err("too many headers".into());
    }
    let mut out = Vec::with_capacity(map.len());
    for (k, val) in map {
        let val = val.as_str().ok_or("header value must be a string")?;
        if k.len() > MAX_HEADER_LEN || val.len() > MAX_HEADER_LEN {
            return Err("header too long".into());
        }
        if !is_header_name(k) {
            return Err(format!("bad header name: {k}"));
        }
        if !is_header_value(val) {
            return Err(format!("bad header value for {k}"));
        }
        let lower = k.to_ascii_lowercase();
        if DENY_HEADERS.contains(&lower.as_str()) {
            return Err(format!("header not allowed: {lower}"));
        }
        out.push((lower, val.to_string()));
    }
    Ok(out)
}

fn is_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn is_header_value(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
}

fn check_url(url: &str) -> Result<(), String> {
    let uri: Uri = url.parse().map_err(|_| "bad url".to_string())?;
    let scheme = uri.scheme_str().ok_or("url must be absolute")?;
    let https = match scheme {
        "http" => false,
        "https" => true,
        s => return Err(format!("scheme not allowed: {s}")),
    };
    match uri.port_u16() {
        None => {}
        Some(80) if !https => {}
        Some(443) if https => {}
        Some(p) => return Err(format!("port not allowed: {p}")),
    }
    let host = uri.host().ok_or("url has no host")?;
    check_host(host)
}

fn check_host(host: &str) -> Result<(), String> {

    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return if ip_is_global(ip) {
            Ok(())
        } else {
            Err(format!("non-public address: {bare}"))
        };
    }
    if host.len() > 253 || !host.contains('.') || host.starts_with('.') || host.ends_with('.') {
        return Err(format!("bad host: {host}"));
    }
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err("non-public address: localhost".into());
    }
    Ok(())
}

fn ip_is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_is_global(a),
        IpAddr::V6(a) => v6_is_global(a),
    }
}

fn v4_is_global(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_multicast()
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && o[1] & 0xfe == 18)
        || o[0] >= 240)
}

fn v6_is_global(a: Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return v4_is_global(v4);
    }
    let s = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || s[0] & 0xfe00 == 0xfc00
        || s[0] & 0xffc0 == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0xdb8))
}

fn execute(req: &Req, proxy: &str) -> Result<Value, String> {
    let agent = build_agent(req, proxy)?;

    let mut resp = match req.method {
        Method::Get => apply(agent.get(&req.url), req).call(),
        Method::Head => apply(agent.head(&req.url), req).call(),
        Method::Post => {
            let rb = apply(agent.post(&req.url), req);
            match &req.body {
                Some(b) => rb.send(b.as_bytes()),
                None => rb.send_empty(),
            }
        }
    }
    .map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    let final_url = resp.get_uri().to_string();
    let (headers, set_cookie) = collect_headers(resp.headers());

    let mut buf = Vec::new();
    resp.body_mut()
        .as_reader()
        .take(req.max_body + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    let truncated = buf.len() as u64 > req.max_body;
    buf.truncate(req.max_body as usize);

    let (body, encoding) = if req.binary {
        (b64_encode(&buf), "base64")
    } else {
        (String::from_utf8_lossy(&buf).into_owned(), "utf8")
    };

    Ok(json!({
        "ok": true,
        "status": status,
        "url": final_url,
        "headers": headers,
        "setCookie": set_cookie,
        "body": body,
        "encoding": encoding,
        "truncated": truncated,
    }))
}

fn build_agent(req: &Req, proxy: &str) -> Result<Agent, String> {
    let redirects = if req.follow { MAX_REDIRECTS } else { 0 };
    let mut b = Config::builder()
        .http_status_as_error(false)
        .max_redirects(redirects)

        .max_redirects_will_error(false)
        .save_redirect_history(true)
        .timeout_global(Some(req.timeout))
        .user_agent(req.ua.clone());
    if !proxy.is_empty() {
        b = b.proxy(Some(ureq::Proxy::new(proxy).map_err(|e| e.to_string())?));
    }
    Ok(b.build().into())
}

fn apply<T>(mut rb: ureq::RequestBuilder<T>, req: &Req) -> ureq::RequestBuilder<T> {
    let has = |name: &str| req.headers.iter().any(|(hk, _)| hk == name);

    for (k, v) in DEFAULT_HEADERS {
        if !has(k) {
            rb = rb.header(*k, *v);
        }
    }

    if !has("referer") {
        if let Some(origin) = origin_of(&req.url) {
            rb = rb.header("referer", &origin);
        }
    }
    for (k, v) in &req.headers {
        rb = rb.header(k, v);
    }

    rb
}

fn origin_of(url: &str) -> Option<String> {
    let uri: Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    Some(format!("{scheme}://{authority}/"))
}

fn collect_headers(h: &ureq::http::HeaderMap) -> (Map<String, Value>, Vec<Value>) {
    let mut map = Map::new();
    let mut cookies = Vec::new();
    for (name, val) in h.iter() {
        let Ok(v) = val.to_str() else { continue };
        let name = name.as_str();
        if name.eq_ignore_ascii_case("set-cookie") {
            cookies.push(json!(v));
            continue;
        }
        match map.get_mut(name) {
            Some(Value::String(prev)) => {
                prev.push_str(", ");
                prev.push_str(v);
            }
            _ => {
                map.insert(name.to_string(), json!(v));
            }
        }
    }
    (map, cookies)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(json_req: &str) -> String {

        let out = run_json(json_req, "");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false, "should be rejected: {out}");
        assert_eq!(
            v["denied"], true,
            "should be denied by sandbox, not a network error: {out}"
        );
        v["error"].as_str().unwrap().to_string()
    }

    #[test]
    fn b64_encode_matches_rfc4648() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    fn rejects_non_public_hosts() {
        for host in [
            "http://127.0.0.1/x",
            "http://localhost/x",
            "http://app.localhost/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://172.16.0.1/x",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.0.1/x",
            "http://198.18.0.1/x",
            "http://[::1]/x",
            "http://[fd00::1]/x",
            "http://[fe80::1]/x",
            "http://[::ffff:127.0.0.1]/x",
            "http://router/x",
        ] {
            let e = denied(&json!({ "url": host }).to_string());
            assert!(
                e.contains("non-public") || e.contains("bad host"),
                "{host} → {e}"
            );
        }
    }

    #[test]
    fn allows_public_hosts() {
        for url in [
            "https://www.netflix.com/title/1",
            "http://example.com",
            "https://1.1.1.1/",
            "https://[2606:4700::1]/",
        ] {
            check_url(url).unwrap_or_else(|e| panic!("{url} should be allowed: {e}"));
        }
    }

    #[test]
    fn rejects_bad_scheme_and_port() {

        denied(&json!({"url":"file:///etc/passwd"}).to_string());
        denied(&json!({"url":"//evil.com/x"}).to_string());
        assert!(denied(&json!({"url":"gopher://example.com/"}).to_string()).contains("scheme"));
        assert!(denied(&json!({"url":"http://example.com:22/"}).to_string()).contains("port"));
        assert!(denied(&json!({"url":"https://example.com:8443/"}).to_string()).contains("port"));

        assert!(denied(&json!({"url":"https://example.com:80/"}).to_string()).contains("port"));
        assert!(denied(&json!({"url":"http://example.com:443/"}).to_string()).contains("port"));
    }

    #[test]
    fn rejects_bad_method_and_body() {
        assert!(
            denied(&json!({"url":"https://example.com","method":"DELETE"}).to_string())
                .contains("method")
        );
        assert!(
            denied(&json!({"url":"https://example.com","method":"PUT"}).to_string())
                .contains("method")
        );

        assert!(
            denied(&json!({"url":"https://example.com","body":"x"}).to_string())
                .contains("body only")
        );
        let big = "x".repeat(MAX_REQ_BODY + 1);
        assert!(
            denied(&json!({"url":"https://example.com","method":"POST","body":big}).to_string())
                .contains("too large")
        );
    }

    #[test]
    fn rejects_denied_and_malformed_headers() {
        for h in DENY_HEADERS {
            let e = denied(&json!({"url":"https://example.com","headers":{ *h: "x" }}).to_string());
            assert!(e.contains("not allowed"), "{h} → {e}");
        }

        assert!(
            denied(&json!({"url":"https://example.com","headers":{"Host":"evil.com"}}).to_string())
                .contains("not allowed")
        );

        assert!(
            denied(
                &json!({"url":"https://example.com","headers":{"X-A":"a\r\nX-B: b"}}).to_string()
            )
            .contains("bad header value")
        );
        assert!(
            denied(&json!({"url":"https://example.com","headers":{"X A":"b"}}).to_string())
                .contains("bad header name")
        );
    }

    #[test]
    fn clamps_limits() {
        let r =
            validate(&json!({"url":"https://example.com","timeoutMs":1,"maxBody":1<<30})).unwrap();
        assert_eq!(r.timeout, Duration::from_millis(MIN_TIMEOUT_MS));
        assert_eq!(r.max_body, MAX_RESP_BODY);

        let r = validate(&json!({"url":"https://example.com","timeoutMs":999_999})).unwrap();
        assert_eq!(r.timeout, Duration::from_millis(MAX_TIMEOUT_MS));

        let r = validate(&json!({"url":"https://example.com"})).unwrap();
        assert_eq!(r.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert_eq!(r.max_body, DEFAULT_RESP_BODY);
        assert!(r.follow);
        assert_eq!(r.ua, UA_BROWSER);
    }

    #[test]
    fn accepts_normal_request() {
        let r = validate(&json!({
            "url": "https://api.kktv.me/v3/ipcheck",
            "method": "POST",
            "headers": { "Accept-Language": "en-US", "X-Trace": "1" },
            "body": "{}",
            "ua": "curl/8",
            "follow": false,
        }))
        .unwrap();
        assert_eq!(r.method, Method::Post);
        assert_eq!(
            r.headers,
            vec![
                ("accept-language".into(), "en-US".into()),
                ("x-trace".into(), "1".into())
            ]
        );
        assert_eq!(r.body.as_deref(), Some("{}"));
        assert!(!r.follow);
    }

    #[test]
    fn bad_json_is_denied_not_panic() {
        let out = run_json("not json", "");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["denied"], true);
        let out = run_json("[1,2,3]", "");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["denied"], true);
    }

    fn spawn_server() -> u16 {
        use std::io::{BufRead, BufReader, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut req = line.clone();
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    req.push_str(&h);
                }
                let resp = match path.as_str() {
                    "/ok" => "HTTP/1.1 200 OK\r\nX-A: 1\r\nX-A: 2\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_string(),
                    "/big" => format!("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}", "x".repeat(100)),
                    "/redir" => "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/teapot" => "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnope".to_string(),

                    _ => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{req}", req.len()),
                };
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
            }
        });
        port
    }

    fn req_to(port: u16, path: &str) -> Req {
        Req {
            method: Method::Get,
            url: format!("http://127.0.0.1:{port}{path}"),
            headers: Vec::new(),
            body: None,
            ua: UA_BROWSER.into(),
            follow: true,
            timeout: Duration::from_secs(5),
            max_body: DEFAULT_RESP_BODY,
            binary: false,
        }
    }

    #[test]
    fn execute_reads_status_headers_cookies_body() {
        let port = spawn_server();
        let v = execute(&req_to(port, "/ok"), "").unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["status"], 200);
        assert_eq!(v["body"], "hello");
        assert_eq!(v["truncated"], false);
        assert_eq!(v["headers"]["x-a"], "1, 2");
        assert_eq!(v["setCookie"], json!(["a=1; Path=/", "b=2"]));
        assert_eq!(v["url"], format!("http://127.0.0.1:{port}/ok"));
    }

    #[test]
    fn execute_returns_error_statuses_not_err() {
        let port = spawn_server();
        let v = execute(&req_to(port, "/teapot"), "").unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["status"], 418);
    }

    #[test]
    fn execute_truncates_oversized_body() {
        let port = spawn_server();
        let mut req = req_to(port, "/big");
        req.max_body = 10;
        let v = execute(&req, "").unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["body"], "xxxxxxxxxx");
        assert_eq!(v["truncated"], true);
    }

    #[test]
    fn execute_follow_toggle() {
        let port = spawn_server();
        let v = execute(&req_to(port, "/redir"), "").unwrap();
        assert_eq!(v["status"], 200);
        assert_eq!(
            v["url"],
            format!("http://127.0.0.1:{port}/ok"),
            "follow=true should report final URL"
        );

        let mut req = req_to(port, "/redir");
        req.follow = false;
        let v = execute(&req, "").unwrap();
        assert_eq!(
            v["status"], 302,
            "follow=false should not follow redirects nor report TooManyRedirects"
        );
        assert_eq!(v["headers"]["location"], "/ok");
    }

    #[test]
    fn execute_sends_headers_ua_and_body() {
        let port = spawn_server();
        let req = Req {
            method: Method::Post,
            url: format!("http://127.0.0.1:{port}/echo"),
            headers: vec![("x-trace".into(), "abc".into())],
            body: Some("payload=1".into()),
            ua: "probe-ua/1".into(),
            follow: true,
            timeout: Duration::from_secs(5),
            max_body: DEFAULT_RESP_BODY,
            binary: false,
        };
        let v = execute(&req, "").unwrap();
        let echo = v["body"].as_str().unwrap().to_ascii_lowercase();
        assert!(echo.starts_with("post /echo"), "{echo}");
        assert!(echo.contains("x-trace: abc"), "{echo}");
        assert!(echo.contains("user-agent: probe-ua/1"), "{echo}");

        assert!(
            echo.contains("accept-encoding: gzip"),
            "should advertise gzip for transparent decompression: {echo}"
        );
        assert!(
            !echo.contains("accept-encoding: identity"),
            "should not send identity (bot signature): {echo}"
        );
    }

    #[test]
    fn execute_defaults_same_origin_referer() {
        let port = spawn_server();
        let v = execute(&req_to(port, "/echo"), "").unwrap();
        let echo = v["body"].as_str().unwrap().to_ascii_lowercase();
        assert!(
            echo.contains(&format!("referer: http://127.0.0.1:{port}/")),
            "missing default same-origin referer: {echo}"
        );

        let mut req = req_to(port, "/echo");
        req.headers = vec![("referer".into(), "https://example.com/x".into())];
        let echo = execute(&req, "").unwrap()["body"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            echo.contains("referer: https://example.com/x"),
            "per-test referer should take priority: {echo}"
        );
        assert_eq!(
            echo.matches("referer:").count(),
            1,
            "referer should not duplicate: {echo}"
        );
    }

    #[test]
    fn execute_fills_default_browser_headers() {
        let port = spawn_server();
        let mut req = req_to(port, "/echo");
        req.headers = vec![("accept-language".into(), "ja-JP".into())];
        let v = execute(&req, "").unwrap();
        let echo = v["body"].as_str().unwrap().to_ascii_lowercase();
        assert!(
            echo.contains("sec-fetch-mode: navigate"),
            "missing default headers: {echo}"
        );
        assert!(echo.contains("accept: text/html"), "missing default accept: {echo}");

        assert!(echo.contains("accept-language: ja-jp"), "{echo}");
        assert_eq!(
            echo.matches("accept-language:").count(),
            1,
            "should not duplicate: {echo}"
        );
    }

    #[test]
    fn run_json_network_error_is_not_denied() {

        let out = run_json(
            &json!({"url":"https://127.0.0.1.nip.io/","timeoutMs":1000}).to_string(),
            "socks5h://127.0.0.1:1",
        );
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v.get("denied").is_none(), "network error is not sandbox denial: {out}");
        assert!(v["ms"].is_number(), "{out}");
        assert!(v["error"].is_string(), "{out}");
    }

    #[test]
    fn collect_headers_merges_dupes_and_splits_cookies() {
        let mut h = ureq::http::HeaderMap::new();
        h.append("x-a", "1".parse().unwrap());
        h.append("x-a", "2".parse().unwrap());
        h.append("set-cookie", "a=1".parse().unwrap());
        h.append("set-cookie", "b=2".parse().unwrap());
        let (map, cookies) = collect_headers(&h);
        assert_eq!(map["x-a"], "1, 2");
        assert_eq!(cookies, vec![json!("a=1"), json!("b=2")]);
        assert!(!map.contains_key("set-cookie"));
    }
}
