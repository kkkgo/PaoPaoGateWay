// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use wreq::Uri;
use wreq::header::USER_AGENT;

use crate::httpcli;

const DEFAULT_HEADERS: &[(&str, &str)] = &[
    ("upgrade-insecure-requests", "1"),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-user", "?1"),
];

const MAX_HEADERS: usize = 24;
const MAX_HEADER_LEN: usize = 8192;
const MAX_UA_LEN: usize = 256;
const MAX_URL_LEN: usize = 2048;
const MAX_REQ_BODY: usize = 8 * 1024;

const MAX_RESP_BODY: u64 = 5 * 1024 * 1024;
const DEFAULT_RESP_BODY: u64 = 256 * 1024;

const MAX_REDIRECTS: usize = 5;
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

    ua: Option<String>,
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

pub async fn run_json(req_json: &str, proxy: &str) -> String {
    run_json_inner(req_json, proxy, false).await
}

pub async fn run_json_relaxed(req_json: &str, proxy: &str) -> String {
    run_json_inner(req_json, proxy, true).await
}

async fn run_json_inner(req_json: &str, proxy: &str, relaxed: bool) -> String {
    let req = match serde_json::from_str::<Value>(req_json)
        .map_err(|e| e.to_string())
        .and_then(|v| validate_with(&v, relaxed))
    {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "denied": true, "error": e }).to_string(),
    };
    let started = Instant::now();
    match execute(&req, proxy).await {
        Ok(mut v) => {
            v["ms"] = json!(started.elapsed().as_millis() as u64);
            v.to_string()
        }
        Err(e) => json!({ "ok": false, "error": e, "ms": started.elapsed().as_millis() as u64 })
            .to_string(),
    }
}

fn validate_with(v: &Value, relaxed: bool) -> Result<Req, String> {
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
    check_url(url, relaxed)?;

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

    let ua = obj.get("ua").and_then(Value::as_str);
    if let Some(ua) = ua
        && (ua.len() > MAX_UA_LEN || !is_header_value(ua))
    {
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
        ua: ua.map(str::to_string),
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

fn check_url(url: &str, relaxed: bool) -> Result<(), String> {
    let uri: Uri = url.parse().map_err(|_| "bad url".to_string())?;
    let scheme = uri.scheme_str().ok_or("url must be absolute")?;
    let https = match scheme {
        "http" => false,
        "https" => true,
        s => return Err(format!("scheme not allowed: {s}")),
    };

    match uri.port_u16() {
        None => {}
        Some(0) => return Err("port not allowed: 0".into()),
        Some(_) if relaxed => {}
        Some(80) if !https => {}
        Some(443) if https => {}
        Some(p) => return Err(format!("port not allowed: {p}")),
    }
    let host = uri.host().ok_or("url has no host")?;
    check_host(host, relaxed)
}

fn check_host(host: &str, allow_lan: bool) -> Result<(), String> {

    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        let ok = if allow_lan {
            ip_is_lan_ok(ip)
        } else {
            ip_is_global(ip)
        };
        return if ok {
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

fn ip_is_lan_ok(ip: IpAddr) -> bool {
    if ip_is_global(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(a) => a.is_private(),
        IpAddr::V6(a) => {
            a.to_ipv4_mapped().is_some_and(|v4| v4.is_private())
                || (a.segments()[0] & 0xfe00) == 0xfc00
        }
    }
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

async fn execute(req: &Req, proxy: &str) -> Result<Value, String> {
    let client = httpcli::secure_client();
    let mut rb = match req.method {
        Method::Get => client.get(&req.url),
        Method::Head => client.head(&req.url),
        Method::Post => client.post(&req.url),
    };

    rb = rb.redirect(if req.follow {
        wreq::redirect::Policy::limited(MAX_REDIRECTS)
    } else {
        wreq::redirect::Policy::none()
    });
    rb = rb.timeout(req.timeout);
    if let Some(p) = httpcli::proxy_for(proxy).map_err(|e| e.to_string())? {
        rb = rb.proxy(p);
    }
    rb = apply(rb, req);
    if let Some(b) = &req.body {
        rb = rb.body(b.clone());
    }

    let resp = rb.send().await.map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();

    let final_url = resp.uri().to_string();
    let (headers, set_cookie) = collect_headers(resp.headers());

    let (mut buf, over) = httpcli::read_body_bounded(resp, req.max_body + 1)
        .await
        .map_err(|e| e.to_string())?;
    let truncated = over || buf.len() as u64 > req.max_body;
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

fn apply(mut rb: wreq::RequestBuilder, req: &Req) -> wreq::RequestBuilder {
    let has = |name: &str| req.headers.iter().any(|(hk, _)| hk == name);

    for (k, v) in DEFAULT_HEADERS {
        if !has(k) {
            rb = rb.header(*k, *v);
        }
    }

    if !has("referer")
        && let Some(origin) = origin_of(&req.url)
    {
        rb = rb.header("referer", &origin);
    }
    for (k, v) in &req.headers {
        rb = rb.header(k, v);
    }

    if let Some(ua) = &req.ua {
        rb = rb.header(USER_AGENT, ua);
    }

    rb
}

fn origin_of(url: &str) -> Option<String> {
    let uri: Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    Some(format!("{scheme}://{authority}/"))
}

fn collect_headers(h: &wreq::header::HeaderMap) -> (Map<String, Value>, Vec<Value>) {
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

        let out = crate::rt::block_on(run_json(json_req, ""));
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false, "should be rejected: {out}");
        assert_eq!(
            v["denied"], true,
            "should be denied by sandbox, not a network error: {out}"
        );
        v["error"].as_str().unwrap().to_string()
    }

    #[test]
    fn relaxed_mode_allows_private_and_any_port_but_still_blocks_loopback_and_friends() {
        for url in [
            "http://192.168.193.25/",
            "http://10.0.0.1/x",
            "http://172.16.0.1/x",
            "http://[fd00::1]/x",
            "http://[::ffff:192.168.1.1]/x",
            "http://192.168.1.1:8080/",
            "https://example.com:8443/",
            "https://example.com/",
        ] {
            check_url(url, true)
                .unwrap_or_else(|e| panic!("{url} should be allowed in relaxed mode: {e}"));
            assert!(
                check_url(url, false).is_err() || url == "https://example.com/",
                "{url} must stay blocked in the default (region-check) mode"
            );
        }
        for url in [
            "http://127.0.0.1/x",
            "http://127.0.0.1:1079/x",
            "http://[::1]/x",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.0.1/x",
            "http://198.18.0.1/x",
            "http://localhost/x",
            "http://router/x",
            "ftp://192.168.1.1/x",
            "http://192.168.1.1:0/x",
        ] {
            assert!(
                check_url(url, true).is_err(),
                "{url} must stay blocked even in relaxed mode"
            );
        }
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
            check_url(url, false).unwrap_or_else(|e| panic!("{url} should be allowed: {e}"));
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
        let r = validate_with(
            &json!({"url":"https://example.com","timeoutMs":1,"maxBody":1<<30}),
            false,
        )
        .unwrap();
        assert_eq!(r.timeout, Duration::from_millis(MIN_TIMEOUT_MS));
        assert_eq!(r.max_body, MAX_RESP_BODY);

        let r = validate_with(
            &json!({"url":"https://example.com","timeoutMs":999_999}),
            false,
        )
        .unwrap();
        assert_eq!(r.timeout, Duration::from_millis(MAX_TIMEOUT_MS));

        let r = validate_with(&json!({"url":"https://example.com"}), false).unwrap();
        assert_eq!(r.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert_eq!(r.max_body, DEFAULT_RESP_BODY);
        assert!(r.follow);
        assert_eq!(r.ua, None, "no `ua` field => emulation Chrome UA");
    }

    #[test]
    fn accepts_normal_request() {
        let r = validate_with(
            &json!({
                "url": "https://api.kktv.me/v3/ipcheck",
                "method": "POST",
                "headers": { "Accept-Language": "en-US", "X-Trace": "1" },
                "body": "{}",
                "ua": "curl/8",
                "follow": false,
            }),
            false,
        )
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
        let out = crate::rt::block_on(run_json("not json", ""));
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["denied"], true);
        let out = crate::rt::block_on(run_json("[1,2,3]", ""));
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
            ua: None,
            follow: true,
            timeout: Duration::from_secs(5),
            max_body: DEFAULT_RESP_BODY,
            binary: false,
        }
    }

    #[test]
    fn execute_reads_status_headers_cookies_body() {
        let port = spawn_server();
        let v = crate::rt::block_on(execute(&req_to(port, "/ok"), "")).unwrap();
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
        let v = crate::rt::block_on(execute(&req_to(port, "/teapot"), "")).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["status"], 418);
    }

    #[test]
    fn execute_truncates_oversized_body() {
        let port = spawn_server();
        let mut req = req_to(port, "/big");
        req.max_body = 10;
        let v = crate::rt::block_on(execute(&req, "")).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["body"], "xxxxxxxxxx");
        assert_eq!(v["truncated"], true);
    }

    #[test]
    fn execute_follow_toggle() {
        let port = spawn_server();
        let v = crate::rt::block_on(execute(&req_to(port, "/redir"), "")).unwrap();
        assert_eq!(v["status"], 200);
        assert_eq!(
            v["url"],
            format!("http://127.0.0.1:{port}/ok"),
            "follow=true should report final URL"
        );

        let mut req = req_to(port, "/redir");
        req.follow = false;
        let v = crate::rt::block_on(execute(&req, "")).unwrap();
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
            ua: Some("probe-ua/1".into()),
            follow: true,
            timeout: Duration::from_secs(5),
            max_body: DEFAULT_RESP_BODY,
            binary: false,
        };
        let v = crate::rt::block_on(execute(&req, "")).unwrap();
        let echo = v["body"].as_str().unwrap().to_ascii_lowercase();
        assert!(echo.starts_with("post /echo"), "{echo}");
        assert!(echo.contains("x-trace: abc"), "{echo}");
        assert!(echo.contains("user-agent: probe-ua/1"), "{echo}");

        let ae = echo
            .lines()
            .find(|l| l.starts_with("accept-encoding:"))
            .unwrap_or_else(|| panic!("no accept-encoding header: {echo}"));
        for enc in ["gzip", "deflate", "br", "zstd"] {
            assert!(
                ae.contains(enc),
                "accept-encoding should advertise {enc} for transparent decompression: {ae}"
            );
        }
        assert!(
            !echo.contains("accept-encoding: identity"),
            "should not send identity (bot signature): {echo}"
        );

        assert!(echo.contains("sec-ch-ua-platform:"), "{echo}");
    }

    #[test]
    fn execute_defaults_same_origin_referer() {
        let port = spawn_server();
        let v = crate::rt::block_on(execute(&req_to(port, "/echo"), "")).unwrap();
        let echo = v["body"].as_str().unwrap().to_ascii_lowercase();
        assert!(
            echo.contains(&format!("referer: http://127.0.0.1:{port}/")),
            "missing default same-origin referer: {echo}"
        );

        let mut req = req_to(port, "/echo");
        req.headers = vec![("referer".into(), "https://example.com/x".into())];
        let echo = crate::rt::block_on(execute(&req, "")).unwrap()["body"]
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
        let v = crate::rt::block_on(execute(&req, "")).unwrap();
        let echo = v["body"].as_str().unwrap().to_ascii_lowercase();
        assert!(
            echo.contains("sec-fetch-mode: navigate"),
            "missing default headers: {echo}"
        );
        assert!(
            echo.contains("accept: text/html"),
            "missing default accept: {echo}"
        );

        assert!(echo.contains("accept-language: ja-jp"), "{echo}");
        assert_eq!(
            echo.matches("accept-language:").count(),
            1,
            "should not duplicate: {echo}"
        );
    }

    #[test]
    fn run_json_network_error_is_not_denied() {

        let out = crate::rt::block_on(run_json(
            &json!({"url":"https://127.0.0.1.nip.io/","timeoutMs":1000}).to_string(),
            "socks5h://127.0.0.1:1",
        ));
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert!(
            v.get("denied").is_none(),
            "network error is not sandbox denial: {out}"
        );
        assert!(v["ms"].is_number(), "{out}");
        assert!(v["error"].is_string(), "{out}");
    }

    #[test]
    fn collect_headers_merges_dupes_and_splits_cookies() {
        let mut h = wreq::header::HeaderMap::new();
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
