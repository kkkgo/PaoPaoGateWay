// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::httpcli::{self, HttpErr};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

const MAX_RACE_IPS: usize = 16;

const MAX_BODY: u64 = 64 * 1024 * 1024;

fn log_get(msg: &str) {
    let _ = writeln!(
        std::io::stdout(),
        "{}{msg}",
        crate::term::green("[PaoPaoGW Get]")
    );
}
fn log_get_warn(msg: &str) {
    let _ = writeln!(
        std::io::stdout(),
        "{}{msg}",
        crate::term::orange("[PaoPaoGW Get]")
    );
}

fn fmt_ips(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Default)]
pub struct SubInfo {

    pub userinfo: Option<String>,
}

pub struct Downloader {
    pub url: String,
    pub output: String,
    timeout: Duration,
    best_effort: bool,
}

impl Downloader {
    pub fn new(url: &str, output: &str) -> Self {
        Self {
            url: url.to_string(),
            output: output.to_string(),
            timeout: TIMEOUT,
            best_effort: false,
        }
    }

    pub fn best_effort(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.best_effort = true;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn via_proxy(&self, proxy: &str) -> Result<SubInfo, HttpErr> {
        crate::rt::block_on(self.via_proxy_async(proxy))
    }

    pub async fn via_proxy_async(&self, proxy: &str) -> Result<SubInfo, HttpErr> {
        log_get(&format!("GET {} (via {proxy})", self.url));
        self.attempt(proxy).await
    }

    pub fn download(&self) -> Result<SubInfo, HttpErr> {
        crate::rt::block_on(self.download_async())
    }

    pub async fn download_async(&self) -> Result<SubInfo, HttpErr> {
        let ipv6 = crate::dnsutil::ipv6_enabled();
        let host = crate::dnsutil::url_hostname(&self.url);
        log_get(&format!("GET {} (host={host})", self.url));

        if host.parse::<IpAddr>().is_ok() {
            log_get(&format!("host is IP literal: {host}"));
            return self.attempt("").await;
        }

        if let Some(ip) = crate::dnsutil::lookup_hosts(&host, ipv6) {
            log_get(&format!("/etc/hosts: {host} -> {ip}"));
            if let Some(info) = self.race_download(&[ip]).await {
                return Ok(info);
            }
        }

        let mut servers = configured_dns_servers();
        if self.best_effort && !servers.is_empty() && servers.iter().all(|s| is_lan(s.ip())) {

            for s in crate::fallback::servers(&servers) {
                servers.push(s);
            }
        }
        if let Some(info) = self.resolve_and_race(&host, &servers, ipv6, "dns").await {
            return Ok(info);
        }
        if self.best_effort {
            log_get_warn("best effort: giving up, no fallback dns and no socks5");
            return Err(HttpErr::Request("best effort: unreachable".into()));
        }

        let fb = crate::fallback::servers(&servers);
        if !fb.is_empty()
            && let Some(info) = self
                .resolve_and_race(&host, &fb, ipv6, "fallback dns")
                .await
        {
            return Ok(info);
        }

        log_get("Trying Socks5 Proxy 127.0.0.1:1080...");
        match self.attempt("socks5h://127.0.0.1:1080").await {
            Ok(info) => {
                log_get("OK via Socks5");
                Ok(info)
            }
            Err(e) => {
                log_get_warn(&format!("Socks5 failed: {e}"));
                Err(e)
            }
        }
    }

    async fn resolve_and_race(
        &self,
        host: &str,
        servers: &[SocketAddr],
        ipv6: bool,
        tag: &str,
    ) -> Option<SubInfo> {
        if servers.is_empty() {
            return None;
        }

        let ips = {
            let (host, servers) = (host.to_string(), servers.to_vec());
            tokio::task::spawn_blocking(move || resolve_concurrent(&host, &servers, ipv6))
                .await
                .unwrap_or_default()
        };
        if ips.is_empty() {
            log_get_warn(&format!(
                "{tag}: no answer from {} server(s)",
                servers.len()
            ));
            return None;
        }
        log_get(&format!(
            "{tag}: {} server(s) -> [{}]",
            servers.len(),
            fmt_ips(&ips)
        ));
        self.race_download(&ips).await
    }

    async fn race_download(&self, ips: &[IpAddr]) -> Option<SubInfo> {

        if let [ip] = ips {
            return match fetch(&self.url, *ip, self.timeout).await {
                Ok((body, userinfo)) => self.finish(*ip, &body, userinfo, 1),
                Err(e) => {
                    log_get_warn(&format!("{ip} failed: {e}"));
                    None
                }
            };
        }

        let n = ips.len();
        let mut set = tokio::task::JoinSet::new();
        for &ip in ips {
            let (url, timeout) = (self.url.clone(), self.timeout);
            set.spawn(async move {
                (
                    ip,
                    fetch(&url, ip, timeout).await.map_err(|e| e.to_string()),
                )
            });
        }

        let mut fails = 0usize;
        while let Some(joined) = set.join_next().await {
            let Ok((ip, res)) = joined else { continue };
            match res {
                Ok((body, userinfo)) => {
                    set.abort_all();
                    return self.finish(ip, &body, userinfo, n);
                }
                Err(e) => {
                    fails += 1;
                    log_get_warn(&format!("{ip} failed: {e}"));
                    if fails == n {
                        break;
                    }
                }
            }
        }
        None
    }

    fn finish(
        &self,
        ip: IpAddr,
        body: &[u8],
        userinfo: Option<String>,
        raced: usize,
    ) -> Option<SubInfo> {
        match std::fs::write(&self.output, body) {
            Ok(()) => {
                log_get(&format!(
                    "OK via {ip} ({} bytes; raced {raced} IP)",
                    body.len()
                ));
                Some(SubInfo { userinfo })
            }
            Err(e) => {
                log_get_warn(&format!("write {} failed: {e}", self.output));
                None
            }
        }
    }

    pub async fn stream_to_file(&self, proxy: &str, ips: &[IpAddr]) -> Result<u64, HttpErr> {
        let have = std::fs::metadata(&self.output)
            .map(|m| m.len())
            .unwrap_or(0);
        let (_client, resp) = self.open_stream(proxy, ips, have).await?;
        let code = resp.status().as_u16();

        if code == 416 {
            let _ = std::fs::remove_file(&self.output);
            return Err(HttpErr::Request(
                "range not satisfiable; partial discarded".into(),
            ));
        }
        if code >= 400 {
            return Err(HttpErr::Request(format!("status {code}")));
        }
        let resuming = code == 206 && have > 0;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(resuming)
            .truncate(!resuming)
            .open(&self.output)?;
        if resuming {
            log_get(&format!("resuming {} from {have} bytes", self.output));
        }
        let mut total = if resuming { have } else { 0 };

        use futures_util::StreamExt;
        use std::io::Write as _;
        let mut stream = resp.bytes_stream();
        loop {
            let next = match tokio::time::timeout(httpcli::BODY_STALL, stream.next()).await {
                Ok(c) => c,
                Err(_) => return Err(httpcli::stalled()),
            };
            let Some(chunk) = next else { break };
            let chunk = chunk.map_err(|e| HttpErr::Request(e.to_string()))?;
            file.write_all(&chunk)?;
            total += chunk.len() as u64;
            if total > MAX_BODY {
                return Err(HttpErr::Request(format!("body exceeds {MAX_BODY} bytes")));
            }
        }
        file.flush()?;
        Ok(total)
    }

    pub fn stream_to_file_blocking(&self, proxy: &str, ips: &[IpAddr]) -> Result<u64, HttpErr> {
        crate::rt::block_on(self.stream_to_file(proxy, ips))
    }

    async fn open_stream(
        &self,
        proxy: &str,
        ips: &[IpAddr],
        from: u64,
    ) -> Result<(wreq::Client, wreq::Response), HttpErr> {
        let build = |client: wreq::Client| {
            let mut rb = httpcli::download_identity(client.get(&self.url)).timeout(self.timeout);
            if from > 0 {
                rb = rb.header("Range", format!("bytes={from}-"));
            }
            (client, rb)
        };
        let host = crate::dnsutil::url_hostname(&self.url);
        if ips.is_empty() {
            let (client, mut rb) = build(httpcli::insecure_client().clone());
            if let Some(p) = httpcli::proxy_for(proxy)? {
                rb = rb.proxy(p);
            }
            let resp = rb
                .send()
                .await
                .map_err(|e| HttpErr::Request(e.to_string()))?;
            return Ok((client, resp));
        }
        if let [ip] = ips {
            let (client, rb) = build(httpcli::client_for_host_ips(&host, vec![*ip]));
            let resp = rb
                .send()
                .await
                .map_err(|e| HttpErr::Request(e.to_string()))?;
            return Ok((client, resp));
        }

        let n = ips.len();
        let mut set = tokio::task::JoinSet::new();
        for &ip in ips {
            let (url, timeout, host) = (self.url.clone(), self.timeout, host.clone());
            set.spawn(async move {
                let client = httpcli::client_for_host_ips(&host, vec![ip]);
                let mut rb = httpcli::download_identity(client.get(&url)).timeout(timeout);
                if from > 0 {
                    rb = rb.header("Range", format!("bytes={from}-"));
                }
                (
                    ip,
                    rb.send()
                        .await
                        .map(|r| (client, r))
                        .map_err(|e| e.to_string()),
                )
            });
        }
        let mut last = String::from("no answer");
        let mut fails = 0usize;
        while let Some(joined) = set.join_next().await {
            let Ok((ip, res)) = joined else { continue };
            match res {
                Ok((client, resp)) => {
                    log_get(&format!("streaming from {ip} (raced {n} IP)"));
                    set.abort_all();
                    return Ok((client, resp));
                }
                Err(e) => {
                    fails += 1;
                    log_get_warn(&format!("{ip} failed: {e}"));
                    last = e;
                    if fails == n {
                        break;
                    }
                }
            }
        }
        Err(HttpErr::Request(last))
    }

    async fn attempt(&self, proxy: &str) -> Result<SubInfo, HttpErr> {
        let mut rb = httpcli::insecure_client().get(&self.url);
        if let Some(p) = httpcli::proxy_for(proxy)? {
            rb = rb.proxy(p);
        }
        let (body, userinfo) = send(rb, &self.url, self.timeout).await?;
        std::fs::write(&self.output, &body)?;
        Ok(SubInfo { userinfo })
    }
}

async fn fetch(
    url: &str,
    ip: IpAddr,
    timeout: Duration,
) -> Result<(Vec<u8>, Option<String>), HttpErr> {
    let client = httpcli::client_for_host_ips(&crate::dnsutil::url_hostname(url), vec![ip]);
    send(client.get(url), url, timeout).await
}

async fn send(
    rb: wreq::RequestBuilder,
    url: &str,
    timeout: Duration,
) -> Result<(Vec<u8>, Option<String>), HttpErr> {
    let mut rb = httpcli::download_identity(rb).timeout(timeout);

    if paopao_host_override(url) {
        rb = rb.header("Host", "paopao.dns");
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| HttpErr::Request(e.to_string()))?;
    let code = resp.status().as_u16();
    if code >= 400 {
        return Err(HttpErr::Request(format!("status {code}")));
    }
    let userinfo = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let (body, truncated) = httpcli::read_body_bounded(resp, MAX_BODY).await?;
    if truncated {
        return Err(HttpErr::Request(format!("body exceeds {MAX_BODY} bytes")));
    }
    Ok((body, userinfo))
}

pub fn resolve_all(host: &str) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    let ipv6 = crate::dnsutil::ipv6_enabled();
    let mut out: Vec<IpAddr> = Vec::new();
    if let Some(ip) = crate::dnsutil::lookup_hosts(host, ipv6) {
        out.push(ip);
    }
    let mut servers = configured_dns_servers();
    for s in crate::fallback::servers(&servers) {
        servers.push(s);
    }
    for ip in resolve_concurrent(host, &servers, ipv6) {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out.retain(|ip| crate::fallback::is_usable_node_ip(*ip));
    out.truncate(MAX_RACE_IPS);
    out
}

fn system_resolve_all(host: &str, ipv6: bool) -> Vec<IpAddr> {
    let Ok(addrs) = (host, 0u16).to_socket_addrs() else {
        return Vec::new();
    };
    let all: Vec<IpAddr> = addrs.map(|s| s.ip()).collect();
    let mut out: Vec<IpAddr> = all.iter().copied().filter(|a| a.is_ipv4()).collect();
    if ipv6 {
        out.extend(all.iter().copied().filter(|a| a.is_ipv6()));
    }
    out.truncate(MAX_RACE_IPS);
    out
}

fn paopao_host_override(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#', ':']).next().unwrap_or("");
    host.parse::<std::net::IpAddr>().is_ok()
}

fn configured_dns_servers() -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let push = |s: SocketAddr, out: &mut Vec<SocketAddr>| {
        if !out.iter().any(|x| x.ip() == s.ip()) {
            out.push(s);
        }
    };
    if let Some(s) = primary_dns_server() {
        push(s, &mut out);
    }
    for s in crate::dnsutil::ex_dns_env_servers() {
        push(s, &mut out);
    }
    for s in resolv_conf_servers() {
        push(s, &mut out);
    }
    out
}

fn resolv_conf_servers() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            it.next().filter(|k| *k == "nameserver").and(it.next())
        })
        .filter_map(crate::dnsutil::parse_dns_server)
        .collect()
}

fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn resolve_concurrent(host: &str, servers: &[SocketAddr], ipv6: bool) -> Vec<IpAddr> {
    let answers: std::sync::Mutex<Vec<(usize, Vec<IpAddr>)>> = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for (i, srv) in servers.iter().enumerate() {
            let answers = &answers;
            sc.spawn(move || {
                let ips = crate::dnsutil::resolve_host_via(host, *srv, ipv6);
                if !ips.is_empty() {
                    answers.lock().unwrap().push((i, ips));
                }
            });
        }

        let answers = &answers;
        sc.spawn(move || {
            let ips = system_resolve_all(host, ipv6);
            if !ips.is_empty() {
                answers.lock().unwrap().push((usize::MAX, ips));
            }
        });
    });
    let mut answers = answers.into_inner().unwrap();
    answers.sort_by_key(|(i, _)| *i);
    let mut out: Vec<IpAddr> = Vec::new();
    for (_, ips) in answers {
        for ip in ips {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out.truncate(MAX_RACE_IPS);
    out
}

fn primary_dns_server() -> Option<SocketAddr> {
    let dns_ip = std::env::var("dns_ip").unwrap_or_default();
    if dns_ip.is_empty() {
        return None;
    }
    let dns_port = std::env::var("dns_port").unwrap_or_default();
    let s = if dns_port.is_empty() {
        dns_ip
    } else {
        format!("{dns_ip}:{dns_port}")
    };
    crate::dnsutil::parse_dns_server(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_override_only_http_ip() {
        assert!(paopao_host_override("http://10.0.0.1:7889/ppgw.ini"));
        assert!(paopao_host_override("http://1.2.3.4/x"));
        assert!(!paopao_host_override("http://paopao.dns:7889/x"));
        assert!(!paopao_host_override("https://1.2.3.4/x"));
        assert!(!paopao_host_override("http://sub.example.com/x"));
    }

    #[test]
    fn system_resolve_all_v4_first_v6_gated() {

        let v4only = system_resolve_all("localhost", false);
        assert!(
            v4only.iter().all(|ip| ip.is_ipv4()),
            "ipv6=false should not contain v6: {v4only:?}"
        );
        assert!(
            v4only.iter().any(|ip| ip.is_ipv4()),
            "localhost should resolve to v4: {v4only:?}"
        );
    }

    #[test]
    fn race_picks_alive_ip_over_refused() {
        use std::io::{Read, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.2:0").expect("bind 127.0.0.2");
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
                );
            }
        });

        let out = std::env::temp_dir().join(format!("ppgw_race_{}.out", std::process::id()));
        let out_s = out.to_string_lossy().into_owned();
        let dl = Downloader::new(&format!("http://testhost:{port}/"), &out_s);

        let dead: IpAddr = "127.0.0.9".parse().unwrap();
        let alive: IpAddr = "127.0.0.2".parse().unwrap();
        let info = crate::rt::block_on(dl.race_download(&[dead, alive]));
        let _ = srv.join();

        assert!(info.is_some(), "should race to a usable IP");
        assert_eq!(
            std::fs::read(&out).unwrap(),
            b"abc",
            "winner should write correct content to disk"
        );
        let _ = std::fs::remove_file(&out);
    }

    fn serve_once(
        ip: &str,
        reply: impl FnOnce(Option<u64>) -> Vec<u8> + Send + 'static,
    ) -> (u16, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind(format!("{ip}:0")).expect("bind");
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                let from = req.split("range: bytes=").nth(1).and_then(|r| {
                    r.split('-')
                        .next()
                        .and_then(|d| d.trim().parse::<u64>().ok())
                });
                let _ = s.write_all(&reply(from));
            }
        });
        (port, h)
    }

    fn tmp_out(tag: &str) -> (std::path::PathBuf, String) {
        let p = std::env::temp_dir().join(format!("ppgw_{tag}_{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let s = p.to_string_lossy().into_owned();
        (p, s)
    }

    #[test]
    fn stream_to_file_writes_the_whole_body() {
        let (port, srv) = serve_once("127.0.0.2", |from| {
            assert_eq!(from, None, "nothing on disk means no Range header");
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec()
        });
        let (out, out_s) = tmp_out("stream_full");
        let dl = Downloader::new(&format!("http://testhost:{port}/"), &out_s);
        let n = dl
            .stream_to_file_blocking("", &["127.0.0.2".parse().unwrap()])
            .expect("download");
        let _ = srv.join();
        assert_eq!(n, 5);
        assert_eq!(std::fs::read(&out).unwrap(), b"hello");
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn stream_to_file_resumes_from_a_partial() {
        let (port, srv) = serve_once("127.0.0.2", |from| {
            assert_eq!(from, Some(3), "must ask for the rest, not the whole file");
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 3-6/7\r\n\
              Content-Length: 4\r\nConnection: close\r\n\r\nlow!"
                .to_vec()
        });
        let (out, out_s) = tmp_out("stream_resume");
        std::fs::write(&out, b"yel").expect("seed partial");
        let dl = Downloader::new(&format!("http://testhost:{port}/"), &out_s);
        let n = dl
            .stream_to_file_blocking("", &["127.0.0.2".parse().unwrap()])
            .expect("download");
        let _ = srv.join();
        assert_eq!(n, 7, "the count covers what was already on disk");
        assert_eq!(std::fs::read(&out).unwrap(), b"yellow!");
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn a_server_ignoring_range_restarts_the_file() {
        let (port, srv) = serve_once("127.0.0.2", |from| {
            assert_eq!(from, Some(3));
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nyellow!".to_vec()
        });
        let (out, out_s) = tmp_out("stream_norange");
        std::fs::write(&out, b"yel").expect("seed partial");
        let dl = Downloader::new(&format!("http://testhost:{port}/"), &out_s);
        let n = dl
            .stream_to_file_blocking("", &["127.0.0.2".parse().unwrap()])
            .expect("download");
        let _ = srv.join();
        assert_eq!(n, 7);
        assert_eq!(std::fs::read(&out).unwrap(), b"yellow!");
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn an_unsatisfiable_range_discards_the_partial() {
        let (port, srv) = serve_once("127.0.0.2", |_| {
            b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec()
        });
        let (out, out_s) = tmp_out("stream_416");
        std::fs::write(&out, b"way too long").expect("seed partial");
        let dl = Downloader::new(&format!("http://testhost:{port}/"), &out_s);
        let err = dl
            .stream_to_file_blocking("", &["127.0.0.2".parse().unwrap()])
            .expect_err("416 must fail");
        let _ = srv.join();
        assert!(err.to_string().contains("range"), "{err}");
        assert!(!out.exists(), "the bad partial must not survive");
    }
}
