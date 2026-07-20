// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::httpcli::{HttpErr, UA_DOWNLOAD, agent, agent_with_ip};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

const MAX_RACE_IPS: usize = 16;

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
}

impl Downloader {
    pub fn new(url: &str, output: &str) -> Self {
        Self {
            url: url.to_string(),
            output: output.to_string(),
        }
    }

    pub fn download(&self) -> Result<SubInfo, HttpErr> {
        let ipv6 = crate::dnsutil::ipv6_enabled();
        let host = crate::dnsutil::url_hostname(&self.url);
        log_get(&format!("GET {} (host={host})", self.url));

        if host.parse::<IpAddr>().is_ok() {
            log_get(&format!("host is IP literal: {host}"));
            return self.attempt("");
        }

        if let Some(ip) = crate::dnsutil::lookup_hosts(&host, ipv6) {
            log_get(&format!("/etc/hosts: {host} -> {ip}"));
            if let Some(info) = self.race_download(&[ip]) {
                return Ok(info);
            }
        }

        if let Some(server) = primary_dns_server() {
            if let Some(info) = self.resolve_and_race("dns_ip", &host, server, ipv6) {
                return Ok(info);
            }
        }

        for server in crate::dnsutil::ex_dns_env_servers() {
            if let Some(info) = self.resolve_and_race("ex_dns", &host, server, ipv6) {
                return Ok(info);
            }
        }

        let sys_ips = system_resolve_all(&host, ipv6);
        if sys_ips.is_empty() {
            log_get_warn("System DNS: no answer");
        } else {
            log_get(&format!("System DNS -> [{}]", fmt_ips(&sys_ips)));
            if let Some(info) = self.race_download(&sys_ips) {
                return Ok(info);
            }
        }

        let mut configured = crate::fallback::configured_servers();
        configured.extend(primary_dns_server());
        for server in crate::fallback::servers(&configured) {
            if let Some(info) = self.resolve_and_race("fallback", &host, server, ipv6) {
                return Ok(info);
            }
        }

        log_get("Trying Socks5 Proxy 127.0.0.1:1080...");
        match self.attempt("socks5h://127.0.0.1:1080") {
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

    fn resolve_and_race(
        &self,
        tag: &str,
        host: &str,
        server: SocketAddr,
        ipv6: bool,
    ) -> Option<SubInfo> {
        let ips: Vec<IpAddr> = crate::dnsutil::resolve_host_via(host, server, ipv6)
            .into_iter()
            .take(MAX_RACE_IPS)
            .collect();
        if ips.is_empty() {
            log_get_warn(&format!("{tag} {server}: no answer"));
            return None;
        }
        log_get(&format!("{tag} {server} -> [{}]", fmt_ips(&ips)));
        self.race_download(&ips)
    }

    fn race_download(&self, ips: &[IpAddr]) -> Option<SubInfo> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};

        if let [ip] = ips {
            return match fetch(&self.url, agent_with_ip(*ip, UA_DOWNLOAD, TIMEOUT)) {
                Ok((body, userinfo)) => self.finish(*ip, &body, userinfo, 1),
                Err(e) => {
                    log_get_warn(&format!("{ip} failed: {e}"));
                    None
                }
            };
        }

        let n = ips.len();
        let (tx, rx) = mpsc::channel::<(IpAddr, Result<(Vec<u8>, Option<String>), String>)>();
        let done = Arc::new(AtomicBool::new(false));
        for &ip in ips {
            let tx = tx.clone();
            let done = Arc::clone(&done);
            let url = self.url.clone();
            std::thread::spawn(move || {
                if done.load(Ordering::Relaxed) {
                    return;
                }
                let res =
                    fetch(&url, agent_with_ip(ip, UA_DOWNLOAD, TIMEOUT)).map_err(|e| e.to_string());
                let _ = tx.send((ip, res));
            });
        }
        drop(tx);

        let mut fails = 0usize;
        while let Ok((ip, res)) = rx.recv() {
            match res {
                Ok((body, userinfo)) => {
                    done.store(true, Ordering::Relaxed);
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

    fn attempt(&self, proxy: &str) -> Result<SubInfo, HttpErr> {
        let agent = agent(proxy, UA_DOWNLOAD, TIMEOUT)?;
        let (body, userinfo) = fetch(&self.url, agent)?;
        std::fs::write(&self.output, &body)?;
        Ok(SubInfo { userinfo })
    }
}

fn fetch(url: &str, agent: ureq::Agent) -> Result<(Vec<u8>, Option<String>), HttpErr> {
    let mut req = agent.get(url);

    if paopao_host_override(url) {
        req = req.header("Host", "paopao.dns");
    }
    let mut resp = req.call().map_err(|e| HttpErr::Request(e.to_string()))?;
    let code = resp.status().as_u16();
    if code >= 400 {
        return Err(HttpErr::Request(format!("status {code}")));
    }
    let userinfo = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body = resp
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| HttpErr::Request(e.to_string()))?;
    Ok((body, userinfo))
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
        let info = dl.race_download(&[dead, alive]);
        let _ = srv.join();

        assert!(info.is_some(), "should race to a usable IP");
        assert_eq!(std::fs::read(&out).unwrap(), b"abc", "winner should write correct content to disk");
        let _ = std::fs::remove_file(&out);
    }
}
