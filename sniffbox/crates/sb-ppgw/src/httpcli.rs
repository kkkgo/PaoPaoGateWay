// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use ureq::Agent;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::tls::TlsConfig;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

pub const UA_PROBE: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0";

pub const UA_DOWNLOAD: &str = match option_env!("UA_DOWNLOAD") {
    Some(v) => v,
    None => "clash-verge/2.5.2+autobuild.0627.b7a454f",
};

#[derive(Debug, thiserror::Error)]
pub enum HttpErr {
    #[error("proxy: {0}")]
    Proxy(String),
    #[error("request: {0}")]
    Request(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

fn normalize_socks5_proxy(proxy: &str) -> String {
    if proxy.starts_with("socks5://") && !proxy.starts_with("socks5h://") {
        proxy.replacen("socks5://", "socks5h://", 1)
    } else {
        proxy.to_string()
    }
}

pub fn agent(proxy: &str, ua: &str, timeout: Duration) -> Result<Agent, HttpErr> {
    let mut b = Config::builder()
        .tls_config(TlsConfig::builder().disable_verification(true).build())
        .http_status_as_error(false)
        .max_redirects(10)
        .timeout_global(Some(timeout))
        .user_agent(ua.to_string());
    if !proxy.is_empty() {
        let proxy = normalize_socks5_proxy(proxy);
        let p = ureq::Proxy::new(&proxy).map_err(|e| HttpErr::Proxy(e.to_string()))?;
        b = b.proxy(Some(p));
    }
    Ok(b.build().into())
}

#[derive(Debug)]
struct DnsResolver {
    server: SocketAddr,
    ipv6: bool,
}

impl Resolver for DnsResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let host = uri.host().ok_or(ureq::Error::HostNotFound)?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let mut result = self.empty();
        if let Ok(ip) = host.parse::<IpAddr>() {
            result.push(SocketAddr::new(ip, port));
            return Ok(result);
        }
        for ip in crate::dnsutil::resolve_host_via(host, self.server, self.ipv6)
            .into_iter()
            .take(16)
        {
            result.push(SocketAddr::new(ip, port));
        }
        if result.is_empty() {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(result)
        }
    }
}

pub fn agent_with_dns(server: SocketAddr, ua: &str, timeout: Duration, ipv6: bool) -> Agent {
    let config = Config::builder()
        .tls_config(TlsConfig::builder().disable_verification(true).build())
        .http_status_as_error(false)
        .max_redirects(10)
        .timeout_global(Some(timeout))
        .user_agent(ua.to_string())
        .build();
    Agent::with_parts(
        config,
        DefaultConnector::default(),
        DnsResolver { server, ipv6 },
    )
}

#[derive(Debug)]
struct StaticResolver {
    ip: IpAddr,
}

impl Resolver for StaticResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let mut result = self.empty();
        result.push(SocketAddr::new(self.ip, port));
        Ok(result)
    }
}

pub fn agent_with_ip(ip: IpAddr, ua: &str, timeout: Duration) -> Agent {
    let config = Config::builder()
        .tls_config(TlsConfig::builder().disable_verification(true).build())
        .http_status_as_error(false)
        .max_redirects(10)
        .timeout_global(Some(timeout))
        .user_agent(ua.to_string())
        .build();
    Agent::with_parts(config, DefaultConnector::default(), StaticResolver { ip })
}

pub fn status_ok(code: u16, expected: &str) -> bool {
    if expected.is_empty() || expected == "0" {
        return true;
    }
    if let Some((lo, hi)) = expected.split_once('-') {
        let lo: u16 = lo.trim().parse().unwrap_or(0);
        let hi: u16 = hi.trim().parse().unwrap_or(0);
        return code >= lo && code <= hi;
    }
    expected.parse::<u16>().map(|e| e == code).unwrap_or(false)
}

pub fn check_url_connectivity(
    target: &str,
    proxy: &str,
    expected: &str,
) -> Result<(bool, u16), HttpErr> {
    let agent = agent(proxy, UA_PROBE, Duration::from_secs(10))?;
    let resp = agent
        .get(target)
        .header("Accept-Encoding", "gzip, deflate, br")
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        )
        .header("Connection", "keep-alive")
        .call()
        .map_err(|e| HttpErr::Request(e.to_string()))?;
    let code = resp.status().as_u16();
    Ok((status_ok(code, expected), code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_ok_semantics() {
        assert!(status_ok(200, "0"));
        assert!(status_ok(503, ""));
        assert!(status_ok(204, "200-299"));
        assert!(!status_ok(404, "200-299"));
        assert!(status_ok(204, "204"));
        assert!(!status_ok(200, "204"));
    }

    #[test]
    fn download_ua_is_clash_verge() {

        assert!(UA_DOWNLOAD.starts_with("clash-verge/"), "UA: {UA_DOWNLOAD}");
    }
}
