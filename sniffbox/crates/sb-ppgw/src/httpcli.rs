// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::future::ready;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use wreq::dns::{Addrs, Name, Resolve, Resolving};
use wreq::header::{ACCEPT, USER_AGENT};
use wreq::{Client, ClientBuilder, Proxy, RequestBuilder, redirect};

pub const UA_DOWNLOAD: &str = match option_env!("UA_DOWNLOAD") {
    Some(v) => v,
    None => "clash-verge/2.5.2+autobuild.0627.b7a454f",
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

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

pub fn proxy_for(proxy: &str) -> Result<Option<Proxy>, HttpErr> {
    if proxy.is_empty() {
        return Ok(None);
    }
    let p = normalize_socks5_proxy(proxy);
    Proxy::all(&p)
        .map(Some)
        .map_err(|e| HttpErr::Proxy(e.to_string()))
}

pub fn latest_chrome() -> wreq_util::Profile {
    wreq_util::Profile::VARIANTS
        .iter()
        .copied()
        .filter_map(|p| {
            Some((
                format!("{p:?}")
                    .strip_prefix("Chrome")?
                    .parse::<u32>()
                    .ok()?,
                p,
            ))
        })
        .max_by_key(|(v, _)| *v)
        .map(|(_, p)| p)
        .expect("wreq-util always ships Chrome profiles")
}

fn emulation() -> wreq_util::Emulation {
    wreq_util::Emulation::builder()
        .profile(latest_chrome())
        .platform(wreq_util::Platform::Linux)
        .build()
}

fn base_builder(verify_certs: bool) -> ClientBuilder {
    Client::builder()
        .emulation(emulation())
        .tls_cert_verification(verify_certs)
        .redirect(redirect::Policy::limited(10))
}

fn no_pool(b: ClientBuilder) -> ClientBuilder {
    b.pool_max_idle_per_host(0)
}

fn build(b: ClientBuilder) -> Client {

    b.build().expect("build wreq client")
}

pub fn insecure_client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| build(no_pool(base_builder(false))))
}

pub fn secure_client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| build(no_pool(base_builder(true))))
}

#[derive(Debug)]
struct PinnedResolver {
    host: Option<String>,
    ips: Vec<IpAddr>,
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let pinned = match &self.host {
            None => true,
            Some(h) => name.as_str().eq_ignore_ascii_case(h),
        };
        if pinned {
            let addrs: Vec<SocketAddr> =
                self.ips.iter().map(|ip| SocketAddr::new(*ip, 0)).collect();
            return Box::pin(ready(if addrs.is_empty() {
                Err("no pinned address".into())
            } else {
                Ok(Box::new(addrs.into_iter()) as Addrs)
            }));
        }

        let host = name.as_str().to_string();
        Box::pin(async move {

            let ips = tokio::task::spawn_blocking(move || crate::download::resolve_all(&host))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    e.to_string().into()
                })?;
            if ips.is_empty() {
                return Err("redirect host not found".into());
            }
            let addrs: Vec<SocketAddr> = ips
                .into_iter()
                .take(16)
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug)]
struct DnsServerResolver {
    server: SocketAddr,
    ipv6: bool,
}

impl Resolve for DnsServerResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let (server, ipv6) = (self.server, self.ipv6);
        let host = name.as_str().to_string();
        Box::pin(async move {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(Box::new(std::iter::once(SocketAddr::new(ip, 0))) as Addrs);
            }

            let ips = tokio::task::spawn_blocking(move || {
                crate::dnsutil::resolve_host_via(&host, server, ipv6)
            })
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
            if ips.is_empty() {
                return Err("host not found".into());
            }
            let addrs: Vec<SocketAddr> = ips
                .into_iter()
                .take(16)
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

pub fn client_for_host_ips(host: &str, ips: Vec<IpAddr>) -> Client {
    build(base_builder(false).dns_resolver(PinnedResolver {
        host: Some(host.to_ascii_lowercase()),
        ips,
    }))
}

pub fn client_for_ips(ips: Vec<IpAddr>) -> Client {
    build(base_builder(false).dns_resolver(PinnedResolver { host: None, ips }))
}

pub fn client_with_dns(server: SocketAddr, ipv6: bool) -> Client {
    build(base_builder(false).dns_resolver(DnsServerResolver { server, ipv6 }))
}

pub fn download_identity(rb: RequestBuilder) -> RequestBuilder {
    rb.default_headers(false)
        .header(USER_AGENT, UA_DOWNLOAD)
        .header(ACCEPT, "*/*")
}

pub fn bare_identity(rb: RequestBuilder) -> RequestBuilder {
    rb.default_headers(false)
}

pub async fn read_body_bounded(
    resp: wreq::Response,
    limit: u64,
) -> Result<(Vec<u8>, bool), HttpErr> {
    use futures_util::StreamExt;

    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    loop {
        let Some(chunk) = (match tokio::time::timeout(BODY_STALL, stream.next()).await {
            Ok(c) => c,
            Err(_) => return Err(stalled()),
        }) else {
            break;
        };
        buf.extend_from_slice(&chunk.map_err(|e| HttpErr::Request(e.to_string()))?);
        if buf.len() as u64 > limit {
            truncated = true;
            buf.truncate(limit as usize);
            break;
        }
    }
    Ok((buf, truncated))
}

pub const BODY_STALL: Duration = Duration::from_secs(20);

pub fn stalled() -> HttpErr {
    HttpErr::Request(format!("stalled: no data for {}s", BODY_STALL.as_secs()))
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

pub async fn check_url_connectivity(
    target: &str,
    proxy: &str,
    expected: &str,
) -> Result<(bool, u16), HttpErr> {
    check_url_connectivity_via(target, proxy, None, expected, PROBE_TIMEOUT).await
}

pub async fn check_url_connectivity_via(
    target: &str,
    proxy: &str,
    pin: Option<IpAddr>,
    expected: &str,
    timeout: Duration,
) -> Result<(bool, u16), HttpErr> {
    let mut rb = match pin {
        Some(ip) => {
            client_for_host_ips(&crate::dnsutil::url_hostname(target), vec![ip]).get(target)
        }
        None => insecure_client().get(target),
    }
    .timeout(timeout);
    if let Some(p) = proxy_for(proxy)? {
        rb = rb.proxy(p);
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| HttpErr::Request(e.to_string()))?;
    let code = resp.status().as_u16();
    Ok((status_ok(code, expected), code))
}

pub async fn head_status_via(
    target: &str,
    proxy: &str,
    pin: Option<IpAddr>,
    timeout: Duration,
) -> Result<(u16, Option<String>), HttpErr> {
    let client = match pin {
        Some(ip) => build(no_redirect(base_builder(false).dns_resolver(
            PinnedResolver {
                host: Some(crate::dnsutil::url_hostname(target).to_ascii_lowercase()),
                ips: vec![ip],
            },
        ))),
        None => head_client().clone(),
    };

    let mut rb = download_identity(client.head(target)).timeout(timeout);
    if let Some(p) = proxy_for(proxy)? {
        rb = rb.proxy(p);
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| HttpErr::Request(e.to_string()))?;
    let location = resp
        .headers()
        .get(wreq::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    Ok((resp.status().as_u16(), location))
}

pub fn head_status_via_blocking(
    target: &str,
    proxy: &str,
    pin: Option<IpAddr>,
    timeout: Duration,
) -> Result<(u16, Option<String>), HttpErr> {
    crate::rt::block_on(head_status_via(target, proxy, pin, timeout))
}

fn no_redirect(b: ClientBuilder) -> ClientBuilder {
    b.redirect(redirect::Policy::none())
}

fn head_client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| build(no_pool(no_redirect(base_builder(false)))))
}

pub fn check_url_connectivity_via_blocking(
    target: &str,
    proxy: &str,
    pin: Option<IpAddr>,
    expected: &str,
    timeout: Duration,
) -> Result<(bool, u16), HttpErr> {
    crate::rt::block_on(check_url_connectivity_via(
        target, proxy, pin, expected, timeout,
    ))
}

pub fn check_url_connectivity_blocking(
    target: &str,
    proxy: &str,
    expected: &str,
) -> Result<(bool, u16), HttpErr> {
    crate::rt::block_on(check_url_connectivity(target, proxy, expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pinned_resolver_only_pins_its_own_host() {
        let pinned: IpAddr = "203.0.113.7".parse().unwrap();
        let r = PinnedResolver {
            host: Some("a.invalid".into()),
            ips: vec![pinned],
        };
        let addrs: Vec<SocketAddr> = r
            .resolve(Name::new("a.invalid".into()))
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, vec![SocketAddr::new(pinned, 0)]);

        let addrs: Vec<SocketAddr> = r
            .resolve(Name::new("A.INVALID".into()))
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, vec![SocketAddr::new(pinned, 0)]);

        let other = r.resolve(Name::new("b.invalid".into())).await;
        let got: Vec<SocketAddr> = other.map(|a| a.collect()).unwrap_or_default();
        assert!(
            !got.contains(&SocketAddr::new(pinned, 0)),
            "a different host must never inherit the pin: {got:?}"
        );

        let blind = PinnedResolver {
            host: None,
            ips: vec![pinned],
        };
        let addrs: Vec<SocketAddr> = blind
            .resolve(Name::new("b.invalid".into()))
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, vec![SocketAddr::new(pinned, 0)]);
    }

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

    #[test]
    fn socks5_is_normalized_to_remote_dns() {
        assert_eq!(
            normalize_socks5_proxy("socks5://127.0.0.1:1080"),
            "socks5h://127.0.0.1:1080"
        );

        assert_eq!(
            normalize_socks5_proxy("socks5h://127.0.0.1:1080"),
            "socks5h://127.0.0.1:1080"
        );
        assert_eq!(
            normalize_socks5_proxy("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
        assert!(proxy_for("").unwrap().is_none());
        assert!(proxy_for("socks5://127.0.0.1:1080").unwrap().is_some());
    }

    #[test]
    fn latest_chrome_parses_a_recent_version() {
        let p = latest_chrome();
        let v: u32 = format!("{p:?}")
            .strip_prefix("Chrome")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unexpected profile name: {p:?}"));
        assert!(v >= 149, "latest Chrome profile went backwards: {v}");
    }

    #[test]
    fn insecure_and_secure_clients_are_distinct() {
        let a = insecure_client();
        let b = secure_client();
        assert!(!std::ptr::eq(a, b));
    }

    #[test]
    fn long_lived_clients_do_not_reuse_connections() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&accepts);
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { continue };
                seen.fetch_add(1, Ordering::SeqCst);

                std::thread::spawn(move || {
                    let mut s = s;
                    let mut buf = [0u8; 2048];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            return;
                        }
                        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .is_err()
                            || s.flush().is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        let url = format!("http://127.0.0.1:{port}/x");
        crate::rt::block_on(async {
            for _ in 0..2 {
                let r = insecure_client()
                    .get(&url)
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await
                    .expect("request should succeed");
                assert_eq!(r.status().as_u16(), 200);

                let _ = r.text().await;
            }
        });

        assert_eq!(
            accepts.load(Ordering::SeqCst),
            2,
            "two sequential requests must open two connections (pool disabled)"
        );
    }

    #[test]
    fn client_hello_carries_chrome_markers() {
        use std::io::Read;
        use std::net::TcpListener;

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let cap = std::thread::spawn(move || {
            let (mut s, _) = l.accept().expect("accept");
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf = vec![0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            buf.truncate(n);
            buf
        });

        let _ = crate::rt::block_on(
            insecure_client()
                .get(format!("https://127.0.0.1:{}/", addr.port()))
                .timeout(Duration::from_secs(5))
                .send(),
        );
        let hello = cap.join().expect("capture thread");

        assert!(
            hello.starts_with(&[0x16, 0x03, 0x01]),
            "not a TLS ClientHello record: {:02x?}",
            &hello[..hello.len().min(8)]
        );

        let exts = client_hello_extensions(&hello).expect("parse ClientHello extensions");

        assert!(
            exts.iter().any(is_grease),
            "no GREASE extension in ClientHello (a rustls tell): {exts:04x?}"
        );

        assert!(
            exts.contains(&17513) || exts.contains(&17613),
            "no ALPS extension — this does not look like Chrome: {exts:04x?}"
        );

        assert!(
            exts.contains(&65037),
            "no ECH (GREASE) extension: {exts:04x?}"
        );
        assert!(
            hello.windows(2).any(|w| w == *b"h2"),
            "ALPN should offer h2"
        );
    }

    fn is_grease(v: &u16) -> bool {
        let [hi, lo] = v.to_be_bytes();
        hi == lo && hi & 0x0f == 0x0a
    }

    fn client_hello_extensions(rec: &[u8]) -> Option<Vec<u16>> {
        let be16 = |b: &[u8], i: usize| -> Option<u16> {
            Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
        };

        let body = rec.get(9..)?;
        let mut i = 2 + 32;
        i += 1 + *body.get(i)? as usize;
        i += 2 + be16(body, i)? as usize;
        i += 1 + *body.get(i)? as usize;
        let ext_total = be16(body, i)? as usize;
        i += 2;
        let end = i + ext_total;
        let mut out = Vec::new();
        while i + 4 <= end.min(body.len()) {
            out.push(be16(body, i)?);
            i += 4 + be16(body, i + 2)? as usize;
        }
        Some(out)
    }

    #[test]
    #[ignore = "requires network: live TLS fingerprint check against tls.peet.ws"]
    fn fingerprint_looks_like_chrome() {
        let body = crate::rt::block_on(async {
            let resp = secure_client()
                .get("https://tls.peet.ws/api/all")
                .timeout(Duration::from_secs(20))
                .send()
                .await
                .expect("reach tls.peet.ws");
            assert_eq!(
                resp.version(),
                wreq::Version::HTTP_2,
                "should negotiate HTTP/2"
            );
            resp.text().await.expect("read body")
        });
        println!("{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");

        let ua = v["http_version"].as_str().unwrap_or_default();
        assert_eq!(ua, "h2", "peet should see h2: {ua}");

        let ja4 = v["tls"]["ja4"].as_str().unwrap_or_default();

        assert!(ja4.starts_with("t13d"), "unexpected JA4: {ja4}");

        let akamai = v["http2"]["akamai_fingerprint"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(
            akamai, "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
            "Akamai H2 fingerprint is not Chrome's"
        );

        let seen_ua = v["http2"]["sent_frames"].to_string();
        assert!(
            seen_ua.to_ascii_lowercase().contains("chrome/"),
            "UA should be Chrome's: {seen_ua}"
        );
    }
}
