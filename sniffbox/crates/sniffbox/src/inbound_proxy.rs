// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::engine::{Established, serve_established};
use crate::outbound::UdpUpstream;
use crate::resolver::Resolver;
use crate::runtime::SharedState;
use sb_outbound::server::{self, DestAddr, REP_CMD_NOT_SUPPORTED, SocksCmd};
use sb_outbound::socks5_udp::{
    decode_udp_reply, encode_udp_request_domain_into, encode_udp_request_into, udp_associate_auth,
};
use sb_stats::types::{ConnRecord, InboundKind, Transport};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

#[derive(Clone)]
pub struct InboundProxyParams {
    pub listen_port: u16,
    pub udp: bool,
    pub udp_idle: Duration,

    pub handshake_timeout: Duration,
}

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct InboundProfile {

    socks5: InboundKind,

    http: InboundKind,

    apply_auth: bool,

    acl: bool,

    sniff: bool,
}

const OPENPORT: InboundProfile = InboundProfile {
    socks5: InboundKind::Socks5,
    http: InboundKind::Http,
    apply_auth: true,
    acl: true,
    sniff: true,
};

const HEALTHCHECK: InboundProfile = InboundProfile {
    socks5: InboundKind::HealthCheck,
    http: InboundKind::HealthCheck,
    apply_auth: false,
    acl: false,
    sniff: false,
};

pub const HEALTHCHECK_PORT: u16 = 1079;

pub fn start_inbound_proxy(
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let ips = lan_ipv4s();
        if ips.is_empty() {
            tracing::warn!("openport fixed-on but no non-loopback IPv4 found; inbound proxy idle");
            return;
        }
        let mut bound = Vec::with_capacity(ips.len());
        for ip in ips {
            let addr = SocketAddr::new(IpAddr::V4(ip), params.listen_port);
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(%addr, ?e, "inbound proxy bind failed; skip this addr");
                    continue;
                }
            };
            tracing::info!(%addr, udp = params.udp, auth = shared.openport_auth().is_some(),
                "inbound proxy (socks5+http) listening");
            bound.push(addr);
            let shared = Arc::clone(&shared);
            let params = params.clone();
            let mut sd = shutdown_rx.clone();
            tokio::spawn(async move {
                accept_loop(listener, shared, params, OPENPORT, &mut sd).await;
            });
        }
        shared.set_openport_listen(bound);
    });
}

pub fn start_healthcheck_listener(
    shared: Arc<SharedState>,
    udp: bool,
    shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HEALTHCHECK_PORT);
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%addr, ?e, "healthcheck listener bind failed; skip");
                return;
            }
        };
        tracing::info!(%addr, udp, "healthcheck socks5 inbound listening");
        let params = InboundProxyParams {
            listen_port: HEALTHCHECK_PORT,
            udp,
            udp_idle: Duration::from_secs(60),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        };
        let mut sd = shutdown_rx;
        accept_loop(listener, shared, params, HEALTHCHECK, &mut sd).await;
    });
}

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    profile: InboundProfile,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
            res = listener.accept() => match res {
                Ok((stream, peer)) => {

                    if profile.acl && !shared.proxy_allowed(peer.ip()) {
                        tracing::debug!(%peer, "inbound proxy peer not in proxy_cidr; reject");
                        continue;
                    }
                    let shared = Arc::clone(&shared);
                    let params = params.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_inbound(stream, peer, shared, params, profile).await {
                            tracing::debug!(%peer, ?e, "inbound proxy conn ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(?e, "inbound proxy accept error; backoff 100ms");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

enum Handshake {

    Tcp(TcpStream, Established),

    Udp(TcpStream, InboundKind),

    Done,
}

async fn handle_inbound(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    profile: InboundProfile,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);

    let hs = {
        let shared = Arc::clone(&shared);
        let params = params.clone();
        match tokio::time::timeout(
            params.handshake_timeout,
            handshake(stream, peer, shared, params.clone(), profile),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                tracing::debug!(%peer, timeout = ?params.handshake_timeout, "inbound handshake timed out");
                return Ok(());
            }
        }
    };
    match hs {
        Handshake::Tcp(stream, est) => serve_established(shared, stream, peer, est).await,
        Handshake::Udp(ctrl, inbound) => {
            udp_associate_inbound(ctrl, peer, shared, params, inbound).await
        }
        Handshake::Done => Ok(()),
    }
}

async fn handshake(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    profile: InboundProfile,
) -> io::Result<Handshake> {
    let mut first = [0u8; 1];

    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(Handshake::Done);
    }
    if first[0] == 0x05 {
        handle_socks5(stream, peer, shared, params, profile).await
    } else {
        handle_http(stream, peer, shared, profile).await
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    profile: InboundProfile,
) -> io::Result<Handshake> {

    let auth = if profile.apply_auth {
        shared.openport_auth()
    } else {
        None
    };
    if let Err(e) = server::negotiate_method(&mut stream, auth.as_deref()).await {
        tracing::debug!(%peer, ?e, "socks5 method negotiation failed");
        return Ok(Handshake::Done);
    }
    let (cmd, dest) = match server::read_request(&mut stream).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(%peer, ?e, "socks5 request parse failed");
            return Ok(Handshake::Done);
        }
    };
    match cmd {
        SocksCmd::Connect => {
            let bnd = stream
                .local_addr()
                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            if server::write_success(&mut stream, bnd).await.is_err() {
                return Ok(Handshake::Done);
            }
            let est = dest_to_established(dest, profile.socks5, profile.sniff);
            Ok(Handshake::Tcp(stream, est))
        }
        SocksCmd::UdpAssociate => {
            if !params.udp {
                let _ = server::write_reply(&mut stream, REP_CMD_NOT_SUPPORTED, unspec()).await;
                return Ok(Handshake::Done);
            }
            Ok(Handshake::Udp(stream, profile.socks5))
        }
        SocksCmd::Other(c) => {
            tracing::debug!(%peer, cmd = c, "socks5 unsupported command");
            let _ = server::write_reply(&mut stream, REP_CMD_NOT_SUPPORTED, unspec()).await;
            Ok(Handshake::Done)
        }
    }
}

fn dest_to_established(dest: DestAddr, inbound: InboundKind, sniff: bool) -> Established {
    match dest {
        DestAddr::Ip(addr) => Established {
            dest: addr,
            inbound,
            domain: None,
            prelude: Vec::new(),
            peeked: Vec::new(),
            http_forward: None,
            sniff,
            group: None,
        },
        DestAddr::Domain(host, port) => Established {

            dest: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            inbound,
            domain: Some(host),
            prelude: Vec::new(),
            peeked: Vec::new(),
            http_forward: None,
            sniff,
            group: None,
        },
    }
}

fn unspec() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

const HTTP_HEAD_MAX: usize = 16 * 1024;

async fn handle_http(
    mut stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
    profile: InboundProfile,
) -> io::Result<Handshake> {

    let (head, leftover) = match read_http_head(&mut stream).await {
        Ok(Some(h)) => h,
        Ok(None) => return Ok(Handshake::Done),
        Err(e) => {
            tracing::debug!(%peer, ?e, "http head read failed");
            return Ok(Handshake::Done);
        }
    };
    let parsed = match parse_http_proxy_request(&head) {
        Some(p) => p,
        None => {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Ok(Handshake::Done);
        }
    };

    if let Some(creds) = profile.apply_auth.then(|| shared.openport_auth()).flatten() {
        let (user, pass) = creds.as_ref();
        let expected = basic_auth_header_value(user, pass);
        if parsed.proxy_authorization.as_deref() != Some(expected.as_str()) {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"sniffbox\"\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
            return Ok(Handshake::Done);
        }
    }

    match parsed.kind {
        HttpReqKind::Connect { host, port } => {
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return Ok(Handshake::Done);
            }

            let est = host_port_to_established(
                host,
                port,
                Vec::new(),
                leftover,
                profile.sniff,
                profile.http,
            );
            Ok(Handshake::Tcp(stream, est))
        }
        HttpReqKind::Forward {
            host,
            port,
            request,
            framing,
        } => {
            let mut est =
                host_port_to_established(host, port, request, leftover, false, profile.http);
            est.http_forward = Some(framing);
            Ok(Handshake::Tcp(stream, est))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn host_port_to_established(
    host: String,
    port: u16,
    prelude: Vec<u8>,
    peeked: Vec<u8>,
    sniff: bool,
    inbound: InboundKind,
) -> Established {

    match host.parse::<IpAddr>() {
        Ok(ip) => Established {
            dest: SocketAddr::new(ip, port),
            inbound,
            domain: None,
            prelude,
            peeked,
            http_forward: None,
            sniff,
            group: None,
        },
        Err(_) => Established {
            dest: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            inbound,
            domain: Some(host),
            prelude,
            peeked,
            http_forward: None,
            sniff,
            group: None,
        },
    }
}

async fn read_http_head(stream: &mut TcpStream) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_head_end(&buf) {
            let leftover = buf.split_off(end);
            return Ok(Some((buf, leftover)));
        }
        if buf.len() > HTTP_HEAD_MAX {
            return Ok(None);
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

enum HttpReqKind {
    Connect {
        host: String,
        port: u16,
    },
    Forward {
        host: String,
        port: u16,
        request: Vec<u8>,
        framing: crate::http_forward::Request,
    },
}

struct ParsedHttpProxy {
    kind: HttpReqKind,
    proxy_authorization: Option<String>,
}

fn parse_http_proxy_request(head: &[u8]) -> Option<ParsedHttpProxy> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let status = req.parse(head).ok()?;
    if status.is_partial() {
        return None;
    }
    let method = req.method?;
    let path = req.path?;

    let proxy_authorization = header_value(&req, "proxy-authorization");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(path, 443)?;
        return Some(ParsedHttpProxy {
            kind: HttpReqKind::Connect { host, port },
            proxy_authorization,
        });
    }

    let (scheme_host, abs_path) = split_absolute_uri(path)?;
    let (host, port) = split_host_port(scheme_host, 80)?;
    let framing = request_framing(&req)?;
    let version = req.version.unwrap_or(1);
    let request = rebuild_origin_request(method, abs_path, version, &headers, &host, port);
    Some(ParsedHttpProxy {
        kind: HttpReqKind::Forward {
            host,
            port,
            request,
            framing,
        },
        proxy_authorization,
    })
}

fn request_framing(req: &httparse::Request) -> Option<crate::http_forward::Request> {
    use crate::http_forward::{Body, Request};
    let mut length = None;
    let mut chunked = false;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            let value = std::str::from_utf8(h.value).ok()?.trim();
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            length = Some(value.parse::<u64>().ok()?);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !h.value.trim_ascii().eq_ignore_ascii_case(b"chunked") {
                return None;
            }
            chunked = true;
        } else if h.name.eq_ignore_ascii_case("connection")
            && h.value.split(|b| *b == b',').any(|v| {
                [b"content-length".as_slice(), b"transfer-encoding"]
                    .iter()
                    .any(|n| v.trim_ascii().eq_ignore_ascii_case(n))
            })
        {
            return None;
        }
    }
    if chunked && length.is_some() {
        return None;
    }
    let upgrade = header_value(req, "upgrade");
    if let Some(protocol) = &upgrade
        && (protocol.is_empty()
            || protocol.contains(',')
            || !req.headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("connection")
                    && h.value
                        .split(|b| *b == b',')
                        .any(|v| v.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
            }))
    {
        return None;
    }
    Some(Request {
        body: if chunked {
            Body::Chunked
        } else {
            Body::Fixed(length.unwrap_or(0))
        },
        upgrade,
    })
}

fn header_value(req: &httparse::Request, name: &str) -> Option<String> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|s| s.to_string())
}

fn split_absolute_uri(uri: &str) -> Option<(&str, &str)> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))?;
    match rest.find('/') {
        Some(i) => Some((&rest[..i], &rest[i..])),
        None => Some((rest, "/")),
    }
}

fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {

        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match s.rsplit_once(':') {

        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            Some((h.to_string(), p.parse().ok()?))
        }
        _ => Some((s.to_string(), default_port)),
    }
}

fn rebuild_origin_request(
    method: &str,
    abs_path: &str,
    version: u8,
    headers: &[httparse::Header],
    host: &str,
    port: u16,
) -> Vec<u8> {
    let ver = if version == 0 { "1.0" } else { "1.1" };
    let upgrade = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("upgrade"))
        .map(|h| h.value);
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("{method} {abs_path} HTTP/{ver}\r\n").as_bytes());
    let mut have_host = false;
    for h in headers {
        if h.name.is_empty() {
            continue;
        }

        if hop_header(h.name)
            || headers.iter().any(|c| {
                c.name.eq_ignore_ascii_case("connection")
                    && c.value
                        .split(|b| *b == b',')
                        .any(|v| v.trim_ascii().eq_ignore_ascii_case(h.name.as_bytes()))
            })
        {
            continue;
        }
        if h.name.eq_ignore_ascii_case("host") {
            have_host = true;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    if !have_host {
        let host_hdr = if port == 80 {
            format!("Host: {host}\r\n")
        } else {
            format!("Host: {host}:{port}\r\n")
        };
        out.extend_from_slice(host_hdr.as_bytes());
    }

    match upgrade {
        Some(v) => {
            out.extend_from_slice(b"Connection: upgrade\r\nUpgrade: ");
            out.extend_from_slice(v);
            out.extend_from_slice(b"\r\n");
        }
        None => out.extend_from_slice(b"Connection: close\r\n"),
    }
    out.extend_from_slice(b"\r\n");
    out
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
];

pub(crate) fn hop_header(name: &str) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

fn basic_auth_header_value(user: &str, pass: &str) -> String {
    let raw = format!("{user}:{pass}");
    format!("Basic {}", base64_encode(raw.as_bytes()))
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18 & 0x3f) as usize] as char);
        out.push(T[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) async fn udp_associate_inbound(
    mut ctrl: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    inbound: InboundKind,
) -> io::Result<()> {
    let local_ip = ctrl.local_addr()?.ip();
    let Some(permit) = shared
        .udp_budget
        .sessions
        .acquire(peer.ip(), inbound == InboundKind::HealthCheck)
    else {
        let _ = server::write_reply(&mut ctrl, server::REP_GENERAL_FAILURE, unspec()).await;
        return Ok(());
    };

    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    let bnd = relay.local_addr()?;
    if server::write_success(&mut ctrl, bnd).await.is_err() {
        return Ok(());
    }
    tracing::debug!(%peer, %bnd, "inbound udp associate established");

    let mut upstream = match InboundUpstream::open(&shared).await {
        Ok(u) => u,
        Err(e) => {
            tracing::debug!(%peer, ?e, "inbound udp: upstream open failed");
            return Ok(());
        }
    };

    let rec = Arc::new(UdpAssocRecords::new(Arc::clone(&shared), peer, inbound));

    let mut up_ctrl = upstream.take_ctrl();

    let client_addr_seen: Arc<parking_lot::Mutex<Option<SocketAddr>>> =
        Arc::new(parking_lot::Mutex::new(None));

    let last_down = Arc::new(AtomicU64::new(sb_stats::now_epoch_ms()));
    let reply_task = upstream.spawn_reply(
        Arc::clone(&relay),
        Arc::clone(&client_addr_seen),
        Arc::clone(&rec),
        Arc::clone(&last_down),
        Arc::clone(&permit),
    );
    let mut reply_task = BudgetedReply {
        task: reply_task,
        _permit: permit,
        records: Arc::clone(&rec),
    };

    let mut rbuf = vec![0u8; 64 * 1024];
    let mut ctrl_buf = [0u8; 1];
    let mut up_buf = Vec::with_capacity(2048);
    let idle = params.udp_idle;
    loop {
        tokio::select! {
            res = relay.recv_from(&mut rbuf) => {
                let (n, from) = match res { Ok(v) => v, Err(_) => break };

                if from.ip() != peer.ip() {
                    continue;
                }
                *client_addr_seen.lock() = Some(from);

                if let Err(e) = upstream.forward(&shared, &rbuf[..n], &mut up_buf, &rec).await {
                    tracing::debug!(%peer, ?e, "inbound udp: dropping one packet (association stays)");
                }
            }

            _ = &mut reply_task.task => {
                tracing::debug!(%peer, "inbound udp reply leg ended; teardown");
                break;
            }
            _ = upstream_ctrl_closed(&mut up_ctrl) => {
                tracing::debug!(%peer, "inbound udp: upstream ctrl closed; teardown");
                break;
            }
            res = ctrl.read(&mut ctrl_buf) => {
                match res {
                    Ok(0) => { tracing::debug!(%peer, "inbound udp ctrl FIN; teardown"); break; }
                    Err(_) => break,
                    Ok(_) => {}
                }
            }
            _ = tokio::time::sleep(idle) => {

                let quiet =
                    sb_stats::now_epoch_ms().saturating_sub(last_down.load(Ordering::Relaxed));
                if quiet < idle.as_millis() as u64 {
                    continue;
                }
                tracing::debug!(%peer, "inbound udp idle timeout; teardown");
                break;
            }
        }
    }

    reply_task.task.abort();
    if let Some(mut c) = up_ctrl {
        let _ = c.shutdown().await;
    }
    Ok(())
}

struct BudgetedReply {
    task: tokio::task::JoinHandle<()>,
    _permit: Arc<crate::udp_budget::Permit>,
    records: Arc<UdpAssocRecords>,
}

impl Drop for BudgetedReply {
    fn drop(&mut self) {
        self.task.abort();
        self.records.close();
    }
}

async fn upstream_ctrl_closed(ctrl: &mut Option<TcpStream>) {
    match ctrl {
        Some(c) => {
            let mut b = [0u8; 1];
            loop {
                match c.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        }
        None => std::future::pending().await,
    }
}

struct UdpAssocRecords {
    shared: Arc<SharedState>,
    peer: SocketAddr,
    inbound: InboundKind,

    inner: parking_lot::Mutex<AssocRecs>,
}

#[derive(Default)]
struct AssocRecs {
    by_target: std::collections::HashMap<TargetKey, Arc<ConnRecord>>,

    last: Option<Arc<ConnRecord>>,
}

#[derive(PartialEq, Eq, Hash)]
enum TargetKey {
    Addr(SocketAddr),
    Host(String, u16),
}

const MAX_TARGETS_PER_ASSOC: usize = 256;

impl UdpAssocRecords {
    fn new(shared: Arc<SharedState>, peer: SocketAddr, inbound: InboundKind) -> Self {
        Self {
            shared,
            peer,
            inbound,
            inner: parking_lot::Mutex::new(AssocRecs::default()),
        }
    }

    fn forward_record(
        &self,
        dst: SocketAddr,
        domain: Option<&str>,
        client_host: bool,
        payload: &[u8],
    ) -> Arc<ConnRecord> {
        let key = match domain {
            Some(h) => TargetKey::Host(h.to_owned(), dst.port()),
            None => TargetKey::Addr(dst),
        };
        let mut g = self.inner.lock();
        if let Some(r) = g.by_target.get(&key) {
            let r = Arc::clone(r);
            g.last = Some(Arc::clone(&r));
            return r;
        }
        if g.by_target.len() >= MAX_TARGETS_PER_ASSOC
            && let Some(r) = &g.last
        {
            return Arc::clone(r);
        }

        let proto = crate::udp_engine::classify_inbound_udp_proto(
            dst,
            payload,
            client_host,
            domain.is_some() && !client_host,
            domain
                .and_then(crate::domain_rules::match_group)
                .or_else(|| self.shared.domain_ips.get(dst.ip())),
        );
        let r = Arc::new(
            ConnRecord::new(
                self.shared.id_gen.next_id(),
                (self.peer.ip(), self.peer.port()),
                (dst.ip(), dst.port()),
                proto,
                domain.map(str::to_owned),
            )
            .with_inbound(self.inbound, Transport::Udp),
        );

        if matches!(
            proto,
            sb_stats::SniffedProto::Socks5
                | sb_stats::SniffedProto::FakeIp
                | sb_stats::SniffedProto::RealIp
        ) {
            r.set_head(payload);
        }
        self.shared.conn_table.insert(Arc::clone(&r));
        if let Some(p) = &self.shared.pplog {
            p.open(&r);
        }
        g.by_target.insert(key, Arc::clone(&r));
        g.last = Some(Arc::clone(&r));
        r
    }

    fn reply_record(&self, src: SocketAddr) -> Option<Arc<ConnRecord>> {
        let g = self.inner.lock();
        g.by_target
            .get(&TargetKey::Addr(src))
            .cloned()
            .or_else(|| g.last.clone())
    }

    fn close(&self) {
        let g = self.inner.lock();
        for r in g.by_target.values() {
            let (du, dd) = r.drain_delta();
            if du != 0 || dd != 0 {
                self.shared.traffic.add_totals(dd, du);
            }
            self.shared.conn_table.close(r.id);
            if let Some(p) = &self.shared.pplog {
                p.close(r);
            }
        }
    }
}

enum InboundUpstream {
    Socks5 {

        ctrl: Option<TcpStream>,
        relay: Arc<UdpSocket>,
    },
    Direct {
        sock: Arc<UdpSocket>,
        resolver: Arc<Resolver>,
    },
}

impl InboundUpstream {

    async fn open(shared: &SharedState) -> io::Result<Self> {

        if !shared.outbound.tun_ready_ok() {
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "ovpn tunnel (tun114) not ready",
            ));
        }
        match shared.outbound.udp_upstream() {
            UdpUpstream::Socks5 { target, auth } => {
                let (ctrl, relay) = open_upstream_udp(target, auth).await?;
                Ok(Self::Socks5 {
                    ctrl: Some(ctrl),
                    relay: Arc::new(relay),
                })
            }
            UdpUpstream::Direct {
                resolver,
                bind_device,
                so_mark,
            } => {

                let std =
                    sb_outbound::direct::bind_udp_socket(true, bind_device.as_deref(), so_mark)
                        .map_err(io::Error::other)?;
                Ok(Self::Direct {
                    sock: Arc::new(UdpSocket::from_std(std)?),
                    resolver,
                })
            }
        }
    }

    async fn forward(
        &self,
        shared: &Arc<SharedState>,
        frame: &[u8],
        up_buf: &mut Vec<u8>,
        rec: &UdpAssocRecords,
    ) -> io::Result<()> {
        match self {
            Self::Socks5 { relay, .. } => {
                forward_client_packet(shared, relay, frame, up_buf, rec).await
            }
            Self::Direct { sock, resolver } => {
                forward_client_packet_direct(shared, sock, resolver, frame, rec).await
            }
        }
    }

    fn spawn_reply(
        &self,
        relay: Arc<UdpSocket>,
        client_seen: Arc<parking_lot::Mutex<Option<SocketAddr>>>,
        rec: Arc<UdpAssocRecords>,
        last_down: Arc<AtomicU64>,
        permit: Arc<crate::udp_budget::Permit>,
    ) -> tokio::task::JoinHandle<()> {
        match self {
            Self::Socks5 {
                relay: up_relay, ..
            } => {
                let up_relay = Arc::clone(up_relay);
                tokio::spawn(async move {
                    let _permit = permit;
                    reply_loop_socks5(up_relay, relay, client_seen, rec, last_down).await;
                })
            }
            Self::Direct { sock, .. } => {
                let sock = Arc::clone(sock);
                tokio::spawn(async move {
                    let _permit = permit;
                    reply_loop_direct(sock, relay, client_seen, rec, last_down).await;
                })
            }
        }
    }

    fn take_ctrl(&mut self) -> Option<TcpStream> {
        match self {
            Self::Socks5 { ctrl, .. } => ctrl.take(),
            Self::Direct { .. } => None,
        }
    }
}

async fn reply_loop_socks5(
    up_relay: Arc<UdpSocket>,
    relay: Arc<UdpSocket>,
    client_seen: Arc<parking_lot::Mutex<Option<SocketAddr>>>,
    rec: Arc<UdpAssocRecords>,
    last_down: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = Vec::with_capacity(2048);
    loop {
        let n = match up_relay.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };
        let (src, off) = match decode_udp_reply(&buf[..n]) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let Some(client) = ({ *client_seen.lock() }) else {
            continue;
        };
        encode_udp_request_into(&mut out, src, &buf[off..n]);
        if relay.send_to(&out, client).await.is_err() {
            break;
        }
        last_down.store(sb_stats::now_epoch_ms(), Ordering::Relaxed);
        if let Some(r) = rec.reply_record(src) {
            r.add_down((n - off) as u64);
        }
    }
}

async fn reply_loop_direct(
    sock: Arc<UdpSocket>,
    relay: Arc<UdpSocket>,
    client_seen: Arc<parking_lot::Mutex<Option<SocketAddr>>>,
    rec: Arc<UdpAssocRecords>,
    last_down: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = Vec::with_capacity(2048);
    loop {
        let (n, real_src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let Some(client) = ({ *client_seen.lock() }) else {
            continue;
        };
        encode_udp_request_into(&mut out, real_src, &buf[..n]);
        if relay.send_to(&out, client).await.is_err() {
            break;
        }
        last_down.store(sb_stats::now_epoch_ms(), Ordering::Relaxed);
        if let Some(r) = rec.reply_record(real_src) {
            r.add_down(n as u64);
        }
    }
}

async fn forward_client_packet(
    shared: &Arc<SharedState>,
    up_relay: &UdpSocket,
    frame: &[u8],
    up_buf: &mut Vec<u8>,
    rec: &UdpAssocRecords,
) -> io::Result<()> {
    let (dst, host, off) = match decode_client_udp_header(frame) {
        Some(v) => v,
        None => return Ok(()),
    };
    let payload = &frame[off..];

    let client_host = host.is_some();
    let domain = host.or_else(|| match (&shared.fakeip, dst.ip()) {
        (Some(f), IpAddr::V4(v4)) if f.contains(dst.ip()) => f.lookback(v4).map(|d| d.to_string()),
        _ => None,
    });
    match &domain {
        Some(h) => encode_udp_request_domain_into(up_buf, h, dst.port(), payload)
            .map_err(io::Error::other)?,
        None => {

            if shared.fakeip.as_ref().is_some_and(|f| f.contains(dst.ip())) {
                return Ok(());
            }
            encode_udp_request_into(up_buf, dst, payload);
        }
    }
    rec.forward_record(dst, domain.as_deref(), client_host, payload)
        .add_up(payload.len() as u64);
    up_relay.send(up_buf).await?;
    Ok(())
}

async fn forward_client_packet_direct(
    shared: &Arc<SharedState>,
    sock: &UdpSocket,
    resolver: &Resolver,
    frame: &[u8],
    rec: &UdpAssocRecords,
) -> io::Result<()> {
    let (dst, host, off) = match decode_client_udp_header(frame) {
        Some(v) => v,
        None => return Ok(()),
    };
    let payload = &frame[off..];

    let client_host = host.is_some();
    let domain = host.or_else(|| match (&shared.fakeip, dst.ip()) {
        (Some(f), IpAddr::V4(v4)) if f.contains(dst.ip()) => f.lookback(v4).map(|d| d.to_string()),
        _ => None,
    });
    let real_dst = match &domain {
        Some(h) => {
            let ip = resolver.resolve_v4(h).await?;
            SocketAddr::new(IpAddr::V4(ip), dst.port())
        }
        None => {

            if shared.fakeip.as_ref().is_some_and(|f| f.contains(dst.ip())) {
                return Ok(());
            }
            dst
        }
    };
    rec.forward_record(dst, domain.as_deref(), client_host, payload)
        .add_up(payload.len() as u64);
    sock.send_to(payload, real_dst).await?;
    Ok(())
}

fn decode_client_udp_header(buf: &[u8]) -> Option<(SocketAddr, Option<String>, usize)> {
    use sb_outbound::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return None;
    }
    match buf[3] {
        ATYP_IPV4 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), None, 10))
        }
        ATYP_IPV6 => {
            if buf.len() < 22 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(o);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Some((SocketAddr::new(IpAddr::V6(ip), port), None, 22))
        }
        ATYP_DOMAIN => {
            let len = *buf.get(4)? as usize;
            let end = 5 + len;
            if buf.len() < end + 2 {
                return None;
            }
            let host = std::str::from_utf8(&buf[5..end]).ok()?.to_string();
            let port = u16::from_be_bytes([buf[end], buf[end + 1]]);

            Some((
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                Some(host),
                end + 2,
            ))
        }
        _ => None,
    }
}

const UP_ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);

async fn open_upstream_udp(
    socks_target: SocketAddr,
    auth: Option<Arc<(String, String)>>,
) -> io::Result<(TcpStream, UdpSocket)> {
    tokio::time::timeout(UP_ASSOCIATE_TIMEOUT, async {
        let mut ctrl = TcpStream::connect(socks_target).await?;
        let bnd = udp_associate_auth(&mut ctrl, "0.0.0.0:0".parse().unwrap(), auth.as_deref())
            .await
            .map_err(io::Error::other)?;
        let relay = UdpSocket::bind("0.0.0.0:0").await?;
        relay.connect(bnd).await?;
        Ok::<_, io::Error>((ctrl, relay))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream udp associate timed out"))?
}

pub fn lan_ipv4s() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return out;
    };
    for ifa in addrs {
        if let Some(addr) = ifa.address
            && let Some(sin) = addr.as_sockaddr_in()
        {
            let ip = sin.ip();
            if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() {
                out.push(ip);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    async fn mock_upstream_socks5() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match l.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tokio::spawn(async move {

                    let mut head = [0u8; 2];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut methods = [0u8; 255];
                    let _ = s.read_exact(&mut methods[..head[1] as usize]).await;
                    let _ = s.write_all(&[0x05, 0x00]).await;

                    let mut req = [0u8; 10];
                    if s.read_exact(&mut req).await.is_err() {
                        return;
                    }

                    let _ = s.write_all(&[0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;

                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    fn shared_with_upstream(upstream: SocketAddr) -> Arc<SharedState> {
        let mut cfg = Config::default();
        cfg.socks5.server = upstream;
        cfg.inbound.splice_copy = false;

        cfg.outbound.mode = crate::config::OutboundMode::Yaml;
        Arc::new(SharedState::new(&cfg))
    }

    async fn spawn_inbound(shared: Arc<SharedState>, params: InboundProxyParams) -> SocketAddr {
        spawn_inbound_profiled(shared, params, OPENPORT).await
    }

    async fn spawn_inbound_profiled(
        shared: Arc<SharedState>,
        params: InboundProxyParams,
        profile: InboundProfile,
    ) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, peer) = l.accept().await.unwrap();
            let _ = handle_inbound(s, peer, shared, params, profile).await;
        });
        addr
    }

    async fn wait_for_inbound(shared: &SharedState, want: InboundKind) -> bool {
        for _ in 0..50 {
            if shared
                .conn_table
                .snapshot()
                .iter()
                .any(|r| r.inbound == want)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    fn params() -> InboundProxyParams {
        InboundProxyParams {
            listen_port: 0,
            udp: false,
            udp_idle: Duration::from_secs(60),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    #[tokio::test]
    async fn socks5_connect_end_to_end() {
        let upstream = mock_upstream_socks5().await;
        let shared = shared_with_upstream(upstream);
        let proxy = spawn_inbound(shared, params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();

        c.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [0x05, 0x00]);

        c.write_all(&[0x05, 0x01, 0, 0x01, 127, 0, 0, 1, 0, 9])
            .await
            .unwrap();
        let mut srep = [0u8; 10];
        c.read_exact(&mut srep).await.unwrap();
        assert_eq!(srep[1], 0x00, "socks5 reply should be success");

        c.write_all(b"ping-data").await.unwrap();
        let mut back = [0u8; 9];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping-data");
    }

    #[tokio::test]
    async fn healthcheck_profile_marks_inbound_healthcheck() {
        let upstream = mock_upstream_socks5().await;
        let shared = shared_with_upstream(upstream);
        let proxy = spawn_inbound_profiled(Arc::clone(&shared), params(), HEALTHCHECK).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [0x05, 0x00]);
        c.write_all(&[0x05, 0x01, 0, 0x01, 127, 0, 0, 1, 0, 9])
            .await
            .unwrap();
        let mut srep = [0u8; 10];
        c.read_exact(&mut srep).await.unwrap();
        assert_eq!(srep[1], 0x00);
        c.write_all(b"hc").await.unwrap();
        let mut back = [0u8; 2];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hc");

        assert!(
            wait_for_inbound(&shared, InboundKind::HealthCheck).await,
            "health-check inbound connection should be recorded as InboundKind::HealthCheck"
        );
    }

    async fn http_origin(body: &'static str) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&b[..n]),
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.flush().await;
                });
            }
        });
        addr
    }

    async fn mock_upstream_socks5_bridge(origin: SocketAddr) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut methods = [0u8; 255];
                    if s.read_exact(&mut methods[..head[1] as usize])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0x00]).await;

                    let mut h = [0u8; 4];
                    if s.read_exact(&mut h).await.is_err() {
                        return;
                    }
                    let ok = match h[3] {
                        0x01 => s.read_exact(&mut [0u8; 4]).await.is_ok(),
                        0x04 => s.read_exact(&mut [0u8; 16]).await.is_ok(),
                        0x03 => {
                            let mut n = [0u8; 1];
                            s.read_exact(&mut n).await.is_ok() && {
                                let mut d = vec![0u8; n[0] as usize];
                                s.read_exact(&mut d).await.is_ok()
                            }
                        }
                        _ => false,
                    };
                    if !ok || s.read_exact(&mut [0u8; 2]).await.is_err() {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;

                    if let Ok(mut up) = TcpStream::connect(origin).await {
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    }
                });
            }
        });
        addr
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_traverses_healthcheck_inbound_and_is_tagged() {
        let origin = http_origin("region=JP").await;
        let upstream = mock_upstream_socks5_bridge(origin).await;
        let shared = shared_with_upstream(upstream);
        let inbound = spawn_inbound_profiled(Arc::clone(&shared), params(), HEALTHCHECK).await;

        let proxy = format!("socks5h://127.0.0.1:{}", inbound.port());
        let req =
            serde_json::json!({ "url": "http://example.com/probe", "timeoutMs": 5000 }).to_string();
        let out = sb_ppgw::probe::run_json(&req, &proxy).await;
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(
            v["ok"], true,
            "probe should get response through proxy chain: {out}"
        );
        assert_eq!(v["status"], 200, "{out}");
        assert_eq!(v["body"], "region=JP", "{out}");
        assert_eq!(v["headers"]["content-type"], "text/plain", "{out}");

        assert!(
            wait_for_inbound(&shared, InboundKind::HealthCheck).await,
            "probe connection should be recorded as InboundKind::HealthCheck, distinct from real user traffic"
        );
        let recs = shared.conn_table.snapshot();
        assert!(
            recs.iter()
                .any(|r| r.domain.as_deref() == Some("example.com")),
            "domain should come from handshake: {:?}",
            recs.iter()
                .map(|r| (&r.domain, r.inbound))
                .collect::<Vec<_>>()
        );

        assert!(
            recs.iter()
                .any(|r| r.domain.as_deref() == Some("example.com")
                    && r.proto == sb_stats::SniffedProto::Http),
            "health-check http:// should be labeled Http by port: {:?}",
            recs.iter()
                .map(|r| (&r.domain, r.proto))
                .collect::<Vec<_>>()
        );
    }

    async fn plain_echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn udp_echo_server() -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut b).await {
                let _ = s.send_to(&b[..n], from).await;
            }
        });
        addr
    }

    async fn mock_dns_a(answer: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if let Ok(q) = sb_dns::message::parse_query(&buf[..n]) {
                    let _ = sock.send_to(&q.answer_a(answer, 60), peer).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn socks5_inbound_direct_mode_resolves_and_forwards() {
        use crate::config::{DnsResolverCfg, OutboundCfg, OutboundMode};
        let echo = plain_echo_server().await;
        let dns = mock_dns_a(Ipv4Addr::LOCALHOST).await;

        let mut cfg = Config::default();
        cfg.inbound.splice_copy = false;
        cfg.outbound = OutboundCfg {
            mode: OutboundMode::Free,
            resolver: DnsResolverCfg { server: Some(dns) },
            ..Default::default()
        };
        let shared = Arc::new(SharedState::new(&cfg));
        assert!(shared.outbound.is_direct());
        let proxy = spawn_inbound(shared, params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [0x05, 0x00]);

        let host = b"echo.test";
        let mut req = vec![0x05, 0x01, 0, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&echo.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut srep = [0u8; 10];
        c.read_exact(&mut srep).await.unwrap();
        assert_eq!(srep[1], 0x00, "socks5 reply should be success");

        c.write_all(b"direct-bytes").await.unwrap();
        let mut back = [0u8; 12];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"direct-bytes");
    }

    #[tokio::test]
    async fn socks5_inbound_udp_direct_mode_resolves_and_relays() {
        use crate::config::{DnsResolverCfg, OutboundCfg, OutboundMode};
        let echo = udp_echo_server().await;
        let dns = mock_dns_a(Ipv4Addr::LOCALHOST).await;

        let mut cfg = Config::default();
        cfg.inbound.splice_copy = false;
        cfg.outbound = OutboundCfg {
            mode: OutboundMode::Free,
            resolver: DnsResolverCfg { server: Some(dns) },
            ..Default::default()
        };
        let shared = Arc::new(SharedState::new(&cfg));
        assert!(shared.outbound.is_direct());
        let mut p = params();
        p.udp = true;
        let proxy = spawn_inbound(Arc::clone(&shared), p).await;

        let mut ctrl = TcpStream::connect(proxy).await.unwrap();
        ctrl.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        ctrl.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [0x05, 0x00]);
        ctrl.write_all(&[0x05, 0x03, 0, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut arep = [0u8; 10];
        ctrl.read_exact(&mut arep).await.unwrap();
        assert_eq!(arep[1], 0x00, "associate should succeed");
        let bnd = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(arep[4], arep[5], arep[6], arep[7])),
            u16::from_be_bytes([arep[8], arep[9]]),
        );

        assert!(
            shared.conn_table.is_empty(),
            "no traffic record before the first datagram"
        );

        let cudp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let host = b"udp.test";
        let mut dg = vec![0u8, 0, 0, 0x03, host.len() as u8];
        dg.extend_from_slice(host);
        dg.extend_from_slice(&echo.port().to_be_bytes());
        dg.extend_from_slice(b"ping");
        cudp.send_to(&dg, bnd).await.unwrap();

        let mut rbuf = [0u8; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), cudp.recv_from(&mut rbuf))
            .await
            .expect("reply within 2s")
            .unwrap();
        let (src, off) = sb_outbound::socks5_udp::decode_udp_reply(&rbuf[..n]).unwrap();
        assert_eq!(
            src,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), echo.port())
        );
        assert_eq!(&rbuf[off..n], b"ping");

        let recs = shared.conn_table.snapshot();
        assert_eq!(recs.len(), 1, "first datagram registers one record");
        let r = &recs[0];
        assert_eq!(r.domain.as_deref(), Some("udp.test"));
        assert_eq!(r.dst.1, echo.port(), "dst port from the first datagram");
        assert_eq!(r.display_domain(), "udp.test");
        assert_eq!(r.transport, Transport::Udp);

        assert_eq!(r.proto, sb_stats::SniffedProto::Socks5);
        assert_eq!(r.head_bytes().as_deref(), Some(&b"ping"[..]));
        assert!(r.upload.load(std::sync::atomic::Ordering::Relaxed) >= 4);
        assert!(r.download.load(std::sync::atomic::Ordering::Relaxed) >= 4);

        let echo2 = udp_echo_server().await;
        let mut dg2 = vec![0u8, 0, 0, 0x01, 127, 0, 0, 1];
        dg2.extend_from_slice(&echo2.port().to_be_bytes());
        dg2.extend_from_slice(b"pong");
        cudp.send_to(&dg2, bnd).await.unwrap();
        let (n2, _) = tokio::time::timeout(Duration::from_secs(2), cudp.recv_from(&mut rbuf))
            .await
            .expect("second target replies within 2s")
            .unwrap();
        let (src2, off2) = sb_outbound::socks5_udp::decode_udp_reply(&rbuf[..n2]).unwrap();
        assert_eq!(src2.port(), echo2.port());
        assert_eq!(&rbuf[off2..n2], b"pong");

        let recs = shared.conn_table.snapshot();
        assert_eq!(
            recs.len(),
            2,
            "one record per target within the association"
        );
        let r2 = recs
            .iter()
            .find(|r| r.dst.1 == echo2.port())
            .expect("second target has its own record");
        assert_eq!(r2.domain, None, "ip-form target keeps its ip as display");
        assert_eq!(r2.display_domain(), "127.0.0.1");
        assert_eq!(r2.proto, sb_stats::SniffedProto::RealIp);
        assert!(r2.upload.load(std::sync::atomic::Ordering::Relaxed) >= 4);

        assert!(r2.download.load(std::sync::atomic::Ordering::Relaxed) >= 4);
        drop(ctrl);
    }

    #[tokio::test]
    async fn socks5_auth_rejected_when_wrong() {
        let upstream = mock_upstream_socks5().await;

        let mut cfg = Config::default();
        cfg.socks5.server = upstream;
        cfg.inbound.splice_copy = false;
        cfg.outbound.mode = crate::config::OutboundMode::Yaml;
        cfg.inbound_proxy.auth = Some(("user".into(), "pass".into()));
        let shared = Arc::new(SharedState::new(&cfg));
        let proxy = spawn_inbound(shared, params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();

        c.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn http_connect_end_to_end() {
        let upstream = mock_upstream_socks5().await;
        let shared = shared_with_upstream(upstream);
        let proxy = spawn_inbound(shared, params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = c.read(&mut tmp).await.unwrap();
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let s = String::from_utf8_lossy(&buf);
        assert!(s.starts_with("HTTP/1.1 200"), "got: {s:?}");

        c.write_all(b"tunnel-bytes").await.unwrap();
        let mut back = [0u8; 12];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"tunnel-bytes");
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");

        assert_eq!(
            basic_auth_header_value("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(
            split_host_port("example.com:443", 80),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            split_host_port("example.com", 80),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            split_host_port("1.2.3.4:8080", 80),
            Some(("1.2.3.4".into(), 8080))
        );
        assert_eq!(
            split_host_port("[::1]:9000", 80),
            Some(("::1".into(), 9000))
        );
        assert_eq!(split_host_port("[::1]", 80), Some(("::1".into(), 80)));
    }

    #[test]
    fn parse_connect_request() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let p = parse_http_proxy_request(head).unwrap();
        match p.kind {
            HttpReqKind::Connect { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected connect"),
        }
    }

    #[test]
    fn parse_absolute_uri_forward() {
        let head = b"GET http://example.com/path?x=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nUser-Agent: t\r\n\r\n";
        let p = parse_http_proxy_request(head).unwrap();
        match p.kind {
            HttpReqKind::Forward {
                host,
                port,
                request,
                framing,
            } => {
                assert_eq!(host, "example.com");
                assert!(matches!(framing.body, crate::http_forward::Body::Fixed(0)));
                assert_eq!(port, 80);
                let s = String::from_utf8(request).unwrap();
                assert!(s.starts_with("GET /path?x=1 HTTP/1.1\r\n"), "got: {s:?}");
                assert!(s.contains("Host: example.com\r\n"));
                assert!(!s.to_ascii_lowercase().contains("proxy-connection"));
                assert!(s.ends_with("\r\n\r\n"));
            }
            _ => panic!("expected forward"),
        }
    }

    #[test]
    fn parse_absolute_uri_with_explicit_port() {
        let head = b"GET http://example.com:8080/ HTTP/1.1\r\n\r\n";
        let p = parse_http_proxy_request(head).unwrap();
        match p.kind {
            HttpReqKind::Forward {
                host,
                port,
                request,
                ..
            } => {
                assert_eq!((host.as_str(), port), ("example.com", 8080));
                let s = String::from_utf8(request).unwrap();

                assert!(s.contains("Host: example.com:8080\r\n"), "got: {s:?}");
            }
            _ => panic!("expected forward"),
        }
    }

    #[test]
    fn ambiguous_http_framing_is_rejected_before_forwarding() {
        for headers in [
            "Content-Length: 1\r\nContent-Length: 2\r\n",
            "Content-Length: abc\r\n",
            "Content-Length: +5\r\n",
            "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: chunked, chunked\r\n",
            "Connection: Content-Length\r\nContent-Length: 5\r\n",
            "Upgrade: websocket\r\n",
        ] {
            let head = format!("POST http://example.com/ HTTP/1.1\r\n{headers}\r\n");
            assert!(
                parse_http_proxy_request(head.as_bytes()).is_none(),
                "accepted {headers:?}"
            );
        }
    }

    #[tokio::test]
    async fn http_forward_late_pipeline_never_reaches_the_first_origin() {
        for splice in [false, true] {
            for chunked in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let origin = tokio::spawn(async move {
                    let (mut s, _) = listener.accept().await.unwrap();
                    let mut head = Vec::new();
                    let mut byte = [0];
                    while !head.ends_with(b"\r\n\r\n") {
                        s.read_exact(&mut byte).await.unwrap();
                        head.push(byte[0]);
                    }
                    ready_tx.send(()).unwrap();
                    let mut body = Vec::new();
                    s.read_to_end(&mut body).await.unwrap();
                    assert_eq!(
                        body,
                        if chunked {
                            b"5\r\nHELLO\r\n0\r\n\r\n".as_slice()
                        } else {
                            b"HELLO"
                        }
                    );
                    assert!(
                        !String::from_utf8_lossy(&head)
                            .to_ascii_lowercase()
                            .contains("proxy-authorization")
                    );
                    s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await
                    .unwrap();
                });
                let upstream = mock_upstream_socks5_routing().await;

                let mut cfg = Config::default();
                cfg.socks5.server = upstream;
                cfg.outbound.mode = crate::config::OutboundMode::Yaml;
                cfg.inbound.splice_copy = splice;
                let shared = Arc::new(SharedState::new(&cfg));
                let proxy = spawn_inbound(shared, params()).await;
                let mut c = TcpStream::connect(proxy).await.unwrap();
                let framing = if chunked {
                    "Transfer-Encoding: chunked"
                } else {
                    "Content-Length: 5"
                };
                c.write_all(
                    format!(
                        "POST http://{addr}/first HTTP/1.1\r\nHost: {addr}\r\n{framing}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                tokio::time::timeout(Duration::from_secs(2), ready_rx)
                    .await
                    .unwrap()
                    .unwrap();
                let body = if chunked {
                    "5\r\nHELLO\r\n0\r\n\r\n"
                } else {
                    "HELLO"
                };
                c.write_all(format!("{body}GET http://elsewhere.invalid/second HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n").as_bytes()).await.unwrap();

                c.shutdown().await.unwrap();
                let response = read_to_end(&mut c).await;
                assert!(
                    response.ends_with("OK"),
                    "first request failed: {response:?}"
                );
                tokio::time::timeout(Duration::from_secs(2), origin)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }

    #[test]
    fn upgrade_request_keeps_the_tunnel_open() {
        let head = b"GET http://x.com/ws HTTP/1.1\r\nHost: x.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let p = parse_http_proxy_request(head).unwrap();
        match p.kind {
            HttpReqKind::Forward {
                request, framing, ..
            } => {
                let s = String::from_utf8(request).unwrap();
                let lower = s.to_ascii_lowercase();
                assert!(s.contains("Upgrade: websocket\r\n"), "got: {s:?}");
                assert!(lower.contains("connection: upgrade"), "got: {s:?}");
                assert!(!lower.contains("connection: close"), "got: {s:?}");
                assert_eq!(
                    framing.upgrade.as_deref(),
                    Some("websocket"),
                    "tunnel bytes require origin acceptance"
                );
            }
            _ => panic!("expected forward"),
        }
    }

    #[test]
    fn parse_extracts_proxy_authorization() {
        let head = b"GET http://x.com/ HTTP/1.1\r\nProxy-Authorization: Basic abc\r\n\r\n";
        let p = parse_http_proxy_request(head).unwrap();
        assert_eq!(p.proxy_authorization.as_deref(), Some("Basic abc"));
    }

    #[test]
    fn decode_client_udp_ipv4() {

        let frame = [0u8, 0, 0, 1, 1, 2, 3, 4, 0, 53, 0xAB, 0xCD];
        let (dst, host, off) = decode_client_udp_header(&frame).unwrap();
        assert_eq!(dst, "1.2.3.4:53".parse().unwrap());
        assert!(host.is_none());
        assert_eq!(off, 10);
        assert_eq!(&frame[off..], &[0xAB, 0xCD]);
    }

    #[test]
    fn decode_client_udp_domain() {
        let host = b"example.com";
        let mut frame = vec![0u8, 0, 0, 3, host.len() as u8];
        frame.extend_from_slice(host);
        frame.extend_from_slice(&443u16.to_be_bytes());
        frame.extend_from_slice(b"data");
        let (dst, h, off) = decode_client_udp_header(&frame).unwrap();
        assert_eq!(dst.port(), 443);
        assert_eq!(h.as_deref(), Some("example.com"));
        assert_eq!(&frame[off..], b"data");
    }

    #[test]
    fn decode_client_udp_rejects_fragment() {
        let frame = [0u8, 0, 1, 1, 1, 2, 3, 4, 0, 53];
        assert!(decode_client_udp_header(&frame).is_none());
    }

    async fn recording_origin(
        tag: &'static str,
    ) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let log: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1024];
                    loop {
                        if let Some(end) = find_head_end(&buf) {
                            let want = content_length(&String::from_utf8_lossy(&buf[..end]));
                            if buf.len() - end >= want {
                                break;
                            }
                        }
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&b[..n]),
                        }
                    }
                    sink.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf).to_string());
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{tag}",
                        tag.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.flush().await;
                });
            }
        });
        (addr, log)
    }

    fn content_length(head: &str) -> usize {
        head.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split_once(':'))
            .and_then(|(_, v)| v.trim().parse().ok())
            .unwrap_or(0)
    }

    async fn mock_upstream_socks5_routing() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut methods = [0u8; 255];
                    if s.read_exact(&mut methods[..head[1] as usize])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0x00]).await;
                    let mut h = [0u8; 4];
                    if s.read_exact(&mut h).await.is_err() || h[3] != 0x01 {
                        return;
                    }
                    let mut ip = [0u8; 4];
                    let mut port = [0u8; 2];
                    if s.read_exact(&mut ip).await.is_err()
                        || s.read_exact(&mut port).await.is_err()
                    {
                        return;
                    }
                    let dst = SocketAddr::from((ip, u16::from_be_bytes(port)));
                    let _ = s.write_all(&[0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    if let Ok(mut up) = TcpStream::connect(dst).await {
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    }
                });
            }
        });
        addr
    }

    async fn read_to_end(s: &mut TcpStream) -> String {
        let mut out = Vec::new();
        let mut b = [0u8; 1024];
        while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&b[..n]);
        }
        String::from_utf8_lossy(&out).to_string()
    }

    #[tokio::test]
    async fn http_connect_keeps_bytes_pipelined_with_the_request() {
        let upstream = mock_upstream_socks5().await;
        let shared = shared_with_upstream(upstream);
        let proxy = spawn_inbound(shared, params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(
            b"CONNECT 127.0.0.1:7000 HTTP/1.1\r\nHost: 127.0.0.1:7000\r\n\r\nPING-PIPELINED",
        )
        .await
        .unwrap();

        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut b))
                .await
                .expect("proxy should answer CONNECT")
                .unwrap();
            assert_ne!(n, 0, "proxy closed before answering CONNECT");
            head.extend_from_slice(&b[..n]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        let mut back = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut back))
            .await
            .expect("bytes sent together with CONNECT must still reach upstream")
            .unwrap();
        assert_eq!(&back, b"PING-PIPELINED");
    }

    #[tokio::test]
    async fn http_forward_keeps_the_body_that_arrived_with_the_head() {
        let (origin, log) = recording_origin("ok-body").await;
        let upstream = mock_upstream_socks5_routing().await;
        let shared = shared_with_upstream(upstream);
        let proxy = spawn_inbound(shared, params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        let port = origin.port();
        let req = format!(
            "POST http://127.0.0.1:{port}/post HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 5\r\n\r\nHELLO"
        );
        c.write_all(req.as_bytes()).await.unwrap();
        let resp = read_to_end(&mut c).await;
        assert!(
            resp.contains("ok-body"),
            "no response from origin: {resp:?}"
        );

        let got = log.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "origin should see exactly one request");
        assert!(
            got[0].ends_with("HELLO"),
            "origin must receive the body that came in the same write as the head: {:?}",
            got[0]
        );
    }

    #[tokio::test]
    async fn http_forward_strips_proxy_credentials_and_ends_the_connection() {
        let (origin_a, log_a) = recording_origin("origin-a").await;
        let (origin_b, _log_b) = recording_origin("origin-b").await;
        let upstream = mock_upstream_socks5_routing().await;
        let shared = shared_with_upstream(upstream);
        let proxy = spawn_inbound(shared, params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        let pa = origin_a.port();
        let first = format!(
            "GET http://127.0.0.1:{pa}/first HTTP/1.1\r\nHost: 127.0.0.1:{pa}\r\n\
             Proxy-Authorization: Basic c2VjcmV0OnBhc3M=\r\nProxy-Connection: keep-alive\r\n\
             Connection: keep-alive\r\n\r\n"
        );
        c.write_all(first.as_bytes()).await.unwrap();

        let pb = origin_b.port();
        let second =
            format!("GET http://127.0.0.1:{pb}/second HTTP/1.1\r\nHost: 127.0.0.1:{pb}\r\n\r\n");
        let _ = c.write_all(second.as_bytes()).await;
        let resp = read_to_end(&mut c).await;
        assert!(resp.contains("origin-a"), "first request failed: {resp:?}");

        let got = log_a.lock().unwrap().clone();
        assert_eq!(
            got.len(),
            1,
            "origin A must not be handed the request addressed to origin B: {got:?}"
        );
        let seen = got[0].to_ascii_lowercase();
        assert!(
            !seen.contains("proxy-authorization"),
            "proxy credentials must never reach the origin: {:?}",
            got[0]
        );
        assert!(
            !seen.contains("proxy-connection") && !seen.contains("keep-alive"),
            "hop-by-hop headers must be stripped: {:?}",
            got[0]
        );
        assert!(
            seen.contains("connection: close"),
            "forwarded request must ask the origin to close: {:?}",
            got[0]
        );
        assert!(
            !seen.contains("/second"),
            "the second request leaked into origin A: {:?}",
            got[0]
        );
    }

    #[tokio::test]
    async fn handshake_timeout_closes_a_silent_client() {
        let upstream = mock_upstream_socks5().await;
        let shared = shared_with_upstream(upstream);
        let mut p = params();
        p.handshake_timeout = Duration::from_millis(100);
        let proxy = spawn_inbound(shared, p).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        let start = std::time::Instant::now();
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut b))
            .await
            .expect("a silent client must be dropped, not held forever")
            .unwrap();
        assert_eq!(n, 0, "proxy should have closed the connection");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "closed too late: {:?}",
            start.elapsed()
        );
    }

    async fn counting_upstream() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                drop(s);
            }
        });
        (addr, hits)
    }

    #[tokio::test]
    async fn zero_byte_client_does_not_dial_upstream() {
        let (upstream, hits) = counting_upstream().await;
        let shared = shared_with_upstream(upstream);
        let proxy = spawn_inbound(Arc::clone(&shared), params()).await;

        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        c.read_exact(&mut rep).await.unwrap();
        c.write_all(&[0x05, 0x01, 0, 0x01, 127, 0, 0, 1, 0, 9])
            .await
            .unwrap();
        let mut srep = [0u8; 10];
        c.read_exact(&mut srep).await.unwrap();

        drop(c);

        tokio::time::sleep(Duration::from_millis(900)).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a client that sent nothing must not cost an upstream dial"
        );
    }

    async fn mock_dns_nx(answer: Ipv4Addr, nx: &'static str) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if let Ok(q) = sb_dns::message::parse_query(&buf[..n]) {
                    let resp = if q.name == nx {
                        q.error(3)
                    } else {
                        q.answer_a(answer, 60)
                    };
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        addr
    }

    async fn associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
        let mut ctrl = TcpStream::connect(proxy).await.unwrap();
        ctrl.write_all(&[0x05, 1, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        ctrl.read_exact(&mut rep).await.unwrap();
        ctrl.write_all(&[0x05, 0x03, 0, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut arep = [0u8; 10];
        ctrl.read_exact(&mut arep).await.unwrap();
        assert_eq!(arep[1], 0x00, "associate should succeed");
        let bnd = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(arep[4], arep[5], arep[6], arep[7])),
            u16::from_be_bytes([arep[8], arep[9]]),
        );
        (ctrl, bnd)
    }

    #[tokio::test]
    async fn udp_large_and_empty_payloads_roundtrip_through_direct_and_socks5() {
        for socks5 in [false, true] {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dst = udp.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut packet = vec![0; 65536];
                while let Ok((n, peer)) = udp.recv_from(&mut packet).await {
                    udp.send_to(&packet[..n], peer).await.unwrap();
                }
            });
            let mut cfg = Config::default();
            cfg.outbound.mode = crate::config::OutboundMode::Free;
            let mut upstream = None;
            if socks5 {
                let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
                cfg.outbound.mode = crate::config::OutboundMode::Socks5;
                cfg.socks5.server = tcp.local_addr().unwrap();
                upstream = Some(tokio::spawn(async move {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    let mut greeting = [0; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    stream.write_all(&[5, 0]).await.unwrap();
                    let mut request = [0; 10];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(request[1], 3);
                    server::write_reply(&mut stream, 0, dst).await.unwrap();
                    let mut end = [0];
                    assert_eq!(stream.read(&mut end).await.unwrap(), 0);
                }));
            }
            let shared = Arc::new(SharedState::new(&cfg));
            let mut p = params();
            p.udp = true;
            let proxy = spawn_inbound(Arc::clone(&shared), p).await;
            let (ctrl, bnd) = associate(proxy).await;
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0; 65536];
            for size in [0, 2048, 2049, 4096, 4097, 16384, 65497, 1] {
                let payload: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
                let frame = sb_outbound::socks5_udp::encode_udp_request(dst, &payload);
                client.send_to(&frame, bnd).await.unwrap();
                let (n, from) =
                    tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut packet))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(from, bnd);
                let (src, off) = decode_udp_reply(&packet[..n]).unwrap();
                assert_eq!(src, dst);
                assert_eq!(&packet[off..n], payload, "size={size}, socks5={socks5}");
            }
            drop(ctrl);
            tokio::time::timeout(Duration::from_secs(2), async {
                while shared.udp_budget.sessions.used()[0] != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if let Some(upstream) = upstream {
                upstream.await.unwrap();
            }
            echo.abort();
        }
    }

    #[tokio::test]
    async fn explicit_udp_budget_rejects_before_success_and_recovers_after_fin() {
        let mut cfg = Config::default();
        cfg.outbound.mode = crate::config::OutboundMode::Free;
        cfg.inbound.udp_max_sessions = 1;
        let shared = Arc::new(SharedState::new(&cfg));
        let mut p = params();
        p.udp = true;
        let proxy = spawn_inbound(Arc::clone(&shared), p.clone()).await;
        let (ctrl, _) = associate(proxy).await;
        let reject_proxy = spawn_inbound(Arc::clone(&shared), p.clone()).await;
        let mut rejected = TcpStream::connect(reject_proxy).await.unwrap();
        rejected.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        rejected.read_exact(&mut method).await.unwrap();
        rejected
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0; 10];
        tokio::time::timeout(Duration::from_secs(2), rejected.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[1], server::REP_GENERAL_FAILURE);
        assert_eq!(shared.udp_budget.sessions.used(), [1, 0]);
        drop(ctrl);
        tokio::time::timeout(Duration::from_secs(2), async {
            while shared.udp_budget.sessions.used()[0] != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let new_proxy = spawn_inbound(Arc::clone(&shared), p).await;
        let (_new_ctrl, _) = associate(new_proxy).await;
        assert_eq!(shared.udp_budget.sessions.used(), [1, 0]);
    }

    fn udp_dg_domain(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
        let mut dg = vec![0u8, 0, 0, 0x03, host.len() as u8];
        dg.extend_from_slice(host.as_bytes());
        dg.extend_from_slice(&port.to_be_bytes());
        dg.extend_from_slice(payload);
        dg
    }

    #[tokio::test]
    async fn one_bad_datagram_does_not_tear_down_the_association() {
        use crate::config::{DnsResolverCfg, OutboundCfg, OutboundMode};
        let echo = udp_echo_server().await;
        let dns = mock_dns_nx(Ipv4Addr::LOCALHOST, "bad.test").await;

        let mut cfg = Config::default();
        cfg.inbound.splice_copy = false;
        cfg.outbound = OutboundCfg {
            mode: OutboundMode::Free,
            resolver: DnsResolverCfg { server: Some(dns) },
            ..Default::default()
        };
        let shared = Arc::new(SharedState::new(&cfg));
        let mut p = params();
        p.udp = true;
        let proxy = spawn_inbound(Arc::clone(&shared), p).await;
        let (mut ctrl, bnd) = associate(proxy).await;

        let cudp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut rbuf = [0u8; 1024];

        cudp.send_to(&udp_dg_domain("ok.test", echo.port(), b"one"), bnd)
            .await
            .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), cudp.recv_from(&mut rbuf))
            .await
            .expect("first reply")
            .unwrap();
        assert!(n > 4);

        cudp.send_to(&udp_dg_domain("bad.test", 9999, b"nope"), bnd)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        cudp.send_to(&udp_dg_domain("ok.test", echo.port(), b"two"), bnd)
            .await
            .unwrap();
        let (n2, _) = tokio::time::timeout(Duration::from_secs(2), cudp.recv_from(&mut rbuf))
            .await
            .expect("association must survive one unresolvable target")
            .unwrap();
        let (_, off) = sb_outbound::socks5_udp::decode_udp_reply(&rbuf[..n2]).unwrap();
        assert_eq!(&rbuf[off..n2], b"two");

        let mut b = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), ctrl.read(&mut b))
                .await
                .is_err(),
            "ctrl must stay open"
        );
    }

    async fn mock_upstream_associate_then_fin() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut m = [0u8; 255];
                    if s.read_exact(&mut m[..head[1] as usize]).await.is_err() {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0x00]).await;
                    let mut req = [0u8; 10];
                    if s.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let p = up.local_addr().unwrap().port().to_be_bytes();
                    let _ = s
                        .write_all(&[0x05, 0, 0, 1, 127, 0, 0, 1, p[0], p[1]])
                        .await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    drop(s);

                    tokio::time::sleep(Duration::from_secs(5)).await;
                    drop(up);
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn upstream_ctrl_fin_tears_down_the_inbound_association() {
        let upstream = mock_upstream_associate_then_fin().await;
        let shared = shared_with_upstream(upstream);
        let mut p = params();
        p.udp = true;
        let proxy = spawn_inbound(Arc::clone(&shared), p).await;
        let (mut ctrl, _bnd) = associate(proxy).await;

        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(3), ctrl.read(&mut b))
            .await
            .expect("inbound ctrl must be closed once the upstream one goes")
            .unwrap();
        assert_eq!(n, 0, "inbound association should be torn down");
    }

    async fn udp_push_server(bursts: usize, gap: Duration) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((_, from)) = sock.recv_from(&mut buf).await {
                for i in 0..bursts {
                    tokio::time::sleep(gap).await;
                    if sock.send_to(&[b'p', i as u8], from).await.is_err() {
                        break;
                    }
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn downlink_traffic_keeps_the_association_alive() {
        use crate::config::{DnsResolverCfg, OutboundCfg, OutboundMode};
        let pushes = 8;
        let push = udp_push_server(pushes, Duration::from_millis(100)).await;
        let dns = mock_dns_a(Ipv4Addr::LOCALHOST).await;

        let mut cfg = Config::default();
        cfg.inbound.splice_copy = false;
        cfg.outbound = OutboundCfg {
            mode: OutboundMode::Free,
            resolver: DnsResolverCfg { server: Some(dns) },
            ..Default::default()
        };
        let shared = Arc::new(SharedState::new(&cfg));
        let mut p = params();
        p.udp = true;

        p.udp_idle = Duration::from_millis(250);
        let proxy = spawn_inbound(Arc::clone(&shared), p).await;
        let (_ctrl, bnd) = associate(proxy).await;

        let cudp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cudp.send_to(&udp_dg_domain("push.test", push.port(), b"go"), bnd)
            .await
            .unwrap();

        let mut got = 0;
        let mut rbuf = [0u8; 1024];
        for _ in 0..pushes {
            match tokio::time::timeout(Duration::from_millis(600), cudp.recv_from(&mut rbuf)).await
            {
                Ok(Ok(_)) => got += 1,
                _ => break,
            }
        }
        assert_eq!(
            got, pushes,
            "an association that only receives must not be reaped by the idle timer"
        );
    }
}
