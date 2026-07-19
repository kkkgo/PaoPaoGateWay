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
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

#[derive(Clone)]
pub struct InboundProxyParams {
    pub listen_port: u16,
    pub udp: bool,
    pub udp_idle: Duration,
}

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
            let shared = Arc::clone(&shared);
            let params = params.clone();
            let mut sd = shutdown_rx.clone();
            tokio::spawn(async move {
                accept_loop(listener, shared, params, OPENPORT, &mut sd).await;
            });
        }
    });
}

pub fn start_healthcheck_listener(shared: Arc<SharedState>, shutdown_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HEALTHCHECK_PORT);
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%addr, ?e, "healthcheck listener bind failed; skip");
                return;
            }
        };
        tracing::info!(%addr, "healthcheck socks5 inbound listening");

        let params = InboundProxyParams {
            listen_port: HEALTHCHECK_PORT,
            udp: false,
            udp_idle: Duration::from_secs(60),
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

async fn handle_inbound(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    profile: InboundProfile,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];

    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
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
) -> io::Result<()> {

    let auth = if profile.apply_auth {
        shared.openport_auth()
    } else {
        None
    };
    if let Err(e) = server::negotiate_method(&mut stream, auth.as_deref()).await {
        tracing::debug!(%peer, ?e, "socks5 method negotiation failed");
        return Ok(());
    }
    let (cmd, dest) = match server::read_request(&mut stream).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(%peer, ?e, "socks5 request parse failed");
            return Ok(());
        }
    };
    match cmd {
        SocksCmd::Connect => {
            let bnd = stream
                .local_addr()
                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            if server::write_success(&mut stream, bnd).await.is_err() {
                return Ok(());
            }
            let est = dest_to_established(dest, profile.socks5, profile.sniff);
            serve_established(shared, stream, peer, est).await
        }
        SocksCmd::UdpAssociate => {
            if !params.udp {
                let _ = server::write_reply(&mut stream, REP_CMD_NOT_SUPPORTED, unspec()).await;
                return Ok(());
            }
            udp_associate_inbound(stream, peer, shared, params, profile.socks5).await
        }
        SocksCmd::Other(c) => {
            tracing::debug!(%peer, cmd = c, "socks5 unsupported command");
            let _ = server::write_reply(&mut stream, REP_CMD_NOT_SUPPORTED, unspec()).await;
            Ok(())
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
            sniff,
        },
        DestAddr::Domain(host, port) => Established {

            dest: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            inbound,
            domain: Some(host),
            prelude: Vec::new(),
            sniff,
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
) -> io::Result<()> {
    let head = match read_http_head(&mut stream).await {
        Ok(Some(h)) => h,
        Ok(None) => return Ok(()),
        Err(e) => {
            tracing::debug!(%peer, ?e, "http head read failed");
            return Ok(());
        }
    };
    let parsed = match parse_http_proxy_request(&head) {
        Some(p) => p,
        None => {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Ok(());
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
            return Ok(());
        }
    }

    match parsed.kind {
        HttpReqKind::Connect { host, port } => {
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return Ok(());
            }
            let est = host_port_to_established(host, port, Vec::new(), profile.sniff, profile.http);
            serve_established(shared, stream, peer, est).await
        }
        HttpReqKind::Forward {
            host,
            port,
            request,
        } => {
            let est = host_port_to_established(host, port, request, false, profile.http);
            serve_established(shared, stream, peer, est).await
        }
    }
}

fn host_port_to_established(
    host: String,
    port: u16,
    prelude: Vec<u8>,
    sniff: bool,
    inbound: InboundKind,
) -> Established {

    match host.parse::<IpAddr>() {
        Ok(ip) => Established {
            dest: SocketAddr::new(ip, port),
            inbound,
            domain: None,
            prelude,
            sniff,
        },
        Err(_) => Established {
            dest: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            inbound,
            domain: Some(host),
            prelude,
            sniff,
        },
    }
}

async fn read_http_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_head_end(&buf).is_some() {
            return Ok(Some(buf));
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
    let request = rebuild_origin_request(
        method,
        abs_path,
        req.version.unwrap_or(1),
        &headers,
        &host,
        port,
    );
    Some(ParsedHttpProxy {
        kind: HttpReqKind::Forward {
            host,
            port,
            request,
        },
        proxy_authorization,
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
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("{method} {abs_path} HTTP/{ver}\r\n").as_bytes());
    let mut have_host = false;
    for h in headers {
        if h.name.is_empty() {
            continue;
        }

        if h.name.eq_ignore_ascii_case("proxy-connection")
            || h.name.eq_ignore_ascii_case("proxy-authorization")
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
    out.extend_from_slice(b"\r\n");
    out
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

async fn udp_associate_inbound(
    mut ctrl: TcpStream,
    peer: SocketAddr,
    shared: Arc<SharedState>,
    params: InboundProxyParams,
    inbound: InboundKind,
) -> io::Result<()> {
    let local_ip = ctrl.local_addr()?.ip();

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

    let rec = Arc::new(
        ConnRecord::new(
            shared.id_gen.next_id(),
            (peer.ip(), peer.port()),
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            sb_stats::SniffedProto::Socks5,
            None,
        )
        .with_inbound(inbound, Transport::Udp),
    );
    shared.conn_table.insert(Arc::clone(&rec));
    if let Some(p) = &shared.pplog {
        p.open(&rec);
    }

    let client_addr_seen: Arc<parking_lot::Mutex<Option<SocketAddr>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let reply_task = upstream.spawn_reply(
        Arc::clone(&relay),
        Arc::clone(&client_addr_seen),
        Arc::clone(&rec),
    );

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
                if upstream.forward(&shared, &rbuf[..n], &mut up_buf, &rec).await.is_err() {
                    break;
                }
            }
            res = ctrl.read(&mut ctrl_buf) => {
                match res {
                    Ok(0) => { tracing::debug!(%peer, "inbound udp ctrl FIN; teardown"); break; }
                    Err(_) => break,
                    Ok(_) => {}
                }
            }
            _ = tokio::time::sleep(idle) => {
                tracing::debug!(%peer, "inbound udp idle timeout; teardown");
                break;
            }
        }
    }

    reply_task.abort();
    upstream.shutdown().await;
    let (du, dd) = rec.drain_delta();
    if du != 0 || dd != 0 {
        shared.traffic.add_totals(dd, du);
    }
    shared.conn_table.close(rec.id);
    if let Some(p) = &shared.pplog {
        p.close(&rec);
    }
    Ok(())
}

enum InboundUpstream {
    Socks5 {
        ctrl: TcpStream,
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
                    ctrl,
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
        rec: &Arc<ConnRecord>,
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
        rec: Arc<ConnRecord>,
    ) -> tokio::task::JoinHandle<()> {
        match self {
            Self::Socks5 {
                relay: up_relay, ..
            } => tokio::spawn(reply_loop_socks5(
                Arc::clone(up_relay),
                relay,
                client_seen,
                rec,
            )),
            Self::Direct { sock, .. } => {
                tokio::spawn(reply_loop_direct(Arc::clone(sock), relay, client_seen, rec))
            }
        }
    }

    async fn shutdown(&mut self) {
        if let Self::Socks5 { ctrl, .. } = self {
            let _ = ctrl.shutdown().await;
        }
    }
}

async fn reply_loop_socks5(
    up_relay: Arc<UdpSocket>,
    relay: Arc<UdpSocket>,
    client_seen: Arc<parking_lot::Mutex<Option<SocketAddr>>>,
    rec: Arc<ConnRecord>,
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
        rec.add_down((n - off) as u64);
    }
}

async fn reply_loop_direct(
    sock: Arc<UdpSocket>,
    relay: Arc<UdpSocket>,
    client_seen: Arc<parking_lot::Mutex<Option<SocketAddr>>>,
    rec: Arc<ConnRecord>,
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
        rec.add_down(n as u64);
    }
}

async fn forward_client_packet(
    shared: &Arc<SharedState>,
    up_relay: &UdpSocket,
    frame: &[u8],
    up_buf: &mut Vec<u8>,
    rec: &Arc<ConnRecord>,
) -> io::Result<()> {
    let (dst, host, off) = match decode_client_udp_header(frame) {
        Some(v) => v,
        None => return Ok(()),
    };
    let payload = &frame[off..];

    let domain = host.or_else(|| match (&shared.fakeip, dst.ip()) {
        (Some(f), IpAddr::V4(v4)) if f.contains(dst.ip()) => f.lookback(v4).map(|d| d.to_string()),
        _ => None,
    });
    match domain {
        Some(h) => encode_udp_request_domain_into(up_buf, &h, dst.port(), payload)
            .map_err(io::Error::other)?,
        None => {

            if shared.fakeip.as_ref().is_some_and(|f| f.contains(dst.ip())) {
                return Ok(());
            }
            encode_udp_request_into(up_buf, dst, payload);
        }
    }
    rec.add_up(payload.len() as u64);
    up_relay.send(up_buf).await?;
    Ok(())
}

async fn forward_client_packet_direct(
    shared: &Arc<SharedState>,
    sock: &UdpSocket,
    resolver: &Resolver,
    frame: &[u8],
    rec: &Arc<ConnRecord>,
) -> io::Result<()> {
    let (dst, host, off) = match decode_client_udp_header(frame) {
        Some(v) => v,
        None => return Ok(()),
    };
    let payload = &frame[off..];

    let domain = host.or_else(|| match (&shared.fakeip, dst.ip()) {
        (Some(f), IpAddr::V4(v4)) if f.contains(dst.ip()) => f.lookback(v4).map(|d| d.to_string()),
        _ => None,
    });
    let real_dst = match domain {
        Some(h) => {
            let ip = resolver.resolve_v4(&h).await?;
            SocketAddr::new(IpAddr::V4(ip), dst.port())
        }
        None => {

            if shared.fakeip.as_ref().is_some_and(|f| f.contains(dst.ip())) {
                return Ok(());
            }
            dst
        }
    };
    rec.add_up(payload.len() as u64);
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
        let out = tokio::task::spawn_blocking(move || sb_ppgw::probe::run_json(&req, &proxy))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["ok"], true, "probe should get response through proxy chain: {out}");
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
        let proxy = spawn_inbound(shared, p).await;

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
            } => {
                assert_eq!(host, "example.com");
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
            } => {
                assert_eq!((host.as_str(), port), ("example.com", 8080));
                let s = String::from_utf8(request).unwrap();

                assert!(s.contains("Host: example.com:8080\r\n"), "got: {s:?}");
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
}
