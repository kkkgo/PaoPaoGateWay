// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::http::{self, ReqHead};
use crate::respond;
use std::io;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UnixStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyOutcome {
    KeepAlive,
    Close,
}

fn is_hop_by_hop(lname: &str) -> bool {
    matches!(
        lname,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "trailers"
            | "upgrade"
    )
}

pub async fn proxy(
    client: &mut TcpStream,
    req: &ReqHead,
    body_prefix: &[u8],
    clash_sock: &Path,
) -> io::Result<ProxyOutcome> {
    let mut up = match UnixStream::connect(clash_sock).await {
        Ok(u) => u,
        Err(_e) => {
            tracing::warn!("Waiting Clash Ready...");
            let ka = req.keep_alive();
            respond::send(
                client,
                502,
                "Bad Gateway",
                &[("Content-Type", "text/plain")],
                b"upstream unavailable\n",
                ka,
            )
            .await?;
            return Ok(if ka {
                ProxyOutcome::KeepAlive
            } else {
                ProxyOutcome::Close
            });
        }
    };

    let upgrade = req.is_upgrade();

    let head = build_upstream_head(req, upgrade);
    up.write_all(&head).await?;
    let req_framing = req.framing()?;
    http::relay_body(client, &mut up, req_framing, body_prefix).await?;
    up.flush().await?;

    let mut up_buf = Vec::new();
    let rhl = http::read_head(&mut up, &mut up_buf).await?;
    let resp = http::parse_response(&up_buf[..rhl])?;
    let resp_prefix: Vec<u8> = up_buf[rhl..].to_vec();

    if upgrade && resp.status == 101 {
        client.write_all(&up_buf[..rhl]).await?;
        if !resp_prefix.is_empty() {
            client.write_all(&resp_prefix).await?;
        }
        client.flush().await?;

        let _ = tokio::io::copy_bidirectional(client, &mut up).await;
        return Ok(ProxyOutcome::Close);
    }

    let head_request = req.method.eq_ignore_ascii_case("HEAD");
    let resp_framing = resp.framing(head_request)?;
    let client_ka = req.keep_alive() && resp_framing != http::Framing::Eof;
    let out_head = build_downstream_head(&resp, client_ka);
    client.write_all(&out_head).await?;
    http::relay_body(&mut up, client, resp_framing, &resp_prefix).await?;
    client.flush().await?;

    Ok(if client_ka {
        ProxyOutcome::KeepAlive
    } else {
        ProxyOutcome::Close
    })
}

fn build_upstream_head(req: &ReqHead, upgrade: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(req.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    let mut has_host = false;
    for (name, value) in &req.headers {
        let lname = name.to_ascii_lowercase();
        if lname == "host" {
            has_host = true;
        }
        if is_hop_by_hop(&lname) {
            continue;
        }
        push_header(&mut out, name, value);
    }
    if !has_host {
        out.extend_from_slice(b"Host: localhost\r\n");
    }
    if upgrade {
        if let Some(u) = req.header("upgrade") {
            out.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: ");
            out.extend_from_slice(u);
            out.extend_from_slice(b"\r\n");
        }
    } else {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn build_downstream_head(resp: &http::RespHead, keep_alive: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(resp.status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(resp.reason.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in &resp.headers {
        if is_hop_by_hop(&name.to_ascii_lowercase()) {
            continue;
        }
        push_header(&mut out, name, value);
    }
    out.extend_from_slice(if keep_alive {
        b"Connection: keep-alive\r\n"
    } else {
        b"Connection: close\r\n"
    });
    out.extend_from_slice(b"\r\n");
    out
}

fn push_header(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::parse_request;

    #[test]
    fn upstream_head_injects_host_and_close() {
        let req =
            parse_request(b"GET /configs HTTP/1.1\r\nAuthorization: Bearer t\r\n\r\n").unwrap();
        let head = build_upstream_head(&req, false);
        let s = String::from_utf8(head).unwrap();
        assert!(s.starts_with("GET /configs HTTP/1.1\r\n"));
        assert!(s.contains("Host: localhost\r\n"));
        assert!(s.contains("Authorization: Bearer t\r\n"));
        assert!(s.contains("Connection: close\r\n"));
    }

    #[test]
    fn upstream_head_preserves_client_host() {
        let req = parse_request(b"GET /x HTTP/1.1\r\nHost: dash.local\r\n\r\n").unwrap();
        let s = String::from_utf8(build_upstream_head(&req, false)).unwrap();
        assert!(s.contains("Host: dash.local\r\n"));
        assert_eq!(s.matches("Host:").count(), 1);
    }

    #[test]
    fn upstream_head_ws_upgrade() {
        let req = parse_request(
            b"GET /connections HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc\r\n\r\n",
        )
        .unwrap();
        let s = String::from_utf8(build_upstream_head(&req, true)).unwrap();
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.contains("Sec-WebSocket-Key: abc\r\n"));
        assert!(!s.contains("Connection: close"));
    }

    #[test]
    fn downstream_head_strips_hop_by_hop() {
        let resp = http::parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\nKeep-Alive: timeout=5\r\n\r\n",
        )
        .unwrap();
        let s = String::from_utf8(build_downstream_head(&resp, true)).unwrap();
        assert!(s.contains("Content-Length: 3\r\n"));
        assert!(!s.contains("Keep-Alive:"));
        assert_eq!(s.matches("Connection:").count(), 1);
        assert!(s.contains("Connection: keep-alive\r\n"));
    }
}
