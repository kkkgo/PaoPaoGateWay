// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub async fn send<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: u16,
    reason: &str,
    extra: &[(&str, &str)],
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    for (k, v) in extra {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

pub async fn redirect<W: AsyncWrite + Unpin>(
    w: &mut W,
    location: &str,
    keep_alive: bool,
) -> io::Result<()> {
    send(w, 302, "Found", &[("Location", location)], b"", keep_alive).await
}

pub async fn unauthorized<W: AsyncWrite + Unpin>(w: &mut W, keep_alive: bool) -> io::Result<()> {
    send(
        w,
        401,
        "Unauthorized",
        &[("WWW-Authenticate", "Bearer")],
        b"unauthorized\n",
        keep_alive,
    )
    .await
}

pub async fn forbidden<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &str,
    keep_alive: bool,
) -> io::Result<()> {
    send(
        w,
        403,
        "Forbidden",
        &[("Content-Type", "text/plain")],
        msg.as_bytes(),
        keep_alive,
    )
    .await
}

pub async fn not_found<W: AsyncWrite + Unpin>(w: &mut W, keep_alive: bool) -> io::Result<()> {
    send(
        w,
        404,
        "Not Found",
        &[("Content-Type", "text/plain")],
        b"not found\n",
        keep_alive,
    )
    .await
}

pub async fn file<W: AsyncWrite + Unpin>(
    w: &mut W,
    content_type: &str,
    cache_control: &str,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    send(
        w,
        200,
        "OK",
        &[
            ("Content-Type", content_type),
            ("Cache-Control", cache_control),
        ],
        body,
        keep_alive,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redirect_frame() {
        let mut out = Vec::new();
        redirect(&mut out, "/ui", true).await.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 302 Found\r\n"));
        assert!(s.contains("Location: /ui\r\n"));
        assert!(s.contains("Connection: keep-alive\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn unauthorized_frame() {
        let mut out = Vec::new();
        unauthorized(&mut out, false).await.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(s.contains("Connection: close\r\n"));
    }
}
