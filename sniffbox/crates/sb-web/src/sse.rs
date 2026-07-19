// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub async fn write_headers<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    w.write_all(
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: text/event-stream\r\n\
          Cache-Control: no-cache\r\n\
          Connection: close\r\n\
          \r\n",
    )
    .await?;
    w.flush().await
}

pub async fn event<W: AsyncWrite + Unpin>(w: &mut W, data: &str) -> io::Result<()> {
    let mut buf = Vec::with_capacity(data.len() + 16);
    for line in data.split('\n') {
        buf.extend_from_slice(b"data: ");
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
    }
    buf.push(b'\n');
    w.write_all(&buf).await?;
    w.flush().await
}

pub async fn comment<W: AsyncWrite + Unpin>(w: &mut W, text: &str) -> io::Result<()> {
    let mut buf = Vec::with_capacity(text.len() + 4);
    buf.extend_from_slice(b": ");
    buf.extend_from_slice(text.as_bytes());
    buf.extend_from_slice(b"\n\n");
    w.write_all(&buf).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn event_single_line() {
        let mut out = Vec::new();
        event(&mut out, r#"{"a":1}"#).await.unwrap();
        assert_eq!(out, b"data: {\"a\":1}\n\n");
    }

    #[tokio::test]
    async fn event_multiline_splits() {
        let mut out = Vec::new();
        event(&mut out, "line1\nline2").await.unwrap();
        assert_eq!(out, b"data: line1\ndata: line2\n\n");
    }

    #[tokio::test]
    async fn headers_and_comment() {
        let mut out = Vec::new();
        write_headers(&mut out).await.unwrap();
        comment(&mut out, "ping").await.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Content-Type: text/event-stream\r\n"));
        assert!(s.ends_with(": ping\n\n"));
    }
}
