// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::events::{LogEvent, LogSource, LogTx};
use crate::http;
use crate::idle_gate::IdleGate;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

const IDLE_WINDOW: Duration = Duration::from_secs(30);

const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

pub fn spawn(clash_sock: PathBuf, log_tx: LogTx, shutdown: watch::Receiver<bool>) {
    tokio::spawn(run(clash_sock, log_tx, shutdown));
}

async fn run(clash_sock: PathBuf, log_tx: LogTx, mut shutdown: watch::Receiver<bool>) {
    let mut idle = IdleGate::new(IDLE_WINDOW);
    loop {
        if *shutdown.borrow() {
            return;
        }
        if idle.tick(log_tx.receiver_count()) {

            tokio::select! {
                _ = shutdown.changed() => { if *shutdown.borrow() { return; } }
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
            }
            continue;
        }
        if let Err(e) = consume_once(&clash_sock, &log_tx, &mut shutdown).await {
            tracing::debug!(?e, "clash logs stream ended; retry in 3s");
        }
        tokio::select! {
            _ = shutdown.changed() => { if *shutdown.borrow() { return; } }
            _ = tokio::time::sleep(Duration::from_secs(3)) => {}
        }
    }
}

async fn consume_once(
    sock: &Path,
    log_tx: &LogTx,
    shutdown: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let mut up = UnixStream::connect(sock).await?;
    up.write_all(
        b"GET /logs?level=debug HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n",
    )
    .await?;
    up.flush().await?;

    let mut buf = Vec::new();
    let hl = http::read_head(&mut up, &mut buf).await?;
    let resp = http::parse_response(&buf[..hl])?;
    let chunked = matches!(resp.framing(false)?, http::Framing::Chunked);
    let overflow = buf.split_off(hl);

    let mut decoder = ChunkDecoder::new();
    let mut line = Vec::new();
    let mut decoded = Vec::new();
    let mut readbuf = [0u8; 8192];
    let mut pending = overflow;

    let mut idle_check = tokio::time::interval(IDLE_CHECK_INTERVAL);
    idle_check.tick().await;
    let mut idle = IdleGate::new(IDLE_WINDOW);

    loop {
        if !pending.is_empty() {
            decoded.clear();
            if chunked {
                decoder.feed(&pending, &mut decoded)?;
            } else {
                decoded.extend_from_slice(&pending);
            }
            pending.clear();
            for &b in &decoded {
                if b == b'\n' {
                    emit_line(&line, log_tx);
                    line.clear();
                } else if line.len() < 64 * 1024 {
                    line.push(b);
                }
            }
            if decoder.done {
                return Ok(());
            }
            continue;
        }
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            r = up.read(&mut readbuf) => {
                let n = r?;
                if n == 0 {
                    return Ok(());
                }
                pending.extend_from_slice(&readbuf[..n]);
            }
            _ = idle_check.tick() => {
                if idle.tick(log_tx.receiver_count()) {
                    tracing::debug!("clash logs consumer idle 30s+; disconnecting until a subscriber returns");
                    return Ok(());
                }
            }
        }
    }
}

fn emit_line(line: &[u8], log_tx: &LogTx) {
    let line = match std::str::from_utf8(line) {
        Ok(s) => s.trim(),
        Err(_) => return,
    };
    if line.is_empty() {
        return;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return;
    };
    let level = v
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("info")
        .to_string();
    let msg = v
        .get("payload")
        .and_then(|p| p.as_str())
        .unwrap_or(line)
        .to_string();

    let _ = log_tx.send(Arc::new(LogEvent::new(LogSource::Clash, level, msg)));
}

struct ChunkDecoder {
    buf: Vec<u8>,
    remaining: usize,
    in_data: bool,
    pub done: bool,
}

impl ChunkDecoder {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            remaining: 0,
            in_data: false,
            done: false,
        }
    }

    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.buf.extend_from_slice(input);
        loop {
            if self.done {
                return Ok(());
            }
            if self.in_data {
                if self.remaining > 0 {
                    let take = self.remaining.min(self.buf.len());
                    out.extend_from_slice(&self.buf[..take]);
                    self.buf.drain(..take);
                    self.remaining -= take;
                    if self.remaining > 0 {
                        return Ok(());
                    }
                }
                if self.buf.len() < 2 {
                    return Ok(());
                }
                self.buf.drain(..2);
                self.in_data = false;
            } else {
                let Some(pos) = find_crlf(&self.buf) else {
                    return Ok(());
                };
                let size_line: Vec<u8> = self.buf[..pos].to_vec();
                self.buf.drain(..pos + 2);
                let hex = size_line.split(|&b| b == b';').next().unwrap_or(&[]);
                let size = usize::from_str_radix(std::str::from_utf8(hex).unwrap_or("").trim(), 16)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
                if size == 0 {
                    self.done = true;
                    return Ok(());
                }
                self.remaining = size;
                self.in_data = true;
            }
        }
    }
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_whole() {
        let mut d = ChunkDecoder::new();
        let mut out = Vec::new();
        d.feed(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", &mut out)
            .unwrap();
        assert_eq!(out, b"Wikipedia");
        assert!(d.done);
    }

    #[test]
    fn dechunk_split_across_feeds() {
        let mut d = ChunkDecoder::new();
        let mut out = Vec::new();

        d.feed(b"4\r\nWi", &mut out).unwrap();
        d.feed(b"ki\r\n5\r\npe", &mut out).unwrap();
        d.feed(b"dia\r\n0\r\n\r\n", &mut out).unwrap();
        assert_eq!(out, b"Wikipedia");
        assert!(d.done);
    }

    #[test]
    fn emit_parses_clash_json() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        emit_line(br#"{"type":"warning","payload":"rule not found"}"#, &tx);
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.source, LogSource::Clash);
        assert_eq!(ev.level, "warning");
        assert_eq!(ev.msg, "rule not found");
    }

    #[test]
    fn emit_ignores_non_json() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        emit_line(b"not json at all", &tx);
        emit_line(b"", &tx);
        assert!(rx.try_recv().is_err());
    }
}
