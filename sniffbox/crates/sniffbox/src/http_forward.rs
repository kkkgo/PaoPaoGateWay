// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

const HEAD_LIMIT: usize = 16 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum Body {
    Fixed(u64),
    Chunked,
}

#[derive(Debug)]
pub struct Request {
    pub body: Body,
    pub upgrade: Option<String>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn write_counted<W: AsyncWrite + Unpin>(
    w: &mut W,
    mut bytes: &[u8],
    count: &AtomicU64,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = w.write(bytes).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        count.fetch_add(n as u64, Ordering::Relaxed);
        bytes = &bytes[n..];
    }
    Ok(())
}

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    count: &AtomicU64,
) -> io::Result<()> {
    let mut buf = [0; 8192];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        write_counted(w, &buf[..n], count).await?;
    }
}

async fn exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    len: u64,
    count: &AtomicU64,
) -> io::Result<()> {
    let mut limited = r.take(len);
    copy(&mut limited, w, count).await?;
    if limited.limit() != 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

async fn line<R: AsyncBufRead + Unpin>(r: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let bytes = r.fill_buf().await?;
        if bytes.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let n = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |i| i + 1);
        if out.len() + n > limit {
            return Err(invalid("HTTP framing too large"));
        }
        out.extend_from_slice(&bytes[..n]);
        r.consume(n);
        if out.ends_with(b"\n") {
            return if out.ends_with(b"\r\n") {
                Ok(out)
            } else {
                Err(invalid("HTTP framing requires CRLF"))
            };
        }
    }
}

async fn chunked<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    count: &AtomicU64,
) -> io::Result<()> {
    loop {
        let size = line(r, HEAD_LIMIT).await?;
        let httparse::Status::Complete((used, n)) =
            httparse::parse_chunk_size(&size).map_err(|_| invalid("invalid chunk size"))?
        else {
            return Err(invalid("incomplete chunk size"));
        };
        if used != size.len() {
            return Err(invalid("invalid chunk extension"));
        }
        write_counted(w, &size, count).await?;
        if n == 0 {
            let mut trailers = Vec::new();
            loop {
                let next = line(r, HEAD_LIMIT - trailers.len()).await?;
                let end = next == b"\r\n";
                trailers.extend_from_slice(&next);
                if end {
                    break;
                }
            }
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let httparse::Status::Complete((_, headers)) =
                httparse::parse_headers(&trailers, &mut headers)
                    .map_err(|_| invalid("invalid HTTP trailers"))?
            else {
                return Err(invalid("incomplete HTTP trailers"));
            };

            for h in headers {
                if crate::inbound_proxy::hop_header(h.name)
                    || [
                        "host",
                        "content-length",
                        "transfer-encoding",
                        "authorization",
                    ]
                    .iter()
                    .any(|n| h.name.eq_ignore_ascii_case(n))
                {
                    continue;
                }
                write_counted(w, h.name.as_bytes(), count).await?;
                write_counted(w, b": ", count).await?;
                write_counted(w, h.value, count).await?;
                write_counted(w, b"\r\n", count).await?;
            }
            return write_counted(w, b"\r\n", count).await;
        }
        exact(r, w, n, count).await?;
        let mut end = [0; 2];
        r.read_exact(&mut end).await?;
        if end != *b"\r\n" {
            return Err(invalid("invalid chunk terminator"));
        }
        write_counted(w, &end, count).await?;
    }
}

pub async fn relay<A, B>(
    client: A,
    upstream: B,
    prefix: Vec<u8>,
    request: Request,
    up: &AtomicU64,
    down: &AtomicU64,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (cr, mut cw) = tokio::io::split(client);
    let (sr, mut sw) = tokio::io::split(upstream);
    let mut cr = BufReader::new(std::io::Cursor::new(prefix).chain(cr));
    let mut sr = BufReader::new(sr);
    let (upgrade_tx, upgrade_rx) = tokio::sync::oneshot::channel();
    let upgraded = AtomicBool::new(false);
    let upload = async {
        match request.body {
            Body::Fixed(len) => exact(&mut cr, &mut sw, len, up).await?,
            Body::Chunked => chunked(&mut cr, &mut sw, up).await?,
        }
        if request.upgrade.is_some() && upgrade_rx.await.unwrap_or(false) {
            copy(&mut cr, &mut sw, up).await?;
        }
        sw.shutdown().await
    };
    let download = async {
        if let Some(protocol) = &request.upgrade {

            loop {
                let mut head = Vec::new();
                loop {
                    let next = line(&mut sr, HEAD_LIMIT - head.len()).await?;
                    let end = next == b"\r\n";
                    head.extend_from_slice(&next);
                    if end {
                        break;
                    }
                }
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut response = httparse::Response::new(&mut headers);
                response
                    .parse(&head)
                    .map_err(|_| invalid("invalid upgrade response"))?;
                let code = response
                    .code
                    .ok_or_else(|| invalid("missing HTTP status"))?;
                if code == 101 {
                    let accepted = response.headers.iter().any(|h| {
                        h.name.eq_ignore_ascii_case("upgrade")
                            && h.value.eq_ignore_ascii_case(protocol.as_bytes())
                    });
                    let connection = response.headers.iter().any(|h| {
                        h.name.eq_ignore_ascii_case("connection")
                            && h.value
                                .split(|b| *b == b',')
                                .any(|v| v.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
                    });
                    if !accepted || !connection {
                        return Err(invalid("unaccepted HTTP upgrade"));
                    }
                }
                write_counted(&mut cw, &head, down).await?;
                if code == 101 || code >= 200 {
                    upgraded.store(code == 101, Ordering::Relaxed);
                    let _ = upgrade_tx.send(code == 101);
                    break;
                }
            }
        } else {
            drop(upgrade_tx);
        }
        copy(&mut sr, &mut cw, down).await?;
        cw.shutdown().await
    };
    tokio::pin!(upload, download);
    tokio::select! {

        result = &mut download => {
            result?;
            if upgraded.load(Ordering::Relaxed) { upload.await } else { Ok(()) }
        },
        result = &mut upload => { result?; download.await }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::duplex;

    #[tokio::test]
    async fn chunked_stream_stops_at_trailers_and_counts_forwarded_bytes() {
        let (client, mut user) = duplex(128);
        let (upstream, mut origin) = duplex(128);
        let up = AtomicU64::new(0);
        let down = AtomicU64::new(0);
        let task = relay(
            client,
            upstream,
            b"3;foo=bar\r".to_vec(),
            Request {
                body: Body::Chunked,
                upgrade: None,
            },
            &up,
            &down,
        );
        let traffic = async {
            user.write_all(b"\nabc\r\n0\r\nProxy-Authorization: secret\r\nX-Checksum: ok\r\n\r\nGET /leak HTTP/1.1\r\n\r\n").await.unwrap();
            let mut got = Vec::new();
            origin.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"3;foo=bar\r\nabc\r\n0\r\nX-Checksum: ok\r\n\r\n");
            origin.write_all(b"OK").await.unwrap();
            origin.shutdown().await.unwrap();
            let mut response = Vec::new();
            user.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"OK");
            got.len()
        };
        let (result, len) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(task, traffic)
        })
        .await
        .unwrap();
        result.unwrap();
        assert_eq!(up.load(Ordering::Relaxed), len as u64);
        assert_eq!(down.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn continue_response_allows_streaming_body() {
        let (client, mut user) = duplex(64);
        let (upstream, mut origin) = duplex(64);
        let up = AtomicU64::new(0);
        let down = AtomicU64::new(0);
        let request = Request {
            body: Body::Fixed(5),
            upgrade: None,
        };
        let traffic = async {
            origin
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            let mut interim = [0; 25];
            user.read_exact(&mut interim).await.unwrap();
            assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
            user.write_all(b"HELLOGET /leak").await.unwrap();
            let mut got = Vec::new();
            origin.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"HELLO");
            origin
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            origin.shutdown().await.unwrap();
        };
        let (result, _) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                relay(client, upstream, vec![], request, &up, &down),
                traffic
            )
        })
        .await
        .unwrap();
        result.unwrap();
        assert_eq!(up.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn early_response_cancels_unfinished_upload() {
        let (client, mut user) = duplex(128);
        let (upstream, mut origin) = duplex(128);
        let task = tokio::spawn(async move {
            relay(
                client,
                upstream,
                vec![],
                Request {
                    body: Body::Fixed(1000),
                    upgrade: None,
                },
                &AtomicU64::new(0),
                &AtomicU64::new(0),
            )
            .await
        });
        origin
            .write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        origin.shutdown().await.unwrap();
        let mut response = Vec::new();
        user.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 413"));
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn optimistic_upgrade_bytes_require_a_valid_101() {
        for accept in [false, true] {
            let (client, mut user) = duplex(128);
            let (upstream, mut origin) = duplex(128);
            let task = tokio::spawn(async move {
                relay(
                    client,
                    upstream,
                    b"PING".to_vec(),
                    Request {
                        body: Body::Fixed(0),
                        upgrade: Some("websocket".into()),
                    },
                    &AtomicU64::new(0),
                    &AtomicU64::new(0),
                )
                .await
            });
            let mut buf = [0; 4];
            assert!(
                tokio::time::timeout(Duration::from_millis(30), origin.read(&mut buf))
                    .await
                    .is_err(),
                "must wait for origin acceptance"
            );
            if accept {
                origin.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nPONG").await.unwrap();
                origin.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"PING");
                user.shutdown().await.unwrap();
            } else {
                origin
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                assert_eq!(origin.read(&mut buf).await.unwrap(), 0);
            }
            origin.shutdown().await.unwrap();
            let mut response = Vec::new();
            user.read_to_end(&mut response).await.unwrap();
            if accept {
                assert!(response.ends_with(b"PONG"));
            }
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn malformed_or_truncated_chunks_never_become_a_tunnel() {
        for body in [
            b"z\r\nGET /leak".as_slice(),
            b"4\r\nabc",
            b"1\r\naXX",
            b"0\r\ninvalid trailer\r\n\r\n",
        ] {
            let (client, user) = duplex(128);
            let (upstream, _origin) = duplex(128);
            drop(user);
            let result = relay(
                client,
                upstream,
                body.to_vec(),
                Request {
                    body: Body::Chunked,
                    upgrade: None,
                },
                &AtomicU64::new(0),
                &AtomicU64::new(0),
            )
            .await;
            assert!(result.is_err(), "accepted malformed body: {body:?}");
        }
    }

    #[tokio::test]
    async fn accepted_upgrade_preserves_half_close_in_both_directions() {
        let (client, mut user) = duplex(256);
        let (upstream, mut origin) = duplex(256);
        let task = tokio::spawn(async move {
            relay(
                client,
                upstream,
                b"PING".to_vec(),
                Request {
                    body: Body::Fixed(0),
                    upgrade: Some("websocket".into()),
                },
                &AtomicU64::new(0),
                &AtomicU64::new(0),
            )
            .await
        });
        origin.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nPONG").await.unwrap();
        origin.shutdown().await.unwrap();
        let mut response = Vec::new();
        user.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"PONG"));

        user.write_all(b"MORE").await.unwrap();
        user.shutdown().await.unwrap();
        let mut upload = Vec::new();
        origin.read_to_end(&mut upload).await.unwrap();
        assert_eq!(upload, b"PINGMORE");
        task.await.unwrap().unwrap();
    }
}
