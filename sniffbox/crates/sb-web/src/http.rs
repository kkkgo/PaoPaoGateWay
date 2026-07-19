// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_HEAD: usize = 64 * 1024;

pub const MAX_HEADERS: usize = 128;

type Headers = Vec<(String, Vec<u8>)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Length(u64),
    Chunked,

    Eof,

    None,
}

#[derive(Debug, Clone)]
pub struct ReqHead {
    pub method: String,

    pub path: String,
    pub http11: bool,
    pub headers: Headers,
}

#[derive(Debug, Clone)]
pub struct RespHead {
    pub status: u16,
    pub reason: String,
    pub http11: bool,
    pub headers: Headers,
}

impl ReqHead {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header(&self.headers, name)
    }
    pub fn keep_alive(&self) -> bool {
        keep_alive(&self.headers, self.http11)
    }
    pub fn is_upgrade(&self) -> bool {
        is_upgrade(&self.headers)
    }
    pub fn framing(&self) -> io::Result<Framing> {
        framing(&self.headers, true, 200, false)
    }

    pub fn path_only(&self) -> &str {
        self.path.split('?').next().unwrap_or(&self.path)
    }
}

impl RespHead {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header(&self.headers, name)
    }
    pub fn keep_alive(&self) -> bool {
        keep_alive(&self.headers, self.http11)
    }
    pub fn is_upgrade(&self) -> bool {
        self.status == 101
    }
    pub fn framing(&self, head_request: bool) -> io::Result<Framing> {
        framing(&self.headers, false, self.status, head_request)
    }
}

pub async fn read_head<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut search_from = 0;
    loop {
        if let Some(pos) = find_head_end(&buf[search_from..]) {
            return Ok(search_from + pos);
        }
        search_from = buf.len().saturating_sub(3);
        if buf.len() >= MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
        let mut tmp = [0u8; 8192];
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                if buf.is_empty() {
                    io::ErrorKind::UnexpectedEof
                } else {
                    io::ErrorKind::InvalidData
                },
                "eof before end of header",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

pub fn parse_request(head: &[u8]) -> io::Result<ReqHead> {
    let mut hbuf = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut hbuf);
    let status = req.parse(head).map_err(bad)?;
    if status.is_partial() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete request head",
        ));
    }
    Ok(ReqHead {
        method: req.method.unwrap_or("GET").to_string(),
        path: req.path.unwrap_or("/").to_string(),
        http11: req.version == Some(1),
        headers: own_headers(req.headers),
    })
}

pub fn parse_response(head: &[u8]) -> io::Result<RespHead> {
    let mut hbuf = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut hbuf);
    let status = resp.parse(head).map_err(bad)?;
    if status.is_partial() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete response head",
        ));
    }
    Ok(RespHead {
        status: resp.code.unwrap_or(0),
        reason: resp.reason.unwrap_or("").to_string(),
        http11: resp.version == Some(1),
        headers: own_headers(resp.headers),
    })
}

fn own_headers(hs: &[httparse::Header<'_>]) -> Headers {
    hs.iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| (h.name.to_string(), h.value.to_vec()))
        .collect()
}

fn bad(e: httparse::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("http parse: {e}"))
}

fn header<'a>(headers: &'a Headers, name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

fn keep_alive(headers: &Headers, http11: bool) -> bool {
    match header(headers, "connection") {
        Some(v) => {
            let v = std::str::from_utf8(v).unwrap_or("");
            if v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")) {
                false
            } else if v
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("keep-alive"))
            {
                true
            } else {
                http11
            }
        }
        None => http11,
    }
}

fn is_upgrade(headers: &Headers) -> bool {
    let conn_upgrade = header(headers, "connection")
        .map(|v| {
            std::str::from_utf8(v)
                .unwrap_or("")
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    conn_upgrade && header(headers, "upgrade").is_some()
}

fn framing(
    headers: &Headers,
    is_request: bool,
    status: u16,
    head_request: bool,
) -> io::Result<Framing> {
    if !is_request
        && (head_request || status == 204 || status == 304 || (100..200).contains(&status))
    {
        return Ok(Framing::None);
    }
    if let Some(te) = header(headers, "transfer-encoding") {
        let te = std::str::from_utf8(te).unwrap_or("");
        if te
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        {
            return Ok(Framing::Chunked);
        }
    }
    if let Some(cl) = header(headers, "content-length") {
        let n: u64 = std::str::from_utf8(cl)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad content-length"))?;
        return Ok(Framing::Length(n));
    }
    Ok(if is_request {
        Framing::None
    } else {
        Framing::Eof
    })
}

pub async fn read_body_bounded<R>(
    src: &mut R,
    framing: Framing,
    prefix: Vec<u8>,
    limit: usize,
) -> io::Result<(Vec<u8>, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    match framing {
        Framing::None => Ok((Vec::new(), prefix)),
        Framing::Length(n) => {
            if n > limit as u64 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            let n = n as usize;
            if prefix.len() >= n {

                let mut body = prefix;
                let leftover = body.split_off(n);
                return Ok((body, leftover));
            }
            let have = prefix.len();
            let mut body = prefix;
            body.resize(n, 0);
            src.read_exact(&mut body[have..]).await?;
            Ok((body, Vec::new()))
        }
        Framing::Chunked => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunked request body not supported",
        )),
        Framing::Eof => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request body needs content-length",
        )),
    }
}

pub async fn relay_body<R, W>(
    src: &mut R,
    dst: &mut W,
    framing: Framing,
    prefix: &[u8],
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        Framing::None => Ok(()),
        Framing::Length(total) => relay_counted(src, dst, total, prefix).await,
        Framing::Eof => {
            dst.write_all(prefix).await?;
            tokio::io::copy(src, dst).await?;
            Ok(())
        }
        Framing::Chunked => relay_chunked(src, dst, prefix).await,
    }
}

async fn relay_counted<R, W>(src: &mut R, dst: &mut W, total: u64, prefix: &[u8]) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = total;
    let take = (prefix.len() as u64).min(remaining) as usize;
    if take > 0 {
        dst.write_all(&prefix[..take]).await?;
        remaining -= take as u64;
    }
    let mut tmp = [0u8; 16 * 1024];
    while remaining > 0 {
        let want = (remaining as usize).min(tmp.len());
        let n = src.read(&mut tmp[..want]).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof mid body"));
        }
        dst.write_all(&tmp[..n]).await?;
        remaining -= n as u64;
    }
    Ok(())
}

async fn relay_chunked<R, W>(src: &mut R, dst: &mut W, prefix: &[u8]) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut rdr = PrefixedReader::new(src, prefix);
    loop {
        let size_line = rdr.read_line(dst).await?;
        let size_hex = size_line.split(|&b| b == b';').next().unwrap_or(&[]);
        let size_str = std::str::from_utf8(size_hex).unwrap_or("").trim();
        let size = u64::from_str_radix(size_str, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            loop {
                let line = rdr.read_line(dst).await?;
                if line.is_empty() {
                    break;
                }
            }
            dst.flush().await?;
            return Ok(());
        }
        rdr.copy_exact(dst, size as usize + 2).await?;
    }
}

struct PrefixedReader<'a, R> {
    src: &'a mut R,
    prefix: &'a [u8],
    pos: usize,
}

impl<'a, R: AsyncRead + Unpin> PrefixedReader<'a, R> {
    fn new(src: &'a mut R, prefix: &'a [u8]) -> Self {
        Self {
            src,
            prefix,
            pos: 0,
        }
    }

    async fn read_byte(&mut self) -> io::Result<u8> {
        if self.pos < self.prefix.len() {
            let b = self.prefix[self.pos];
            self.pos += 1;
            return Ok(b);
        }
        let mut one = [0u8; 1];
        let n = self.src.read(&mut one).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof in chunked",
            ));
        }
        Ok(one[0])
    }

    async fn read_line<W: AsyncWrite + Unpin>(&mut self, dst: &mut W) -> io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let b = self.read_byte().await?;
            dst.write_all(&[b]).await?;
            if b == b'\n' {
                while line.last() == Some(&b'\r') || line.last() == Some(&b'\n') {
                    line.pop();
                }
                return Ok(line);
            }
            line.push(b);
        }
    }

    async fn copy_exact<W: AsyncWrite + Unpin>(
        &mut self,
        dst: &mut W,
        mut n: usize,
    ) -> io::Result<()> {
        while n > 0 && self.pos < self.prefix.len() {
            let take = (self.prefix.len() - self.pos).min(n);
            dst.write_all(&self.prefix[self.pos..self.pos + take])
                .await?;
            self.pos += take;
            n -= take;
        }
        let mut tmp = [0u8; 16 * 1024];
        while n > 0 {
            let want = n.min(tmp.len());
            let r = self.src.read(&mut tmp[..want]).await?;
            if r == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof in chunk data",
                ));
            }
            dst.write_all(&tmp[..r]).await?;
            n -= r;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_and_parse_request() {
        let req = b"GET /configs?x=1 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer t\r\n\r\nBODY";
        let mut src = &req[..];
        let mut buf = Vec::new();
        let head = read_head(&mut src, &mut buf).await.unwrap();
        assert_eq!(&buf[head..], b"BODY");
        let rh = parse_request(&buf[..head]).unwrap();
        assert_eq!(rh.method, "GET");
        assert_eq!(rh.path, "/configs?x=1");
        assert_eq!(rh.path_only(), "/configs");
        assert!(rh.http11);
        assert_eq!(rh.header("authorization"), Some(&b"Bearer t"[..]));
        assert!(rh.keep_alive());
    }

    #[test]
    fn parse_resp_and_framing() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.framing(false).unwrap(), Framing::Length(5));
        let r = parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(r.framing(false).unwrap(), Framing::None);
        let r = parse_response(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        assert_eq!(r.framing(false).unwrap(), Framing::Eof);
    }

    #[tokio::test]
    async fn relay_counted_body() {

        let mut src = &b"lo world extra"[..];
        let mut out = Vec::new();
        relay_body(&mut src, &mut out, Framing::Length(11), b"hel")
            .await
            .unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn read_body_bounded_cases() {

        let mut src = &b"lo world"[..];
        let (body, leftover) =
            read_body_bounded(&mut src, Framing::Length(11), b"hel".to_vec(), 64)
                .await
                .unwrap();
        assert_eq!(body, b"hello world");
        assert!(leftover.is_empty());

        let mut src = &b""[..];
        let (body, leftover) =
            read_body_bounded(&mut src, Framing::Length(5), b"helloGET /x".to_vec(), 64)
                .await
                .unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(leftover, b"GET /x");

        let mut src = &b""[..];
        let (body, leftover) = read_body_bounded(&mut src, Framing::None, b"GET /y".to_vec(), 64)
            .await
            .unwrap();
        assert!(body.is_empty());
        assert_eq!(leftover, b"GET /y");

        let mut src = &b"xxxxxxxxxx"[..];
        let e = read_body_bounded(&mut src, Framing::Length(100), Vec::new(), 8)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(src.len(), 10, "should not consume src when rejected");

        let mut src = &b""[..];
        assert_eq!(
            read_body_bounded(&mut src, Framing::Chunked, Vec::new(), 64)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut src = &b""[..];
        assert_eq!(
            read_body_bounded(&mut src, Framing::Eof, Vec::new(), 64)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn relay_chunked_body_verbatim() {
        let body = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut src = body.as_bytes();
        let mut out = Vec::new();
        relay_body(&mut src, &mut out, Framing::Chunked, b"")
            .await
            .unwrap();
        assert_eq!(out, body.as_bytes());
    }

    #[test]
    fn upgrade_detection() {
        let r = parse_request(
            b"GET /connections HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
        assert!(r.is_upgrade());
        let r = parse_request(b"GET /configs HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        assert!(!r.is_upgrade());
        assert!(!r.keep_alive());
    }
}
