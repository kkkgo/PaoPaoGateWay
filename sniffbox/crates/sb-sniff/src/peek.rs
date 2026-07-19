// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use bytes::BytesMut;
use parking_lot::Mutex;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub const DEFAULT_PEEK_LIMIT: usize = 8 * 1024;

pub const POOL_BUF_CAPACITY: usize = DEFAULT_PEEK_LIMIT;

pub const POOL_DEFAULT_SLOTS: usize = 32;

pub struct PeekBufPool {
    inner: Mutex<Vec<BytesMut>>,
    cap_slots: usize,
    buf_size: usize,
}

impl PeekBufPool {
    pub fn new(cap_slots: usize, buf_size: usize) -> Self {
        Self {
            inner: Mutex::new(Vec::with_capacity(cap_slots.min(64))),
            cap_slots,
            buf_size,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(POOL_DEFAULT_SLOTS, POOL_BUF_CAPACITY)
    }

    pub fn idle(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn take(self: &Arc<Self>) -> PeekBuf {
        let buf = self.inner.lock().pop().unwrap_or_else(|| {
            let mut b = BytesMut::with_capacity(self.buf_size);
            b.reserve(self.buf_size);
            b
        });
        PeekBuf {
            buf,
            limit: self.buf_size,
            pool: Some(Arc::clone(self)),
        }
    }

    fn give_back(&self, mut buf: BytesMut) {
        if buf.capacity() < self.buf_size {
            return;
        }
        buf.clear();
        let mut g = self.inner.lock();
        if g.len() >= self.cap_slots {
            return;
        }
        g.push(buf);
    }
}

pub struct PeekBuf {
    buf: BytesMut,
    limit: usize,

    pool: Option<Arc<PeekBufPool>>,
}

impl PeekBuf {
    pub fn with_limit(limit: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(limit.min(4096)),
            limit,
            pool: None,
        }
    }

    pub fn new() -> Self {
        Self::with_limit(DEFAULT_PEEK_LIMIT)
    }

    pub fn empty() -> Self {
        Self {
            buf: BytesMut::new(),
            limit: 0,
            pool: None,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.buf.len() >= self.limit
    }

    pub async fn read_some<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> io::Result<usize> {
        if self.is_full() {
            return Ok(0);
        }
        let remaining = self.limit - self.buf.len();

        let chunk = remaining.min(4 * 1024);
        let mut tmp = [0u8; 4 * 1024];
        let n = r.read(&mut tmp[..chunk]).await?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    pub fn into_replay<R: AsyncRead + Unpin>(mut self, inner: R) -> ReplayReader<R> {
        let pool = self.pool.take();
        let buf = std::mem::take(&mut self.buf);
        ReplayReader {
            buffered: buf,
            pos: 0,
            inner,
            pool,
        }
    }
}

impl Drop for PeekBuf {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            let buf = std::mem::take(&mut self.buf);
            pool.give_back(buf);
        }
    }
}

impl Default for PeekBuf {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReplayReader<R> {
    buffered: BytesMut,
    pos: usize,
    inner: R,
    pool: Option<Arc<PeekBufPool>>,
}

impl<R> Drop for ReplayReader<R> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            let buf = std::mem::take(&mut self.buffered);
            pool.give_back(buf);
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ReplayReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;
        let this = &mut *self;

        if this.pos < this.buffered.len() {
            let remaining = &this.buffered[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }

        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for ReplayReader<R> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex};

    #[tokio::test]
    async fn accumulates_until_limit() {
        let mut peek = PeekBuf::with_limit(100);
        let (mut a, b) = duplex(1024);
        let mut b = b;
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(&vec![b'x'; 250]).await.unwrap();
        });
        while !peek.is_full() {
            let n = peek.read_some(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
        }
        assert_eq!(peek.len(), 100);
        writer.abort();
    }

    #[tokio::test]
    async fn pool_take_returns_buffer_with_capacity() {
        let pool = Arc::new(PeekBufPool::with_defaults());
        let pb = pool.take();
        assert_eq!(pb.bytes().len(), 0);

        assert!(!pb.is_full());
        drop(pb);

        assert!(pool.idle() >= 1);
    }

    #[tokio::test]
    async fn pool_recycles_on_drop() {
        let pool = Arc::new(PeekBufPool::new(2, 8 * 1024));
        let p1 = pool.take();
        let p2 = pool.take();
        let p3 = pool.take();

        assert_eq!(pool.idle(), 0);
        drop(p1);
        drop(p2);
        drop(p3);

        assert_eq!(pool.idle(), 2);
    }

    #[tokio::test]
    async fn pool_does_not_recycle_wrong_capacity() {
        let pool = Arc::new(PeekBufPool::new(4, 8 * 1024));

        let _bad = PeekBuf {
            buf: BytesMut::with_capacity(123),
            limit: 100,
            pool: Some(Arc::clone(&pool)),
        };
        drop(_bad);
        assert_eq!(pool.idle(), 0);
    }

    #[tokio::test]
    async fn replay_drop_recycles_buffer() {
        let pool = Arc::new(PeekBufPool::with_defaults());
        let (_w, r) = duplex(64);
        let pb = pool.take();
        let replay = pb.into_replay(r);
        assert_eq!(pool.idle(), 0);
        drop(replay);
        assert_eq!(pool.idle(), 1);
    }

    #[tokio::test]
    async fn empty_peekbuf_zero_alloc_and_passthrough() {
        let pb = PeekBuf::empty();
        assert!(pb.is_empty());
        assert!(pb.is_full(), "limit=0 → always full, read_some always 0");
        let (mut w, r) = duplex(64);
        use tokio::io::AsyncWriteExt;
        w.write_all(b"xyz").await.unwrap();
        drop(w);
        let mut replay = pb.into_replay(r);
        let mut out = Vec::new();
        replay.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"xyz", "empty buffer replay = pure pass-through");
    }

    #[tokio::test]
    async fn replay_then_passthrough() {
        let (mut w, r) = duplex(1024);
        let mut r = r;
        use tokio::io::AsyncWriteExt;
        w.write_all(b"HELLOWORLD").await.unwrap();

        let mut peek = PeekBuf::with_limit(8);
        let n = peek.read_some(&mut r).await.unwrap();
        assert!(n >= 5);

        peek.buf.truncate(5);
        assert_eq!(peek.bytes(), b"HELLO");

        w.write_all(b"MOREDATA!!").await.unwrap();
        drop(w);

        let mut replay = peek.into_replay(r);
        let mut out = Vec::new();
        replay.read_to_end(&mut out).await.unwrap();

        assert!(out.starts_with(b"HELLO"));
        assert!(out.ends_with(b"!!"));
    }
}
