// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use parking_lot::Mutex;
use std::io;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const COPY_BUF_SIZE: usize = 32 * 1024;
const POOL_CAP: usize = 64;

static BUF_POOL: LazyLock<Mutex<Vec<Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(Vec::with_capacity(POOL_CAP)));

pub(crate) struct PooledBuf(Option<Vec<u8>>);

impl PooledBuf {
    pub(crate) fn take() -> Self {
        let buf = BUF_POOL
            .lock()
            .pop()
            .unwrap_or_else(|| vec![0u8; COPY_BUF_SIZE]);
        Self(Some(buf))
    }
}

impl std::ops::Deref for PooledBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_deref().unwrap()
    }
}

impl std::ops::DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_deref_mut().unwrap()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.0.take()
            && buf.capacity() == COPY_BUF_SIZE
        {
            let mut pool = BUF_POOL.lock();
            if pool.len() < POOL_CAP {
                pool.push(buf);
            }
        }
    }
}

pub async fn counting_copy_bidirectional<A, B>(
    a: A,
    b: B,
    up: &AtomicU64,
    down: &AtomicU64,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up_fut = copy_and_count(&mut ar, &mut bw, up);
    let dn_fut = copy_and_count(&mut br, &mut aw, down);

    tokio::try_join!(up_fut, dn_fut)
}

async fn copy_and_count<R, W>(r: &mut R, w: &mut W, c: &AtomicU64) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = PooledBuf::take();
    let mut total: u64 = 0;

    let res = loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => break Err(e),
        };
        if n == 0 {
            break Ok(total);
        }
        if let Err(e) = w.write_all(&buf[..n]).await {
            break Err(e);
        }
        total += n as u64;
        c.fetch_add(n as u64, Ordering::Relaxed);
    };

    let _ = w.shutdown().await;
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn both_directions_counted() {

        let (a, a_peer) = duplex(4096);
        let (b, b_peer) = duplex(4096);

        let a_peer_task = tokio::spawn(async move {
            let mut p = a_peer;
            p.write_all(b"hello").await.unwrap();
            p.shutdown().await.unwrap();

            let mut out = Vec::new();
            p.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"world!!");
        });
        let b_peer_task = tokio::spawn(async move {
            let mut p = b_peer;
            let mut out = Vec::new();
            p.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"hello");
            p.write_all(b"world!!").await.unwrap();
            p.shutdown().await.unwrap();
        });

        let up = AtomicU64::new(0);
        let down = AtomicU64::new(0);
        let (u, d) = counting_copy_bidirectional(a, b, &up, &down).await.unwrap();

        a_peer_task.await.unwrap();
        b_peer_task.await.unwrap();

        assert_eq!(u, 5);
        assert_eq!(d, 7);
        assert_eq!(up.load(Ordering::Relaxed), 5);
        assert_eq!(down.load(Ordering::Relaxed), 7);
    }

    #[tokio::test]
    async fn zero_bytes_on_immediate_eof() {
        let (a, a_peer) = duplex(128);
        let (b, b_peer) = duplex(128);
        drop(a_peer);
        drop(b_peer);
        let up = AtomicU64::new(0);
        let down = AtomicU64::new(0);
        let (u, d) = counting_copy_bidirectional(a, b, &up, &down).await.unwrap();
        assert_eq!(u, 0);
        assert_eq!(d, 0);
    }
}
