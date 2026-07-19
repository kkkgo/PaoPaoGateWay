// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::counting_copy::PooledBuf;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::Interest;
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};

#[cfg(target_os = "linux")]
const SPLICE_LEN: usize = 1 << 20;

#[cfg(target_os = "linux")]
const PIPE_CAPACITY: libc::c_int = 256 * 1024;

pub async fn adaptive_copy_bidirectional(
    client: TcpStream,
    upstream: TcpStream,
    up: &AtomicU64,
    down: &AtomicU64,
    threshold: u64,
) -> io::Result<(u64, u64)> {
    let client = Arc::new(client);
    let upstream = Arc::new(upstream);
    tokio::try_join!(
        copy_dir(Arc::clone(&client), Arc::clone(&upstream), up, threshold),
        copy_dir(Arc::clone(&upstream), Arc::clone(&client), down, threshold),
    )
}

async fn copy_dir(
    src: Arc<TcpStream>,
    dst: Arc<TcpStream>,
    counter: &AtomicU64,
    threshold: u64,
) -> io::Result<u64> {
    let dst_fd = dst.as_raw_fd();
    let res = relay_dir(&src, &dst, counter, threshold).await;
    shutdown_write(dst_fd);
    res
}

async fn relay_dir(
    src: &TcpStream,
    dst: &TcpStream,
    counter: &AtomicU64,
    threshold: u64,
) -> io::Result<u64> {

    let threshold = if cfg!(target_os = "linux") {
        threshold
    } else {
        u64::MAX
    };

    let mut total: u64 = 0;

    {
        let mut buf = PooledBuf::take();
        loop {
            let n = read_once(src, &mut buf[..]).await?;
            if n == 0 {
                return Ok(total);
            }
            write_all_once(dst, &buf[..n]).await?;
            total += n as u64;
            counter.fetch_add(n as u64, Ordering::Relaxed);
            if total >= threshold {
                break;
            }
        }
    }

    #[cfg(target_os = "linux")]
    splice_to_eof(src, dst, counter, &mut total).await?;

    Ok(total)
}

async fn read_once(s: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        s.readable().await?;
        match s.try_read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

async fn write_all_once(s: &TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        s.writable().await?;
        match s.try_write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn splice_to_eof(
    src: &TcpStream,
    dst: &TcpStream,
    counter: &AtomicU64,
    total: &mut u64,
) -> io::Result<()> {
    let pipe = Pipe::new()?;
    let (pr, pw) = (pipe.r.as_raw_fd(), pipe.w.as_raw_fd());
    let sfd = src.as_raw_fd();
    let dfd = dst.as_raw_fd();
    loop {

        let n = src
            .async_io(Interest::READABLE, || splice_raw(sfd, pw, SPLICE_LEN))
            .await?;
        if n == 0 {
            return Ok(());
        }

        let mut left = n;
        while left > 0 {
            let m = dst
                .async_io(Interest::WRITABLE, || splice_raw(pr, dfd, left))
                .await?;
            if m == 0 {
                return Ok(());
            }
            left -= m;
            counter.fetch_add(m as u64, Ordering::Relaxed);
            *total += m as u64;
        }
    }
}

#[cfg(target_os = "linux")]
fn splice_raw(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {

    let ret = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as libc::c_uint,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

fn shutdown_write(fd: RawFd) {

    unsafe {
        libc::shutdown(fd, libc::SHUT_WR);
    }
}

#[cfg(target_os = "linux")]
struct Pipe {
    r: OwnedFd,
    w: OwnedFd,
}

#[cfg(target_os = "linux")]
impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];

        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let _ = unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_CAPACITY) };
        Ok(Self { r, w })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::Duration;

    #[tokio::test]
    async fn pure_counting_small_transfer() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
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

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let up_c = Arc::clone(&up);
        let down_c = Arc::clone(&down);
        let proxy_h = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            let upstream = TcpStream::connect(echo_addr).await.unwrap();

            adaptive_copy_bidirectional(client, upstream, &up_c, &down_c, u64::MAX).await
        });

        let mut c = TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(&vec![0xAAu8; 2048]).await.unwrap();
        let mut sink = vec![0u8; 2048];
        c.read_exact(&mut sink).await.unwrap();
        drop(c);
        let _ = tokio::time::timeout(Duration::from_secs(2), proxy_h).await;

        assert_eq!(up.load(Ordering::Relaxed), 2048);
        assert_eq!(down.load(Ordering::Relaxed), 2048);
    }

    #[tokio::test]
    async fn splice_phase_exact_and_directional() {
        const REQ: usize = 256;
        const RESP: usize = 2 * 1024 * 1024;
        const THRESHOLD: u64 = 4096;

        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            let mut buf = vec![0u8; REQ];
            let _ = s.read_exact(&mut buf).await;
            let _ = s.write_all(&vec![0x5Au8; RESP]).await;
            let _ = s.shutdown().await;
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let up_c = Arc::clone(&up);
        let down_c = Arc::clone(&down);
        let proxy_h = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            let upstream = TcpStream::connect(server_addr).await.unwrap();
            adaptive_copy_bidirectional(client, upstream, &up_c, &down_c, THRESHOLD).await
        });

        let mut c = TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(&vec![0xAAu8; REQ]).await.unwrap();
        let mut sink = vec![0u8; RESP];
        c.read_exact(&mut sink).await.unwrap();
        assert_eq!(sink, vec![0x5Au8; RESP]);
        drop(c);
        let _ = tokio::time::timeout(Duration::from_secs(5), proxy_h).await;

        assert_eq!(up.load(Ordering::Relaxed), REQ as u64, "upload must equal REQ exactly");
        assert_eq!(
            down.load(Ordering::Relaxed),
            RESP as u64,
            "download (via splice) must equal RESP exactly"
        );
    }

    #[tokio::test]
    async fn bidirectional_large_no_hang() {
        const N: usize = 8 * 1024 * 1024;
        const THRESHOLD: u64 = 64 * 1024;

        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
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
            let _ = s.shutdown().await;
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let up_c = Arc::clone(&up);
        let down_c = Arc::clone(&down);
        let proxy_h = tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            let upstream = TcpStream::connect(echo_addr).await.unwrap();
            adaptive_copy_bidirectional(client, upstream, &up_c, &down_c, THRESHOLD).await
        });

        let mut c = TcpStream::connect(proxy_addr).await.unwrap();
        let payload = vec![0x5Au8; N];
        let writer = tokio::spawn(async move {
            c.write_all(&payload).await.unwrap();
            c.shutdown().await.unwrap();
            let mut sink = vec![0u8; N];
            c.read_exact(&mut sink).await.unwrap();
            drop(c);
        });
        tokio::time::timeout(Duration::from_secs(10), writer)
            .await
            .expect("writer should finish")
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(3), proxy_h).await;

        assert_eq!(up.load(Ordering::Relaxed), N as u64);
        assert_eq!(down.load(Ordering::Relaxed), N as u64);
    }
}
