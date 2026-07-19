// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::OutboundErr;
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};

pub async fn connect_tcp_direct(
    addr: SocketAddr,
    bind_device: Option<&str>,
    so_mark: Option<u32>,
    timeout: Duration,
) -> Result<TcpStream, OutboundErr> {
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(dev) = bind_device {
        bind_to_device(sock.as_raw_fd(), dev)?;
    }
    if let Some(mark) = so_mark {
        set_so_mark(sock.as_raw_fd(), mark)?;
    }
    let stream = match tokio::time::timeout(timeout, sock.connect(addr)).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(OutboundErr::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "direct connect timed out",
            )));
        }
    };

    stream.set_nodelay(true).ok();
    Ok(stream)
}

pub fn bind_to_device(fd: std::os::fd::RawFd, dev: &str) -> Result<(), OutboundErr> {
    let cdev = CString::new(dev).map_err(|_| OutboundErr::Proto("device name has NUL"))?;

    let bytes = cdev.as_bytes_with_nul();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(OutboundErr::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub fn set_so_mark(fd: std::os::fd::RawFd, mark: u32) -> Result<(), OutboundErr> {
    let mark = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(OutboundErr::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub fn bind_udp_socket(
    is_ipv4: bool,
    bind_device: Option<&str>,
    so_mark: Option<u32>,
) -> Result<std::net::UdpSocket, OutboundErr> {
    let sock = if is_ipv4 {
        std::net::UdpSocket::bind("0.0.0.0:0")?
    } else {
        std::net::UdpSocket::bind("[::]:0")?
    };
    sock.set_nonblocking(true)?;
    let fd = sock.as_raw_fd();
    if let Some(dev) = bind_device {
        bind_to_device(fd, dev)?;
    }
    if let Some(mark) = so_mark {
        set_so_mark(fd, mark)?;
    }
    Ok(sock)
}

pub fn device_exists(name: &str) -> bool {
    let Ok(c) = CString::new(name) else {
        return false;
    };
    unsafe { libc::if_nametoindex(c.as_ptr()) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_connect_no_device_echoes() {

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let mut s = connect_tcp_direct(addr, None, None, Duration::from_secs(2))
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
    }

    #[tokio::test]
    async fn direct_connect_times_out_on_blackhole() {

        let addr: SocketAddr = "198.51.100.1:9".parse().unwrap();
        let r = connect_tcp_direct(addr, None, None, Duration::from_millis(300)).await;
        assert!(r.is_err());
    }

    #[test]
    fn device_exists_loopback_yes_garbage_no() {
        assert!(device_exists("lo"), "loopback should always exist");
        assert!(!device_exists("definitely-not-a-real-iface-xyz"));
        assert!(!device_exists("bad\0name"));
    }
}
