// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub mod error;

#[cfg(target_os = "linux")]
pub mod spoof_cache;
#[cfg(target_os = "linux")]
pub mod tcp;
#[cfg(target_os = "linux")]
pub mod udp;

#[cfg(not(target_os = "linux"))]
pub mod tcp {
    use std::io;
    use std::net::SocketAddr;

    pub fn bind_tproxy_tcp(_addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TPROXY is Linux-only",
        ))
    }
    pub fn original_dst(s: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
        s.local_addr()
    }
}

#[cfg(not(target_os = "linux"))]
pub mod udp {
    use std::io;
    use std::net::SocketAddr;

    pub fn bind_tproxy_udp(_addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TPROXY is Linux-only",
        ))
    }
}

pub use error::TproxyErr;
