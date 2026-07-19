// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, TcpStream};

pub fn bind_tproxy_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;

    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;

    set_transparent(&sock, addr.is_ipv6())?;

    if addr.is_ipv6() {
        sock.set_only_v6(false)?;
    }

    sock.bind(&addr.into())?;

    let somaxconn = read_somaxconn();
    let backlog = somaxconn.unwrap_or(4096).max(4096);
    if let Some(s) = somaxconn
        && s < 4096
    {
        tracing::warn!(
            somaxconn = s,
            "net.core.somaxconn < 4096; accept backlog capped by kernel, raise it for high-burst"
        );
    }
    sock.listen(backlog)?;
    TcpListener::from_std(sock.into())
}

fn read_somaxconn() -> Option<i32> {
    std::fs::read_to_string("/proc/sys/net/core/somaxconn")
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    stream.local_addr()
}

pub fn set_tcp_keepalive(stream: &TcpStream, idle_s: i32, intvl_s: i32, cnt: i32) {
    let fd = stream.as_raw_fd();
    let set = |level: libc::c_int, name: libc::c_int, val: libc::c_int| unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
    };
    set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, idle_s);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, intvl_s);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPCNT, cnt);
}

fn set_transparent(sock: &Socket, v6: bool) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let on: libc::c_int = 1;
    let (level, name) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, libc::IP_TRANSPARENT)
    };

    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socketaddr_parse_sanity() {
        let addr: SocketAddr = "127.0.0.1:1081".parse().unwrap();
        assert_eq!(addr.port(), 1081);
    }
}
