// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use tokio::io::Interest;
use tokio::net::UdpSocket;

pub const MMSG_VLEN: usize = 16;
pub const MMSG_SLOT_CAP: usize = 2048;

const UDP_RCVBUF_BYTES: libc::c_int = 1024 * 1024;

pub struct TproxyUdp {
    inner: UdpSocket,
}

impl TproxyUdp {
    pub fn from_socket(sock: UdpSocket) -> Self {
        Self { inner: sock }
    }

    pub fn inner(&self) -> &UdpSocket {
        &self.inner
    }

    pub async fn recv_with_origdst(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        loop {
            self.inner.readable().await?;
            match self.inner.try_io(Interest::READABLE, || {
                recv_with_origdst_nonblocking(self.inner.as_raw_fd(), buf)
            }) {
                Ok(r) => return Ok(r),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn recv_batch(&self, buf: &mut MmsgBuf) -> io::Result<usize> {
        loop {
            self.inner.readable().await?;
            match self.inner.try_io(Interest::READABLE, || {
                recv_mmsg_with_origdst_nonblocking(self.inner.as_raw_fd(), buf)
            }) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, peer).await
    }
}

pub fn bind_spoof_udp(spoof_src: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if spoof_src.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    set_int_opt(
        sock.as_raw_fd(),
        if spoof_src.is_ipv6() {
            libc::IPPROTO_IPV6
        } else {
            libc::IPPROTO_IP
        },
        if spoof_src.is_ipv6() {
            libc::IPV6_TRANSPARENT
        } else {
            libc::IP_TRANSPARENT
        },
        1,
        "IP_TRANSPARENT",
    )?;
    if spoof_src.is_ipv6() {
        sock.set_only_v6(false)?;
    }

    set_sockbuf_forced(
        sock.as_raw_fd(),
        libc::SO_SNDBUF,
        libc::SO_SNDBUFFORCE,
        UDP_RCVBUF_BYTES,
        "SO_SNDBUF",
    );
    sock.bind(&spoof_src.into())?;
    UdpSocket::from_std(sock.into())
}

pub fn bind_tproxy_udp(addr: SocketAddr) -> io::Result<TproxyUdp> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;

    set_int_opt(
        sock.as_raw_fd(),
        if addr.is_ipv6() {
            libc::IPPROTO_IPV6
        } else {
            libc::IPPROTO_IP
        },
        if addr.is_ipv6() {
            libc::IPV6_TRANSPARENT
        } else {
            libc::IP_TRANSPARENT
        },
        1,
        "IP_TRANSPARENT",
    )?;
    set_int_opt(
        sock.as_raw_fd(),
        if addr.is_ipv6() {
            libc::IPPROTO_IPV6
        } else {
            libc::IPPROTO_IP
        },
        if addr.is_ipv6() {
            libc::IPV6_RECVORIGDSTADDR
        } else {
            libc::IP_RECVORIGDSTADDR
        },
        1,
        "IP_RECVORIGDSTADDR",
    )?;

    if addr.is_ipv6() {
        sock.set_only_v6(false)?;
    }

    set_sockbuf_forced(
        sock.as_raw_fd(),
        libc::SO_RCVBUF,
        libc::SO_RCVBUFFORCE,
        UDP_RCVBUF_BYTES,
        "SO_RCVBUF",
    );
    sock.bind(&addr.into())?;
    Ok(TproxyUdp::from_socket(UdpSocket::from_std(sock.into())?))
}

pub struct MmsgBuf {
    bufs: Vec<Vec<u8>>,
    peers: Vec<libc::sockaddr_storage>,
    cmsgs: Vec<[u8; 64]>,
    iovecs: Vec<libc::iovec>,
    mmsghdrs: Vec<libc::mmsghdr>,

    filled: usize,
}

unsafe impl Send for MmsgBuf {}

unsafe impl Sync for MmsgBuf {}

impl MmsgBuf {
    pub fn new(vlen: usize, slot_cap: usize) -> Self {
        let vlen = vlen.max(1);
        let slot_cap = slot_cap.max(1);
        let bufs = (0..vlen).map(|_| vec![0u8; slot_cap]).collect();

        let peers = vec![unsafe { std::mem::zeroed::<libc::sockaddr_storage>() }; vlen];
        let cmsgs = vec![[0u8; 64]; vlen];
        let iovecs = vec![
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0
            };
            vlen
        ];
        let mmsghdrs = vec![unsafe { std::mem::zeroed::<libc::mmsghdr>() }; vlen];
        Self {
            bufs,
            peers,
            cmsgs,
            iovecs,
            mmsghdrs,
            filled: 0,
        }
    }

    pub fn vlen(&self) -> usize {
        self.mmsghdrs.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], SocketAddr, SocketAddr)> + '_ {
        (0..self.filled).filter_map(move |i| {
            let n = self.mmsghdrs[i].msg_len as usize;
            let payload = &self.bufs[i][..n.min(self.bufs[i].len())];
            let peer = unsafe {
                sockaddr_storage_to_sa(
                    &self.peers[i] as *const _,
                    self.mmsghdrs[i].msg_hdr.msg_namelen,
                )
            }
            .ok()?;
            let orig = unsafe { parse_origdst_cmsg(&self.mmsghdrs[i].msg_hdr) }.ok()?;
            Some((payload, peer, orig))
        })
    }
}

pub fn recv_mmsg_with_origdst_nonblocking(fd: RawFd, buf: &mut MmsgBuf) -> io::Result<usize> {
    let vlen = buf.mmsghdrs.len();

    for i in 0..vlen {
        let slot_cap = buf.bufs[i].len();
        buf.iovecs[i] = libc::iovec {
            iov_base: buf.bufs[i].as_mut_ptr() as *mut libc::c_void,
            iov_len: slot_cap,
        };
        let h = &mut buf.mmsghdrs[i].msg_hdr;
        h.msg_name = &mut buf.peers[i] as *mut _ as *mut libc::c_void;
        h.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        h.msg_iov = &mut buf.iovecs[i] as *mut libc::iovec;
        h.msg_iovlen = 1;
        h.msg_control = buf.cmsgs[i].as_mut_ptr() as *mut libc::c_void;
        h.msg_controllen = buf.cmsgs[i].len() as _;
        h.msg_flags = 0;
        buf.mmsghdrs[i].msg_len = 0;
    }
    let rc = unsafe {
        libc::recvmmsg(
            fd,
            buf.mmsghdrs.as_mut_ptr(),
            vlen as libc::c_uint,

            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 {
        buf.filled = 0;
        return Err(io::Error::last_os_error());
    }
    buf.filled = rc as usize;

    if tracing::enabled!(tracing::Level::DEBUG) {
        let truncated = buf.mmsghdrs[..buf.filled]
            .iter()
            .filter(|h| h.msg_hdr.msg_flags & libc::MSG_TRUNC != 0)
            .count();
        if truncated > 0 {
            tracing::debug!(
                truncated,
                batch = buf.filled,
                slot_cap = buf.bufs.first().map_or(0, |b| b.len()),
                "recvmmsg datagram(s) truncated; raise MMSG_SLOT_CAP if frequent (jumbo/GSO)"
            );
        }
    }
    Ok(buf.filled)
}

pub struct MmsgRxBuf {
    bufs: Vec<Vec<u8>>,
    iovecs: Vec<libc::iovec>,
    mmsghdrs: Vec<libc::mmsghdr>,
    filled: usize,
}

unsafe impl Send for MmsgRxBuf {}
unsafe impl Sync for MmsgRxBuf {}

impl MmsgRxBuf {
    pub fn new(vlen: usize, slot_cap: usize) -> Self {
        let vlen = vlen.max(1);
        let slot_cap = slot_cap.max(1);
        let bufs = (0..vlen).map(|_| vec![0u8; slot_cap]).collect();
        let iovecs = vec![
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0
            };
            vlen
        ];
        let mmsghdrs = vec![unsafe { std::mem::zeroed::<libc::mmsghdr>() }; vlen];
        Self {
            bufs,
            iovecs,
            mmsghdrs,
            filled: 0,
        }
    }

    pub fn vlen(&self) -> usize {
        self.mmsghdrs.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> + '_ {
        (0..self.filled).map(move |i| {
            let n = self.mmsghdrs[i].msg_len as usize;
            &self.bufs[i][..n.min(self.bufs[i].len())]
        })
    }
}

pub fn recv_mmsg_payloads_nonblocking(fd: RawFd, buf: &mut MmsgRxBuf) -> io::Result<usize> {
    let vlen = buf.mmsghdrs.len();
    for i in 0..vlen {
        let slot_cap = buf.bufs[i].len();
        buf.iovecs[i] = libc::iovec {
            iov_base: buf.bufs[i].as_mut_ptr() as *mut libc::c_void,
            iov_len: slot_cap,
        };
        let h = &mut buf.mmsghdrs[i].msg_hdr;
        h.msg_name = std::ptr::null_mut();
        h.msg_namelen = 0;
        h.msg_iov = &mut buf.iovecs[i] as *mut libc::iovec;
        h.msg_iovlen = 1;
        h.msg_control = std::ptr::null_mut();
        h.msg_controllen = 0;
        h.msg_flags = 0;
        buf.mmsghdrs[i].msg_len = 0;
    }
    let rc = unsafe {
        libc::recvmmsg(
            fd,
            buf.mmsghdrs.as_mut_ptr(),
            vlen as libc::c_uint,
            libc::MSG_DONTWAIT as _,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 {
        buf.filled = 0;
        return Err(io::Error::last_os_error());
    }
    buf.filled = rc as usize;
    Ok(buf.filled)
}

pub fn send_mmsg_to(fd: RawFd, payloads: &[&[u8]], dest: SocketAddr) -> io::Result<usize> {
    let n = payloads.len().min(MMSG_VLEN);
    if n == 0 {
        return Ok(0);
    }

    let sa = SockAddr::from(dest);
    let mut iovecs: [libc::iovec; MMSG_VLEN] = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; MMSG_VLEN];
    let mut hdrs: [libc::mmsghdr; MMSG_VLEN] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        iovecs[i] = libc::iovec {
            iov_base: payloads[i].as_ptr() as *mut libc::c_void,
            iov_len: payloads[i].len(),
        };
        let h = &mut hdrs[i].msg_hdr;
        h.msg_name = sa.as_ptr() as *mut libc::c_void;
        h.msg_namelen = sa.len();
        h.msg_iov = &mut iovecs[i] as *mut libc::iovec;
        h.msg_iovlen = 1;
    }
    let rc = unsafe {
        libc::sendmmsg(
            fd,
            hdrs.as_mut_ptr(),
            n as libc::c_uint,
            libc::MSG_DONTWAIT as _,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

pub fn recv_with_origdst_nonblocking(
    fd: RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cmsg_buf = [0u8; 256];
    let mut peer_storage: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::uninit();

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = peer_storage.as_mut_ptr() as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let peer = unsafe { sockaddr_storage_to_sa(peer_storage.as_ptr(), msg.msg_namelen)? };
    let orig = unsafe { parse_origdst_cmsg(&msg)? };
    Ok((n as usize, peer, orig))
}

unsafe fn sockaddr_storage_to_sa(
    sa: *const libc::sockaddr_storage,
    _len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let family = unsafe { (*sa).ss_family as i32 };
    match family {
        libc::AF_INET => {
            let s: &libc::sockaddr_in = unsafe { &*(sa as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr));
            Ok(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(s.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let s: &libc::sockaddr_in6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(s.sin6_addr.s6_addr);
            Ok(normalize_v4_mapped(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(s.sin6_port),
                u32::from_be(s.sin6_flowinfo),
                s.sin6_scope_id,
            ))))
        }
        _ => Err(io::Error::other("unsupported address family")),
    }
}

pub fn normalize_v4_mapped(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::V4(SocketAddrV4::new(v4, v6.port()))
            } else {
                SocketAddr::V6(v6)
            }
        }
        other => other,
    }
}

unsafe fn parse_origdst_cmsg(msg: &libc::msghdr) -> io::Result<SocketAddr> {
    let mut cm: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cm.is_null() {
        let level = unsafe { (*cm).cmsg_level };
        let typ = unsafe { (*cm).cmsg_type };
        let data = unsafe { libc::CMSG_DATA(cm) };
        match (level, typ) {
            (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR) => {
                let s: &libc::sockaddr_in = unsafe { &*(data as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr));
                return Ok(SocketAddr::V4(SocketAddrV4::new(
                    ip,
                    u16::from_be(s.sin_port),
                )));
            }
            (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR) => {
                let s: &libc::sockaddr_in6 = unsafe { &*(data as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(s.sin6_addr.s6_addr);
                return Ok(normalize_v4_mapped(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    u16::from_be(s.sin6_port),
                    u32::from_be(s.sin6_flowinfo),
                    s.sin6_scope_id,
                ))));
            }
            _ => {}
        }
        cm = unsafe { libc::CMSG_NXTHDR(msg, cm) };
    }
    Err(io::Error::other("no IP_ORIGDSTADDR cmsg"))
}

fn set_int_opt(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: libc::c_int,
    label: &'static str,
) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        tracing::warn!(opt = label, ?err, "setsockopt failed");
        return Err(err);
    }
    Ok(())
}

fn set_sockbuf_forced(
    fd: RawFd,
    opt: libc::c_int,
    force_opt: libc::c_int,
    bytes: libc::c_int,
    label: &'static str,
) {

    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            force_opt,
            &bytes as *const _ as *const libc::c_void,
            std::mem::size_of_val(&bytes) as libc::socklen_t,
        )
    };
    if rc == 0 {

        return;
    }
    let force_err = io::Error::last_os_error();

    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &bytes as *const _ as *const libc::c_void,
            std::mem::size_of_val(&bytes) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::debug!(
            opt = label, err = ?io::Error::last_os_error(), want = bytes,
            "sockbuf setsockopt failed; kernel may silently drop on burst"
        );
        return;
    }

    let mut actual: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&actual) as libc::socklen_t;
    let grc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut actual as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if grc == 0 && actual < bytes {
        tracing::warn!(
            opt = label, want = bytes, effective = actual, force_err = ?force_err,
            "sockbuf capped by sysctl and *BUFFORCE unavailable (need CAP_NET_ADMIN); raise net.core.rmem_max/wmem_max"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libc_constants_sane() {
        assert_eq!(libc::AF_INET, 2);
        assert_eq!(libc::AF_INET6, 10);
    }

    #[test]
    fn v4_mapped_is_normalized() {
        let a: SocketAddr = "[::ffff:1.2.3.4]:443".parse().unwrap();
        let n = normalize_v4_mapped(a);
        assert!(matches!(n, SocketAddr::V4(_)));
        assert_eq!(n.port(), 443);
        assert_eq!(n.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn genuine_v6_stays_v6() {
        let a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let n = normalize_v4_mapped(a);
        assert!(matches!(n, SocketAddr::V6(_)));
    }

    #[test]
    fn v4_stays_v4() {
        let a: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let n = normalize_v4_mapped(a);
        assert_eq!(a, n);
    }

    #[test]
    fn mmsg_buf_construct_and_empty_iter() {
        let buf = MmsgBuf::new(8, 1500);
        assert_eq!(buf.vlen(), 8);

        assert_eq!(buf.iter().count(), 0);
    }

    #[test]
    fn mmsg_buf_minimum_one_slot() {

        let buf = MmsgBuf::new(0, 0);
        assert_eq!(buf.vlen(), 1);
    }

    #[test]
    fn mmsg_rx_buf_construct_and_empty_iter() {
        let buf = MmsgRxBuf::new(8, 2048);
        assert_eq!(buf.vlen(), 8);
        assert_eq!(buf.iter().count(), 0);

        assert_eq!(MmsgRxBuf::new(0, 0).vlen(), 1);
    }

    #[test]
    fn sendmmsg_recvmmsg_roundtrip() {
        use std::net::UdpSocket as StdUdp;
        let rx = StdUdp::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = StdUdp::bind("127.0.0.1:0").unwrap();
        let dest = rx.local_addr().unwrap();

        let big = vec![0xABu8; 1400];
        let payloads: [&[u8]; 4] = [b"hello", b"world!!", b"", &big];
        let sent = send_mmsg_to(tx.as_raw_fd(), &payloads, dest).unwrap();
        assert_eq!(sent, 4);

        let mut rxbuf = MmsgRxBuf::new(MMSG_VLEN, 2048);
        let mut got: Vec<Vec<u8>> = Vec::new();
        for _ in 0..200 {
            match recv_mmsg_payloads_nonblocking(rx.as_raw_fd(), &mut rxbuf) {
                Ok(n) if n > 0 => {
                    got.extend(rxbuf.iter().map(<[u8]>::to_vec));
                    if got.len() >= 4 {
                        break;
                    }
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(2)),
            }
        }
        assert_eq!(got.len(), 4, "should receive all 4 datagrams");
        assert_eq!(got[0], b"hello");
        assert_eq!(got[1], b"world!!");
        assert_eq!(got[2], b"");
        assert_eq!(got[3], big);
    }

    #[test]
    fn sendmmsg_empty_is_noop() {
        use std::net::UdpSocket as StdUdp;
        let tx = StdUdp::bind("127.0.0.1:0").unwrap();
        let dest: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(send_mmsg_to(tx.as_raw_fd(), &[], dest).unwrap(), 0);
    }

    #[test]
    fn sendmmsg_caps_at_vlen() {

        use std::net::UdpSocket as StdUdp;
        let rx = StdUdp::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = StdUdp::bind("127.0.0.1:0").unwrap();
        let dest = rx.local_addr().unwrap();
        let one = b"x".as_slice();
        let payloads = vec![one; MMSG_VLEN + 5];
        let sent = send_mmsg_to(tx.as_raw_fd(), &payloads, dest).unwrap();
        assert_eq!(sent, MMSG_VLEN);
    }
}
