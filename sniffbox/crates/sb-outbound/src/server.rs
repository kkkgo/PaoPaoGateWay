// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::OutboundErr;
use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT, REP_SUCCEEDED, VER};
use crate::socks5_udp::CMD_UDP_ASSOCIATE;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USERPASS: u8 = 0x02;
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

pub const AUTH_VER: u8 = 0x01;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksCmd {
    Connect,
    UdpAssociate,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl DestAddr {
    pub fn port(&self) -> u16 {
        match self {
            DestAddr::Ip(a) => a.port(),
            DestAddr::Domain(_, p) => *p,
        }
    }
}

pub async fn negotiate_method<S>(
    stream: &mut S,
    require_auth: Option<&(String, String)>,
) -> Result<(), OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(OutboundErr::Proto("bad version in client greeting"));
    }
    let nmethods = head[1] as usize;
    if nmethods == 0 {
        return Err(OutboundErr::Proto("client offered zero methods"));
    }
    let mut methods = [0u8; 255];
    stream.read_exact(&mut methods[..nmethods]).await?;
    let offered = &methods[..nmethods];

    match require_auth {
        Some((user, pass)) => {
            if !offered.contains(&METHOD_USERPASS) {
                stream.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await?;
                return Err(OutboundErr::Proto("client did not offer user/pass auth"));
            }
            stream.write_all(&[VER, METHOD_USERPASS]).await?;
            verify_userpass(stream, user, pass).await
        }
        None => {
            if !offered.contains(&METHOD_NO_AUTH) {
                stream.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await?;
                return Err(OutboundErr::Proto("client did not offer no-auth"));
            }
            stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
            Ok(())
        }
    }
}

async fn verify_userpass<S>(stream: &mut S, user: &str, pass: &str) -> Result<(), OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != AUTH_VER {
        return Err(OutboundErr::Proto("bad auth subnegotiation version"));
    }
    let ulen = head[1] as usize;
    let mut ubuf = [0u8; 255];
    stream.read_exact(&mut ubuf[..ulen]).await?;
    let mut plen_b = [0u8; 1];
    stream.read_exact(&mut plen_b).await?;
    let plen = plen_b[0] as usize;
    let mut pbuf = [0u8; 255];
    stream.read_exact(&mut pbuf[..plen]).await?;

    let ok = ubuf[..ulen] == *user.as_bytes() && pbuf[..plen] == *pass.as_bytes();
    if ok {
        stream.write_all(&[AUTH_VER, 0x00]).await?;
        Ok(())
    } else {
        stream.write_all(&[AUTH_VER, 0x01]).await?;
        Err(OutboundErr::Proto("user/pass auth failed"))
    }
}

pub async fn read_request<S>(stream: &mut S) -> Result<(SocksCmd, DestAddr), OutboundErr>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(OutboundErr::Proto("bad version in request"));
    }
    let cmd = match head[1] {
        CMD_CONNECT => SocksCmd::Connect,
        CMD_UDP_ASSOCIATE => SocksCmd::UdpAssociate,
        other => SocksCmd::Other(other),
    };
    let dest = match head[3] {
        ATYP_IPV4 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            DestAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&b[..16]);
            let ip = Ipv6Addr::from(oct);
            let port = u16::from_be_bytes([b[16], b[17]]);
            DestAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port))
        }
        ATYP_DOMAIN => {
            let mut n = [0u8; 1];
            stream.read_exact(&mut n).await?;
            let len = n[0] as usize;
            if len == 0 {
                return Err(OutboundErr::Proto("empty domain in request"));
            }
            let mut buf = [0u8; 257];
            stream.read_exact(&mut buf[..len + 2]).await?;
            let host = std::str::from_utf8(&buf[..len])
                .map_err(|_| OutboundErr::Proto("non-utf8 domain"))?
                .to_string();
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            DestAddr::Domain(host, port)
        }
        _ => return Err(OutboundErr::Proto("unknown ATYP in request")),
    };
    Ok((cmd, dest))
}

pub async fn write_reply<S>(stream: &mut S, rep: u8, bnd: SocketAddr) -> Result<(), OutboundErr>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 22];
    buf[0] = VER;
    buf[1] = rep;
    buf[2] = 0x00;
    let n = match bnd.ip() {
        IpAddr::V4(v4) => {
            buf[3] = ATYP_IPV4;
            buf[4..8].copy_from_slice(&v4.octets());
            8
        }
        IpAddr::V6(v6) => {
            buf[3] = ATYP_IPV6;
            buf[4..20].copy_from_slice(&v6.octets());
            20
        }
    };
    buf[n..n + 2].copy_from_slice(&bnd.port().to_be_bytes());
    stream.write_all(&buf[..n + 2]).await?;
    Ok(())
}

pub async fn write_success<S>(stream: &mut S, bnd: SocketAddr) -> Result<(), OutboundErr>
where
    S: AsyncWrite + Unpin,
{
    write_reply(stream, REP_SUCCEEDED, bnd).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn negotiate_no_auth_ok() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {
            negotiate_method(&mut server, None).await.unwrap();
        });

        client.write_all(&[VER, 1, METHOD_NO_AUTH]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [VER, METHOD_NO_AUTH]);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn negotiate_no_auth_rejects_when_not_offered() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move { negotiate_method(&mut server, None).await });
        client.write_all(&[VER, 1, METHOD_USERPASS]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [VER, METHOD_NONE_ACCEPTABLE]);
        assert!(srv.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn negotiate_userpass_ok() {
        let creds = ("alice".to_string(), "secret".to_string());
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {
            negotiate_method(&mut server, Some(&creds)).await.unwrap();
        });
        client.write_all(&[VER, 1, METHOD_USERPASS]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [VER, METHOD_USERPASS]);

        client.write_all(&[AUTH_VER, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"secret").await.unwrap();
        let mut authrep = [0u8; 2];
        client.read_exact(&mut authrep).await.unwrap();
        assert_eq!(authrep, [AUTH_VER, 0x00]);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn negotiate_userpass_wrong_password() {
        let creds = ("alice".to_string(), "secret".to_string());
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move { negotiate_method(&mut server, Some(&creds)).await });
        client.write_all(&[VER, 1, METHOD_USERPASS]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        client.write_all(&[AUTH_VER, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[4]).await.unwrap();
        client.write_all(b"nope").await.unwrap();
        let mut authrep = [0u8; 2];
        client.read_exact(&mut authrep).await.unwrap();
        assert_eq!(authrep, [AUTH_VER, 0x01]);
        assert!(srv.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn read_request_connect_ipv4() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move { read_request(&mut server).await.unwrap() });

        client
            .write_all(&[VER, CMD_CONNECT, 0, ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xBB])
            .await
            .unwrap();
        let (cmd, dest) = srv.await.unwrap();
        assert_eq!(cmd, SocksCmd::Connect);
        assert_eq!(dest, DestAddr::Ip("1.2.3.4:443".parse().unwrap()));
    }

    #[tokio::test]
    async fn read_request_connect_domain() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move { read_request(&mut server).await.unwrap() });
        let host = b"example.com";
        let mut req = vec![VER, CMD_CONNECT, 0, ATYP_DOMAIN, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let (cmd, dest) = srv.await.unwrap();
        assert_eq!(cmd, SocksCmd::Connect);
        assert_eq!(dest, DestAddr::Domain("example.com".into(), 443));
    }

    #[tokio::test]
    async fn read_request_udp_associate() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move { read_request(&mut server).await.unwrap() });
        client
            .write_all(&[VER, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (cmd, _) = srv.await.unwrap();
        assert_eq!(cmd, SocksCmd::UdpAssociate);
    }

    #[tokio::test]
    async fn write_reply_ipv4_roundtrip() {
        let (mut client, mut server) = duplex(64);
        let bnd: SocketAddr = "10.0.0.1:1080".parse().unwrap();
        let srv = tokio::spawn(async move { write_success(&mut server, bnd).await.unwrap() });
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], VER);
        assert_eq!(buf[1], REP_SUCCEEDED);
        assert_eq!(buf[3], ATYP_IPV4);
        assert_eq!(&buf[4..8], &[10, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([buf[8], buf[9]]), 1080);
        srv.await.unwrap();
    }
}
