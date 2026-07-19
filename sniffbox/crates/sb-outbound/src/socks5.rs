// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::OutboundErr;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VER: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USERPASS: u8 = 0x02;
pub const METHOD_REJECTED: u8 = 0xFF;

pub const AUTH_VER: u8 = 0x01;
pub const CMD_CONNECT: u8 = 0x01;
pub const REP_SUCCEEDED: u8 = 0x00;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub async fn handshake_no_auth<S>(stream: &mut S) -> Result<(), OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(stream, None).await
}

pub async fn handshake<S>(
    stream: &mut S,
    auth: Option<&(String, String)>,
) -> Result<(), OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match auth {
        Some((user, pass)) => {
            stream
                .write_all(&[VER, 0x02, METHOD_NO_AUTH, METHOD_USERPASS])
                .await?;
            let chosen = read_method_reply(stream).await?;
            match chosen {
                METHOD_NO_AUTH => Ok(()),
                METHOD_USERPASS => send_userpass(stream, user, pass).await,
                _ => Err(OutboundErr::Proto("server chose unsupported method")),
            }
        }
        None => {
            stream.write_all(&[VER, 0x01, METHOD_NO_AUTH]).await?;
            match read_method_reply(stream).await? {
                METHOD_NO_AUTH => Ok(()),
                _ => Err(OutboundErr::Proto("server chose unsupported method")),
            }
        }
    }
}

async fn read_method_reply<S>(stream: &mut S) -> Result<u8, OutboundErr>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != VER {
        return Err(OutboundErr::Proto("bad version in method reply"));
    }
    if buf[1] == METHOD_REJECTED {
        return Err(OutboundErr::Proto("server rejected all methods"));
    }
    Ok(buf[1])
}

async fn send_userpass<S>(stream: &mut S, user: &str, pass: &str) -> Result<(), OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if user.len() > 255 {
        return Err(OutboundErr::HostTooLong(user.len()));
    }
    if pass.len() > 255 {
        return Err(OutboundErr::HostTooLong(pass.len()));
    }
    let mut req = [0u8; 1 + 1 + 255 + 1 + 255];
    req[0] = AUTH_VER;
    req[1] = user.len() as u8;
    let mut n = 2;
    req[n..n + user.len()].copy_from_slice(user.as_bytes());
    n += user.len();
    req[n] = pass.len() as u8;
    n += 1;
    req[n..n + pass.len()].copy_from_slice(pass.as_bytes());
    n += pass.len();
    stream.write_all(&req[..n]).await?;
    let mut rep = [0u8; 2];
    stream.read_exact(&mut rep).await?;
    if rep[0] != AUTH_VER {
        return Err(OutboundErr::Proto("bad auth subnegotiation version"));
    }
    if rep[1] != 0 {
        return Err(OutboundErr::Proto("user/pass auth rejected by upstream"));
    }
    Ok(())
}

pub const CONNECT_MAX_LEN: usize = 3 + 1 + 1 + 255 + 2;

pub fn encode_connect_into(
    buf: &mut [u8],
    dst: SocketAddr,
    host: Option<&str>,
) -> Result<usize, OutboundErr> {
    buf[0] = VER;
    buf[1] = CMD_CONNECT;
    buf[2] = 0x00;
    let mut n = match host {
        Some(h) if h.len() <= 255 && !h.is_empty() => {
            buf[3] = ATYP_DOMAIN;
            buf[4] = h.len() as u8;
            buf[5..5 + h.len()].copy_from_slice(h.as_bytes());
            5 + h.len()
        }
        Some(h) => return Err(OutboundErr::HostTooLong(h.len())),
        None => match dst.ip() {
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
        },
    };
    buf[n..n + 2].copy_from_slice(&dst.port().to_be_bytes());
    n += 2;
    Ok(n)
}

pub fn encode_connect(dst: SocketAddr, host: Option<&str>) -> Result<Vec<u8>, OutboundErr> {
    let mut buf = [0u8; CONNECT_MAX_LEN];
    let n = encode_connect_into(&mut buf, dst, host)?;
    Ok(buf[..n].to_vec())
}

pub async fn read_connect_reply<S>(stream: &mut S) -> Result<(), OutboundErr>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(OutboundErr::Proto("bad version in connect reply"));
    }
    if head[1] != REP_SUCCEEDED {
        return Err(OutboundErr::Rejected(head[1]));
    }

    if head[2] != 0x00 {
        return Err(OutboundErr::Proto("RSV != 0 in connect reply"));
    }
    match head[3] {
        ATYP_IPV4 => {
            let mut skip = [0u8; 4 + 2];
            stream.read_exact(&mut skip).await?;
        }
        ATYP_IPV6 => {
            let mut skip = [0u8; 16 + 2];
            stream.read_exact(&mut skip).await?;
        }
        ATYP_DOMAIN => {
            let mut n = [0u8; 1];
            stream.read_exact(&mut n).await?;
            let len = n[0] as usize;

            let mut skip = [0u8; 257];
            stream.read_exact(&mut skip[..len + 2]).await?;
        }
        _ => return Err(OutboundErr::Proto("unknown ATYP in reply")),
    }
    Ok(())
}

pub async fn send_connect<S>(
    stream: &mut S,
    dst: SocketAddr,
    host: Option<&str>,
) -> Result<(), OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; CONNECT_MAX_LEN];
    let n = encode_connect_into(&mut buf, dst, host)?;
    stream.write_all(&buf[..n]).await?;
    read_connect_reply(stream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[test]
    fn encode_connect_ipv4() {
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let bytes = encode_connect(dst, None).unwrap();
        assert_eq!(
            bytes,
            vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB]
        );
    }

    #[test]
    fn encode_connect_ipv6() {
        let dst: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let bytes = encode_connect(dst, None).unwrap();
        assert_eq!(bytes[0..4], [0x05, 0x01, 0x00, 0x04]);
        assert_eq!(&bytes[20..22], &[0, 80]);
        assert_eq!(bytes.len(), 22);
    }

    #[test]
    fn encode_connect_domain() {
        let dst: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let bytes = encode_connect(dst, Some("example.com")).unwrap();
        assert_eq!(bytes[0..4], [0x05, 0x01, 0x00, 0x03]);
        assert_eq!(bytes[4], 11);
        assert_eq!(&bytes[5..16], b"example.com");
        assert_eq!(&bytes[16..18], &[0x01, 0xBB]);
    }

    #[test]
    fn encode_connect_rejects_long_domain() {
        let dst: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let too_long: String = "a".repeat(256);
        let r = encode_connect(dst, Some(&too_long));
        assert!(matches!(r, Err(OutboundErr::HostTooLong(256))));
    }

    #[tokio::test]
    async fn handshake_roundtrip() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {
            let mut req = [0u8; 3];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req, [VER, 0x01, METHOD_NO_AUTH]);
            server.write_all(&[VER, METHOD_NO_AUTH]).await.unwrap();
        });
        handshake_no_auth(&mut client).await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_server_rejects() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {
            let mut req = [0u8; 3];
            server.read_exact(&mut req).await.unwrap();
            server.write_all(&[VER, METHOD_REJECTED]).await.unwrap();
        });
        let r = handshake_no_auth(&mut client).await;
        assert!(matches!(r, Err(OutboundErr::Proto(_))));
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_userpass_ok() {
        let (mut client, mut server) = duplex(128);
        let srv = tokio::spawn(async move {

            let mut g = [0u8; 4];
            server.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [VER, 0x02, METHOD_NO_AUTH, METHOD_USERPASS]);
            server.write_all(&[VER, METHOD_USERPASS]).await.unwrap();

            let mut head = [0u8; 2];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], AUTH_VER);
            let mut user = vec![0u8; head[1] as usize];
            server.read_exact(&mut user).await.unwrap();
            let mut pl = [0u8; 1];
            server.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            server.read_exact(&mut pass).await.unwrap();
            assert_eq!(&user, b"alice");
            assert_eq!(&pass, b"secret");
            server.write_all(&[AUTH_VER, 0x00]).await.unwrap();
        });
        let creds = ("alice".to_string(), "secret".to_string());
        handshake(&mut client, Some(&creds)).await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_userpass_rejected() {
        let (mut client, mut server) = duplex(128);
        let srv = tokio::spawn(async move {
            let mut g = [0u8; 4];
            server.read_exact(&mut g).await.unwrap();
            server.write_all(&[VER, METHOD_USERPASS]).await.unwrap();

            let mut head = [0u8; 2];
            server.read_exact(&mut head).await.unwrap();
            let mut user = vec![0u8; head[1] as usize];
            server.read_exact(&mut user).await.unwrap();
            let mut pl = [0u8; 1];
            server.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            server.read_exact(&mut pass).await.unwrap();
            server.write_all(&[AUTH_VER, 0x01]).await.unwrap();
        });
        let creds = ("alice".to_string(), "wrong".to_string());
        let r = handshake(&mut client, Some(&creds)).await;
        assert!(matches!(r, Err(OutboundErr::Proto(_))));
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_userpass_server_picks_noauth() {

        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {
            let mut g = [0u8; 4];
            server.read_exact(&mut g).await.unwrap();
            server.write_all(&[VER, METHOD_NO_AUTH]).await.unwrap();
        });
        let creds = ("u".to_string(), "p".to_string());
        handshake(&mut client, Some(&creds)).await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn connect_reply_parsed() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {

            server
                .write_all(&[VER, REP_SUCCEEDED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0x01, 0xBB])
                .await
                .unwrap();
        });
        read_connect_reply(&mut client).await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn connect_reply_rejected() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {
            server
                .write_all(&[
                    VER, 0x05,
                    0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0,
                ])
                .await
                .unwrap();
        });
        let r = read_connect_reply(&mut client).await;
        assert!(matches!(r, Err(OutboundErr::Rejected(0x05))));
        srv.await.unwrap();
    }
}
