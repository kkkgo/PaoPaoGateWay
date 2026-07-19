// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::OutboundErr;
use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, REP_SUCCEEDED, VER, handshake};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub async fn udp_associate<S>(
    stream: &mut S,
    local_hint: SocketAddr,
) -> Result<SocketAddr, OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    udp_associate_auth(stream, local_hint, None).await
}

pub async fn udp_associate_auth<S>(
    stream: &mut S,
    local_hint: SocketAddr,
    auth: Option<&(String, String)>,
) -> Result<SocketAddr, OutboundErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(stream, auth).await?;

    let mut req = [0u8; 22];
    req[0] = VER;
    req[1] = CMD_UDP_ASSOCIATE;
    req[2] = 0x00;
    let n = match local_hint.ip() {
        IpAddr::V4(v4) => {
            req[3] = ATYP_IPV4;
            req[4..8].copy_from_slice(&v4.octets());
            8
        }
        IpAddr::V6(v6) => {
            req[3] = ATYP_IPV6;
            req[4..20].copy_from_slice(&v6.octets());
            20
        }
    };
    req[n..n + 2].copy_from_slice(&local_hint.port().to_be_bytes());
    stream.write_all(&req[..n + 2]).await?;
    read_associate_reply(stream).await
}

async fn read_associate_reply<S>(stream: &mut S) -> Result<SocketAddr, OutboundErr>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(OutboundErr::Proto("bad version in associate reply"));
    }
    if head[1] != REP_SUCCEEDED {
        return Err(OutboundErr::Rejected(head[1]));
    }
    if head[2] != 0x00 {
        return Err(OutboundErr::Proto("RSV != 0 in associate reply"));
    }
    let atyp = head[3];
    let ip: IpAddr = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            IpAddr::V4(Ipv4Addr::from(b))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
        ATYP_DOMAIN => {
            let mut n = [0u8; 1];
            stream.read_exact(&mut n).await?;
            let len = n[0] as usize;

            let mut skip = [0u8; 257];
            stream.read_exact(&mut skip[..len + 2]).await?;

            return Err(OutboundErr::Proto(
                "ASSOCIATE reply with domain not supported",
            ));
        }
        _ => return Err(OutboundErr::Proto("unknown ATYP in associate reply")),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    Ok(SocketAddr::new(ip, port))
}

pub fn encode_udp_request_into(out: &mut Vec<u8>, dst: SocketAddr, payload: &[u8]) {
    out.clear();
    out.reserve(payload.len() + 22);
    out.extend_from_slice(&[0, 0, 0]);
    match dst.ip() {
        IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&dst.port().to_be_bytes());
    out.extend_from_slice(payload);
}

pub fn encode_udp_request_domain_into(
    out: &mut Vec<u8>,
    host: &str,
    dst_port: u16,
    payload: &[u8],
) -> Result<(), OutboundErr> {
    if host.is_empty() || host.len() > 255 {
        return Err(OutboundErr::HostTooLong(host.len()));
    }
    out.clear();
    out.reserve(payload.len() + 5 + host.len() + 2);
    out.extend_from_slice(&[0, 0, 0, ATYP_DOMAIN]);
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

pub fn encode_udp_request(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    encode_udp_request_into(&mut out, dst, payload);
    out
}

pub fn encode_udp_request_domain(
    host: &str,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundErr> {
    let mut out = Vec::with_capacity(payload.len() + 5 + host.len() + 2);
    encode_udp_request_domain_into(&mut out, host, dst_port, payload)?;
    Ok(out)
}

pub fn decode_udp_reply(buf: &[u8]) -> Result<(SocketAddr, usize), OutboundErr> {
    if buf.len() < 4 {
        return Err(OutboundErr::Proto("udp reply too short"));
    }
    if buf[0] != 0 || buf[1] != 0 {
        return Err(OutboundErr::Proto("udp reply RSV != 0"));
    }
    if buf[2] != 0 {
        return Err(OutboundErr::Proto("udp reply fragmented"));
    }
    let atyp = buf[3];
    let (ip, off): (IpAddr, usize) = match atyp {
        ATYP_IPV4 => {
            if buf.len() < 4 + 4 + 2 {
                return Err(OutboundErr::Proto("ipv4 udp reply truncated"));
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&buf[4..8]);
            (IpAddr::V4(Ipv4Addr::from(b)), 8)
        }
        ATYP_IPV6 => {
            if buf.len() < 4 + 16 + 2 {
                return Err(OutboundErr::Proto("ipv6 udp reply truncated"));
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[4..20]);
            (IpAddr::V6(Ipv6Addr::from(b)), 20)
        }
        ATYP_DOMAIN => {
            if buf.len() < 5 {
                return Err(OutboundErr::Proto("domain udp reply truncated"));
            }
            let n = buf[4] as usize;
            let end = 5 + n;
            if buf.len() < end + 2 {
                return Err(OutboundErr::Proto("domain udp reply truncated"));
            }

            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), end)
        }
        _ => return Err(OutboundErr::Proto("unknown ATYP in udp reply")),
    };
    let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
    let payload_off = off + 2;
    Ok((SocketAddr::new(ip, port), payload_off))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks5::{AUTH_VER, METHOD_NO_AUTH, METHOD_USERPASS};
    use tokio::io::duplex;

    #[test]
    fn encode_udp_v4_roundtrip() {
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let pkt = encode_udp_request(dst, b"hello");

        assert_eq!(pkt.len(), 3 + 1 + 4 + 2 + 5);
        assert_eq!(&pkt[0..4], &[0, 0, 0, ATYP_IPV4]);
        assert_eq!(&pkt[4..8], &[1, 2, 3, 4]);
        assert_eq!(&pkt[8..10], &[0x01, 0xBB]);
        assert_eq!(&pkt[10..15], b"hello");

        let (src, off) = decode_udp_reply(&pkt).unwrap();
        assert_eq!(src, dst);
        assert_eq!(&pkt[off..], b"hello");
    }

    #[test]
    fn encode_udp_v6_roundtrip() {
        let dst: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let pkt = encode_udp_request(dst, b"x");
        assert_eq!(pkt[3], ATYP_IPV6);
        let (src, off) = decode_udp_reply(&pkt).unwrap();
        assert_eq!(src, dst);
        assert_eq!(&pkt[off..], b"x");
    }

    #[test]
    fn encode_udp_domain_form() {
        let pkt = encode_udp_request_domain("a.com", 443, b"PING").unwrap();

        assert_eq!(pkt.len(), 3 + 1 + 1 + 5 + 2 + 4);
        assert_eq!(&pkt[0..4], &[0, 0, 0, ATYP_DOMAIN]);
        assert_eq!(pkt[4], 5);
        assert_eq!(&pkt[5..10], b"a.com");
        assert_eq!(&pkt[10..12], &[0x01, 0xBB]);
        assert_eq!(&pkt[12..], b"PING");
    }

    #[test]
    fn encode_udp_domain_rejects_oversize() {
        let big = "a".repeat(256);
        let r = encode_udp_request_domain(&big, 443, b"");
        assert!(matches!(r, Err(OutboundErr::HostTooLong(256))));
    }

    #[test]
    fn fragmented_reply_rejected() {
        let mut pkt = encode_udp_request("1.2.3.4:53".parse().unwrap(), b"q");
        pkt[2] = 1;
        assert!(matches!(decode_udp_reply(&pkt), Err(OutboundErr::Proto(_))));
    }

    #[test]
    fn truncated_reply_rejected() {
        let buf = [0u8, 0, 0, ATYP_IPV4, 1, 2, 3];
        assert!(decode_udp_reply(&buf).is_err());
    }

    #[tokio::test]
    async fn associate_reply_parsed() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {

            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&[VER, METHOD_NO_AUTH]).await.unwrap();

            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], CMD_UDP_ASSOCIATE);

            server
                .write_all(&[VER, REP_SUCCEEDED, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0xC3, 0x50])
                .await
                .unwrap();
        });
        let local = "0.0.0.0:0".parse().unwrap();
        let bnd = udp_associate(&mut client, local).await.unwrap();
        assert_eq!(bnd, "1.2.3.4:50000".parse().unwrap());
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn associate_with_userpass_auth() {
        let (mut client, mut server) = duplex(128);
        let srv = tokio::spawn(async move {

            let mut g = [0u8; 4];
            server.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [VER, 0x02, METHOD_NO_AUTH, METHOD_USERPASS]);
            server.write_all(&[VER, METHOD_USERPASS]).await.unwrap();

            let mut head = [0u8; 2];
            server.read_exact(&mut head).await.unwrap();
            let mut user = vec![0u8; head[1] as usize];
            server.read_exact(&mut user).await.unwrap();
            let mut pl = [0u8; 1];
            server.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            server.read_exact(&mut pass).await.unwrap();
            assert_eq!(&user, b"u");
            assert_eq!(&pass, b"p");
            server.write_all(&[AUTH_VER, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], CMD_UDP_ASSOCIATE);
            server
                .write_all(&[VER, REP_SUCCEEDED, 0x00, ATYP_IPV4, 5, 6, 7, 8, 0xC3, 0x50])
                .await
                .unwrap();
        });
        let creds = ("u".to_string(), "p".to_string());
        let bnd = udp_associate_auth(&mut client, "0.0.0.0:0".parse().unwrap(), Some(&creds))
            .await
            .unwrap();
        assert_eq!(bnd, "5.6.7.8:50000".parse().unwrap());
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn associate_rejected() {
        let (mut client, mut server) = duplex(64);
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&[VER, METHOD_NO_AUTH]).await.unwrap();
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            server
                .write_all(&[VER, 0x01, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let r = udp_associate(&mut client, "0.0.0.0:0".parse().unwrap()).await;
        assert!(matches!(r, Err(OutboundErr::Rejected(0x01))));
        srv.await.unwrap();
    }
}
