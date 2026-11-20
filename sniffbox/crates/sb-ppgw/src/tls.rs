// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

pub type TlsStream<S> = tokio_btls::SslStream<S>;

pub(crate) fn insecure_connector() -> &'static btls::ssl::SslConnector {
    static CFG: OnceLock<btls::ssl::SslConnector> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut b = btls::ssl::SslConnector::builder(btls::ssl::SslMethod::tls())
            .expect("btls connector builder");
        b.set_verify(btls::ssl::SslVerifyMode::NONE);
        b.build()
    })
}

pub async fn connect<S>(stream: S, host: &str, timeout: Duration) -> Option<TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut cfg = insecure_connector().configure().ok()?;
    cfg.set_verify_hostname(false);
    if host.parse::<IpAddr>().is_ok() {
        cfg.set_use_server_name_indication(false);
    }
    let ssl = cfg.into_ssl(host).ok()?;
    let mut tls = tokio_btls::SslStream::new(ssl, stream).ok()?;
    tokio::time::timeout(timeout, std::pin::Pin::new(&mut tls).connect())
        .await
        .ok()?
        .ok()?;
    Some(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn self_signed() -> btls::ssl::SslAcceptor {
        use btls::{asn1::Asn1Time, bn::BigNum, ec, hash::MessageDigest, nid::Nid, pkey::PKey};
        let group = ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(ec::EcKey::generate(&group).unwrap()).unwrap();
        let mut name = btls::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "probe.example").unwrap();
        let name = name.build();
        let mut cert = btls::x509::X509Builder::new().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let mut acc =
            btls::ssl::SslAcceptor::mozilla_intermediate(btls::ssl::SslMethod::tls()).unwrap();
        acc.set_private_key(&key).unwrap();
        acc.set_certificate(&cert.build()).unwrap();
        acc.build()
    }

    #[tokio::test]
    async fn handshakes_with_sni_and_carries_bytes() {
        let acceptor = self_signed();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = l.accept().await.unwrap();
            let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut s = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            std::pin::Pin::new(&mut s).accept().await.unwrap();
            let sni = s
                .ssl()
                .servername(btls::ssl::NameType::HOST_NAME)
                .map(str::to_string);
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(b"pong").await.unwrap();
            s.shutdown().await.ok();
            (sni, req)
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connect(tcp, "four-words.trycloudflare.com", Duration::from_secs(5))
            .await
            .expect("handshake against a self-signed server must succeed");
        tls.write_all(b"ping").await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.ok();
        assert_eq!(resp, b"pong");
        let (sni, req) = server.await.unwrap();
        assert_eq!(&req, b"ping");
        assert_eq!(sni.as_deref(), Some("four-words.trycloudflare.com"));
    }

    #[tokio::test]
    async fn ip_literal_host_sends_no_sni() {
        let acceptor = self_signed();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = l.accept().await.unwrap();
            let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut s = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            std::pin::Pin::new(&mut s).accept().await.unwrap();
            s.ssl()
                .servername(btls::ssl::NameType::HOST_NAME)
                .map(str::to_string)
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connect(tcp, "127.0.0.1", Duration::from_secs(5)).await;
        assert!(tls.is_some());
        assert_eq!(server.await.unwrap(), None);
    }

    #[tokio::test]
    async fn failed_handshake_is_none_not_a_panic() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((s, _)) = l.accept().await {
                drop(s);
            }
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            connect(tcp, "probe.example", Duration::from_secs(2))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn silent_peer_is_bounded_by_the_timeout() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let started = std::time::Instant::now();
        assert!(
            connect(tcp, "probe.example", Duration::from_millis(300))
                .await
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
