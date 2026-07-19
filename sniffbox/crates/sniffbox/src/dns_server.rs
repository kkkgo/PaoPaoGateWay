// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use sb_dns::FakeIpPool;
use sb_dns::is_valid_fakeip_domain;
use sb_dns::message::{
    self, CLASS_IN, RCODE_FORMERR, RCODE_NOTIMP, RCODE_NXDOMAIN, TYPE_A, parse_query,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;

pub async fn bind_dns(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}

pub async fn run_dns_server(
    sock: UdpSocket,
    pool: Arc<FakeIpPool>,
    mut shutdown: watch::Receiver<bool>,
) {

    let mut buf = [0u8; 1500];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
            res = sock.recv_from(&mut buf) => match res {
                Ok((n, peer)) => {
                    let resp = handle_query(&buf[..n], &pool);
                    if let Err(e) = sock.send_to(&resp, peer).await {
                        tracing::debug!(%peer, ?e, "dns send_to failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(?e, "dns recv_from error; backoff 50ms");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
    tracing::info!("dns server stopped");
}

fn handle_query(buf: &[u8], pool: &FakeIpPool) -> Vec<u8> {
    let q = match parse_query(buf) {
        Ok(q) => q,
        Err(e) => {
            tracing::debug!(?e, "dns parse failed; FORMERR");
            return message::error_response(buf, RCODE_FORMERR);
        }
    };
    if q.qclass != CLASS_IN {
        return q.error(RCODE_NOTIMP);
    }
    match q.qtype {
        TYPE_A => {

            if !is_valid_fakeip_domain(&q.name) {
                tracing::debug!(name = %q.name, "invalid/reserved domain; no fakeip (NXDOMAIN)");
                return q.error(RCODE_NXDOMAIN);
            }
            let ip = pool.intern(&q.name);
            tracing::debug!(name = %q.name, %ip, "fakeip assigned");
            q.answer_a(ip, pool.ttl())
        }

        _ => q.nodata(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_dns::FakeIpConfig;
    use sb_dns::message::{CLASS_IN, RCODE_NXDOMAIN, TYPE_A, TYPE_AAAA, TYPE_HTTPS};

    fn test_pool() -> Arc<FakeIpPool> {
        Arc::new(
            FakeIpPool::new(FakeIpConfig {
                cidr: "7.0.0.0/8".parse().unwrap(),
                max_entries: 1024,
                ttl: 3,
                shards: 16,
            })
            .unwrap(),
        )
    }

    fn make_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x0100u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    #[test]
    fn a_query_gets_fakeip_and_reverse_resolves() {
        let pool = test_pool();
        let resp = handle_query(&make_query(0x42, "example.com", TYPE_A), &pool);

        assert_eq!(resp[2] & 0x80, 0x80);
        assert_eq!(&resp[6..8], &[0, 1]);

        let ip = std::net::Ipv4Addr::new(
            resp[resp.len() - 4],
            resp[resp.len() - 3],
            resp[resp.len() - 2],
            resp[resp.len() - 1],
        );
        assert!(pool.contains(std::net::IpAddr::V4(ip)));

        assert_eq!(pool.lookback(ip).as_deref(), Some("example.com"));
    }

    #[test]
    fn aaaa_and_https_are_nodata() {
        let pool = test_pool();
        for qt in [TYPE_AAAA, TYPE_HTTPS] {
            let resp = handle_query(&make_query(1, "example.com", qt), &pool);
            assert_eq!(resp[2] & 0x80, 0x80, "QR set");
            assert_eq!(&resp[6..8], &[0, 0], "qtype {qt}: NODATA (ANCOUNT=0)");
        }

        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn malformed_query_is_formerr_no_panic() {
        let pool = test_pool();
        let resp = handle_query(&[0x00, 0x01, 0x02], &pool);
        assert_eq!(resp[3] & 0x0F, RCODE_FORMERR);

        for junk in [&b""[..], &[0xff; 12][..], &[0x00; 1][..]] {
            let _ = handle_query(junk, &pool);
        }
    }

    #[test]
    fn invalid_domain_nxdomain_no_alloc() {
        let pool = test_pool();
        for name in [
            "host.local",
            "x.onion",
            "noTLD",
            "1.2.3.4.in-addr.arpa",
            "under_score.com",
        ] {
            let resp = handle_query(&make_query(9, name, TYPE_A), &pool);
            assert_eq!(resp[2] & 0x80, 0x80, "QR set");
            assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN, "{name}: expected NXDOMAIN");
            assert_eq!(&resp[6..8], &[0, 0], "{name}: no answer");
        }
        assert_eq!(
            pool.len(),
            0,
            "invalid/reserved domains must not allocate fakeip"
        );
    }

    #[test]
    fn same_name_stable_ip() {
        let pool = test_pool();
        let r1 = handle_query(&make_query(1, "stable.com", TYPE_A), &pool);
        let r2 = handle_query(&make_query(2, "stable.com", TYPE_A), &pool);
        assert_eq!(
            r1[r1.len() - 4..],
            r2[r2.len() - 4..],
            "same domain → same fakeip"
        );
    }
}
