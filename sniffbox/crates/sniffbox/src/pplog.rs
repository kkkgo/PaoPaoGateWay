// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sb_stats::ConnRecord;
use sb_stats::types::{InboundKind, RecordKind, SniffedProto, Transport};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

const QUEUE_CAP: usize = 4096;

const MAGIC: [u8; 2] = [0x50, 0x4C];

const LEVEL_OPEN: u8 = 10;
const LEVEL_UPDATE: u8 = 11;
const LEVEL_CLOSE: u8 = 12;
const LEVEL_NODE: u8 = 13;

#[derive(Debug)]
pub enum Event {
    Open {
        id: u64,
        ts_sec: u32,
        src: IpAddr,
        inbound: u8,
        transport: u8,
        sniff: u8,
        domain: Option<String>,

        head: Vec<u8>,
    },
    Update {
        id: u64,
        up: u64,
        down: u64,
    },
    Close {
        id: u64,
        up: u64,
        down: u64,
        dur_ms: u32,
        inbound: u8,
    },

    NodeDist {
        nodes: Vec<(String, u64, u64)>,
    },
}

#[derive(Clone)]
pub struct PplogHandle {
    tx: mpsc::Sender<Event>,
    dropped: Arc<AtomicU64>,
}

impl PplogHandle {
    pub fn emit(&self, ev: Event) {
        if self.tx.try_send(ev).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn open(&self, r: &ConnRecord) {
        self.emit(Event::Open {
            id: r.id.0,
            ts_sec: (r.created_epoch_ms / 1000) as u32,
            src: r.src.0,
            inbound: inbound_code(r),
            transport: transport_code(r.transport),
            sniff: sniff_code(r.proto),
            domain: Some(r.display_domain()),
            head: r.head_bytes().unwrap_or_default(),
        });
    }

    pub fn close(&self, r: &ConnRecord) {
        self.emit(Event::Close {
            id: r.id.0,
            up: r.upload.load(Ordering::Relaxed),
            down: r.download.load(Ordering::Relaxed),
            dur_ms: r.started.elapsed().as_millis().min(u32::MAX as u128) as u32,
            inbound: inbound_code(r),
        });
    }

    pub fn node_dist(&self, nodes: Vec<(String, u64, u64)>) {
        if !nodes.is_empty() {
            self.emit(Event::NodeDist { nodes });
        }
    }
}

fn inbound_code(r: &ConnRecord) -> u8 {
    if r.kind == RecordKind::Internal {
        return 3;
    }
    match r.inbound {
        InboundKind::TProxy => 0,
        InboundKind::Socks5 => 1,
        InboundKind::Http => 2,
        InboundKind::HealthCheck => 4,
        InboundKind::Clash(_) => 5,
    }
}

fn transport_code(t: Transport) -> u8 {
    match t {
        Transport::Tcp => 0,
        Transport::Udp => 1,
    }
}

fn sniff_code(p: SniffedProto) -> u8 {
    match p {
        SniffedProto::Unknown => 0,
        SniffedProto::Http => 1,
        SniffedProto::Tls => 2,
        SniffedProto::Quic => 3,
        SniffedProto::Bittorrent => 4,
        SniffedProto::Skipped => 5,
        SniffedProto::IpGroup(_) => 6,
        SniffedProto::FakeIp => 7,
        SniffedProto::RealIp => 8,
        SniffedProto::Socks5 => 9,
        SniffedProto::HttpProxy => 10,
    }
}

pub fn start(addr: SocketAddr, uuid: [u8; 16], shutdown: watch::Receiver<bool>) -> PplogHandle {
    let (tx, rx) = mpsc::channel(QUEUE_CAP);
    let dropped = Arc::new(AtomicU64::new(0));
    tokio::spawn(run(addr, uuid, rx, Arc::clone(&dropped), shutdown));
    tracing::info!(%addr, "pplog reporter started (udp + chacha20-poly1305)");
    PplogHandle { tx, dropped }
}

async fn run(
    addr: SocketAddr,
    uuid: [u8; 16],
    mut rx: mpsc::Receiver<Event>,
    dropped: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) {
    let crypto = Crypto::new(uuid);
    let sock = match bind_connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%addr, %e, "pplog udp bind/connect failed; reporting disabled");
            return;
        }
    };
    let mut seq: u32 = 0;
    let mut payload = Vec::with_capacity(512);
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => { if *shutdown.borrow() { return; } }
            _ = tick.tick() => {
                let d = dropped.swap(0, Ordering::Relaxed);
                if d > 0 {
                    tracing::warn!(dropped = d, "pplog queue overflow dropped events");
                }
            }
            ev = rx.recv() => match ev {
                Some(ev) => {
                    payload.clear();
                    let level = encode_event(&mut payload, &ev);
                    let pkt = crypto.seal(seq, level, &payload);
                    seq = seq.wrapping_add(1);
                    if let Err(e) = sock.send(&pkt).await {
                        tracing::debug!(%e, "pplog udp send failed");
                    }
                }
                None => return,
            }
        }
    }
}

async fn bind_connect(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    Ok(sock)
}

struct Crypto {
    cipher: ChaCha20Poly1305,
    key_hint: [u8; 4],
    session_id: [u8; 4],
}

impl Crypto {
    fn new(uuid: [u8; 16]) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(&Sha256::digest(uuid));
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
        Self {
            cipher,
            key_hint: [key[0], key[1], key[2], key[3]],
            session_id: random4(),
        }
    }

    fn seal(&self, seq: u32, level: u8, payload: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.session_id);
        nonce[4..8].copy_from_slice(&seq.to_be_bytes());

        let mut header = Vec::with_capacity(18);
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(&self.key_hint);
        header.extend_from_slice(&nonce);

        let mut pt = Vec::with_capacity(7 + payload.len());
        pt.extend_from_slice(&seq.to_be_bytes());
        pt.push(level);
        pt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pt.extend_from_slice(payload);

        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: &header,
                },
            )
            .expect("aead encrypt");
        let mut pkt = header;
        pkt.extend_from_slice(&ct);
        pkt
    }
}

fn random4() -> [u8; 4] {
    use std::io::Read;
    let mut b = [0u8; 4];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok()
    {
        return b;
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0);
    t.to_le_bytes()
}

fn encode_event(buf: &mut Vec<u8>, ev: &Event) -> u8 {
    match ev {
        Event::Open {
            id,
            ts_sec,
            src,
            inbound,
            transport,
            sniff,
            domain,
            head,
        } => {
            buf.extend_from_slice(&id.to_be_bytes());
            buf.extend_from_slice(&ts_sec.to_be_bytes());
            buf.push(u8::from(src.is_ipv6()));
            buf.push(*inbound);
            buf.push(*transport);
            buf.push(*sniff);
            match src {
                IpAddr::V4(a) => buf.extend_from_slice(&a.octets()),
                IpAddr::V6(a) => buf.extend_from_slice(&a.octets()),
            }
            push_str(buf, domain.as_deref().unwrap_or(""));

            let hn = head.len().min(8);
            buf.push(hn as u8);
            buf.extend_from_slice(&head[..hn]);
            LEVEL_OPEN
        }
        Event::Update { id, up, down } => {
            buf.extend_from_slice(&id.to_be_bytes());
            buf.extend_from_slice(&up.to_be_bytes());
            buf.extend_from_slice(&down.to_be_bytes());
            LEVEL_UPDATE
        }
        Event::Close {
            id,
            up,
            down,
            dur_ms,
            inbound,
        } => {
            buf.extend_from_slice(&id.to_be_bytes());
            buf.extend_from_slice(&up.to_be_bytes());
            buf.extend_from_slice(&down.to_be_bytes());
            buf.extend_from_slice(&dur_ms.to_be_bytes());
            buf.push(*inbound);
            LEVEL_CLOSE
        }
        Event::NodeDist { nodes } => {

            buf.extend_from_slice(&0u16.to_be_bytes());
            let mut n: u16 = 0;
            for (name, up, down) in nodes {
                if buf.len() + 1 + name.len().min(255) + 16 > 1200 {
                    break;
                }
                push_str(buf, name);
                buf.extend_from_slice(&up.to_be_bytes());
                buf.extend_from_slice(&down.to_be_bytes());
                n += 1;
            }
            buf[0..2].copy_from_slice(&n.to_be_bytes());
            LEVEL_NODE
        }
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    let n = s.len().min(255);
    buf.push(n as u8);
    buf.extend_from_slice(&s.as_bytes()[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    const UUID: [u8; 16] = [
        0x99, 0x0c, 0x7c, 0x49, 0xdb, 0xb2, 0x47, 0x0b, 0xbb, 0x05, 0x2f, 0x82, 0x60, 0x28, 0x17,
        0x59,
    ];

    fn open_packet(uuid: [u8; 16], pkt: &[u8]) -> (u8, Vec<u8>) {
        assert_eq!(&pkt[0..2], &MAGIC);
        let mut key = [0u8; 32];
        key.copy_from_slice(&Sha256::digest(uuid));
        assert_eq!(&pkt[2..6], &key[0..4], "KeyHint matches sha256(uuid)[0:4]");
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let header = &pkt[0..18];
        let nonce = &pkt[6..18];
        let pt = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &pkt[18..],
                    aad: header,
                },
            )
            .expect("decrypt");
        let level = pt[4];
        let plen = u16::from_be_bytes([pt[5], pt[6]]) as usize;
        (level, pt[7..7 + plen].to_vec())
    }

    #[test]
    fn seal_roundtrip_and_keyhint() {
        let c = Crypto::new(UUID);
        let pkt = c.seal(7, LEVEL_OPEN, b"hello");
        let (lvl, payload) = open_packet(UUID, &pkt);
        assert_eq!(lvl, LEVEL_OPEN);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn wrong_uuid_fails_decrypt() {
        let c = Crypto::new(UUID);
        let pkt = c.seal(0, LEVEL_OPEN, b"x");
        let mut bad = UUID;
        bad[0] ^= 0xff;

        let mut key = [0u8; 32];
        key.copy_from_slice(&Sha256::digest(bad));
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(&pkt[6..18]),
                    Payload {
                        msg: &pkt[18..],
                        aad: &pkt[0..18]
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn encode_open_fields() {
        let mut buf = Vec::new();
        let level = encode_event(
            &mut buf,
            &Event::Open {
                id: 0x0102030405060708,
                ts_sec: 0x11223344,
                src: "10.0.0.5".parse().unwrap(),
                inbound: 0,
                transport: 0,
                sniff: 8,
                domain: Some("ex.com".into()),
                head: vec![0x2a, 0x31, 0x0d, 0x0a],
            },
        );
        assert_eq!(level, LEVEL_OPEN);
        assert_eq!(&buf[0..8], &0x0102030405060708u64.to_be_bytes());
        assert_eq!(&buf[8..12], &0x11223344u32.to_be_bytes());
        assert_eq!(buf[12], 0);
        assert_eq!(buf[13], 0);
        assert_eq!(buf[15], 8);
        assert_eq!(&buf[16..20], &[10, 0, 0, 5]);
        assert_eq!(buf[20], 6);
        assert_eq!(&buf[21..27], b"ex.com");
        assert_eq!(buf[27], 4);
        assert_eq!(&buf[28..32], &[0x2a, 0x31, 0x0d, 0x0a]);
    }

    #[tokio::test]
    async fn reporter_sends_encrypted_udp() {
        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        let h = start(addr, UUID, rx);
        h.emit(Event::Open {
            id: 42,
            ts_sec: 1700,
            src: "10.10.10.9".parse().unwrap(),
            inbound: 3,
            transport: 0,
            sniff: 2,
            domain: Some("clash.dev".into()),
            head: Vec::new(),
        });
        let mut buf = [0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(2), srv.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (level, payload) = open_packet(UUID, &buf[..n]);
        assert_eq!(level, LEVEL_OPEN);
        assert_eq!(u64::from_be_bytes(payload[0..8].try_into().unwrap()), 42);
        assert_eq!(payload[13], 3);
        assert_eq!(*payload.last().unwrap(), 0);
        assert!(payload[..payload.len() - 1].ends_with(b"clash.dev"));
    }
}
