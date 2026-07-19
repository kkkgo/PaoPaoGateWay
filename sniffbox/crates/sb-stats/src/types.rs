// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crossbeam_utils::CachePadded;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct ConnId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SniffedProto {
    Tls,
    Http,
    Bittorrent,
    Quic,

    IpGroup(&'static str),

    Skipped,

    FakeIp,

    RealIp,

    Socks5,

    HttpProxy,

    Unknown,
}

impl SniffedProto {

    pub fn as_str(self) -> &'static str {
        match self {
            SniffedProto::Tls => "tls",
            SniffedProto::Http => "http",
            SniffedProto::Bittorrent => "bt",
            SniffedProto::Quic => "quic",
            SniffedProto::IpGroup(label) => label,
            SniffedProto::Skipped => "skip",
            SniffedProto::FakeIp => "FakeIP",
            SniffedProto::RealIp => "RealIP",
            SniffedProto::Socks5 => "SOCKS5",
            SniffedProto::HttpProxy => "httpProxy",
            SniffedProto::Unknown => "",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    TProxy,
    Socks5,
    Http,

    HealthCheck,

    Clash(&'static str),
}
impl InboundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InboundKind::TProxy => "tproxy",
            InboundKind::Socks5 => "socks5",
            InboundKind::Http => "http",
            InboundKind::HealthCheck => "healthcheck",
            InboundKind::Clash(label) => label,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}
impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Normal,
    Internal,
}
impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Normal => "normal",
            RecordKind::Internal => "internal",
        }
    }
}

pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct ConnRecord {
    pub id: ConnId,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    pub domain: Option<String>,
    pub proto: SniffedProto,
    pub upload: CachePadded<AtomicU64>,
    pub download: CachePadded<AtomicU64>,

    pub last_drained_up: AtomicU64,
    pub last_drained_down: AtomicU64,

    pub last_folded_up: AtomicU64,
    pub last_folded_down: AtomicU64,
    pub started: Instant,
    pub last_seen_ms: AtomicU64,

    pub closed_ms: AtomicU64,

    pub created_epoch_ms: u64,

    pub inbound: InboundKind,

    pub transport: Transport,

    pub kind: RecordKind,

    pub head: AtomicU64,
    pub head_len: AtomicU8,

    pub agg_counted: AtomicBool,

    pub socks_src_port: AtomicU16,
}

impl ConnRecord {
    pub fn new(
        id: ConnId,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        proto: SniffedProto,
        domain: Option<String>,
    ) -> Self {
        Self {
            id,
            src,
            dst,
            domain,
            proto,
            upload: CachePadded::new(AtomicU64::new(0)),
            download: CachePadded::new(AtomicU64::new(0)),
            last_drained_up: AtomicU64::new(0),
            last_drained_down: AtomicU64::new(0),
            last_folded_up: AtomicU64::new(0),
            last_folded_down: AtomicU64::new(0),
            started: Instant::now(),
            last_seen_ms: AtomicU64::new(0),
            closed_ms: AtomicU64::new(0),
            created_epoch_ms: now_epoch_ms(),
            inbound: InboundKind::TProxy,
            transport: Transport::Tcp,
            kind: RecordKind::Normal,
            head: AtomicU64::new(0),
            head_len: AtomicU8::new(0),
            agg_counted: AtomicBool::new(false),
            socks_src_port: AtomicU16::new(0),
        }
    }

    pub fn set_head(&self, bytes: &[u8]) {
        let n = bytes.len().min(8);
        if n == 0 {
            return;
        }
        let mut buf = [0u8; 8];
        buf[..n].copy_from_slice(&bytes[..n]);
        self.head.store(u64::from_be_bytes(buf), Ordering::Relaxed);
        self.head_len.store(n as u8, Ordering::Relaxed);
    }

    pub fn head_bytes(&self) -> Option<Vec<u8>> {
        let len = self.head_len.load(Ordering::Relaxed) as usize;
        if len == 0 {
            return None;
        }
        Some(self.head.load(Ordering::Relaxed).to_be_bytes()[..len].to_vec())
    }

    pub fn head_hex(&self) -> Option<String> {
        self.head_bytes()
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
    }

    pub fn with_inbound(mut self, inbound: InboundKind, transport: Transport) -> Self {
        self.inbound = inbound;
        self.transport = transport;
        self
    }

    pub fn internal(id: ConnId, dst: (IpAddr, u16), domain: Option<String>) -> Self {
        let mut r = Self::new(
            id,
            (IpAddr::from([127, 0, 0, 1]), 0),
            dst,
            SniffedProto::Unknown,
            domain,
        );
        r.kind = RecordKind::Internal;
        r
    }

    pub fn display_domain(&self) -> String {
        match &self.domain {
            Some(d) => d.clone(),
            None => self.dst.0.to_string(),
        }
    }

    pub fn add_up(&self, n: u64) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_down(&self, n: u64) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }

    pub fn drain_delta(&self) -> (u64, u64) {
        (
            drain_one(&self.upload, &self.last_drained_up),
            drain_one(&self.download, &self.last_drained_down),
        )
    }

    pub fn fold_delta(&self) -> (u64, u64) {
        (
            drain_one(&self.upload, &self.last_folded_up),
            drain_one(&self.download, &self.last_folded_down),
        )
    }
}

fn drain_one(cur: &AtomicU64, last: &AtomicU64) -> u64 {
    let mut prev = last.load(Ordering::Acquire);
    loop {
        let now = cur.load(Ordering::Acquire);
        if now <= prev {
            return 0;
        }
        match last.compare_exchange_weak(prev, now, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return now - prev,
            Err(observed) => prev = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_delta_is_atomic_and_idempotent() {
        let r = ConnRecord::new(
            ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1234),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            Some("x".into()),
        );
        r.add_up(100);
        r.add_down(200);
        assert_eq!(r.drain_delta(), (100, 200));

        assert_eq!(r.drain_delta(), (0, 0));
        r.add_up(7);
        assert_eq!(r.drain_delta(), (7, 0));
    }

    #[test]
    fn concurrent_drain_conserves_bytes() {
        use std::sync::Arc;
        use std::thread;

        let r = Arc::new(ConnRecord::new(
            ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            None,
        ));
        const ADDS: u64 = 100_000;
        let adder = {
            let r = Arc::clone(&r);
            thread::spawn(move || {
                for _ in 0..ADDS {
                    r.add_up(1);
                }
            })
        };
        let drained = Arc::new(AtomicU64::new(0));
        let mut drainers = Vec::new();
        for _ in 0..3 {
            let r = Arc::clone(&r);
            let drained = Arc::clone(&drained);
            drainers.push(thread::spawn(move || {
                for _ in 0..ADDS {
                    let (du, _) = r.drain_delta();
                    drained.fetch_add(du, Ordering::Relaxed);
                }
            }));
        }
        adder.join().unwrap();
        for d in drainers {
            d.join().unwrap();
        }

        let (tail, _) = r.drain_delta();
        let total = drained.load(Ordering::Relaxed) + tail;
        assert_eq!(total, ADDS, "concurrent drain must conserve exactly, no double-counting or loss");
    }

    #[test]
    fn set_head_roundtrips_to_hex() {
        let r = ConnRecord::new(
            ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::RealIp,
            None,
        );
        assert_eq!(r.head_hex(), None);
        r.set_head(&[0x2a, 0x31, 0x0d, 0x0a]);
        assert_eq!(r.head_hex().as_deref(), Some("2a310d0a"));
        assert_eq!(r.head_bytes().unwrap(), vec![0x2a, 0x31, 0x0d, 0x0a]);

        r.set_head(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(r.head_hex().as_deref(), Some("0102030405060708"));

        r.set_head(&[]);
        assert_eq!(r.head_hex().as_deref(), Some("0102030405060708"));
    }

    #[test]
    fn unknown_label_exports_empty_not_none() {
        assert_eq!(SniffedProto::Unknown.as_str(), "");
        assert_eq!(SniffedProto::FakeIp.as_str(), "FakeIP");
        assert_eq!(SniffedProto::RealIp.as_str(), "RealIP");
        assert_eq!(SniffedProto::Socks5.as_str(), "SOCKS5");
        assert_eq!(SniffedProto::HttpProxy.as_str(), "httpProxy");
    }

    #[test]
    fn atomic_counters_increment() {
        let r = ConnRecord::new(
            ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1234),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            Some("example.com".into()),
        );
        r.add_up(100);
        r.add_up(50);
        r.add_down(1000);
        assert_eq!(r.upload.load(Ordering::Relaxed), 150);
        assert_eq!(r.download.load(Ordering::Relaxed), 1000);
    }
}
