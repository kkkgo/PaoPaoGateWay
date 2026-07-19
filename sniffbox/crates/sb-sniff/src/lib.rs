// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub mod bittorrent;
pub mod error;
pub mod http;
pub mod neg_cache;
pub mod peek;
pub mod quic;
pub mod tls;

pub use error::{ParseErr, SniffErr};
pub use neg_cache::SniffNegCache;
pub use peek::{PeekBuf, PeekBufPool, ReplayReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SniffedProto {
    Tls,
    Http,
    Bittorrent,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Sniffed {
    pub proto: SniffedProto,

    pub domain: Option<String>,

    pub ech_outer: bool,
}

impl Sniffed {
    pub const UNKNOWN: Self = Sniffed {
        proto: SniffedProto::Unknown,
        domain: None,
        ech_outer: false,
    };
}

pub fn sniff_all(buf: &[u8]) -> Sniffed {

    if buf.is_empty() {
        return Sniffed::UNKNOWN;
    }
    if let Ok(h) = tls::parse_client_hello(buf) {
        return Sniffed {
            proto: SniffedProto::Tls,
            domain: h.sni.map(str::to_string),
            ech_outer: h.ech_outer,
        };
    }
    if let Ok(host) = http::parse_host(buf) {

        if host.is_some() || looks_like_http_request_line(buf) {
            return Sniffed {
                proto: SniffedProto::Http,
                domain: host.map(str::to_string),
                ech_outer: false,
            };
        }
    }
    if bittorrent::is_bittorrent_handshake(buf) {
        return Sniffed {
            proto: SniffedProto::Bittorrent,
            domain: None,
            ech_outer: false,
        };
    }
    Sniffed::UNKNOWN
}

fn looks_like_http_request_line(buf: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    METHODS.iter().any(|m| buf.starts_with(m))
}
