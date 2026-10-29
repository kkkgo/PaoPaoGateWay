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

    pub need_more: bool,
}

impl Sniffed {
    pub const UNKNOWN: Self = Sniffed {
        proto: SniffedProto::Unknown,
        domain: None,
        ech_outer: false,
        need_more: false,
    };
}

pub fn sniff_all(buf: &[u8]) -> Sniffed {

    if buf.is_empty() {
        return Sniffed::UNKNOWN;
    }

    if let Ok(hs) = tls::collect_handshake(buf)
        && let Ok(h) = tls::parse_handshake(&hs)
    {
        return Sniffed {
            proto: SniffedProto::Tls,
            domain: h.sni.map(str::to_string),
            ech_outer: h.ech_outer,
            need_more: false,
        };
    }
    if let Ok((host, head_complete)) = http::parse_head(buf) {

        if host.is_some() || looks_like_http_request_line(buf) {
            return Sniffed {
                proto: SniffedProto::Http,
                domain: host.map(str::to_string),
                ech_outer: false,

                need_more: host.is_none() && !head_complete,
            };
        }
    }
    if bittorrent::is_bittorrent_handshake(buf) {
        return Sniffed {
            proto: SniffedProto::Bittorrent,
            domain: None,
            ech_outer: false,
            need_more: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        let list_len = 3 + name.len();
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&((2 + list_len) as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.push(0x00);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn fragmented(sni: &str, cut: usize) -> Vec<u8> {
        let single = client_hello(sni);
        let hs = &single[5..];
        let mut out = Vec::new();
        for part in [&hs[..cut], &hs[cut..]] {
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn tls_single_record_sniffs_sni() {
        let s = sniff_all(&client_hello("whole.example"));
        assert_eq!(s.proto, SniffedProto::Tls);
        assert_eq!(s.domain.as_deref(), Some("whole.example"));
        assert!(!s.need_more);
    }

    #[test]
    fn tls_split_across_records_still_sniffs_sni() {
        for cut in [1, 4, 30] {
            let s = sniff_all(&fragmented("frag.example", cut));
            assert_eq!(s.proto, SniffedProto::Tls, "cut={cut}");
            assert_eq!(s.domain.as_deref(), Some("frag.example"), "cut={cut}");
        }
    }

    #[test]
    fn truncated_tls_stays_unknown() {
        let buf = client_hello("later.example");
        let s = sniff_all(&buf[..buf.len() - 5]);
        assert_eq!(s.proto, SniffedProto::Unknown);
    }

    #[test]
    fn http_without_host_yet_asks_for_more() {
        let s = sniff_all(b"GET /some/very/long/path HTTP/1.1\r\n");
        assert_eq!(s.proto, SniffedProto::Http);
        assert_eq!(s.domain, None);
        assert!(s.need_more, "header block is still open");
    }

    #[test]
    fn http_with_host_is_final() {
        let s = sniff_all(b"GET / HTTP/1.1\r\nHost: a.example\r\n");
        assert_eq!(s.proto, SniffedProto::Http);
        assert_eq!(s.domain.as_deref(), Some("a.example"));
        assert!(!s.need_more, "host found, nothing better to wait for");
    }

    #[test]
    fn complete_http_head_without_host_is_final() {
        let s = sniff_all(b"GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n");
        assert_eq!(s.proto, SniffedProto::Http);
        assert_eq!(s.domain, None);
        assert!(!s.need_more);
    }
}
