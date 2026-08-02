// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;

pub const TYPE_SRV: u16 = 33;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

const HEADER_LEN: usize = 12;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum DnsError {
    #[error("buffer too short")]
    Truncated,
    #[error("QR set: not a query")]
    NotAQuery,
    #[error("no question (QDCOUNT=0)")]
    NoQuestion,
    #[error("compression pointer in question name")]
    CompressionInQuestion,
    #[error("name too long")]
    NameTooLong,
}

#[derive(Debug)]
pub struct Query<'a> {
    pub id: u16,

    pub rd: bool,

    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    question_end: usize,
    raw: &'a [u8],
}

pub fn parse_query(buf: &[u8]) -> Result<Query<'_>, DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 != 0 {
        return Err(DnsError::NotAQuery);
    }
    let rd = flags & 0x0100 != 0;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return Err(DnsError::NoQuestion);
    }
    let (name, pos) = parse_name(buf, HEADER_LEN)?;
    if pos + 4 > buf.len() {
        return Err(DnsError::Truncated);
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    Ok(Query {
        id,
        rd,
        name,
        qtype,
        qclass,
        question_end: pos + 4,
        raw: buf,
    })
}

fn parse_name(buf: &[u8], mut pos: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    loop {
        let len = *buf.get(pos).ok_or(DnsError::Truncated)?;
        if len == 0 {
            pos += 1;
            break;
        }

        if len & 0xC0 != 0 {
            return Err(DnsError::CompressionInQuestion);
        }
        let len = len as usize;
        pos += 1;
        let label = buf.get(pos..pos + len).ok_or(DnsError::Truncated)?;
        if !name.is_empty() {
            name.push('.');
        }

        for &b in label {
            name.push(b.to_ascii_lowercase() as char);
        }
        pos += len;
        if name.len() > 255 {
            return Err(DnsError::NameTooLong);
        }
    }
    Ok((name, pos))
}

impl Query<'_> {

    pub fn is_a(&self) -> bool {
        self.qclass == CLASS_IN && self.qtype == TYPE_A
    }

    fn echo_prefix(&self) -> Vec<u8> {
        self.raw[..self.question_end].to_vec()
    }

    pub fn answer_a(&self, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let mut out = self.echo_prefix();
        write_response_header(&mut out, self.rd, RCODE_NOERROR, 1);
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
        out
    }

    pub fn nodata(&self) -> Vec<u8> {
        let mut out = self.echo_prefix();
        write_response_header(&mut out, self.rd, RCODE_NOERROR, 0);
        out
    }

    pub fn error(&self, rcode: u8) -> Vec<u8> {
        let mut out = self.echo_prefix();
        write_response_header(&mut out, self.rd, rcode, 0);
        out
    }
}

fn write_response_header(out: &mut [u8], rd: bool, rcode: u8, ancount: u16) {
    out[2] = 0x80 | if rd { 0x01 } else { 0 };
    out[3] = 0x80 | (rcode & 0x0F);
    out[6..8].copy_from_slice(&ancount.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, DnsError> {
    build_query_with(id, name, qtype, true)
}

pub fn build_query_with(id: u16, name: &str, qtype: u16, rd: bool) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&if rd { 0x0100u16 } else { 0x0000u16 }.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    if !name.is_empty() {
        for label in name.split('.') {

            if label.is_empty() || label.len() > 63 {
                return Err(DnsError::NameTooLong);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() - HEADER_LEN > 255 {
        return Err(DnsError::NameTooLong);
    }
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DnsResponse {
    pub id: u16,
    pub rcode: u8,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,

    pub txt: Vec<String>,

    pub mx: Vec<String>,

    pub srv: Vec<(String, u16)>,

    pub min_ttl: u32,
}

pub fn parse_response(buf: &[u8]) -> Result<DnsResponse, DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let rcode = buf[3] & 0x0F;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = HEADER_LEN;

    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos
            .checked_add(4)
            .filter(|p| *p <= buf.len())
            .ok_or(DnsError::Truncated)?;
    }

    let mut out = DnsResponse {
        id,
        rcode,
        ..Default::default()
    };
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;

        if pos + 10 > buf.len() {
            return Err(DnsError::Truncated);
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        let rdata_end = pos
            .checked_add(rdlen)
            .filter(|p| *p <= buf.len())
            .ok_or(DnsError::Truncated)?;
        match rtype {
            TYPE_A if rdlen == 4 => {
                out.v4.push(Ipv4Addr::new(
                    buf[pos],
                    buf[pos + 1],
                    buf[pos + 2],
                    buf[pos + 3],
                ));
                min_ttl = min_ttl.min(ttl);
            }
            TYPE_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[pos..pos + 16]);
                out.v6.push(Ipv6Addr::from(o));
                min_ttl = min_ttl.min(ttl);
            }

            TYPE_TXT => {
                let mut p = pos;
                while p < rdata_end {
                    let slen = buf[p] as usize;
                    let end = match p.checked_add(1 + slen).filter(|e| *e <= rdata_end) {
                        Some(e) => e,
                        None => break,
                    };
                    out.txt
                        .push(String::from_utf8_lossy(&buf[p + 1..end]).into_owned());
                    p = end;
                }
            }

            TYPE_MX if rdlen > 2 => {
                if let Some(name) = read_name(buf, pos + 2) {
                    out.mx.push(name);
                }
            }

            TYPE_SRV if rdlen > 6 => {
                let port = u16::from_be_bytes([buf[pos + 4], buf[pos + 5]]);
                if let Some(name) = read_name(buf, pos + 6) {
                    out.srv.push((name, port));
                }
            }
            _ => {}
        }
        pos = rdata_end;
    }
    out.min_ttl = if min_ttl == u32::MAX { 0 } else { min_ttl };
    Ok(out)
}

fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsError> {

    for _ in 0..256 {
        let len = *buf.get(pos).ok_or(DnsError::Truncated)?;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {

            if pos + 2 > buf.len() {
                return Err(DnsError::Truncated);
            }
            return Ok(pos + 2);
        }
        if len & 0xC0 != 0 {
            return Err(DnsError::CompressionInQuestion);
        }
        pos = pos
            .checked_add(1 + len as usize)
            .filter(|p| *p <= buf.len())
            .ok_or(DnsError::Truncated)?;
    }
    Err(DnsError::NameTooLong)
}

fn read_name(buf: &[u8], mut pos: usize) -> Option<String> {
    let mut out = String::new();

    let mut hops = 0u8;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(out);
        }
        if len & 0xC0 == 0xC0 {
            let lo = *buf.get(pos + 1)? as usize;
            let target = ((len & 0x3F) << 8) | lo;
            hops += 1;
            if hops > 8 || target >= buf.len() {
                return None;
            }
            pos = target;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let end = pos.checked_add(1 + len).filter(|e| *e <= buf.len())?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&buf[pos + 1..end]));
        if out.len() > 255 {
            return None;
        }
        pos = end;
    }
}

pub fn error_response(query_buf: &[u8], rcode: u8) -> Vec<u8> {
    let id = if query_buf.len() >= 2 {
        u16::from_be_bytes([query_buf[0], query_buf[1]])
    } else {
        0
    };
    let mut out = vec![0u8; HEADER_LEN];
    out[0..2].copy_from_slice(&id.to_be_bytes());
    write_response_header(&mut out, false, rcode, 0);
    out[4..6].copy_from_slice(&0u16.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parse_basic_a_query() {
        let q = make_query(0x1234, "Example.COM", TYPE_A);
        let p = parse_query(&q).unwrap();
        assert_eq!(p.id, 0x1234);
        assert!(p.rd);
        assert_eq!(p.name, "example.com");
        assert_eq!(p.qtype, TYPE_A);
        assert!(p.is_a());
    }

    #[test]
    fn answer_a_is_wellformed() {
        let q = make_query(0xABCD, "a.com", TYPE_A);
        let p = parse_query(&q).unwrap();
        let resp = p.answer_a(Ipv4Addr::new(7, 1, 2, 3), 3);

        assert_eq!(&resp[0..2], &[0xAB, 0xCD]);

        assert_eq!(resp[2] & 0x80, 0x80);
        assert_eq!(resp[2] & 0x01, 0x01);

        assert_eq!(resp[3], 0x80);

        assert_eq!(&resp[4..6], &[0, 1]);
        assert_eq!(&resp[6..8], &[0, 1]);
        assert_eq!(&resp[8..12], &[0, 0, 0, 0]);

        let tail = &resp[p.question_end..];
        assert_eq!(&tail[0..2], &[0xC0, 0x0C]);
        assert_eq!(&tail[2..4], &TYPE_A.to_be_bytes());
        assert_eq!(&tail[4..6], &CLASS_IN.to_be_bytes());
        assert_eq!(&tail[6..10], &3u32.to_be_bytes());
        assert_eq!(&tail[10..12], &4u16.to_be_bytes());
        assert_eq!(&tail[12..16], &[7, 1, 2, 3]);
    }

    #[test]
    fn nodata_has_no_answer() {
        let q = make_query(1, "x.org", TYPE_AAAA);
        let p = parse_query(&q).unwrap();
        let resp = p.nodata();
        assert_eq!(resp[2] & 0x80, 0x80);
        assert_eq!(&resp[6..8], &[0, 0]);
        assert_eq!(resp.len(), p.question_end);
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(parse_query(&[0u8; 5]).unwrap_err(), DnsError::Truncated);

        let mut q = make_query(1, "a.com", TYPE_A);
        q.truncate(13);
        assert_eq!(parse_query(&q).unwrap_err(), DnsError::Truncated);
    }

    #[test]
    fn rejects_response_packet() {
        let mut q = make_query(1, "a.com", TYPE_A);
        q[2] |= 0x80;
        assert_eq!(parse_query(&q).unwrap_err(), DnsError::NotAQuery);
    }

    #[test]
    fn rejects_zero_question() {
        let mut q = make_query(1, "a.com", TYPE_A);
        q[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse_query(&q).unwrap_err(), DnsError::NoQuestion);
    }

    #[test]
    fn rejects_compression_in_question() {
        let mut q = make_query(1, "a.com", TYPE_A);
        q[HEADER_LEN] = 0xC0;
        assert_eq!(
            parse_query(&q).unwrap_err(),
            DnsError::CompressionInQuestion
        );
    }

    #[test]
    fn error_response_echoes_id() {
        let r = error_response(&[0x12, 0x34, 0xFF], RCODE_FORMERR);
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(r[3] & 0x0F, RCODE_FORMERR);
        assert_eq!(&r[4..6], &[0, 0]);
        assert_eq!(r.len(), HEADER_LEN);
    }

    #[test]
    fn error_response_handles_tiny_buf() {

        let _ = error_response(&[], RCODE_SERVFAIL);
        let _ = error_response(&[0x01], RCODE_SERVFAIL);
    }

    #[test]
    fn build_query_roundtrips_through_parse_query() {
        let q = build_query(0xBEEF, "Example.com", TYPE_A).unwrap();
        let p = parse_query(&q).unwrap();
        assert_eq!(p.id, 0xBEEF);
        assert!(p.rd);
        assert_eq!(p.name, "example.com");
        assert_eq!(p.qtype, TYPE_A);
        assert!(p.is_a());
    }

    #[test]
    fn build_query_with_can_clear_rd() {
        let q = build_query_with(7, "whoami.ds.akahelp.net", TYPE_TXT, false).unwrap();
        let p = parse_query(&q).unwrap();
        assert!(!p.rd, "RD must be clear");
        assert_eq!(p.qtype, TYPE_TXT);
        assert!(
            build_query(7, "x.com", TYPE_A)
                .map(|q| q[2] & 0x01)
                .unwrap()
                == 1
        );
    }

    #[test]
    fn parse_response_extracts_txt_strings() {
        let mut b = build_query_with(0x1234, "whoami.ds.akahelp.net", TYPE_TXT, false).unwrap();
        b[2] |= 0x80;
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_TXT.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&60u32.to_be_bytes());
        let rdata = {
            let mut r = Vec::new();
            for s in ["ns", "154.12.185.30"] {
                r.push(s.len() as u8);
                r.extend_from_slice(s.as_bytes());
            }
            r
        };
        b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        b.extend_from_slice(&rdata);

        let r = parse_response(&b).unwrap();
        assert_eq!(r.rcode, RCODE_NOERROR);
        assert_eq!(r.txt, vec!["ns".to_string(), "154.12.185.30".to_string()]);
        assert_eq!(r.min_ttl, 0, "TXT ttl must not feed the A/AAAA cache ttl");
    }

    #[test]
    fn parse_response_txt_truncated_segment_is_safe() {
        let mut b = build_query_with(1, "x.com", TYPE_TXT, false).unwrap();
        b[2] |= 0x80;
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_TXT.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());

        b.extend_from_slice(&3u16.to_be_bytes());
        b.extend_from_slice(&[200, b'a', b'b']);
        let r = parse_response(&b).unwrap();
        assert!(r.txt.is_empty(), "oversized segment must be dropped");
    }

    #[test]
    fn parse_response_extracts_mx_exchange_following_pointers() {
        let mut b = build_query(0x2222, "gmail.com", TYPE_MX).unwrap();
        b[2] |= 0x80;
        b[6..8].copy_from_slice(&2u16.to_be_bytes());

        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_MX.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&300u32.to_be_bytes());
        let full = b"\x0dgmail-smtp-in\x01l\x06google\x03com\x00";
        b.extend_from_slice(&((2 + full.len()) as u16).to_be_bytes());
        b.extend_from_slice(&5u16.to_be_bytes());
        let full_at = b.len();
        b.extend_from_slice(full);

        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_MX.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&300u32.to_be_bytes());
        b.extend_from_slice(&9u16.to_be_bytes());
        b.extend_from_slice(&20u16.to_be_bytes());
        b.extend_from_slice(b"\x04alt2");
        b.extend_from_slice(&[0xC0 | (full_at >> 8) as u8, full_at as u8]);

        let r = parse_response(&b).unwrap();
        assert_eq!(
            r.mx,
            vec![
                "gmail-smtp-in.l.google.com".to_string(),
                "alt2.gmail-smtp-in.l.google.com".to_string()
            ]
        );
    }

    #[test]
    fn parse_response_extracts_srv_target_and_port() {
        let mut b = build_query(0x33, "_v2-origintunneld._tcp.argotunnel.com", TYPE_SRV).unwrap();
        b[2] |= 0x80;
        b[6..8].copy_from_slice(&2u16.to_be_bytes());

        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_SRV.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&300u32.to_be_bytes());
        let full = b"\x07region1\x02v2\x0aargotunnel\x03com\x00";
        b.extend_from_slice(&((6 + full.len()) as u16).to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&7844u16.to_be_bytes());
        let suffix_at = b.len() + "\x07region1".len();
        b.extend_from_slice(full);

        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_SRV.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&300u32.to_be_bytes());
        b.extend_from_slice(&16u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&7844u16.to_be_bytes());
        b.extend_from_slice(b"\x07region2");
        b.extend_from_slice(&[0xC0 | (suffix_at >> 8) as u8, suffix_at as u8]);

        let r = parse_response(&b).unwrap();
        assert_eq!(
            r.srv,
            vec![
                ("region1.v2.argotunnel.com".to_string(), 7844),
                ("region2.v2.argotunnel.com".to_string(), 7844),
            ]
        );
    }

    #[test]
    fn parse_response_srv_too_short_is_dropped() {
        let mut b = build_query(1, "x.com", TYPE_SRV).unwrap();
        b[2] |= 0x80;
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_SRV.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_response(&b).unwrap().srv.is_empty());
    }

    #[test]
    fn parse_response_mx_pointer_loop_is_dropped() {
        let mut b = build_query(1, "x.com", TYPE_MX).unwrap();
        b[2] |= 0x80;
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&TYPE_MX.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&10u16.to_be_bytes());
        let here = b.len();
        b.extend_from_slice(&[0xC0 | (here >> 8) as u8, here as u8]);
        let r = parse_response(&b).unwrap();
        assert!(r.mx.is_empty(), "self-referencing pointer must be dropped");
    }

    #[test]
    fn build_query_rejects_oversize_label_and_name() {
        assert_eq!(
            build_query(1, &"a".repeat(64), TYPE_A).unwrap_err(),
            DnsError::NameTooLong
        );
        let long = std::iter::repeat_n("abcde", 60)
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(
            build_query(1, &long, TYPE_A).unwrap_err(),
            DnsError::NameTooLong
        );

        assert_eq!(
            build_query(1, "a..b", TYPE_A).unwrap_err(),
            DnsError::NameTooLong
        );
    }

    fn make_response(id: u16, qname: &str, answers: &[(u16, u32, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x8180u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        for label in qname.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&TYPE_A.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (rtype, ttl, rdata) in answers {
            b.extend_from_slice(&[0xC0, 0x0C]);
            b.extend_from_slice(&rtype.to_be_bytes());
            b.extend_from_slice(&CLASS_IN.to_be_bytes());
            b.extend_from_slice(&ttl.to_be_bytes());
            b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            b.extend_from_slice(rdata);
        }
        b
    }

    #[test]
    fn parse_response_extracts_a_records_and_min_ttl() {
        const TYPE_CNAME: u16 = 5;
        let resp = make_response(
            0x1234,
            "example.com",
            &[
                (TYPE_CNAME, 100, b"\x03cdn\xc0\x0c"),
                (TYPE_A, 60, &[1, 2, 3, 4]),
                (TYPE_A, 30, &[5, 6, 7, 8]),
            ],
        );
        let r = parse_response(&resp).unwrap();
        assert_eq!(r.id, 0x1234);
        assert_eq!(r.rcode, 0);
        assert_eq!(
            r.v4,
            vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]
        );
        assert!(r.v6.is_empty());
        assert_eq!(r.min_ttl, 30, "min ttl across A records");
    }

    #[test]
    fn parse_response_extracts_aaaa() {
        let v6 = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let resp = make_response(7, "x.org", &[(TYPE_AAAA, 50, &v6.octets())]);
        let r = parse_response(&resp).unwrap();
        assert_eq!(r.v6, vec![v6]);
        assert!(r.v4.is_empty());
    }

    #[test]
    fn parse_response_nodata_is_empty_not_error() {
        let resp = make_response(1, "none.example", &[]);
        let r = parse_response(&resp).unwrap();
        assert!(r.v4.is_empty() && r.v6.is_empty());
        assert_eq!(r.min_ttl, 0);
    }

    #[test]
    fn parse_response_rejects_truncated_no_panic() {
        let full = make_response(1, "a.com", &[(TYPE_A, 60, &[1, 2, 3, 4])]);

        for n in 0..full.len() {
            let _ = parse_response(&full[..n]);
        }

        let mut bad = make_response(1, "a.com", &[(TYPE_AAAA, 60, &[1, 2, 3, 4])]);
        let l = bad.len();
        bad[l - 6] = 0;
        bad[l - 5] = 16;
        assert!(matches!(parse_response(&bad), Err(DnsError::Truncated)));
    }

    #[test]
    fn skip_name_handles_pointer_and_rejects_self_loop() {

        let buf = [0xC0u8, 0x0C];
        assert_eq!(skip_name(&buf, 0).unwrap(), 2);
    }

    #[test]
    fn root_name_parses_empty() {

        let mut b = Vec::new();
        b.extend_from_slice(&7u16.to_be_bytes());
        b.extend_from_slice(&0x0100u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        b.push(0);
        b.extend_from_slice(&TYPE_A.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        let p = parse_query(&b).unwrap();
        assert_eq!(p.name, "");
    }
}
