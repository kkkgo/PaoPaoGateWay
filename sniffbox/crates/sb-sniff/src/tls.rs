// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::ParseErr;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TlsClientHello<'a> {

    pub version: u16,
    pub sni: Option<&'a str>,
    pub alpns: Vec<&'a [u8]>,

    pub ech_outer: bool,
}

pub fn parse_client_hello(buf: &[u8]) -> Result<TlsClientHello<'_>, ParseErr> {
    let mut r = Reader::new(buf);

    let ct = r.u8()?;
    if ct != 0x16 {
        return Err(ParseErr::NotHandshake);
    }
    let _rec_ver = r.u16()?;
    let rec_len = r.u16()? as usize;
    let rec = r.slice(rec_len)?;

    let mut rr = Reader::new(rec);

    let ht = rr.u8()?;
    if ht != 0x01 {
        return Err(ParseErr::NotClientHello);
    }
    let hs_len = rr.u24()? as usize;
    let body = rr.slice(hs_len)?;

    let mut br = Reader::new(body);
    let legacy_version = br.u16()?;
    let _random = br.slice(32)?;
    let sid_len = br.u8()? as usize;
    br.skip(sid_len)?;
    let cs_len = br.u16()? as usize;
    br.skip(cs_len)?;
    let cm_len = br.u8()? as usize;
    br.skip(cm_len)?;

    let mut out = TlsClientHello {
        version: legacy_version,
        ..Default::default()
    };
    if br.is_empty() {
        return Ok(out);
    }
    let ext_len = br.u16()? as usize;
    let exts = br.slice(ext_len)?;

    let mut er = Reader::new(exts);
    while !er.is_empty() {
        let kind = er.u16()?;
        let len = er.u16()? as usize;
        let body = er.slice(len)?;
        match kind {
            0x0000 => {
                if let Some(sni) = parse_sni_ext(body)? {
                    out.sni = Some(sni);
                }
            }
            0x0010 => {
                out.alpns = parse_alpn_ext(body)?;
            }
            0xfe0d => {

                out.ech_outer = matches!(body.first(), Some(0));
            }
            _ => {}
        }
    }
    Ok(out)
}

fn parse_sni_ext(body: &[u8]) -> Result<Option<&str>, ParseErr> {
    let mut r = Reader::new(body);
    let list_len = r.u16()? as usize;
    let list = r.slice(list_len)?;
    let mut lr = Reader::new(list);
    while !lr.is_empty() {
        let name_type = lr.u8()?;
        let name_len = lr.u16()? as usize;
        let name = lr.slice(name_len)?;
        if name_type == 0x00 {

            return Ok(std::str::from_utf8(name).ok());
        }
    }
    Ok(None)
}

fn parse_alpn_ext(body: &[u8]) -> Result<Vec<&[u8]>, ParseErr> {
    let mut r = Reader::new(body);
    let list_len = r.u16()? as usize;
    let list = r.slice(list_len)?;
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while !lr.is_empty() {
        let n = lr.u8()? as usize;
        let p = lr.slice(n)?;
        out.push(p);
    }
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn need(&self, n: usize) -> Result<(), ParseErr> {
        if self.remaining() < n {
            Err(ParseErr::Short {
                need: n,
                have: self.remaining(),
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8, ParseErr> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, ParseErr> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn u24(&mut self) -> Result<u32, ParseErr> {
        self.need(3)?;
        let b = &self.buf[self.pos..self.pos + 3];
        let v = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        self.pos += 3;
        Ok(v)
    }
    fn slice(&mut self, n: usize) -> Result<&'a [u8], ParseErr> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> Result<(), ParseErr> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch_example_com() -> Vec<u8> {

        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);

        let rec_len_pos = buf.len();
        buf.extend_from_slice(&[0, 0]);

        buf.push(0x01);
        let hs_len_pos = buf.len();
        buf.extend_from_slice(&[0, 0, 0]);

        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x04, 0xc0, 0x2f, 0x00, 0x35]);
        buf.push(0x01);
        buf.push(0x00);

        let ext_len_pos = buf.len();
        buf.extend_from_slice(&[0, 0]);

        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x10, 0x00, 0x0E, 0x00, 0x00, 0x0B]);
        buf.extend_from_slice(b"example.com");

        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x0E, 0x00, 0x0C, 0x02, b'h', b'2', 0x08]);
        buf.extend_from_slice(b"http/1.1");

        let body_len = buf.len() - (hs_len_pos + 3);
        let hs_total = body_len;
        buf[hs_len_pos] = ((hs_total >> 16) & 0xff) as u8;
        buf[hs_len_pos + 1] = ((hs_total >> 8) & 0xff) as u8;
        buf[hs_len_pos + 2] = (hs_total & 0xff) as u8;

        let ext_len = buf.len() - (ext_len_pos + 2);
        buf[ext_len_pos] = ((ext_len >> 8) & 0xff) as u8;
        buf[ext_len_pos + 1] = (ext_len & 0xff) as u8;

        let rec_len = buf.len() - (rec_len_pos + 2);
        buf[rec_len_pos] = ((rec_len >> 8) & 0xff) as u8;
        buf[rec_len_pos + 1] = (rec_len & 0xff) as u8;

        buf
    }

    #[test]
    fn parse_example_com() {
        let buf = ch_example_com();
        let h = parse_client_hello(&buf).expect("parse ok");
        assert_eq!(h.version, 0x0303);
        assert_eq!(h.sni, Some("example.com"));
        assert_eq!(h.alpns.len(), 2);
        assert_eq!(h.alpns[0], b"h2");
        assert_eq!(h.alpns[1], b"http/1.1");
    }

    #[test]
    fn truncated_returns_short() {
        let buf = ch_example_com();

        let r = parse_client_hello(&buf[..5]);
        assert!(matches!(r, Err(ParseErr::Short { .. })));
    }

    #[test]
    fn not_handshake() {
        let buf = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        assert_eq!(parse_client_hello(&buf), Err(ParseErr::NotHandshake));
    }

    #[test]
    fn not_client_hello() {

        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
        buf[3] = 0;
        buf[4] = 4;
        assert_eq!(parse_client_hello(&buf), Err(ParseErr::NotClientHello));
    }

    #[test]
    fn normal_client_hello_has_no_ech() {
        let ch = ch_example_com();
        let h = parse_client_hello(&ch).expect("parse ok");
        assert!(!h.ech_outer);
    }

    fn ch_with_ext(sni: &str, extra_ext: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);
        let rec_len_pos = buf.len();
        buf.extend_from_slice(&[0, 0]);
        buf.push(0x01);
        let hs_len_pos = buf.len();
        buf.extend_from_slice(&[0, 0, 0]);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        buf.push(0x01);
        buf.push(0x00);

        let ext_len_pos = buf.len();
        buf.extend_from_slice(&[0, 0]);

        let name = sni.as_bytes();
        let list_len = 3 + name.len();
        let sni_ext_len = 2 + list_len;
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        buf.extend_from_slice(&(list_len as u16).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name);

        buf.extend_from_slice(extra_ext);

        let hs_total = buf.len() - (hs_len_pos + 3);
        buf[hs_len_pos] = ((hs_total >> 16) & 0xff) as u8;
        buf[hs_len_pos + 1] = ((hs_total >> 8) & 0xff) as u8;
        buf[hs_len_pos + 2] = (hs_total & 0xff) as u8;
        let ext_len = buf.len() - (ext_len_pos + 2);
        buf[ext_len_pos] = ((ext_len >> 8) & 0xff) as u8;
        buf[ext_len_pos + 1] = (ext_len & 0xff) as u8;
        let rec_len = buf.len() - (rec_len_pos + 2);
        buf[rec_len_pos] = ((rec_len >> 8) & 0xff) as u8;
        buf[rec_len_pos + 1] = (rec_len & 0xff) as u8;
        buf
    }

    fn ech_outer_ext() -> Vec<u8> {
        let body = [
            0x00,
            0x00, 0x01, 0x00, 0x01,
            0x2a,
            0x00, 0x02, 0xab, 0xcd,
            0x00, 0x03, 0x11, 0x22, 0x33,
        ];
        let mut ext = vec![0xfe, 0x0d];
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    #[test]
    fn detects_ech_outer_and_keeps_cover_sni() {
        let buf = ch_with_ext("cloudflare-ech.com", &ech_outer_ext());
        let h = parse_client_hello(&buf).expect("parse ok");

        assert_eq!(h.sni, Some("cloudflare-ech.com"));
        assert!(h.ech_outer);
    }

    #[test]
    fn ech_inner_type_not_flagged_as_outer() {

        let mut ext = vec![0xfe, 0x0d, 0x00, 0x01, 0x01];
        let buf = ch_with_ext("example.com", &ext);
        let h = parse_client_hello(&buf).expect("parse ok");
        assert!(!h.ech_outer);

        ext = vec![0xfe, 0x0d, 0x00, 0x00];
        let buf = ch_with_ext("example.com", &ext);
        assert!(!parse_client_hello(&buf).expect("parse ok").ech_outer);
    }
}
