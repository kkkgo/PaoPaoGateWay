// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::ParseErr;
use crate::tls;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes128Gcm, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeMap;

const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const QUIC_V1: u32 = 0x0000_0001;

pub fn extract_sni(pkt: &[u8]) -> Result<Option<String>, ParseErr> {
    let mut s = IncrementalSniffer::new();
    s.feed(pkt)?;
    Ok(s.try_take_sni())
}

pub struct IncrementalSniffer {

    pieces: BTreeMap<u64, Vec<u8>>,
    total_bytes: usize,

    done: bool,

    feeds: u32,

    cached_dcid: Vec<u8>,
    cached_keys: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,

    ech_outer: bool,
}

pub fn is_quic_initial(pkt: &[u8]) -> bool {
    parse_long_header_initial(pkt).is_ok()
}

const MAX_TOTAL_CRYPTO: usize = 64 * 1024;

const MAX_PIECES: usize = 64;

const MAX_FEED_ATTEMPTS: u32 = 16;

impl Default for IncrementalSniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalSniffer {
    pub fn new() -> Self {
        Self {
            pieces: BTreeMap::new(),
            total_bytes: 0,
            done: false,
            feeds: 0,
            cached_dcid: Vec::new(),
            cached_keys: None,
            ech_outer: false,
        }
    }

    pub fn ech_outer(&self) -> bool {
        self.ech_outer
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn feed(&mut self, pkt: &[u8]) -> Result<(), ParseErr> {
        if self.done {
            return Ok(());
        }
        self.feeds += 1;
        if self.feeds > MAX_FEED_ATTEMPTS {
            self.pieces.clear();
            self.total_bytes = 0;
            self.done = true;
            return Ok(());
        }
        let init = parse_long_header_initial(pkt)?;

        if self.cached_keys.is_none() || self.cached_dcid != init.dcid {
            self.cached_keys = Some(derive_initial_keys(init.dcid));
            self.cached_dcid.clear();
            self.cached_dcid.extend_from_slice(init.dcid);
        }
        let (key, iv, hp) = self.cached_keys.as_ref().expect("keys just set");
        let plaintext = decrypt_initial(pkt, &init, key, iv, hp)?;
        let new_pieces = extract_crypto_frames(&plaintext)?;
        for (off, data) in new_pieces {
            self.ingest_piece(off, data)?;
        }
        Ok(())
    }

    fn ingest_piece(&mut self, off: u64, data: Vec<u8>) -> Result<(), ParseErr> {
        let old_len = self.pieces.get(&off).map(|v| v.len());

        if old_len == Some(data.len()) {
            return Ok(());
        }

        let is_new_offset = old_len.is_none();
        let projected = self
            .total_bytes
            .saturating_sub(old_len.unwrap_or(0))
            .saturating_add(data.len());
        if (is_new_offset && self.pieces.len() >= MAX_PIECES) || projected > MAX_TOTAL_CRYPTO {
            self.pieces.clear();
            self.total_bytes = 0;
            self.done = true;
            return Err(ParseErr::Malformed("quic crypto buffer limit"));
        }
        self.total_bytes = projected;
        self.pieces.insert(off, data);
        Ok(())
    }

    pub fn try_take_sni(&mut self) -> Option<String> {
        let ch = self.try_reassemble_handshake_record()?;
        let parsed = tls::parse_client_hello(&ch).ok();
        if let Some(h) = &parsed {
            self.ech_outer = h.ech_outer;
        }
        let sni = parsed.and_then(|h| h.sni.map(String::from));
        if sni.is_some() {

            self.pieces.clear();
            self.total_bytes = 0;
            self.done = true;
        }
        sni
    }

    fn try_reassemble_handshake_record(&self) -> Option<Vec<u8>> {

        let mut hs = Vec::with_capacity(self.total_bytes + 5);
        let mut expected = 0u64;
        for (off, data) in &self.pieces {
            if *off != expected {

                return None;
            }
            expected += data.len() as u64;
            hs.extend_from_slice(data);
        }
        if hs.len() < 4 {
            return None;
        }

        let need = 4 + u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
        if hs.len() < need {
            return None;
        }

        let mut wrapped = Vec::with_capacity(5 + hs.len());
        wrapped.push(0x16);
        wrapped.extend_from_slice(&[0x03, 0x01]);
        wrapped.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        wrapped.extend_from_slice(&hs);
        Some(wrapped)
    }
}

fn extract_crypto_frames(plaintext: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, ParseErr> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < plaintext.len() {
        let t = plaintext[p];
        p += 1;
        match t {
            0x00 | 0x01 => {   }
            0x02 | 0x03 => {

                let (_largest, n) = read_varint(&plaintext[p..])?;
                p += n;
                let (_delay, n) = read_varint(&plaintext[p..])?;
                p += n;
                let (rc, n) = read_varint(&plaintext[p..])?;
                p += n;
                let (_first, n) = read_varint(&plaintext[p..])?;
                p += n;
                for _ in 0..rc {
                    let (_g, n) = read_varint(&plaintext[p..])?;
                    p += n;
                    let (_r, n) = read_varint(&plaintext[p..])?;
                    p += n;
                }
                if t == 0x03 {
                    for _ in 0..3 {
                        let (_c, n) = read_varint(&plaintext[p..])?;
                        p += n;
                    }
                }
            }
            0x06 => {
                let (off, n) = read_varint(&plaintext[p..])?;
                p += n;
                let (len, n) = read_varint(&plaintext[p..])?;
                p += n;
                let len = len as usize;
                if p + len > plaintext.len() {
                    return Err(ParseErr::Malformed("crypto frame truncated"));
                }
                out.push((off, plaintext[p..p + len].to_vec()));
                p += len;
            }
            _ => {

                break;
            }
        }
    }
    Ok(out)
}

struct LongHeaderInitial<'a> {

    dcid: &'a [u8],

    pn_offset: usize,

    length: usize,
}

fn parse_long_header_initial(buf: &[u8]) -> Result<LongHeaderInitial<'_>, ParseErr> {
    if buf.len() < 7 {
        return Err(ParseErr::Short {
            need: 7,
            have: buf.len(),
        });
    }
    let byte0 = buf[0];

    if (byte0 & 0xC0) != 0xC0 {
        return Err(ParseErr::Malformed("not long header"));
    }

    if (byte0 >> 4) & 0x03 != 0 {
        return Err(ParseErr::Malformed("not initial type"));
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != QUIC_V1 {
        return Err(ParseErr::Malformed("not quic v1"));
    }
    let mut p = 5usize;
    let dcid_len = buf[p] as usize;
    p += 1;
    if dcid_len > 20 || p + dcid_len > buf.len() {
        return Err(ParseErr::Malformed("bad dcid"));
    }
    let dcid = &buf[p..p + dcid_len];
    p += dcid_len;
    if p >= buf.len() {
        return Err(ParseErr::Short {
            need: p + 1,
            have: buf.len(),
        });
    }
    let scid_len = buf[p] as usize;
    p += 1;
    if scid_len > 20 || p + scid_len > buf.len() {
        return Err(ParseErr::Malformed("bad scid"));
    }
    p += scid_len;

    let (tok_len, tok_n) = read_varint(&buf[p..])?;
    p += tok_n;
    let tok_len = tok_len as usize;
    if p + tok_len > buf.len() {
        return Err(ParseErr::Malformed("bad token"));
    }
    p += tok_len;

    let (length, ln) = read_varint(&buf[p..])?;
    p += ln;
    let length = length as usize;
    if p + length > buf.len() {
        return Err(ParseErr::Short {
            need: p + length,
            have: buf.len(),
        });
    }
    Ok(LongHeaderInitial {
        dcid,
        pn_offset: p,
        length,
    })
}

fn read_varint(buf: &[u8]) -> Result<(u64, usize), ParseErr> {
    if buf.is_empty() {
        return Err(ParseErr::Short { need: 1, have: 0 });
    }
    let prefix = buf[0] >> 6;
    let n = 1usize << prefix;
    if buf.len() < n {
        return Err(ParseErr::Short {
            need: n,
            have: buf.len(),
        });
    }
    let mut v = (buf[0] & 0x3F) as u64;
    for &b in &buf[1..n] {
        v = (v << 8) | b as u64;
    }
    Ok((v, n))
}

fn hkdf_expand_label(prk: &[u8], label: &str, out_len: usize) -> Vec<u8> {

    let label_full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + label_full.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(label_full.len() as u8);
    info.extend_from_slice(label_full.as_bytes());
    info.push(0);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk len for sha256");
    let mut okm = vec![0u8; out_len];
    hk.expand(&info, &mut okm)
        .expect("okm len within sha256 bound");
    okm
}

fn derive_initial_keys(dcid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), dcid);
    let initial_secret = prk.to_vec();
    let client_initial = hkdf_expand_label(&initial_secret, "client in", 32);
    let key = hkdf_expand_label(&client_initial, "quic key", 16);
    let iv = hkdf_expand_label(&client_initial, "quic iv", 12);
    let hp = hkdf_expand_label(&client_initial, "quic hp", 16);
    (key, iv, hp)
}

fn decrypt_initial(
    pkt: &[u8],
    init: &LongHeaderInitial<'_>,
    key: &[u8],
    iv: &[u8],
    hp: &[u8],
) -> Result<Vec<u8>, ParseErr> {
    let pn_off = init.pn_offset;

    if pn_off + 20 > pkt.len() {
        return Err(ParseErr::Short {
            need: pn_off + 20,
            have: pkt.len(),
        });
    }
    let sample = &pkt[pn_off + 4..pn_off + 20];

    let aes = Aes128::new(GenericArray::from_slice(hp));
    let mut block = *GenericArray::from_slice(sample);
    aes.encrypt_block(&mut block);
    let mask = block;

    let mut hdr_and_pn = pkt.to_vec();

    hdr_and_pn[0] ^= mask[0] & 0x0F;
    let pn_len = ((hdr_and_pn[0] & 0x03) as usize) + 1;
    for i in 0..pn_len {
        hdr_and_pn[pn_off + i] ^= mask[1 + i];
    }

    let mut pn: u64 = 0;
    for i in 0..pn_len {
        pn = (pn << 8) | hdr_and_pn[pn_off + i] as u64;
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);
    for i in 0..8 {
        nonce[11 - i] ^= ((pn >> (i * 8)) & 0xFF) as u8;
    }

    let aad_end = pn_off + pn_len;

    let ct_end = pn_off + init.length;
    if ct_end > pkt.len() {
        return Err(ParseErr::Short {
            need: ct_end,
            have: pkt.len(),
        });
    }

    if ct_end < aad_end {
        return Err(ParseErr::Malformed("quic: length shorter than pn_len"));
    }
    let aad = &hdr_and_pn[..aad_end];
    let ct = &hdr_and_pn[aad_end..ct_end];

    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| ParseErr::Malformed("quic parse"))?;
    Ok(pt)
}

#[cfg(test)]
fn reassemble_crypto_to_client_hello(plaintext: &[u8]) -> Result<Vec<u8>, ParseErr> {

    let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut p = 0usize;
    while p < plaintext.len() {
        let frame_type = plaintext[p];
        p += 1;
        match frame_type {
            0x00 => {   }
            0x01 => {   }
            0x06 => {

                let (off, n) = read_varint(&plaintext[p..])?;
                p += n;
                let (len, n2) = read_varint(&plaintext[p..])?;
                p += n2;
                let len = len as usize;
                if p + len > plaintext.len() {
                    return Err(ParseErr::Malformed("quic header"));
                }
                pieces.push((off, plaintext[p..p + len].to_vec()));
                p += len;
            }
            0x02 | 0x03 => {

                return Err(ParseErr::Malformed("quic header"));
            }
            _ => {

                return Err(ParseErr::Malformed("quic header"));
            }
        }
    }
    pieces.sort_by_key(|(o, _)| *o);

    let mut hs = Vec::new();
    let mut expected = 0u64;
    for (off, data) in pieces {
        if off != expected {
            return Err(ParseErr::Malformed("quic header"));
        }
        expected += data.len() as u64;
        hs.extend_from_slice(&data);
    }
    if hs.is_empty() {
        return Err(ParseErr::Malformed("quic header"));
    }

    let mut wrapped = Vec::with_capacity(5 + hs.len());
    wrapped.push(0x16);
    wrapped.extend_from_slice(&[0x03, 0x01]);
    wrapped.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    wrapped.extend_from_slice(&hs);
    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9001_appendix_a_test_vector_decrypts() {

        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let (key, iv, hp) = derive_initial_keys(&dcid);
        assert_eq!(hex::encode(&key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(&iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(&hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn varint_lengths() {
        assert_eq!(read_varint(&[0x25]).unwrap(), (0x25, 1));
        assert_eq!(read_varint(&[0x40, 0x25]).unwrap(), (0x25, 2));
        assert_eq!(read_varint(&[0x80, 0x00, 0x00, 0x25]).unwrap(), (0x25, 4));
    }

    #[test]
    fn rejects_non_long_header() {

        let bad = [0u8; 64];
        assert!(parse_long_header_initial(&bad).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = [0u8; 64];
        buf[0] = 0xC0;
        buf[1..5].copy_from_slice(&0x0000_0099u32.to_be_bytes());
        buf[5] = 0;
        assert!(parse_long_header_initial(&buf).is_err());
    }

    #[test]
    fn reassemble_orders_crypto_and_wraps_record() {

        let mut plaintext = Vec::new();

        plaintext.push(0x06);
        plaintext.push(0x05);
        plaintext.push(0x05);
        plaintext.extend_from_slice(b"world");

        plaintext.push(0x06);
        plaintext.push(0x00);
        plaintext.push(0x05);
        plaintext.extend_from_slice(b"hello");
        let wrapped = reassemble_crypto_to_client_hello(&plaintext).unwrap();

        assert_eq!(&wrapped[0..3], &[0x16, 0x03, 0x01]);
        assert_eq!(&wrapped[5..], b"helloworld");
    }

    #[test]
    fn empty_buf_errors() {
        assert!(extract_sni(&[]).is_err());
    }

    #[test]
    fn is_quic_initial_classifies_without_decrypt() {

        let mut pkt = vec![0xC0u8, 0, 0, 0, 1, 0, 0, 0, 0x04];
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(is_quic_initial(&pkt));

        assert!(!is_quic_initial(
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        ));
        assert!(!is_quic_initial(&[]));
    }

    #[test]
    fn repeated_same_offset_does_not_inflate_total() {
        let mut s = IncrementalSniffer::new();

        for len in 1..=2000usize {
            s.ingest_piece(0, vec![0u8; len])
                .expect("must not hit limit");
            assert_eq!(s.total_bytes, len, "total_bytes should equal current offset=0 segment length");
            assert!(!s.done, "should not be misjudged as over-limit abandonment");
            assert_eq!(s.pieces.len(), 1, "same offset should not increase piece count");
        }
    }

    #[test]
    fn ingest_accounting_tracks_distinct_offsets() {
        let mut s = IncrementalSniffer::new();
        s.ingest_piece(0, vec![0u8; 100]).unwrap();
        s.ingest_piece(100, vec![0u8; 50]).unwrap();
        assert_eq!(s.total_bytes, 150);

        s.ingest_piece(0, vec![0u8; 120]).unwrap();
        assert_eq!(s.total_bytes, 170);
        assert_eq!(s.pieces.len(), 2);
    }

    #[test]
    fn feed_budget_gives_up_after_max_attempts() {
        let mut s = IncrementalSniffer::new();

        let mut pkt = vec![0xC0u8, 0, 0, 0, 1, 0, 0, 0, 0x20];
        pkt.extend_from_slice(&[0u8; 0x20]);
        for _ in 0..MAX_FEED_ATTEMPTS {
            assert!(s.feed(&pkt).is_err(), "decrypt must fail on garbage");
            assert!(!s.is_done(), "budget not yet exhausted");
        }
        assert!(s.feed(&pkt).is_ok(), "past budget: short-circuit Ok");
        assert!(s.is_done(), "sniffer must give up after feed budget");
        assert!(s.try_take_sni().is_none());
    }

    #[test]
    fn fuzz_regression_decrypt_initial_short_length() {
        let crash: &[u8] = &[
            0x01, 0x05, 0x01, 0xc3, 0x00, 0x01, 0xc3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x0a, 0x0a, 0x00, 0x01, 0x01, 0xc3, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x0a, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xff,
            0xff, 0xff, 0xff, 0x01, 0x01, 0x01, 0xc3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xff,
            0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
        ];
        let mut s = IncrementalSniffer::new();

        let mut i = 0;
        while i < crash.len() {
            let take = (crash[i] as usize).max(1).min(crash.len() - i);
            let _ = s.feed(&crash[i..i + take]);
            let _ = s.try_take_sni();
            i += take;
        }

    }
}
