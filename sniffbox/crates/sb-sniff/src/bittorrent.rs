// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub const BT_HANDSHAKE_PREFIX: &[u8] = b"\x13BitTorrent protocol";

pub fn is_bittorrent_handshake(buf: &[u8]) -> bool {
    buf.starts_with(BT_HANDSHAKE_PREFIX)
}

pub const UTP_HEADER_LEN: usize = 20;

pub const BT_UDP_TRACKER_MAGIC: [u8; 8] = [0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80];

pub fn is_utp_packet(buf: &[u8]) -> bool {
    if buf.len() < UTP_HEADER_LEN {
        return false;
    }
    let b0 = buf[0];
    let version = b0 & 0x0f;
    let ptype = b0 >> 4;
    if version != 1 || ptype > 4 {
        return false;
    }
    let ext = buf[1];

    ext <= 3
}

pub fn is_udp_tracker(buf: &[u8]) -> bool {
    buf.len() >= 16 && buf.starts_with(&BT_UDP_TRACKER_MAGIC)
}

pub fn is_bittorrent_udp_packet(buf: &[u8]) -> bool {
    is_utp_packet(buf) || is_udp_tracker(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tcp_handshake() {
        let mut h = Vec::new();
        h.extend_from_slice(BT_HANDSHAKE_PREFIX);
        h.extend_from_slice(&[0u8; 8]);
        h.extend_from_slice(&[0u8; 20]);
        h.extend_from_slice(&[0u8; 20]);
        assert!(is_bittorrent_handshake(&h));
    }

    #[test]
    fn rejects_http_as_bt_handshake() {
        assert!(!is_bittorrent_handshake(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn rejects_short_tcp_prefix() {
        assert!(!is_bittorrent_handshake(b"\x13BitTor"));
    }

    fn utp_packet(ptype: u8, ext: u8) -> Vec<u8> {
        let mut v = vec![(ptype << 4) | 0x01, ext];
        v.extend_from_slice(&[0u8; UTP_HEADER_LEN - 2]);
        v
    }

    #[test]
    fn detects_utp_st_data() {
        let p = utp_packet(0, 0);
        assert!(is_utp_packet(&p));
    }

    #[test]
    fn detects_utp_st_syn_with_sack_ext() {
        let p = utp_packet(4, 1);
        assert!(is_utp_packet(&p));
    }

    #[test]
    fn rejects_utp_wrong_version() {

        let mut p = utp_packet(0, 0);
        p[0] = 0x02;
        assert!(!is_utp_packet(&p));
    }

    #[test]
    fn rejects_utp_invalid_type() {

        let mut p = utp_packet(0, 0);
        p[0] = (5u8 << 4) | 0x01;
        assert!(!is_utp_packet(&p));
    }

    #[test]
    fn rejects_utp_short() {
        let p = utp_packet(0, 0);
        assert!(!is_utp_packet(&p[..UTP_HEADER_LEN - 1]));
    }

    #[test]
    fn rejects_utp_extension_out_of_range() {
        let mut p = utp_packet(0, 0);
        p[1] = 10;
        assert!(!is_utp_packet(&p));
    }

    #[test]
    fn detects_udp_tracker_connect() {

        let mut p = Vec::new();
        p.extend_from_slice(&BT_UDP_TRACKER_MAGIC);
        p.extend_from_slice(&[0, 0, 0, 0]);
        p.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        assert!(is_udp_tracker(&p));
    }

    #[test]
    fn rejects_too_short_tracker() {
        let short = &BT_UDP_TRACKER_MAGIC[..7];
        assert!(!is_udp_tracker(short));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut p = vec![0u8; 16];
        p[7] = 0x99;
        assert!(!is_udp_tracker(&p));
    }

    #[test]
    fn udp_path_detects_either() {
        let utp = utp_packet(2, 0);
        let tracker = {
            let mut p = BT_UDP_TRACKER_MAGIC.to_vec();
            p.extend_from_slice(&[0u8; 8]);
            p
        };
        assert!(is_bittorrent_udp_packet(&utp));
        assert!(is_bittorrent_udp_packet(&tracker));

        let noise = [0xffu8; 20];
        assert!(!is_bittorrent_udp_packet(&noise));
    }
}
