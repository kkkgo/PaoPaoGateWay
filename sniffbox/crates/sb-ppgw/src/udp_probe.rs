// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use sb_dns::message::{self, RCODE_NOERROR, TYPE_A, TYPE_MX, TYPE_TXT};
use sb_outbound::socks5_udp::{decode_udp_reply, encode_udp_request_into};

const WHOAMI_NAME: &str = "whoami.ds.akahelp.net";

const AKAHELP_NS: &[(&str, Ipv4Addr)] = &[
    ("a5-67.akam.net", Ipv4Addr::new(95, 100, 168, 67)),
    ("a20-65.akam.net", Ipv4Addr::new(95, 100, 175, 65)),
    ("a14-64.akam.net", Ipv4Addr::new(184, 26, 161, 64)),
    ("a9-64.akam.net", Ipv4Addr::new(184, 85, 248, 64)),
    ("a24-66.akam.net", Ipv4Addr::new(2, 16, 130, 66)),
    ("a1-133.akam.net", Ipv4Addr::new(193, 108, 91, 133)),
];

const REACH_NAME: &str = "gmail.com";

const REACH_HINT: &str = "smtp";

const REACH_RESOLVERS: &[Ipv4Addr] = &[Ipv4Addr::new(208, 67, 222, 222), Ipv4Addr::new(9, 9, 9, 9)];

const BOOTSTRAP: &[Ipv4Addr] = &[
    Ipv4Addr::new(1, 0, 0, 1),
    Ipv4Addr::new(8, 8, 4, 4),
    Ipv4Addr::new(223, 6, 6, 6),
];

const DNS_PORT: u16 = 53;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);

const REACH_BUDGET: Duration = Duration::from_secs(5);

const DIRECT_BUDGET: Duration = Duration::from_secs(11);

const TOTAL_BUDGET: Duration = Duration::from_secs(16);

const RECV_CAP: usize = 4096;

pub enum UdpOutcome {

    Egress {

        ip: IpAddr,

        via: String,

        ms: u64,
    },

    Partial {

        via: String,

        err: String,

        ms: u64,
    },
}

pub fn run(socks_proxy: SocketAddr) -> Result<UdpOutcome, String> {
    let started = Instant::now();

    let (_ctrl, sock) = associate(socks_proxy)?;

    let reach = check_reachable(&sock, started + REACH_BUDGET);
    match find_egress(&sock, started) {
        Ok((ip, via, ms)) => Ok(UdpOutcome::Egress { ip, via, ms }),
        Err(err) => match reach {
            Ok((via, ms)) => Ok(UdpOutcome::Partial { via, err, ms }),

            Err(reach_err) => Err(reach_err),
        },
    }
}

fn dig_cmd(name: &str, qtype: u16, server: Ipv4Addr) -> String {
    let t = match qtype {
        TYPE_MX => "mx ",
        TYPE_TXT => "txt ",
        _ => "",
    };
    format!("dig {t}{name} @{server}")
}

fn check_reachable(sock: &UdpSocket, deadline: Instant) -> Result<(String, u64), String> {
    let mut first_err: Option<String> = None;
    for r in REACH_RESOLVERS {
        let cmd = dig_cmd(REACH_NAME, TYPE_MX, *r);
        if Instant::now() >= deadline {
            first_err.get_or_insert(cmd);
            break;
        }
        let addr = SocketAddr::new(IpAddr::V4(*r), DNS_PORT);
        let t0 = Instant::now();
        match query(sock, addr, REACH_NAME, TYPE_MX, true) {
            Ok(resp) if resp.rcode == RCODE_NOERROR && has_hint(&resp.mx) => {
                return Ok((format!("{REACH_NAME}@{r}"), elapsed_ms(t0)));
            }

            _ => {
                first_err.get_or_insert(cmd);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| dig_cmd(REACH_NAME, TYPE_MX, REACH_RESOLVERS[0])))
}

fn elapsed_ms(t0: Instant) -> u64 {
    t0.elapsed().as_millis() as u64
}

fn has_hint(mx: &[String]) -> bool {
    mx.iter()
        .any(|n| n.to_ascii_lowercase().contains(REACH_HINT))
}

fn find_egress(sock: &UdpSocket, started: Instant) -> Result<(IpAddr, String, u64), String> {
    let first_err = dig_cmd(WHOAMI_NAME, TYPE_TXT, AKAHELP_NS[0].1);
    let direct_deadline = started + DIRECT_BUDGET;
    for (ns_name, ns_ip) in AKAHELP_NS {
        if Instant::now() >= direct_deadline {
            break;
        }
        if let Some(hit) = whoami(sock, ns_name, *ns_ip) {
            return Ok(hit);
        }
    }

    let deadline = started + TOTAL_BUDGET;
    for (ns_name, _) in AKAHELP_NS {
        for boot in BOOTSTRAP {
            if Instant::now() >= deadline {
                return Err(first_err);
            }
            let boot_addr = SocketAddr::new(IpAddr::V4(*boot), DNS_PORT);

            let Ok(r) = query(sock, boot_addr, ns_name, TYPE_A, true) else {
                continue;
            };
            let Some(ns_ip) = r.v4.first().copied() else {
                continue;
            };

            if AKAHELP_NS.iter().any(|(_, known)| *known == ns_ip) {
                continue;
            }
            if let Some(hit) = whoami(sock, ns_name, ns_ip) {
                return Ok(hit);
            }
        }
    }
    Err(first_err)
}

fn whoami(sock: &UdpSocket, ns_name: &str, ns_ip: Ipv4Addr) -> Option<(IpAddr, String, u64)> {
    let addr = SocketAddr::new(IpAddr::V4(ns_ip), DNS_PORT);
    let t0 = Instant::now();
    let r = query(sock, addr, WHOAMI_NAME, TYPE_TXT, false).ok()?;
    if r.rcode != RCODE_NOERROR {
        return None;
    }
    let ip = pick_ip(&r.txt)?;
    Some((ip, format!("{ns_name}@{ns_ip}"), elapsed_ms(t0)))
}

fn pick_ip(txt: &[String]) -> Option<IpAddr> {
    txt.iter().find_map(|s| s.trim().parse::<IpAddr>().ok())
}

fn associate(proxy: SocketAddr) -> Result<(TcpStream, UdpSocket), String> {
    use std::io::Write;
    let mut ctrl = TcpStream::connect_timeout(&proxy, ASSOCIATE_TIMEOUT)
        .map_err(|e| format!("connect {proxy}: {e}"))?;
    ctrl.set_read_timeout(Some(ASSOCIATE_TIMEOUT)).ok();
    ctrl.set_write_timeout(Some(ASSOCIATE_TIMEOUT)).ok();

    ctrl.write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("greeting: {e}"))?;
    let mut rep = [0u8; 2];
    ctrl.read_exact(&mut rep)
        .map_err(|e| format!("greeting reply: {e}"))?;
    if rep != [0x05, 0x00] {
        return Err(format!("socks5 auth rejected: {rep:02x?}"));
    }

    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| format!("associate: {e}"))?;
    let mut head = [0u8; 4];
    ctrl.read_exact(&mut head)
        .map_err(|e| format!("associate reply: {e}"))?;
    if head[0] != 0x05 {
        return Err(format!("bad socks5 version: {:#04x}", head[0]));
    }
    if head[1] != 0x00 {

        return Err(format!("associate rejected: REP={:#04x}", head[1]));
    }
    let bnd = read_bnd(&mut ctrl, head[3])?;

    let relay = if bnd.ip().is_unspecified() {
        SocketAddr::new(proxy.ip(), bnd.port())
    } else {
        bnd
    };

    let sock = UdpSocket::bind(if relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| format!("bind udp: {e}"))?;
    sock.connect(relay)
        .map_err(|e| format!("connect relay {relay}: {e}"))?;
    sock.set_read_timeout(Some(QUERY_TIMEOUT)).ok();
    Ok((ctrl, sock))
}

fn read_bnd(ctrl: &mut TcpStream, atyp: u8) -> Result<SocketAddr, String> {
    let ip = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            ctrl.read_exact(&mut b).map_err(|e| e.to_string())?;
            IpAddr::from(b)
        }
        0x04 => {
            let mut b = [0u8; 16];
            ctrl.read_exact(&mut b).map_err(|e| e.to_string())?;
            IpAddr::from(b)
        }

        a => return Err(format!("unsupported BND ATYP: {a:#04x}")),
    };
    let mut p = [0u8; 2];
    ctrl.read_exact(&mut p).map_err(|e| e.to_string())?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(p)))
}

fn query(
    sock: &UdpSocket,
    server: SocketAddr,
    name: &str,
    qtype: u16,
    rd: bool,
) -> Result<message::DnsResponse, String> {
    let id = query_id();
    let q = message::build_query_with(id, name, qtype, rd).map_err(|e| format!("{e:?}"))?;
    let mut frame = Vec::with_capacity(q.len() + 22);
    encode_udp_request_into(&mut frame, server, &q);
    sock.send(&frame).map_err(|e| format!("send: {e}"))?;

    let until = Instant::now() + QUERY_TIMEOUT;
    let mut buf = vec![0u8; RECV_CAP];
    loop {
        let n = sock.recv(&mut buf).map_err(|e| format!("recv: {e}"))?;
        if let Ok((_, off)) = decode_udp_reply(&buf[..n])
            && let Ok(resp) = message::parse_response(&buf[off..n])
            && resp.id == id
        {
            return Ok(resp);
        }
        if Instant::now() >= until {
            return Err("no matching dns reply".into());
        }
    }
}

fn query_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static SEQ: AtomicU16 = AtomicU16::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    seq ^ nanos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_ip_takes_the_address_segment() {
        assert_eq!(
            pick_ip(&["ns".into(), "154.12.185.30".into()]),
            Some("154.12.185.30".parse().unwrap())
        );
        assert_eq!(
            pick_ip(&["ns".into(), "2001:db8::1".into()]),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(pick_ip(&["ns".into(), "not-an-ip".into()]), None);
        assert_eq!(pick_ip(&[]), None);
    }

    #[test]
    fn has_hint_matches_gmail_exchanges_case_insensitively() {
        assert!(has_hint(&["alt2.gmail-smtp-in.l.google.com".into()]));
        assert!(has_hint(&["ALT1.GMAIL-SMTP-IN.L.GOOGLE.COM".into()]));
        assert!(
            !has_hint(&["mail.example.com".into()]),
            "unrelated exchange must not count as reachable"
        );
        assert!(!has_hint(&[]), "empty answer is not reachable");
    }

    #[test]
    fn budgets_leave_room_for_the_next_stage() {
        assert!(REACH_BUDGET < DIRECT_BUDGET && DIRECT_BUDGET < TOTAL_BUDGET);
        assert!(
            DIRECT_BUDGET - REACH_BUDGET >= QUERY_TIMEOUT * 2,
            "direct whoami needs at least two shots at the built-in NS table"
        );
        assert!(
            TOTAL_BUDGET - DIRECT_BUDGET >= QUERY_TIMEOUT,
            "fallback needs at least one bootstrap round"
        );
    }

    #[test]
    fn dig_cmd_formats_like_the_real_thing() {
        assert_eq!(
            dig_cmd(WHOAMI_NAME, TYPE_TXT, Ipv4Addr::new(95, 100, 168, 67)),
            "dig txt whoami.ds.akahelp.net @95.100.168.67"
        );
        assert_eq!(
            dig_cmd(REACH_NAME, TYPE_MX, Ipv4Addr::new(208, 67, 222, 222)),
            "dig mx gmail.com @208.67.222.222"
        );
        assert_eq!(
            dig_cmd("a20-65.akam.net", TYPE_A, Ipv4Addr::new(1, 0, 0, 1)),
            "dig a20-65.akam.net @1.0.0.1"
        );
    }

    #[test]
    fn builtin_ns_table_is_sane() {
        for (i, (name, ip)) in AKAHELP_NS.iter().enumerate() {
            assert!(name.ends_with(".akam.net"), "unexpected ns name: {name}");
            assert!(
                crate::fallback::is_usable_node_ip(IpAddr::V4(*ip)),
                "{ip} must be a public unicast address (it is queried directly)"
            );
            for (other, other_ip) in &AKAHELP_NS[i + 1..] {
                assert_ne!(name, other, "duplicate ns name");
                assert_ne!(ip, other_ip, "duplicate ns ip");
            }
        }
    }

    #[test]
    fn query_id_varies() {
        let a = query_id();
        let b = query_id();
        assert_ne!(a, b, "consecutive ids must differ");
    }

    #[test]
    fn associate_reports_refusal_when_nothing_listens() {

        let err = associate("127.0.0.1:1".parse().unwrap()).unwrap_err();
        assert!(err.starts_with("connect "), "unexpected error: {err}");
    }
}
