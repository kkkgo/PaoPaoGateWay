// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

pub const FALLBACK_DNS: [&str; 4] = ["223.5.5.5", "119.29.29.29", "8.8.4.4", "1.0.0.1"];

const PPGW_INI: &str = "/tmp/ppgw.ini";

const DEFAULT_FAKE_CIDR: &str = "7.0.0.0/8";

pub fn servers(configured: &[SocketAddr]) -> Vec<SocketAddr> {
    FALLBACK_DNS
        .iter()
        .filter_map(|s| crate::dnsutil::parse_dns_server(s))
        .filter(|f| !configured.iter().any(|c| c.ip() == f.ip()))
        .collect()
}

pub fn server_strings(configured: &[String]) -> Vec<String> {
    let parsed: Vec<SocketAddr> = configured
        .iter()
        .filter_map(|s| crate::dnsutil::parse_dns_server(s))
        .collect();
    servers(&parsed)
        .into_iter()
        .map(|a| a.ip().to_string())
        .collect()
}

pub fn configured_servers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let dns_ip = std::env::var("dns_ip").unwrap_or_default();
    if !dns_ip.is_empty() {
        let dns_port = std::env::var("dns_port").unwrap_or_default();
        let s = if dns_port.is_empty() {
            dns_ip
        } else {
            format!("{dns_ip}:{dns_port}")
        };
        out.extend(crate::dnsutil::parse_dns_server(&s));
    }
    out.extend(crate::dnsutil::ex_dns_env_servers());
    out
}

pub fn is_usable_node_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_usable_v4(v4),
        IpAddr::V6(v6) => {

            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_usable_v4(v4);
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.segments()[..2] == [0x2001, 0x0db8]
                || v6.segments()[..4] == [0x0100, 0, 0, 0])
        }
    }
}

fn is_usable_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if o[0] == 0
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] >= 240
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)

    {
        return false;
    }
    !in_fake_cidr(ip)
}

fn in_fake_cidr(ip: Ipv4Addr) -> bool {
    let (net, prefix) = *fake_cidr();
    if prefix == 0 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn fake_cidr() -> &'static (Ipv4Addr, u32) {
    static CIDR: OnceLock<(Ipv4Addr, u32)> = OnceLock::new();
    CIDR.get_or_init(|| {
        let raw = std::env::var("fake_cidr")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| ini_value(PPGW_INI, "fake_cidr"))
            .unwrap_or_else(|| DEFAULT_FAKE_CIDR.to_string());
        parse_v4_cidr(&raw).unwrap_or_else(|| {
            parse_v4_cidr(DEFAULT_FAKE_CIDR).expect("default fake_cidr is valid")
        })
    })
}

fn ini_value(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    ini_value_in(&text, key)
}

fn ini_value_in(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() != key {
            continue;
        }
        let v = v.trim().trim_matches(['"', '\'']).trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

fn parse_v4_cidr(s: &str) -> Option<(Ipv4Addr, u32)> {
    let (ip, len) = s.trim().split_once('/')?;
    let ip: Ipv4Addr = ip.trim().parse().ok()?;
    let len: u32 = len.trim().parse().ok()?;
    (len <= 32).then_some((ip, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_skips_already_configured() {
        let configured = vec![
            "223.5.5.5:53".parse().unwrap(),
            "8.8.4.4:5353".parse().unwrap(),
        ];
        let got: Vec<String> = servers(&configured)
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        assert_eq!(got, vec!["119.29.29.29", "1.0.0.1"], "{got:?}");

        assert_eq!(servers(&[]).len(), FALLBACK_DNS.len());
    }

    #[test]
    fn fallback_strings_dedup_against_specs() {
        let specs = vec![
            "https://doh.pub/dns-query".to_string(),
            "119.29.29.29".to_string(),
        ];
        let got = server_strings(&specs);
        assert_eq!(got, vec!["223.5.5.5", "8.8.4.4", "1.0.0.1"], "{got:?}");
    }

    #[test]
    fn lan_addresses_stay_usable() {

        for ip in [
            "10.0.0.1",
            "172.16.5.9",
            "192.168.1.1",
            "100.64.0.1",
            "1.2.3.4",
            "104.16.0.1",
        ] {
            assert!(
                is_usable_node_ip(ip.parse().unwrap()),
                "{ip} should be usable"
            );
        }
        assert!(is_usable_node_ip("2606:4700::1111".parse().unwrap()));
        assert!(
            is_usable_node_ip("fd00::1".parse().unwrap()),
            "ULA is the v6 LAN analog"
        );
    }

    #[test]
    fn junk_addresses_rejected() {
        for ip in [
            "7.1.2.3",
            "198.18.0.5",
            "198.19.255.255",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
        ] {
            assert!(
                !is_usable_node_ip(ip.parse().unwrap()),
                "{ip} should be rejected"
            );
        }
        for ip in ["::1", "::", "ff02::1", "fe80::1", "2001:db8::1", "100::1"] {
            assert!(
                !is_usable_node_ip(ip.parse().unwrap()),
                "{ip} should be rejected"
            );
        }

        assert!(!is_usable_node_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_usable_node_ip("::ffff:7.1.2.3".parse().unwrap()));
    }

    #[test]
    fn ini_value_parsing() {
        let ini = "# comment\nudp_enable=true\nfake_cidr = \"28.0.0.0/8\"  # inline\nmax_rec=5000\n";
        assert_eq!(ini_value_in(ini, "fake_cidr").as_deref(), Some("28.0.0.0/8"));
        assert_eq!(ini_value_in(ini, "udp_enable").as_deref(), Some("true"));
        assert_eq!(ini_value_in(ini, "absent"), None);

        assert_eq!(ini_value_in("fake_cidr=\n", "fake_cidr"), None);
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let (net, len) = parse_v4_cidr("198.18.0.0/15").unwrap();
        assert_eq!((net.to_string().as_str(), len), ("198.18.0.0", 15));
        assert!(parse_v4_cidr("7.0.0.0/33").is_none());
        assert!(parse_v4_cidr("notanip/8").is_none());
        assert!(parse_v4_cidr("7.0.0.0").is_none());
    }
}
