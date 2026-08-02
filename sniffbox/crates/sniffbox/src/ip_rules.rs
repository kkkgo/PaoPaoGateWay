// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::LazyLock;

type Group = (&'static str, &'static [&'static str]);

const TELEGRAM_CIDRS: &[&str] = &[
    "91.105.192.0/23",
    "91.108.4.0/22",
    "91.108.8.0/21",
    "91.108.16.0/21",
    "91.108.56.0/22",
    "95.161.64.0/20",
    "149.154.160.0/20",
    "185.76.151.0/24",
    "2001:67c:4e8::/48",
    "2001:b28:f23c::/47",
    "2001:b28:f23f::/48",
    "2a0a:f280::/32",
];

const CLOUDFLARED_EDGE_CIDRS: &[&str] = &[
    "198.41.192.0/24",
    "198.41.200.0/24",
    "2606:4700:a0::/48",
    "2606:4700:a8::/48",
];

const GROUPS: &[Group] = &[
    ("telegram", TELEGRAM_CIDRS),
    (crate::cf_ctl::CF_LABEL, CLOUDFLARED_EDGE_CIDRS),
];

static NETS: LazyLock<Vec<(&'static str, Vec<IpNet>)>> = LazyLock::new(|| {
    GROUPS
        .iter()
        .map(|(label, cidrs)| {
            let nets = cidrs
                .iter()
                .map(|s| s.parse::<IpNet>().expect("static ip-group cidr must parse"))
                .collect();
            (*label, nets)
        })
        .collect()
});

pub fn match_group(ip: IpAddr) -> Option<&'static str> {
    NETS.iter()
        .find(|(_, nets)| nets.iter().any(|n| n.contains(&ip)))
        .map(|(label, _)| *label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_cidrs_parse() {
        let total: usize = GROUPS.iter().map(|(_, c)| c.len()).sum();
        let parsed: usize = NETS.iter().map(|(_, n)| n.len()).sum();
        assert_eq!(total, parsed);
    }

    #[test]
    fn matches_known_telegram_ipv4() {
        assert_eq!(
            match_group("149.154.167.51".parse().unwrap()),
            Some("telegram")
        );
        assert_eq!(match_group("91.108.4.1".parse().unwrap()), Some("telegram"));
        assert_eq!(
            match_group("185.76.151.200".parse().unwrap()),
            Some("telegram")
        );
    }

    #[test]
    fn matches_known_telegram_ipv6() {
        assert_eq!(
            match_group("2001:67c:4e8::1".parse().unwrap()),
            Some("telegram")
        );
        assert_eq!(
            match_group("2a0a:f280:1::1234".parse().unwrap()),
            Some("telegram")
        );
    }

    #[test]
    fn matches_cloudflared_edge_ranges() {
        for ip in crate::cf_edge::BUILTIN_V4 {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(
                match_group(ip),
                Some("cloudflared"),
                "builtin edge {ip} must fall inside the cloudflared group"
            );
        }

        assert_eq!(
            match_group("2606:4700:a0::1".parse().unwrap()),
            Some("cloudflared")
        );
        assert_eq!(
            match_group("2606:4700:a8::10".parse().unwrap()),
            Some("cloudflared")
        );

        assert_eq!(match_group("104.16.0.1".parse().unwrap()), None);
        assert_eq!(match_group("198.41.128.1".parse().unwrap()), None);
    }

    #[test]
    fn rejects_non_group() {
        assert_eq!(match_group("8.8.8.8".parse().unwrap()), None);
        assert_eq!(match_group("1.1.1.1".parse().unwrap()), None);
        assert_eq!(match_group("2606:4700::1".parse().unwrap()), None);

        assert_eq!(match_group("91.105.194.0".parse().unwrap()), None);
    }
}
