// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::process::Command;

const TABLE: &str = "ppgw";
const CHAIN_INPUT: &str = "ppgw_input";
const CHAIN_TPROXY: &str = "ppgw_tproxy";

const OPENPORT_DPORT: &str = "dport 1080";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NftFacts {

    pub openport_open: Option<bool>,

    pub udp_open: Option<bool>,
}

pub fn read_facts() -> NftFacts {
    match list_table() {
        Some(out) => parse_facts(&out),
        None => NftFacts::default(),
    }
}

fn list_table() -> Option<String> {
    for bin in ["/usr/sbin/nft", "nft"] {
        let out = match Command::new(bin)
            .args(["list", "table", "ip", TABLE])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };
        if !out.status.success() {
            continue;
        }
        return String::from_utf8(out.stdout).ok();
    }
    None
}

fn parse_facts(text: &str) -> NftFacts {
    let mut facts = NftFacts::default();
    let mut chain: Option<&str> = None;

    for line in text.lines() {
        let line = line.trim();
        if line == "}" {
            chain = None;
            continue;
        }
        if let Some(name) = chain_header(line) {

            chain = match name {
                CHAIN_INPUT => {
                    facts.openport_open = Some(true);
                    Some(CHAIN_INPUT)
                }
                CHAIN_TPROXY => {
                    facts.udp_open = Some(true);
                    Some(CHAIN_TPROXY)
                }
                _ => None,
            };
            continue;
        }
        match chain {
            Some(CHAIN_INPUT) if is_drop(line) && line.contains(OPENPORT_DPORT) => {
                facts.openport_open = Some(false);
            }
            Some(CHAIN_TPROXY) if is_drop(line) && is_udp_rule(line) => {
                facts.udp_open = Some(false);
            }
            _ => {}
        }
    }
    facts
}

fn chain_header(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("chain ")?;
    let (name, tail) = rest.split_once(' ')?;
    tail.trim().starts_with('{').then_some(name)
}

fn is_drop(line: &str) -> bool {
    line.split_whitespace().any(|w| w == "drop")
}

fn is_udp_rule(line: &str) -> bool {
    let w: Vec<&str> = line.split_whitespace().collect();
    w.windows(2)
        .any(|p| matches!(p, ["l4proto", "udp"] | ["protocol", "udp"]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: &str = r#"table ip ppgw {
	set localnetwork {
		typeof ip daddr
		flags interval
		elements = { 10.0.0.0/8 }
	}

	chain ppgw_tproxy {
		type filter hook prerouting priority mangle; policy accept;
		ip protocol != { tcp, udp } return
		iif "lo" return
		ip daddr @localnetwork return
		fib daddr type local return
		meta l4proto udp tproxy to 127.0.0.1:1081 meta mark set 1
		ip protocol tcp tproxy to 127.0.0.1:1081 meta mark set 1
	}

	chain ppgw_input {
		type filter hook input priority filter; policy accept;
	}
}
"#;

    const CLOSED: &str = r#"table ip ppgw {
	chain ppgw_tproxy {
		type filter hook prerouting priority mangle; policy accept;
		iif "lo" return
		udp dport 443 reject
		meta l4proto udp drop
		ip protocol tcp tproxy to 127.0.0.1:1081 meta mark set 1
	}

	chain ppgw_input {
		type filter hook input priority filter; policy accept;
		iifname "lo" accept
		meta l4proto { tcp, udp } th dport 1080 drop
	}
}
"#;

    #[test]
    fn empty_input_chain_means_openport_open() {
        let f = parse_facts(OPEN);
        assert_eq!(
            f.openport_open,
            Some(true),
            "empty ppgw_input = not blocked"
        );
        assert_eq!(f.udp_open, Some(true), "udp tproxy rule = udp allowed");
    }

    #[test]
    fn drop_rules_are_detected() {
        let f = parse_facts(CLOSED);
        assert_eq!(f.openport_open, Some(false), "dport 1080 drop = blocked");
        assert_eq!(f.udp_open, Some(false), "meta l4proto udp drop = blocked");
    }

    #[test]
    fn tcp_tproxy_rule_is_not_read_as_udp() {

        let text = "table ip ppgw {\n\tchain ppgw_tproxy {\n\t\tip protocol tcp tproxy to 127.0.0.1:1081 meta mark set 1\n\t}\n}\n";
        assert_eq!(parse_facts(text).udp_open, Some(true));
        assert!(!is_udp_rule("ip protocol tcp tproxy to 127.0.0.1:1081"));
        assert!(is_udp_rule("meta l4proto udp drop"));
    }

    #[test]
    fn dport_1080_in_another_chain_is_ignored() {
        let text = "table ip ppgw {\n\tchain other {\n\t\ttcp dport 1080 drop\n\t}\n\n\tchain ppgw_input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n";
        assert_eq!(parse_facts(text).openport_open, Some(true));
    }

    #[test]
    fn missing_chains_stay_unknown() {
        assert_eq!(parse_facts(""), NftFacts::default());
        assert_eq!(
            parse_facts("table ip nat {\n\tchain prerouting {\n\t}\n}\n"),
            NftFacts::default()
        );
        let only_input =
            "table ip ppgw {\n\tchain ppgw_input {\n\t\tiifname \"lo\" accept\n\t}\n}\n";
        let f = parse_facts(only_input);
        assert_eq!(f.openport_open, Some(true));
        assert_eq!(
            f.udp_open, None,
            "no ppgw_tproxy chain = unknown, not false"
        );
    }

    #[test]
    fn reading_a_missing_table_is_not_a_panic() {

        let _ = read_facts();
    }
}
