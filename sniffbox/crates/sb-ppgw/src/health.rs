// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::clash::ClashClient;
use crate::httpcli::check_url_connectivity;
use std::thread::sleep;
use std::time::Duration;

const DEFAULT_URL: &str = "http://cp.cloudflare.com/generate_204";

const SOCKS5_LOCAL: &str = crate::HEALTHCHECK_SOCKS5;
const TIMEOUT_MS: u32 = 5000;

pub fn run(config_json: &str, client: &ClashClient, io: &mut crate::Io) -> i32 {
    let cfg: serde_json::Value = match serde_json::from_str(config_json) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(io.out, "[PaoPaoGW Health]Failed to parse config file: {e}");
            return 255;
        }
    };

    run_group_failover(client, &cfg, io);

    let monitor = cfg.get("global_monitor");
    let enable = monitor
        .and_then(|m| m.get("enable"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    if !enable {
        return 0;
    }
    let target = monitor
        .and_then(|m| m.get("url"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_URL);
    let mut retries = monitor
        .and_then(|m| m.get("retries"))
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    if retries <= 0 {
        retries = 3;
    }
    let expected = monitor
        .and_then(|m| m.get("expected_status"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("0");

    for i in 0..=retries {
        match check_url_connectivity(target, SOCKS5_LOCAL, expected) {
            Ok((true, code)) => {
                let _ = writeln!(
                    io.out,
                    "{} {target} Success HTTP CODE: {code}",
                    crate::term::green("[PaoPaoGW Health]")
                );
                return 0;
            }
            Ok((false, code)) => {
                let _ = writeln!(
                    io.out,
                    "{} Failed. {target} CODE:[{code}], Need: {expected}",
                    crate::term::red("[PaoPaoGW Health]")
                );
            }
            Err(e) => {
                let _ = writeln!(io.out, "[PaoPaoGW Health] {target} failed: {e}");
            }
        }
        if i == retries {
            let _ = writeln!(
                io.out,
                "{} Max retries reached. Exiting.",
                crate::term::red("[PaoPaoGW Health]")
            );
            return 255;
        }
        sleep(Duration::from_secs(1));
    }
    255
}

fn run_group_failover(client: &ClashClient, cfg: &serde_json::Value, io: &mut crate::Io) {
    let default_url = cfg
        .get("global_monitor")
        .and_then(|m| m.get("url"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_URL)
        .to_string();
    let Some(groups) = cfg.get("node-groups").and_then(|x| x.as_array()) else {
        return;
    };
    for g in groups {
        if !g.get("failover").and_then(|x| x.as_bool()).unwrap_or(false) {
            continue;
        }

        let speedtest = g
            .get("speedtest_url")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let interval = g.get("interval").and_then(|x| x.as_i64()).unwrap_or(0);
        if !speedtest.is_empty() || interval > 0 {
            continue;
        }
        let name = match g.get("name").and_then(|x| x.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let test_url = g
            .get("monitor_url")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default_url.as_str());
        let expected = g
            .get("expected_status")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let mut retries = g.get("retries").and_then(|x| x.as_i64()).unwrap_or(3);
        if retries < 0 {
            retries = 0;
        }

        let info = match client.get_group_info(name) {
            Ok(i) => i,
            Err(e) => {
                let _ = writeln!(
                    io.out,
                    "[PaoPaoGW Failover] Group {name:?}: lookup failed: {e}"
                );
                continue;
            }
        };
        if !info.typ.eq_ignore_ascii_case("Selector") {
            let _ = writeln!(
                io.out,
                "[PaoPaoGW Failover] Group {name:?}: not a Selector ({}), skip",
                info.typ
            );
            continue;
        }
        if info.now.is_empty() {
            let _ = writeln!(
                io.out,
                "[PaoPaoGW Failover] Group {name:?}: no current node, skip"
            );
            continue;
        }

        let mut node_ok = false;
        for attempt in 0..=retries {
            if client
                .test_node_delay(&info.now, test_url, expected, TIMEOUT_MS)
                .is_ok()
            {
                node_ok = true;
                break;
            }
            if attempt < retries {
                sleep(Duration::from_secs(1));
            }
        }
        if node_ok {
            continue;
        }

        let delays = match client.test_group_delay(name, test_url, expected, TIMEOUT_MS) {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(
                    io.out,
                    "[PaoPaoGW Failover] Group {name:?}: group delay error: {e}"
                );
                continue;
            }
        };
        let best = delays
            .iter()
            .filter(|(_, d)| **d > 0)
            .min_by_key(|(_, d)| **d)
            .map(|(n, _)| n.clone());
        let best = match best {
            Some(b) => b,
            None => {
                let _ = writeln!(
                    io.out,
                    "[PaoPaoGW Failover] Group {name:?}: all timeout, keep current"
                );
                continue;
            }
        };
        if best == info.now {
            continue;
        }
        match client.set_group_selected(name, &best) {
            Ok(()) => {
                let _ = writeln!(
                    io.out,
                    "{} Group {name:?}: switched {} -> {best}",
                    crate::term::green("[PaoPaoGW Failover]"),
                    info.now
                );
            }
            Err(e) => {
                let _ = writeln!(
                    io.out,
                    "[PaoPaoGW Failover] Group {name:?}: switch to {best:?} failed: {e}"
                );
            }
        }
    }
}
