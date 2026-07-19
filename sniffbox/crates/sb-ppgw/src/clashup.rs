// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::Io;
use crate::httpcli::{UA_PROBE, agent};
use std::time::{Duration, Instant};

const READY_WAIT: Duration = Duration::from_secs(15);

pub fn cmd_clash_up(io: &mut Io) -> i32 {
    let port = env_or("clash_web_port", "80");
    let url = format!("http://127.0.0.1:{port}/sniffbox/clash/up");
    let ag = match agent("", UA_PROBE, Duration::from_secs(10)) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(
                io.err,
                "{}clash-up agent build failed: {e}",
                crate::term::red("[PaoPaoGW Clash]")
            );
            return 1;
        }
    };
    let deadline = Instant::now() + READY_WAIT;
    loop {
        match ag.post(&url).send_empty() {

            Ok(resp) => {
                let code = resp.status().as_u16();
                if (200..300).contains(&code) {
                    let _ = writeln!(
                        io.out,
                        "{}clash up (HTTP {code})",
                        crate::term::green("[PaoPaoGW Clash]")
                    );
                    return 0;
                }
                let _ = writeln!(
                    io.err,
                    "{}clash-up {url} -> HTTP {code}",
                    crate::term::orange("[PaoPaoGW Clash]")
                );
                return 1;
            }

            Err(e) => {
                if Instant::now() >= deadline {
                    let _ = writeln!(
                        io.err,
                        "{}sniffbox not ready after {}s: {e}",
                        crate::term::orange("[PaoPaoGW Clash]"),
                        READY_WAIT.as_secs()
                    );
                    return 1;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_string(),
    }
}
