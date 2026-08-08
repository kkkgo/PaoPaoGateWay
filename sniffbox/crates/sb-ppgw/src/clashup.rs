// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::Io;
use crate::httpcli;
use std::time::{Duration, Instant};

const READY_WAIT: Duration = Duration::from_secs(15);
const REQ_TIMEOUT: Duration = Duration::from_secs(10);

pub fn cmd_clash_up(io: &mut Io) -> i32 {
    crate::rt::block_on(run(io))
}

async fn run(io: &mut Io<'_>) -> i32 {
    let port = env_or("clash_web_port", "80");
    let url = format!("http://127.0.0.1:{port}/sniffbox/clash/up");
    let client = httpcli::insecure_client();
    let deadline = Instant::now() + READY_WAIT;
    loop {
        match client.post(&url).timeout(REQ_TIMEOUT).send().await {

            Ok(resp) => {
                let code = resp.status().as_u16();
                if (200..300).contains(&code) {

                    crate::procinfo::touch_ready_marker();
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
                tokio::time::sleep(Duration::from_millis(500)).await;
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
