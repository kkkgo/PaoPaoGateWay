// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sb_outbound::SocksPool;

const CLASH_BIN: &str = "/usr/bin/clash";
const CLASH_DIR: &str = "/etc/config/clash";
pub const CLASH_YAML: &str = "/tmp/clash.yaml";

const CLASH_NOFILE: u64 = 1_048_576;

pub struct ClashSupervisor {

    pid: Mutex<Option<u32>>,

    pool: Option<Arc<SocksPool>>,
}

impl Default for ClashSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ClashSupervisor {

    pub fn new() -> Self {
        Self::with_pool(None)
    }

    pub fn with_pool(pool: Option<Arc<SocksPool>>) -> Self {
        let adopted = find_clash_pid();
        if let Some(pid) = adopted {
            tracing::info!(pid, "adopted running clash");
        }
        Self {
            pid: Mutex::new(adopted),
            pool,
        }
    }

    fn flush_pool_for_new_clash(&self) {
        if let Some(pool) = &self.pool {
            let dropped = pool.flush_idle();
            if dropped > 0 {
                tracing::info!(dropped, "flushed socks pool for freshly spawned clash");
            }
        }
    }

    pub fn restart(&self) -> io::Result<()> {
        let mut guard = self.pid.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(pid) = (*guard).or_else(find_clash_pid) {
            if proc_is_clash(pid) {

                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                wait_gone(pid, Duration::from_secs(5));
            }
        }
        *guard = None;

        let pid = spawn_clash()?;
        *guard = Some(pid);
        self.flush_pool_for_new_clash();
        tracing::info!(pid, "clash cold-restarted (geo reload)");
        Ok(())
    }
}

fn wait_gone(pid: u32, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !proc_is_clash(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl sb_web::ClashControl for ClashSupervisor {
    fn ensure_up(&self) -> io::Result<bool> {
        let mut guard = self.pid.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(pid) = *guard {
            if proc_is_clash(pid) {
                return Ok(false);
            }
        }

        if let Some(pid) = find_clash_pid() {
            *guard = Some(pid);
            return Ok(false);
        }

        let pid = spawn_clash()?;
        *guard = Some(pid);
        self.flush_pool_for_new_clash();
        tracing::info!(pid, "spawned clash");
        Ok(true)
    }
}

fn spawn_clash() -> io::Result<u32> {
    let mut cmd = Command::new(CLASH_BIN);
    cmd.args(["-d", CLASH_DIR, "-f", CLASH_YAML])
        .env("SAFE_PATHS", "/tmp/")
        .stdin(Stdio::null())

        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            let lim = libc::rlimit {
                rlim_cur: CLASH_NOFILE,
                rlim_max: CLASH_NOFILE,
            };
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

fn proc_is_clash(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "clash")
        .unwrap_or(false)
}

fn find_clash_pid() -> Option<u32> {
    let rd = std::fs::read_dir("/proc").ok()?;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if proc_is_clash(pid) {
            return Some(pid);
        }
    }
    None
}
