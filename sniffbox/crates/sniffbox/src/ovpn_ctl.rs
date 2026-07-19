// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const OVPN_BIN: &str = "/usr/sbin/openvpn";

pub const OVPN_CONFIG: &str = "/tmp/paopao.ovpn";

const OVPN_TUN: &str = "tun114";

const OVPN_NOFILE: u64 = 1_048_576;

const MONITOR_INTERVAL: Duration = Duration::from_secs(30);

const MAX_RESTARTS_PER_CYCLE: u32 = 2;

const TUN_UP_WAIT: Duration = Duration::from_secs(15);

pub struct OvpnSupervisor {
    inner: Mutex<Inner>,

    tun_ready: Option<Arc<AtomicBool>>,
}

struct Inner {

    pid: Option<u32>,

    config_mtime: Option<SystemTime>,
}

impl Default for OvpnSupervisor {
    fn default() -> Self {
        Self::new(None)
    }
}

impl OvpnSupervisor {

    pub fn new(tun_ready: Option<Arc<AtomicBool>>) -> Self {
        let adopted = find_ovpn_pid();
        if let Some(pid) = adopted {
            tracing::info!(pid, "adopted running openvpn");
        }
        let sup = Self {
            inner: Mutex::new(Inner {
                pid: adopted,

                config_mtime: if adopted.is_some() {
                    config_mtime()
                } else {
                    None
                },
            }),
            tun_ready,
        };
        sup.refresh_ready();
        sup
    }

    fn refresh_ready(&self) {
        if let Some(gate) = &self.tun_ready {
            gate.store(self.is_healthy(), Ordering::Relaxed);
        }
    }

    pub fn ensure_up(&self) -> io::Result<bool> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pid) = g.pid
            && proc_is_ovpn(pid)
        {
            return Ok(false);
        }
        if let Some(pid) = find_ovpn_pid() {
            g.pid = Some(pid);
            return Ok(false);
        }
        if !config_exists() {
            tracing::warn!(config = OVPN_CONFIG, "openvpn config missing; skip spawn (awaiting ppg.sh)");
            return Ok(false);
        }
        let pid = spawn_ovpn()?;
        g.pid = Some(pid);
        g.config_mtime = config_mtime();
        tracing::info!(pid, "spawned openvpn");
        Ok(true)
    }

    pub fn cold_restart(&self) -> io::Result<()> {
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            kill_locked(&mut g);
        }

        delete_tun();
        if !config_exists() {
            tracing::warn!(config = OVPN_CONFIG, "openvpn config missing; cannot cold-restart");
            return Err(io::Error::new(io::ErrorKind::NotFound, "openvpn config missing"));
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let pid = spawn_ovpn()?;
        g.pid = Some(pid);
        g.config_mtime = config_mtime();
        tracing::info!(pid, "openvpn cold-restarted");
        Ok(())
    }

    pub fn kill(&self) {

        if let Some(gate) = &self.tun_ready {
            gate.store(false, Ordering::Relaxed);
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        kill_locked(&mut g);
        delete_tun();
        tracing::info!("openvpn stopped");
    }

    fn is_healthy(&self) -> bool {
        let running = {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.pid.map(proc_is_ovpn).unwrap_or(false) || find_ovpn_pid().is_some()
        };
        running && sb_outbound::direct::device_exists(OVPN_TUN)
    }

    fn config_changed(&self) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match (config_mtime(), g.config_mtime) {
            (Some(now), Some(then)) => now != then,

            (Some(_), None) => true,
            _ => false,
        }
    }
}

fn kill_locked(g: &mut Inner) {
    if let Some(pid) = g.pid.or_else(find_ovpn_pid)
        && proc_is_ovpn(pid)
    {

        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        wait_gone(pid, Duration::from_secs(5));
    }
    g.pid = None;
}

fn spawn_ovpn() -> io::Result<u32> {
    let mut cmd = Command::new(OVPN_BIN);
    cmd.args(["--config", OVPN_CONFIG])
        .stdin(Stdio::null())
        .stdout(tty_or_null())
        .stderr(tty_or_null());

    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            let lim = libc::rlimit {
                rlim_cur: OVPN_NOFILE,
                rlim_max: OVPN_NOFILE,
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

fn delete_tun() {
    if !sb_outbound::direct::device_exists(OVPN_TUN) {
        return;
    }
    let _ = Command::new("ip")
        .args(["link", "delete", OVPN_TUN])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn wait_gone(pid: u32, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !proc_is_ovpn(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tty_or_null() -> Stdio {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty0")
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null())
}

fn proc_is_ovpn(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "openvpn")
        .unwrap_or(false)
}

fn find_ovpn_pid() -> Option<u32> {
    let rd = std::fs::read_dir("/proc").ok()?;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if proc_is_ovpn(pid) {
            return Some(pid);
        }
    }
    None
}

fn config_exists() -> bool {
    std::path::Path::new(OVPN_CONFIG).is_file()
}

fn config_mtime() -> Option<SystemTime> {
    std::fs::metadata(OVPN_CONFIG).and_then(|m| m.modified()).ok()
}

pub fn spawn_monitor(
    sup: std::sync::Arc<OvpnSupervisor>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {

        let s = sup.clone();
        let _ = tokio::task::spawn_blocking(move || {
            s.ensure_up().ok();
            wait_tun_up(TUN_UP_WAIT);
            s.refresh_ready();
        })
        .await;

        let mut tick = tokio::time::interval(MONITOR_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
                _ = tick.tick() => {
                    let sup = sup.clone();

                    let _ = tokio::task::spawn_blocking(move || {
                        monitor_tick(&sup);
                        sup.refresh_ready();
                    })
                    .await;
                }
            }
        }
    });
}

fn monitor_tick(sup: &OvpnSupervisor) {

    if sup.config_changed() {
        tracing::info!("openvpn config changed; cold-restart to reload");
        if let Err(e) = sup.cold_restart() {
            tracing::warn!(?e, "openvpn config-reload cold-restart failed");
        }

        wait_tun_up(TUN_UP_WAIT);
        return;
    }
    if sup.is_healthy() {
        return;
    }

    for attempt in 1..=MAX_RESTARTS_PER_CYCLE {
        tracing::warn!(attempt, max = MAX_RESTARTS_PER_CYCLE,
            "openvpn unhealthy (tun114/process missing); cold-restart");
        match sup.cold_restart() {
            Ok(()) => {
                if wait_tun_up(TUN_UP_WAIT) && sup.is_healthy() {
                    tracing::info!(attempt, "openvpn recovered");
                    return;
                }
            }
            Err(e) => tracing::warn!(attempt, ?e, "openvpn cold-restart failed"),
        }
    }
    tracing::error!(max = MAX_RESTARTS_PER_CYCLE,
        "openvpn still unhealthy after retries; will retry next cycle");
}

fn wait_tun_up(timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if sb_outbound::direct::device_exists(OVPN_TUN) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    sb_outbound::direct::device_exists(OVPN_TUN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adopts_none_when_no_ovpn() {

        let sup = OvpnSupervisor::new(None);
        let g = sup.inner.lock().unwrap();
        assert!(g.pid.is_none() || proc_is_ovpn(g.pid.unwrap()));
    }

    #[test]
    fn proc_is_ovpn_rejects_self() {

        assert!(!proc_is_ovpn(std::process::id()));
    }

    #[test]
    fn config_missing_ensure_up_is_noop() {

        if config_exists() {
            return;
        }
        let sup = OvpnSupervisor::new(None);
        assert!(!sup.ensure_up().unwrap());
    }

    #[test]
    fn config_changed_false_without_file() {
        if config_exists() {
            return;
        }
        let sup = OvpnSupervisor::new(None);
        assert!(!sup.config_changed());
    }
}
