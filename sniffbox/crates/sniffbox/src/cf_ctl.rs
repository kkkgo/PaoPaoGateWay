// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::ConfigSource;
use crate::config::{CfProxyMode, OutboundMode};

pub const CF_BIN: &str = "/usr/bin/cloudflared";

pub const CF_UID: u32 = 7844;
pub const CF_GID: u32 = 7844;

pub const CF_UID_DIRECT: u32 = 7845;
pub const CF_GID_DIRECT: u32 = 7845;

const CF_HOME: &str = "/tmp/cloudflared";
const CF_HOME_DIRECT: &str = "/tmp/cloudflared-direct";

const CF_HOME_FS: &str = "/tmp";

pub const CF_LABEL: &str = "cloudflared";

const METRICS_PROXIED: &str = "127.0.0.1:20241";
const METRICS_DIRECT: &str = "127.0.0.1:20242";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {

    Proxied,

    Direct,
}

impl Egress {

    pub const ALL: [Egress; 2] = [Egress::Direct, Egress::Proxied];

    pub fn as_str(self) -> &'static str {
        match self {
            Egress::Proxied => "proxy",
            Egress::Direct => "direct",
        }
    }

    fn idx(self) -> usize {
        match self {
            Egress::Direct => 0,
            Egress::Proxied => 1,
        }
    }

    pub fn uid_gid(self) -> (u32, u32) {
        match self {
            Egress::Proxied => (CF_UID, CF_GID),
            Egress::Direct => (CF_UID_DIRECT, CF_GID_DIRECT),
        }
    }

    fn home(self) -> &'static str {
        match self {
            Egress::Proxied => CF_HOME,
            Egress::Direct => CF_HOME_DIRECT,
        }
    }

    fn upd_dir(self) -> String {
        format!("{}/upd", self.home())
    }

    fn proxy_arg(self) -> &'static str {
        match self {
            Egress::Proxied => HEALTH_SOCKS5,
            Egress::Direct => "",
        }
    }

    pub fn metrics_addr(self) -> &'static str {
        match self {
            Egress::Proxied => METRICS_PROXIED,
            Egress::Direct => METRICS_DIRECT,
        }
    }

    fn user_name(self) -> &'static str {
        match self {
            Egress::Proxied => "cloudflared",
            Egress::Direct => "cloudflared-direct",
        }
    }

    pub fn from_uid(uid: u32) -> Option<Self> {
        match uid {
            CF_UID => Some(Egress::Proxied),
            CF_UID_DIRECT => Some(Egress::Direct),
            _ => None,
        }
    }
}

const MONITOR_INTERVAL: Duration = Duration::from_secs(30);

const STARTUP_GRACE: Duration = Duration::from_secs(60);

const DOWNLOAD_RETRY_PROXY: Duration = Duration::from_secs(300);

const DOWNLOAD_RETRY_DIRECT: Duration = Duration::from_secs(60);

const UPDATE_TIMEOUT: Duration = Duration::from_secs(180);

const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 3600);

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

const READY_URL: &str = "http://cp.cloudflare.com/generate_204";

const HEALTH_SOCKS5: &str = "socks5h://127.0.0.1:1079";

const CLASH_READY_MARKER: &str = "/tmp/ppgw_clash_ready.ts";

const RELOAD_MARKER: &str = "/tmp/ppgw_reload.ts";

const OVPN_TUN: &str = "tun114";

const CF_RELEASE_BASE: &str = "https://github.com/cloudflare/cloudflared/releases/latest/download/";

const fn cf_asset() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "cloudflared-linux-arm64"
    } else {
        "cloudflared-linux-amd64"
    }
}

const fn cf_elf_machine() -> u16 {
    if cfg!(target_arch = "aarch64") {
        0xb7
    } else {
        0x3e
    }
}

pub struct CloudflaredSupervisor {

    direct: Mutex<Proc>,
    proxied: Mutex<Proc>,

    source: ConfigSource,
    mode: OutboundMode,

    tun_ready: Option<Arc<AtomicBool>>,

    started: Instant,

    logs: Arc<sb_web::LineHistory>,

    start_lock: Mutex<()>,

    global: Mutex<Global>,

    bytes: [crate::cf_metrics::ByteAccum; 2],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum BinaryState {

    Ready,

    EgressDown,

    DownloadFailed,
}

impl BinaryState {

    fn note(self) -> &'static str {
        match self {
            BinaryState::Ready => "",
            BinaryState::EgressDown => "waiting for a usable egress to download cloudflared",
            BinaryState::DownloadFailed => "cloudflared binary missing (download failed)",
        }
    }
}

#[derive(Default)]
struct Global {

    last_download: Option<Instant>,

    last_update: Option<Instant>,

    link_ok: bool,
}

#[derive(Default)]
struct Proc {

    pid: Option<u32>,

    token: Option<String>,

    stamp: Option<String>,

    bin_fp: Option<(u64, std::time::SystemTime)>,

    edges: Vec<String>,

    note: Option<&'static str>,
}

pub struct CfProcStatus {
    pub egress: Egress,
    pub running: bool,
    pub pid: Option<u32>,

    pub uptime: Option<u64>,

    pub wanted: bool,

    pub note: Option<&'static str>,
    pub metrics: &'static str,

    pub edges: Vec<String>,
    pub uid: u32,
}

pub struct CfStatus {

    pub enabled: bool,

    pub proxy_mode: CfProxyMode,

    pub binary: bool,

    pub version: Option<String>,
    pub procs: Vec<CfProcStatus>,
}

impl CloudflaredSupervisor {

    pub fn new(
        source: ConfigSource,
        mode: OutboundMode,
        tun_ready: Option<Arc<AtomicBool>>,
    ) -> Self {
        let mut direct = Proc::default();
        let mut proxied = Proc::default();
        for pid in find_cf_pids() {
            match proc_uid(pid).and_then(Egress::from_uid) {
                Some(Egress::Direct) => {
                    tracing::info!(pid, egress = "direct", "adopted running cloudflared");
                    direct.pid = Some(pid);
                }
                Some(Egress::Proxied) => {
                    tracing::info!(pid, egress = "proxy", "adopted running cloudflared");
                    proxied.pid = Some(pid);
                }

                None => tracing::warn!(pid, "cloudflared running under an unmanaged uid; ignoring"),
            }
        }
        Self {
            direct: Mutex::new(direct),
            proxied: Mutex::new(proxied),
            source,
            mode,
            tun_ready,
            started: Instant::now(),

            logs: sb_web::LineHistory::new(2000),
            start_lock: Mutex::new(()),
            global: Mutex::new(Global::default()),
            bytes: Default::default(),
        }
    }

    fn slot(&self, egress: Egress) -> &Mutex<Proc> {
        match egress {
            Egress::Direct => &self.direct,
            Egress::Proxied => &self.proxied,
        }
    }

    pub fn bytes(&self, egress: Egress) -> &crate::cf_metrics::ByteAccum {
        &self.bytes[egress.idx()]
    }

    fn with_proc<R>(&self, egress: Egress, f: impl FnOnce(&mut Proc) -> R) -> R {
        let mut g = self.slot(egress).lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }

    pub fn logs(&self) -> Arc<sb_web::LineHistory> {
        Arc::clone(&self.logs)
    }

    pub fn status(&self) -> CfStatus {
        let (token, proxy_mode) = self.load_cf_cfg();
        let enabled = token.is_some();
        let procs = Egress::ALL
            .iter()
            .map(|&egress| {
                let wanted = enabled && want_egress(egress, proxy_mode, self.mode);
                self.with_proc(egress, |p| {
                    let pid = p.pid.filter(|pid| proc_is_cf(*pid));
                    CfProcStatus {
                        egress,
                        running: pid.is_some(),
                        pid,
                        uptime: pid.and_then(crate::sysinfo::process_uptime),
                        wanted,

                        note: if !enabled {
                            Some("no token")
                        } else if !wanted {

                            if self.mode == OutboundMode::Free {
                                Some("no separate proxy egress in free mode")
                            } else if egress == Egress::Direct {
                                Some("disabled by cf_proxy=yes")
                            } else {
                                Some("disabled by cf_proxy=no")
                            }
                        } else if pid.is_some() {
                            None
                        } else {
                            p.note.or(Some("starting"))
                        },
                        metrics: egress.metrics_addr(),
                        edges: p.edges.clone(),
                        uid: egress.uid_gid().0,
                    }
                })
            })
            .collect();
        CfStatus {
            enabled,
            proxy_mode,
            binary: Path::new(CF_BIN).is_file(),
            version: Path::new(CF_BIN).is_file().then(cf_version),
            procs,
        }
    }

    pub fn restart(&self, which: Option<Egress>) -> Result<usize, &'static str> {
        let (token, mode) = self.load_cf_cfg();
        if token.is_none() {
            return Err("cloudflared_token not configured");
        }
        if let Some(e) = which
            && !want_egress(e, mode, self.mode)
        {
            return Err("that replica is disabled in this configuration");
        }
        tracing::info!(which = ?which.map(|e| e.as_str()), "cloudflared restart requested via web");

        let _guard = self
            .start_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        {

            let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
            g.last_download = None;
        }

        for egress in Egress::ALL {
            if which.is_none_or(|w| w == egress) {
                self.kill_one(egress);
            }
        }
        self.tick_locked();
        Ok(Egress::ALL.iter().filter(|&&e| self.running(e)).count())
    }

    fn load_cf_cfg(&self) -> (Option<String>, CfProxyMode) {
        match self.source.load() {
            Ok(cfg) => (
                cfg.cloudflared.token.filter(|t| !t.is_empty()),
                cfg.cloudflared.proxy,
            ),
            Err(e) => {
                tracing::debug!(
                    ?e,
                    "cloudflared: config reload failed; treat token as unset"
                );
                (None, CfProxyMode::default())
            }
        }
    }

    fn stamp(&self, egress: Egress) -> Option<String> {
        let base = match egress {
            Egress::Proxied => self.proxy_stamp()?,
            Egress::Direct => "direct-egress".to_string(),
        };
        Some(match reload_gen() {
            Some(g) => format!("{base}#reload={g}"),
            None => base,
        })
    }

    fn proxy_stamp(&self) -> Option<String> {
        if self.mode.via_clash() {
            let pid = sb_ppgw::procinfo::clash_pid()?;
            let marker = std::fs::read_to_string(CLASH_READY_MARKER)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            return Some(format!("clash:{pid}:{marker}"));
        }
        if self.mode == OutboundMode::Ovpn {
            let up = match &self.tun_ready {
                Some(gate) => gate.load(Ordering::Relaxed),
                None => sb_outbound::direct::device_exists(OVPN_TUN),
            };
            return up.then(|| "ovpn:up".to_string());
        }

        Some("direct".to_string())
    }

    fn proxy_chores_possible(&self) -> bool {
        match self.mode {
            OutboundMode::Yaml | OutboundMode::Suburl | OutboundMode::Ovpn => {
                self.proxy_stamp().is_some()
            }
            OutboundMode::Free | OutboundMode::Socks5 => true,
        }
    }

    fn link_ready(&self, egress: Egress) -> bool {
        match sb_ppgw::httpcli::check_url_connectivity(READY_URL, egress.proxy_arg(), "0") {
            Ok((ok, _)) => ok,
            Err(e) => {
                tracing::debug!(
                    ?e,
                    egress = egress.as_str(),
                    "cloudflared: link probe failed"
                );
                false
            }
        }
    }

    fn running(&self, egress: Egress) -> bool {
        self.with_proc(egress, |p| p.pid.map(proc_is_cf).unwrap_or(false))
    }

    pub fn kill_one(&self, egress: Egress) {
        let killed = self.with_proc(egress, kill_locked);
        if killed {
            tracing::info!(egress = egress.as_str(), "cloudflared stopped");
        }
    }

    pub fn kill(&self) {
        for egress in Egress::ALL {
            self.kill_one(egress);
        }
    }

    fn tick(&self) {
        let _guard = match self.start_lock.try_lock() {
            Ok(g) => g,

            Err(std::sync::TryLockError::Poisoned(g)) => g.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                tracing::debug!("cloudflared: (re)start already in flight; skip this tick");
                return;
            }
        };
        self.tick_locked();
    }

    fn tick_locked(&self) {
        let (token, mode) = self.load_cf_cfg();
        let Some(token) = token else {
            for egress in Egress::ALL {
                if self.running(egress) {
                    tracing::info!(
                        egress = egress.as_str(),
                        "cloudflared_token cleared; stopping cloudflared"
                    );
                    self.kill_one(egress);
                }
            }
            return;
        };

        let mut plan: Vec<(Egress, String)> = Vec::new();
        for egress in Egress::ALL {
            if !want_egress(egress, mode, self.mode) {
                if self.running(egress) {
                    tracing::info!(
                        egress = egress.as_str(),
                        cf_proxy = mode.as_str(),
                        outbound = ?self.mode,
                        "replica not wanted in this configuration; stopping"
                    );
                    self.kill_one(egress);
                }
                continue;
            }

            let stamp = self.stamp(egress);
            let Some(stamp) = stamp else {
                if self.running(egress) {
                    tracing::warn!(mode = ?self.mode, "proxy engine not ready; stopping proxy replica");
                    self.kill_one(egress);
                }
                self.note(egress, "proxy engine not ready");
                continue;
            };
            let running = self.running(egress);
            let need = self.with_proc(egress, |p| {
                !running || p.token.as_ref() != Some(&token) || p.stamp.as_ref() != Some(&stamp)
            });
            if need {
                plan.push((egress, stamp));
            }
        }
        if plan.is_empty() {

            if self.update_due()
                && self.proxy_chores_possible()
                && self.ensure_binary() == BinaryState::Ready
                && self.run_update()
            {
                tracing::info!("cloudflared binary updated; restarting both replicas");
                self.restart_all_for_update(&token, mode);
            }
            return;
        }

        if self.started.elapsed() < STARTUP_GRACE {
            tracing::debug!("cloudflared: still in startup grace; defer");
            for (egress, _) in &plan {
                self.note(*egress, "waiting for system to settle");
            }
            return;
        }

        if !Path::new(CF_BIN).is_file() {
            if !self.proxy_chores_possible() {
                tracing::debug!(
                    "cloudflared binary missing and no proxy to download it; waiting for the proxy"
                );
                for (egress, _) in &plan {
                    self.note(*egress, "waiting for the proxy to download cloudflared");
                }
                return;
            }
            let state = self.ensure_binary();
            if state != BinaryState::Ready {
                for (egress, _) in &plan {
                    self.note(*egress, state.note());
                }
                return;
            }
        }

        let changed = if self.proxy_chores_possible() {
            self.run_update()
        } else {

            tracing::info!(
                "no proxy available (clash/openvpn down); skipping the cloudflared update check \
                 so the direct replica can start now"
            );
            false
        };
        if changed {
            tracing::info!("cloudflared binary changed; both replicas will restart");
            for egress in Egress::ALL {
                if want_egress(egress, mode, self.mode) && !plan.iter().any(|(e, _)| *e == egress) {
                    let stamp = self.stamp(egress);
                    if let Some(stamp) = stamp {
                        plan.push((egress, stamp));
                    }
                }
            }
        }

        for (egress, stamp) in plan {
            self.start_replica(egress, &token, stamp);
        }
    }

    fn restart_all_for_update(&self, token: &str, mode: CfProxyMode) {
        for egress in Egress::ALL {
            if !want_egress(egress, mode, self.mode) {
                continue;
            }
            let stamp = self.stamp(egress);
            if let Some(stamp) = stamp {
                self.start_replica(egress, token, stamp);
            }
        }
    }

    fn start_replica(&self, egress: Egress, token: &str, stamp: String) {

        let edges = block_on_edges(egress);
        if edges.is_empty() && !self.link_ready(egress) {

            if self.running(egress) {
                tracing::warn!(
                    egress = egress.as_str(),
                    "egress became unusable; stopping replica until it recovers"
                );
                self.kill_one(egress);
            }
            self.note(egress, "egress cannot reach the internet");
            return;
        }

        self.kill_one(egress);
        let edge_args: Vec<String> = edges
            .iter()
            .map(|e| format!("{}:{}", e.ip, crate::cf_edge::EDGE_PORT))
            .collect();
        match spawn_cf(token, egress, &edge_args, &self.logs) {
            Ok(pid) => {
                let bin_fp = file_fingerprint(CF_BIN);
                self.with_proc(egress, |p| {
                    p.pid = Some(pid);
                    p.token = Some(token.to_string());
                    p.stamp = Some(stamp);
                    p.bin_fp = bin_fp;
                    p.edges = edge_args.clone();
                    p.note = None;
                });
                tracing::info!(
                    pid,
                    egress = egress.as_str(),
                    uid = egress.uid_gid().0,
                    metrics = egress.metrics_addr(),
                    edges = %edge_args.join(","),
                    "spawned cloudflared replica"
                );
            }
            Err(e) => {
                tracing::warn!(
                    ?e,
                    egress = egress.as_str(),
                    bin = CF_BIN,
                    "spawn cloudflared failed"
                );
                self.note(egress, "spawn failed");
            }
        }
    }

    fn note(&self, egress: Egress, why: &'static str) {
        self.with_proc(egress, |p| p.note = Some(why));
    }

    fn update_due(&self) -> bool {
        let g = self.global.lock().unwrap_or_else(|e| e.into_inner());
        g.last_update.is_none_or(|t| t.elapsed() >= UPDATE_INTERVAL)
    }

    fn download_retry(&self) -> Duration {
        match self.mode {
            OutboundMode::Free => DOWNLOAD_RETRY_DIRECT,
            _ => DOWNLOAD_RETRY_PROXY,
        }
    }

    fn ensure_binary(&self) -> BinaryState {
        if Path::new(CF_BIN).is_file() {
            return BinaryState::Ready;
        }

        let healthy = self.link_ready(Egress::Proxied);
        let retry = self.download_retry();
        {
            let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
            if !healthy {
                g.link_ok = false;
                tracing::debug!("cloudflared: egress not usable yet; skip the download attempt");
                return BinaryState::EgressDown;
            }
            let just_became_usable = !g.link_ok;
            g.link_ok = true;
            if !just_became_usable
                && let Some(last) = g.last_download
                && last.elapsed() < retry
            {
                return BinaryState::DownloadFailed;
            }
            g.last_download = Some(Instant::now());
        }
        let url = format!("{CF_RELEASE_BASE}{}", cf_asset());
        tracing::warn!(%url, "cloudflared binary missing; egress is up — downloading now");
        match download_binary(&url) {
            Ok(()) => {
                tracing::info!(bin = CF_BIN, version = %cf_version(), "cloudflared downloaded");
                BinaryState::Ready
            }
            Err(e) => {
                tracing::warn!(?e, %url, retry_secs = retry.as_secs(),
                    "cloudflared download failed; will retry");
                BinaryState::DownloadFailed
            }
        }
    }

    fn run_update(&self) -> bool {
        let egress = Egress::Proxied;
        let upd_dir = egress.upd_dir();
        let before = file_fingerprint(CF_BIN);
        let _ = std::fs::remove_dir_all(&upd_dir);
        let r = self.update_in_workdir(egress);
        if let Err(e) = std::fs::remove_dir_all(&upd_dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(?e, dir = %upd_dir, "cloudflared: update workdir cleanup failed");
        }
        if let Err(e) = r {
            tracing::debug!(?e, "cloudflared update skipped");
        }
        {
            let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
            g.last_update = Some(Instant::now());
        }
        let after = file_fingerprint(CF_BIN);
        after.is_some() && after != before
    }

    fn update_in_workdir(&self, egress: Egress) -> io::Result<()> {
        let upd_dir = egress.upd_dir();
        let need = std::fs::metadata(CF_BIN)?.len();

        if let Some(free) = fs_free_bytes(CF_HOME_FS)
            && free < need * 3
        {
            tracing::warn!(
                free_mb = free / 1_048_576,
                need_mb = (need * 3) / 1_048_576,
                "not enough tmpfs room for cloudflared update; skip (tunnel still starts)"
            );
            return Ok(());
        }
        prepare_home(egress)?;
        std::fs::create_dir_all(&upd_dir)?;
        chown_cf(&upd_dir, egress)?;
        set_mode(&upd_dir, 0o700)?;
        let staged = format!("{upd_dir}/cloudflared");
        std::fs::copy(CF_BIN, &staged)?;
        chown_cf(&staged, egress)?;
        set_mode(&staged, 0o755)?;

        let before = file_fingerprint(&staged);
        match run_as_cf(&staged, &["update"], egress, UPDATE_TIMEOUT, &self.logs) {
            Ok(true) => {
                let after = file_fingerprint(&staged);
                if after != before && after.is_some() {
                    match std::fs::copy(&staged, CF_BIN).and_then(|_| set_mode(CF_BIN, 0o755)) {
                        Ok(()) => tracing::info!(version = %cf_version(), "cloudflared updated"),
                        Err(e) => tracing::warn!(?e, "cloudflared: install of update failed"),
                    }
                } else {
                    tracing::info!("cloudflared already up to date");
                }
            }
            Ok(false) => tracing::info!("cloudflared update reported no change / failed; continue"),
            Err(e) => tracing::warn!(?e, "cloudflared update could not run; continue"),
        }
        Ok(())
    }
}

fn want_egress(egress: Egress, mode: CfProxyMode, outbound: OutboundMode) -> bool {

    if outbound == OutboundMode::Free {
        return egress == Egress::Direct;
    }
    match egress {
        Egress::Direct => matches!(mode, CfProxyMode::No | CfProxyMode::Both),
        Egress::Proxied => matches!(mode, CfProxyMode::Yes | CfProxyMode::Both),
    }
}

fn reload_gen() -> Option<String> {
    let raw = std::fs::read_to_string(RELOAD_MARKER).ok()?;
    let g: String = raw.trim().chars().take(32).collect();
    (!g.is_empty()).then_some(g)
}

fn block_on_edges(egress: Egress) -> Vec<crate::cf_edge::EdgeRtt> {
    match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(crate::cf_edge::pick_edges(egress)),
        Err(_) => Vec::new(),
    }
}

fn fs_free_bytes(path: &str) -> Option<u64> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };

    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st.f_bavail as u64 * st.f_frsize as u64)
}

fn kill_locked(g: &mut Proc) -> bool {
    let mut killed = false;
    if let Some(pid) = g.pid
        && proc_is_cf(pid)
    {

        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        if !wait_gone(pid, Duration::from_secs(10)) {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            wait_gone(pid, Duration::from_secs(2));
        }
        killed = true;
    }
    g.pid = None;
    g.token = None;
    g.stamp = None;
    g.bin_fp = None;
    g.edges.clear();
    killed
}

fn prepare_home(egress: Egress) -> io::Result<()> {
    ensure_passwd_entry(egress);
    let home = egress.home();
    std::fs::create_dir_all(home)?;
    chown_cf(home, egress)?;
    set_mode(home, 0o700)
}

fn ensure_passwd_entry(egress: Egress) {
    let (uid, gid) = egress.uid_gid();
    let name = egress.user_name();
    let home = egress.home();
    append_line_if_missing(
        "/etc/passwd",
        &format!("{name}:"),
        &format!("{name}:x:{uid}:{gid}:{name}:{home}:/bin/false\n"),
    );
    append_line_if_missing(
        "/etc/group",
        &format!("{name}:"),
        &format!("{name}:x:{gid}:\n"),
    );
}

fn append_line_if_missing(path: &str, prefix: &str, line: &str) {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|l| l.starts_with(prefix)) {
        return;
    }
    use std::io::Write;
    let mut out = match std::fs::OpenOptions::new().append(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(?e, path, "cloudflared: cannot append account entry");
            return;
        }
    };

    if !existing.is_empty() && !existing.ends_with('\n') {
        let _ = out.write_all(b"\n");
    }
    let _ = out.write_all(line.as_bytes());
}

fn chown_cf(path: &str, egress: Egress) -> io::Result<()> {
    let (uid, gid) = egress.uid_gid();
    let c = std::ffi::CString::new(path).map_err(|_| io::Error::other("path has NUL"))?;

    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_mode(path: &str, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn file_fingerprint(path: &str) -> Option<(u64, std::time::SystemTime)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.len(), m.modified().ok()?))
}

fn cf_version() -> String {
    Command::new(CF_BIN)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn run_as_cf(
    bin: &str,
    args: &[&str],
    egress: Egress,
    timeout: Duration,
    logs: &Arc<sb_web::LineHistory>,
) -> io::Result<bool> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("HOME", egress.home())
        .current_dir(egress.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (uid, gid) = egress.uid_gid();

    unsafe {
        cmd.pre_exec(move || drop_to_cf(uid, gid));
    }
    let mut child = cmd.spawn()?;
    pump(child.stdout.take(), egress, logs);
    pump(child.stderr.take(), egress, logs);
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(st) => return Ok(st.success()),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cloudflared update",
                ));
            }
            None => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn spawn_cf(
    token: &str,
    egress: Egress,
    edges: &[String],
    logs: &Arc<sb_web::LineHistory>,
) -> io::Result<u32> {

    if let Err(e) = prepare_home(egress) {
        tracing::debug!(?e, dir = egress.home(), "cloudflared home prepare failed");
    }
    let mut argv: Vec<String> = vec![
        "tunnel".into(),
        "--no-autoupdate".into(),
        "--metrics".into(),
        egress.metrics_addr().into(),
    ];
    for e in edges {
        argv.push("--edge".into());
        argv.push(e.clone());
    }
    argv.push("run".into());
    argv.push("--token".into());
    argv.push(token.to_string());
    let mut cmd = Command::new(CF_BIN);
    cmd.args(&argv)
        .env("HOME", egress.home())
        .current_dir(egress.home())
        .stdin(Stdio::null())

        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (uid, gid) = egress.uid_gid();

    unsafe {
        cmd.pre_exec(move || drop_to_cf(uid, gid));
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    pump(child.stdout.take(), egress, logs);
    pump(child.stderr.take(), egress, logs);
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

fn pump<R: std::io::Read + Send + 'static>(
    src: Option<R>,
    egress: Egress,
    logs: &Arc<sb_web::LineHistory>,
) {
    let Some(src) = src else { return };
    let logs = Arc::clone(logs);

    let tag = format!("[{}]", egress.as_str());
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut r = std::io::BufReader::new(src);
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let text = line.trim_end_matches(['\r', '\n']).to_string();
            if text.is_empty() {
                continue;
            }
            let text = format!("{tag} {text}");
            println!("{text}");
            logs.push_lines(&[text]);
        }
    });
}

fn drop_to_cf(uid: u32, gid: u32) -> io::Result<()> {

    unsafe {
        libc::setsid();
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn download_binary(url: &str) -> io::Result<()> {
    let tmp = format!("{CF_BIN}.download");
    sb_ppgw::download::Downloader::new(url, &tmp)
        .timeout(DOWNLOAD_TIMEOUT)
        .via_proxy(HEALTH_SOCKS5)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let verdict = verify_elf(&tmp);
    if let Err(e) = verdict {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    set_mode(&tmp, 0o755)?;
    std::fs::rename(&tmp, CF_BIN)?;
    Ok(())
}

fn verify_elf(path: &str) -> io::Result<()> {
    let meta = std::fs::metadata(path)?;
    if meta.len() < 1_000_000 {
        return Err(io::Error::other(format!("too small: {} bytes", meta.len())));
    }
    let mut head = [0u8; 20];
    {
        use std::io::Read;
        std::fs::File::open(path)?.read_exact(&mut head)?;
    }
    if &head[..4] != b"\x7fELF" {
        return Err(io::Error::other("not an ELF"));
    }
    let machine = u16::from_le_bytes([head[18], head[19]]);
    if machine != cf_elf_machine() {
        return Err(io::Error::other(format!(
            "ELF e_machine {machine:#x}, expected {:#x}",
            cf_elf_machine()
        )));
    }
    Ok(())
}

fn wait_gone(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !proc_is_cf(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !proc_is_cf(pid)
}

fn proc_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn proc_is_cf(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "cloudflared")
        .unwrap_or(false)
}

fn find_cf_pids() -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if proc_is_cf(pid) {
            out.push(pid);
        }
    }
    out.sort_unstable();
    out
}

pub fn spawn_monitor(
    sup: Arc<CloudflaredSupervisor>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
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
                    let sup = Arc::clone(&sup);

                    let _ = tokio::task::spawn_blocking(move || sup.tick()).await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sup() -> CloudflaredSupervisor {
        CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Free, None)
    }

    #[test]
    fn proc_is_cf_rejects_self() {
        assert!(!proc_is_cf(std::process::id()));
    }

    #[test]
    fn egress_paths_are_fully_separated() {
        let (p, d) = (Egress::Proxied, Egress::Direct);
        assert_eq!(p.uid_gid(), (CF_UID, CF_GID));
        assert_eq!(d.uid_gid(), (CF_UID_DIRECT, CF_GID_DIRECT));
        assert_ne!(
            p.uid_gid(),
            d.uid_gid(),
            "direct must NOT reuse the nft uid"
        );
        assert_ne!(p.home(), d.home());
        assert_ne!(p.upd_dir(), d.upd_dir());
        assert_ne!(p.user_name(), d.user_name());

        assert_eq!(p.proxy_arg(), HEALTH_SOCKS5);
        assert_eq!(d.proxy_arg(), "");

        assert_ne!(p.metrics_addr(), d.metrics_addr());
        assert_eq!(p.metrics_addr(), METRICS_PROXIED);
        assert_eq!(d.metrics_addr(), METRICS_DIRECT);
        assert_eq!(p.as_str(), "proxy");
        assert_eq!(d.as_str(), "direct");

        assert_eq!(Egress::ALL, [Egress::Direct, Egress::Proxied]);
    }

    #[test]
    fn egress_from_uid_maps_only_the_two_known_uids() {
        assert_eq!(Egress::from_uid(CF_UID), Some(Egress::Proxied));
        assert_eq!(Egress::from_uid(CF_UID_DIRECT), Some(Egress::Direct));
        assert_eq!(Egress::from_uid(0), None);
        assert_eq!(Egress::from_uid(65534), None);

        let me = proc_uid(std::process::id()).expect("own /proc/<pid>/status readable");
        assert_eq!(me, unsafe { libc::getuid() });
        assert_eq!(proc_uid(u32::MAX), None);
    }

    #[test]
    fn cf_proxy_selects_which_replicas_run() {
        use OutboundMode::*;

        for m in [Socks5, Ovpn, Yaml, Suburl] {
            assert!(
                !want_egress(Egress::Direct, CfProxyMode::Yes, m),
                "{m:?}: yes = tunnel goes through the proxy, direct replica off"
            );
            assert!(want_egress(Egress::Direct, CfProxyMode::No, m), "{m:?}");
            assert!(want_egress(Egress::Direct, CfProxyMode::Both, m), "{m:?}");
            assert!(
                want_egress(Egress::Proxied, CfProxyMode::Yes, m),
                "{m:?} has a distinct egress (clash node / upstream socks5 / tun114)"
            );
            assert!(!want_egress(Egress::Proxied, CfProxyMode::No, m), "{m:?}");
            assert!(want_egress(Egress::Proxied, CfProxyMode::Both, m), "{m:?}");

            for mode in [CfProxyMode::Yes, CfProxyMode::No, CfProxyMode::Both] {
                assert!(
                    Egress::ALL.iter().any(|&e| want_egress(e, mode, m)),
                    "{m:?} + {mode:?} must keep at least one replica"
                );
            }

            assert_eq!(
                Egress::ALL
                    .iter()
                    .filter(|&&e| want_egress(e, CfProxyMode::Both, m))
                    .count(),
                2,
                "{m:?}: both must run two replicas"
            );
        }

        for mode in [CfProxyMode::Yes, CfProxyMode::No, CfProxyMode::Both] {
            assert!(
                want_egress(Egress::Direct, mode, Free),
                "free mode always keeps the direct replica ({mode:?})"
            );
            assert!(
                !want_egress(Egress::Proxied, mode, Free),
                "free mode has no second path; a proxied replica would be a pointless twin"
            );
        }
    }

    #[test]
    fn modes_without_a_proxy_process_never_wait_for_one() {
        for mode in [OutboundMode::Free, OutboundMode::Socks5] {
            let s = CloudflaredSupervisor::new(ConfigSource::Production, mode, None);
            assert!(
                s.proxy_chores_possible(),
                "{mode:?}: nothing to wait for — download/update must be attempted best-effort"
            );
        }

        let ovpn = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Ovpn, None);
        if !sb_outbound::direct::device_exists(OVPN_TUN) {
            assert!(
                !ovpn.proxy_chores_possible(),
                "ovpn without tun114 has a real proxy to wait for"
            );
        }

        let yaml = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Yaml, None);
        assert_eq!(
            yaml.proxy_chores_possible(),
            sb_ppgw::procinfo::clash_pid().is_some(),
            "clash modes must gate on the clash process"
        );

        assert_eq!(DOWNLOAD_RETRY_PROXY, Duration::from_secs(300));
        assert_eq!(DOWNLOAD_RETRY_DIRECT, Duration::from_secs(60));
        for (mode, want) in [
            (OutboundMode::Free, DOWNLOAD_RETRY_DIRECT),
            (OutboundMode::Socks5, DOWNLOAD_RETRY_PROXY),
            (OutboundMode::Ovpn, DOWNLOAD_RETRY_PROXY),
            (OutboundMode::Yaml, DOWNLOAD_RETRY_PROXY),
            (OutboundMode::Suburl, DOWNLOAD_RETRY_PROXY),
        ] {
            let s = CloudflaredSupervisor::new(ConfigSource::Production, mode, None);
            assert_eq!(s.download_retry(), want, "{mode:?}");
        }
    }

    #[test]
    fn missing_binary_without_egress_is_not_an_attempt() {
        if Path::new(CF_BIN).is_file() {
            return;
        }
        let s = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Free, None);
        assert_eq!(s.ensure_binary(), BinaryState::EgressDown);
        let g = s.global.lock().unwrap();
        assert!(
            g.last_download.is_none(),
            "a skipped attempt must not start the backoff window"
        );
        assert!(
            !g.link_ok,
            "egress stays marked down so recovery triggers a retry"
        );
    }

    #[test]
    fn gateway_reload_generation_restamps_both_replicas() {
        let saved = std::fs::read_to_string(RELOAD_MARKER).ok();
        let s = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Free, None);

        std::fs::write(RELOAD_MARKER, "1000000001\n").expect("write marker");
        let first: Vec<String> = Egress::ALL
            .iter()
            .map(|&e| s.stamp(e).expect("free mode always has a stamp"))
            .collect();
        assert!(
            first.iter().all(|st| st.contains("#reload=1000000001")),
            "both replicas must carry the reload generation: {first:?}"
        );

        std::fs::write(RELOAD_MARKER, "1000000002\n").expect("write marker");
        for (i, &e) in Egress::ALL.iter().enumerate() {
            assert_ne!(
                s.stamp(e).unwrap(),
                first[i],
                "{} must be restamped after a gateway reload",
                e.as_str()
            );
        }

        std::fs::write(RELOAD_MARKER, "x".repeat(4096)).expect("write marker");
        assert_eq!(reload_gen().map(|g| g.len()), Some(32));
        std::fs::write(RELOAD_MARKER, "   \n").expect("write marker");
        assert_eq!(reload_gen(), None, "blank marker adds nothing to the stamp");

        match saved {
            Some(prev) => std::fs::write(RELOAD_MARKER, prev).expect("restore marker"),
            None => std::fs::remove_file(RELOAD_MARKER).expect("remove marker"),
        }
    }

    #[test]
    fn binary_state_notes_are_distinct() {
        assert_eq!(
            BinaryState::EgressDown.note(),
            "waiting for a usable egress to download cloudflared"
        );
        assert_eq!(
            BinaryState::DownloadFailed.note(),
            "cloudflared binary missing (download failed)"
        );
        assert!(BinaryState::Ready.note().is_empty());
    }

    fn method_body<'a>(src: &'a str, sig: &str) -> &'a str {
        let after = src.split(sig).nth(1).unwrap_or_else(|| panic!("no {sig}"));
        let end = ["\n    fn ", "\n    pub fn "]
            .iter()
            .filter_map(|m| after.find(m))
            .min()
            .unwrap_or(after.len());
        &after[..end]
    }

    #[test]
    fn direct_replica_start_does_not_depend_on_the_proxy() {
        let src = include_str!("cf_ctl.rs");
        let tick = method_body(src, "fn tick_locked(&self)");

        assert!(
            tick.contains("let changed = if self.proxy_chores_possible() {")
                && tick.contains("self.run_update()"),
            "run_update() must stay behind a proxy_chores_possible() gate"
        );

        assert!(
            tick.contains("if !Path::new(CF_BIN).is_file() {")
                && tick.contains("if !self.proxy_chores_possible() {"),
            "the download path must be gated too"
        );
        let start = method_body(src, "fn start_replica(&self");
        assert!(
            !start.contains("proxy_chores_possible") && !start.contains("proxy_stamp"),
            "picking edges and spawning must never wait on the proxy; body was:\n{start}"
        );

        assert!(start.contains("block_on_edges(egress)") && start.contains("spawn_cf("));
        assert!(
            !start.contains("fn "),
            "extraction must stop at the next fn"
        );
    }

    #[test]
    fn cf_proxy_mode_parsing() {
        use CfProxyMode::*;
        for (s, want) in [
            ("yes", Yes),
            ("YES", Yes),
            (" true ", Yes),
            ("1", Yes),
            ("proxy", Yes),
            ("no", No),
            ("false", No),
            ("0", No),
            ("direct", No),

            ("only", Yes),
            ("both", Both),
            ("BOTH", Both),
            (" dual ", Both),
        ] {
            assert_eq!(CfProxyMode::parse(s), Some(want), "parsing {s:?}");
        }
        assert_eq!(CfProxyMode::parse("maybe"), None);
        assert_eq!(CfProxyMode::parse(""), None);

        assert_eq!(CfProxyMode::parse("auto"), None);
        assert_eq!(
            CfProxyMode::default(),
            Yes,
            "default keeps the tunnel behind the proxy"
        );
        assert_eq!(Yes.as_str(), "yes");
        assert_eq!(No.as_str(), "no");
        assert_eq!(Both.as_str(), "both");
    }

    #[test]
    fn tick_is_noop_without_token() {

        let s = sup();
        if s.load_cf_cfg().0.is_some() {
            return;
        }
        s.tick();
        assert!(Egress::ALL.iter().all(|&e| !s.running(e)));
    }

    #[test]
    fn status_and_restart_without_token() {
        let s = sup();
        if s.load_cf_cfg().0.is_some() {
            return;
        }
        let st = s.status();
        assert!(!st.enabled);
        assert_eq!(st.procs.len(), 2, "both replicas are always reported");
        for p in &st.procs {
            assert!(!p.wanted, "nothing is wanted without a token");
            assert_eq!(
                p.note,
                Some("no token"),
                "note must explain the disabled feature even when a stray process is running \
                 (egress={} running={})",
                p.egress.as_str(),
                p.running
            );
            assert_eq!(p.metrics, p.egress.metrics_addr());

            assert_eq!(p.running, p.pid.is_some());
        }
        assert!(
            s.restart(None).is_err(),
            "nothing to restart without a token"
        );
        assert!(s.restart(Some(Egress::Direct)).is_err());
    }

    #[test]
    fn monitor_tick_skips_while_a_start_is_in_flight() {
        let s = sup();
        let held = s
            .start_lock
            .try_lock()
            .expect("fresh supervisor lock is free");

        let t0 = Instant::now();
        s.tick();
        assert!(t0.elapsed() < Duration::from_secs(1), "tick must not block");
        drop(held);

        assert!(s.start_lock.try_lock().is_ok());
    }

    #[test]
    fn logs_handle_is_shared() {
        let s = sup();
        let web_side = s.logs();
        s.logs
            .push_lines(&["INF Registered tunnel connection".to_string()]);
        assert!(
            web_side.snapshot_text().contains("Registered tunnel"),
            "web handle must observe lines pushed by the supervisor"
        );
    }

    #[test]
    fn free_mode_stamp_is_direct() {
        assert_eq!(sup().proxy_stamp().as_deref(), Some("direct"));
    }

    #[test]
    fn asset_and_elf_machine_match_target_arch() {
        if cfg!(target_arch = "aarch64") {
            assert_eq!(cf_asset(), "cloudflared-linux-arm64");
            assert_eq!(cf_elf_machine(), 0xb7);
        } else {
            assert_eq!(cf_asset(), "cloudflared-linux-amd64");
            assert_eq!(cf_elf_machine(), 0x3e);
        }
    }

    #[test]
    fn update_workdir_is_wiped_whole() {

        for egress in [Egress::Proxied, Egress::Direct] {
            let upd = egress.upd_dir();

            std::fs::create_dir_all(&upd).unwrap();
            std::fs::write(format!("{upd}/cloudflared"), b"staged").unwrap();
            std::fs::write(format!("{upd}/cloudflared.old"), b"backup").unwrap();
            std::fs::write(format!("{upd}/download.tmp"), b"partial").unwrap();

            std::fs::remove_dir_all(&upd).unwrap();
            assert!(!std::path::Path::new(&upd).exists());

            let e = std::fs::remove_dir_all(&upd).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::NotFound);
        }

        assert_ne!(Egress::Proxied.upd_dir(), Egress::Direct.upd_dir());
    }

    #[test]
    fn fs_free_bytes_reports_something_for_tmp() {

        if let Some(free) = fs_free_bytes(CF_HOME_FS) {
            assert!(free > 0);
        }
        assert!(fs_free_bytes("/definitely/not/here").is_none());
    }

    #[test]
    fn verify_elf_rejects_html_error_page() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fake");
        std::fs::write(&p, vec![b'<'; 2_000_000]).unwrap();
        assert!(verify_elf(p.to_str().unwrap()).is_err());
    }

    #[test]
    fn verify_elf_rejects_truncated_download() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("short");
        let mut buf = b"\x7fELF".to_vec();
        buf.resize(4096, 0);
        std::fs::write(&p, buf).unwrap();
        assert!(verify_elf(p.to_str().unwrap()).is_err());
    }

    #[test]
    fn verify_elf_accepts_native_arch_binary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok");
        let mut buf = vec![0u8; 2_000_000];
        buf[..4].copy_from_slice(b"\x7fELF");
        buf[18..20].copy_from_slice(&cf_elf_machine().to_le_bytes());
        std::fs::write(&p, buf).unwrap();
        verify_elf(p.to_str().unwrap()).unwrap();
    }
}
