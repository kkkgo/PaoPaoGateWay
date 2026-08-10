// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io;
use std::net::IpAddr;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::ConfigSource;
use crate::cf_quality::VerdictSource;
use crate::config::{CfProtocol, CfProxyMode, CloudflaredCfg, OutboundMode, Protocol};

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

    pub(crate) fn idx(self) -> usize {
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

    pub(crate) fn home(self) -> &'static str {
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

const MONITOR_INTERVAL_PENDING: Duration = Duration::from_secs(5);

const STARTUP_GRACE: Duration = Duration::from_secs(60);

const DOWNLOAD_BACKOFF: [Duration; 8] = [
    Duration::from_secs(10),
    Duration::from_secs(20),
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(180),
    Duration::from_secs(240),
    Duration::from_secs(300),
];

const EGRESS_DOWN_FORCE_AFTER: Duration = Duration::from_secs(600);

const UPDATE_TIMEOUT: Duration = Duration::from_secs(180);

const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 3600);

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(900);

const DOWNLOAD_TIMEOUT_PROBATION: Duration = Duration::from_secs(60);

const READY_EXPECT: &str = "200-399";

const READY_TIMEOUT: Duration = Duration::from_secs(5);

const VERSION_TIMEOUT: Duration = Duration::from_secs(20);

const PARTIAL_MAX_AGE: Duration = Duration::from_secs(3600);

const HEALTH_SOCKS5: &str = "socks5h://127.0.0.1:1079";

const CLASH_READY_MARKER: &str = "/tmp/ppgw_clash_ready.ts";

const RELOAD_MARKER: &str = "/tmp/ppgw_reload.ts";

const OVPN_TUN: &str = "tun114";

const CF_RELEASE_BASE: &str = "https://github.com/cloudflare/cloudflared/releases/latest/download/";

const READY_WAIT: Duration = Duration::from_secs(25);

const READY_MISSES: u32 = 3;

const RESCORE_AFTER: Duration = Duration::from_secs(3 * 60);

struct Rung {
    proto: Protocol,

    pin_edges: bool,
}

const LADDER: [Rung; 3] = [
    Rung {
        proto: Protocol::Quic,
        pin_edges: true,
    },
    Rung {
        proto: Protocol::Http2,
        pin_edges: true,
    },
    Rung {
        proto: Protocol::Http2,
        pin_edges: false,
    },
];

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

    download_fails: u32,

    last_update: Option<Instant>,

    link_ok: bool,

    egress_down_since: Option<Instant>,
}

#[derive(Default)]
struct Proc {

    pid: Option<u32>,

    token: Option<String>,

    stamp: Option<String>,

    bin_fp: Option<(u64, std::time::SystemTime)>,

    edges: Vec<String>,

    note: Option<&'static str>,

    protocol: Option<Protocol>,

    protocol_why: ProtocolWhy,

    ready_misses: u32,

    unready_since: Option<Instant>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProtocolWhy {
    #[default]
    Unknown,

    Locked,

    Initial,

    Scored,

    Fallback,
}

impl From<crate::cf_quality::VerdictSource> for ProtocolWhy {
    fn from(v: crate::cf_quality::VerdictSource) -> Self {
        match v {
            crate::cf_quality::VerdictSource::Scored => Self::Scored,
            crate::cf_quality::VerdictSource::Fallback => Self::Fallback,
        }
    }
}

impl ProtocolWhy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Locked => "locked",
            Self::Initial => "initial preference (not scored yet)",
            Self::Scored => "scored",
            Self::Fallback => "fallback: the preferred transport would not register",
        }
    }
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

    pub protocol: Option<Protocol>,
    pub protocol_why: ProtocolWhy,

    pub next_probe_min: Option<u64>,

    pub last_round: Option<crate::cf_quality::LastRound>,
}

pub struct CfStatus {

    pub enabled: bool,

    pub proxy_mode: CfProxyMode,

    pub protocol: CfProtocol,

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
        let cfg = self.load_cf_cfg();
        let (token, proxy_mode) = (cfg.token, cfg.proxy);
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
                        protocol: p.protocol,
                        protocol_why: why_now(p.protocol, p.protocol_why, egress),
                        next_probe_min: (wanted && cfg.protocol.adaptive())
                            .then(|| crate::cf_quality::probe_wait(egress).as_secs() / 60),
                        last_round: cfg
                            .protocol
                            .adaptive()
                            .then(|| crate::cf_quality::last_round(egress))
                            .flatten(),
                    }
                })
            })
            .collect();
        CfStatus {
            enabled,
            proxy_mode,
            protocol: cfg.protocol,
            binary: Path::new(CF_BIN).is_file(),
            version: Path::new(CF_BIN).is_file().then(cf_version),
            procs,
        }
    }

    pub fn current_protocol(&self, egress: Egress) -> Option<Protocol> {
        if !self.running(egress) {
            return None;
        }
        self.with_proc(egress, |p| p.protocol)
    }

    pub fn scoring_wanted(&self, egress: Egress) -> bool {
        let cfg = self.load_cf_cfg();
        cfg.token.is_some() && cfg.protocol.adaptive() && want_egress(egress, cfg.proxy, self.mode)
    }

    pub async fn switch_protocol(self: &Arc<Self>, egress: Egress, proto: Protocol) {
        crate::cf_quality::remember_verdict(egress, proto, VerdictSource::Scored);
        let sup = Arc::clone(self);
        let _ = tokio::task::spawn_blocking(move || {
            let _guard = sup
                .start_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sup.kill_one(egress);
            sup.tick_locked();
        })
        .await;
    }

    pub fn restart(&self, which: Option<Egress>) -> Result<usize, &'static str> {
        let cfg = self.load_cf_cfg();
        if cfg.token.is_none() {
            return Err("cloudflared_token not configured");
        }
        if let Some(e) = which
            && !want_egress(e, cfg.proxy, self.mode)
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

    fn load_cf_cfg(&self) -> CloudflaredCfg {
        match self.source.load() {
            Ok(cfg) => CloudflaredCfg {
                token: cfg.cloudflared.token.filter(|t| !t.is_empty()),
                ..cfg.cloudflared
            },
            Err(e) => {
                tracing::debug!(
                    ?e,
                    "cloudflared: config reload failed; treat token as unset"
                );
                CloudflaredCfg {
                    token: None,
                    ..Default::default()
                }
            }
        }
    }

    fn stamp(&self, egress: Egress, cfg: &CloudflaredCfg) -> Option<String> {
        let base = self.stamp_base(egress)?;
        Some(stamp_with(&base, self.desired_protocol(egress, cfg)))
    }

    fn stamp_base(&self, egress: Egress) -> Option<String> {
        let base = match egress {
            Egress::Proxied => self.proxy_stamp()?,
            Egress::Direct => "direct-egress".to_string(),
        };
        Some(match reload_gen() {
            Some(g) => format!("{base}#reload={g}"),
            None => base,
        })
    }

    fn desired_protocol(&self, egress: Egress, cfg: &CloudflaredCfg) -> Protocol {
        match cfg.protocol {
            CfProtocol::Fixed(p) => p,
            CfProtocol::Auto => crate::cf_quality::fresh_verdict(egress)
                .map(|(p, _)| p)
                .unwrap_or_else(|| cfg.protocol.initial()),
        }
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
        let pin = match egress {
            Egress::Proxied => None,
            Egress::Direct => match sb_ppgw::download::resolve_all(download_host()).first() {
                Some(ip) => Some(*ip),
                None => return false,
            },
        };
        probe_download(&download_url(), egress.proxy_arg(), pin).0
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

                for egress in Egress::ALL {
                    self.with_proc(egress, |p| {
                        p.ready_misses = 0;
                        p.unready_since = None;
                    });
                }
                tracing::debug!("cloudflared: (re)start already in flight; skip this tick");
                return;
            }
        };
        self.tick_locked();
    }

    fn ready_watchdog(&self, cfg: &CloudflaredCfg) -> Vec<Egress> {
        let mut rescore = Vec::new();
        for egress in Egress::ALL {
            if !want_egress(egress, cfg.proxy, self.mode) {
                continue;
            }
            let Ok(addr) = egress.metrics_addr().parse() else {
                continue;
            };
            let ready = crate::cf_metrics::ready(addr).unwrap_or(0);
            if ready >= 1 {
                self.with_proc(egress, |p| {
                    p.ready_misses = 0;
                    p.unready_since = None;
                });
                continue;
            }

            if self.with_proc(egress, |p| p.protocol.is_none()) {
                continue;
            }
            let (misses, down_for) = self.with_proc(egress, |p| {
                p.ready_misses = p.ready_misses.saturating_add(1);
                let since = *p.unready_since.get_or_insert_with(Instant::now);
                (p.ready_misses, since.elapsed())
            });

            if down_for >= RESCORE_AFTER && cfg.protocol.adaptive() {
                tracing::warn!(
                    egress = egress.as_str(),
                    down_s = down_for.as_secs(),
                    "tunnel has not registered for a while; re-scoring the transport"
                );
                self.kill_one(egress);
                self.with_proc(egress, |p| {
                    p.ready_misses = 0;
                    p.unready_since = None;
                });
                rescore.push(egress);
                continue;
            }
            if misses >= READY_MISSES {
                tracing::warn!(
                    egress = egress.as_str(),
                    misses,
                    "running but no ready edge connection; restarting it"
                );
                self.kill_one(egress);
                self.with_proc(egress, |p| p.ready_misses = 0);
            }
        }
        rescore
    }

    fn tick_locked(&self) {
        let cfg = self.load_cf_cfg();
        let mode = cfg.proxy;
        let Some(token) = cfg.token.clone() else {
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

        if !cfg.protocol.adaptive() {
            for egress in Egress::ALL {
                crate::cf_quality::forget(egress);
            }
        }

        let rescore = self.ready_watchdog(&cfg);
        for egress in rescore {

            if let Some(winner) = block_on_scoring(egress) {
                crate::cf_quality::remember_verdict(egress, winner, VerdictSource::Scored);
            }
        }

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

            let stamp = self.stamp(egress, &cfg);
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

            if cfg.protocol.adaptive() && self.started.elapsed() >= STARTUP_GRACE {
                self.spawn_background_scoring();
            }

            if self.update_due()
                && self.proxy_chores_possible()
                && self.ensure_binary() == BinaryState::Ready
                && self.run_update()
            {
                tracing::info!("cloudflared binary updated; restarting both replicas");
                self.restart_all_for_update(&token, &cfg);
            }
            return;
        }

        if !Path::new(CF_BIN).is_file() {
            let state = self.ensure_binary();
            if state != BinaryState::Ready {
                for (egress, _) in &plan {
                    self.note(*egress, state.note());
                }
                return;
            }
        }

        if self.started.elapsed() < STARTUP_GRACE {
            tracing::debug!("cloudflared: still in startup grace; defer");
            for (egress, _) in &plan {
                self.note(*egress, "waiting for system to settle");
            }
            return;
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
                    let stamp = self.stamp(egress, &cfg);
                    if let Some(stamp) = stamp {
                        plan.push((egress, stamp));
                    }
                }
            }
        }

        for (egress, stamp) in plan {
            self.start_replica(egress, &token, stamp, cfg.protocol);
        }

        if cfg.protocol.adaptive() {
            self.spawn_background_scoring();
        }
    }

    fn restart_all_for_update(&self, token: &str, cfg: &CloudflaredCfg) {
        for egress in Egress::ALL {
            if !want_egress(egress, cfg.proxy, self.mode) {
                continue;
            }
            let stamp = self.stamp(egress, cfg);
            if let Some(stamp) = stamp {
                self.start_replica(egress, token, stamp, cfg.protocol);
            }
        }
    }

    fn spawn_background_scoring(&self) {
        let cfg = self.load_cf_cfg();
        let wanted: Vec<Egress> = Egress::ALL
            .into_iter()
            .filter(|&e| {
                want_egress(e, cfg.proxy, self.mode)
                    && crate::cf_quality::fresh_verdict(e).is_none()
                    && crate::cf_quality::probe_wait(e).is_zero()
            })
            .collect();
        if wanted.is_empty() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        if SCORING_IN_FLIGHT.swap(true, Ordering::SeqCst) {
            return;
        }
        tokio::spawn(async move {
            for egress in wanted {
                match crate::cf_quality::pick(egress).await {
                    Some(winner) => {
                        tracing::info!(
                            egress = egress.as_str(),
                            protocol = winner.as_str(),
                            "cloudflared: scoring picked a transport"
                        );
                        crate::cf_quality::remember_verdict(egress, winner, VerdictSource::Scored);
                    }

                    None => tracing::info!(
                        egress = egress.as_str(),
                        next_probe_in_min = crate::cf_quality::probe_wait(egress).as_secs() / 60,
                        "cloudflared: scoring produced no verdict; keeping the current transport"
                    ),
                }
            }
            SCORING_IN_FLIGHT.store(false, Ordering::SeqCst);
        });
    }

    fn start_replica(&self, egress: Egress, token: &str, stamp: String, policy: CfProtocol) {

        let base = stamp
            .split_once("#proto=")
            .map(|(b, _)| b.to_string())
            .unwrap_or(stamp);
        let rungs = ladder_for(policy, crate::cf_quality::fresh_verdict(egress));
        let last = rungs.len() - 1;
        for (i, (proto, why, pin_edges)) in rungs.into_iter().enumerate() {

            let edges = if pin_edges {
                block_on_edges_proto(egress, proto)
            } else {
                Vec::new()
            };
            if pin_edges && edges.is_empty() && !self.link_ready(egress) {

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
                .map(|e| crate::cf_edge::edge_arg(e.ip))
                .collect();
            let pid = match spawn_cf(token, egress, proto, &edge_args, &self.logs) {
                Ok(pid) => pid,
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        egress = egress.as_str(),
                        bin = CF_BIN,
                        "spawn cloudflared failed"
                    );
                    self.note(egress, "spawn failed");
                    return;
                }
            };
            let bin_fp = file_fingerprint(CF_BIN);
            let stamp_now = stamp_with(&base, proto);
            self.with_proc(egress, |p| {
                p.pid = Some(pid);
                p.token = Some(token.to_string());
                p.stamp = Some(stamp_now);
                p.bin_fp = bin_fp;
                p.edges = edge_args.clone();
                p.protocol = Some(proto);
                p.protocol_why = why;
                p.note = None;
                p.ready_misses = 0;
                p.unready_since = None;
            });
            tracing::info!(
                pid,
                egress = egress.as_str(),
                uid = egress.uid_gid().0,
                metrics = egress.metrics_addr(),
                protocol = proto.as_str(),
                why = why.as_str(),
                edges = %edge_args.join(","),
                "spawned cloudflared replica"
            );

            if policy.adaptive() && i < last && !wait_ready(egress, READY_WAIT) {
                tracing::warn!(
                    egress = egress.as_str(),
                    protocol = proto.as_str(),
                    wait_s = READY_WAIT.as_secs(),
                    "transport did not register; falling back to the next rung"
                );
                self.kill_one(egress);
                continue;
            }

            if policy.adaptive() && i > 0 {
                crate::cf_quality::remember_verdict(egress, proto, VerdictSource::Fallback);
            }
            return;
        }
    }

    fn note(&self, egress: Egress, why: &'static str) {
        self.with_proc(egress, |p| p.note = Some(why));
    }

    fn update_due(&self) -> bool {
        let g = self.global.lock().unwrap_or_else(|e| e.into_inner());
        g.last_update.is_none_or(|t| t.elapsed() >= UPDATE_INTERVAL)
    }

    fn download_wait(&self) -> Option<Duration> {
        let g = self.global.lock().unwrap_or_else(|e| e.into_inner());
        let last = g.last_download?;
        download_backoff(g.download_fails).checked_sub(last.elapsed())
    }

    fn next_tick_delay(&self) -> Duration {
        if Path::new(CF_BIN).is_file() || Egress::ALL.into_iter().any(|e| self.running(e)) {
            return MONITOR_INTERVAL;
        }
        self.download_wait()
            .unwrap_or(Duration::ZERO)
            .clamp(MONITOR_INTERVAL_PENDING, MONITOR_INTERVAL)
    }

    fn ensure_binary(&self) -> BinaryState {
        if Path::new(CF_BIN).is_file() {

            sweep_partial();
            return BinaryState::Ready;
        }

        let arms = self.download_arms(false);
        if let Err(state) = self.throttle(!arms.is_empty()) {
            return state;
        }

        let arms = if arms.is_empty() {
            self.download_arms(true)
        } else {
            arms
        };
        let url = download_url();

        let proxy_tried = arms.iter().any(|a| matches!(a, DownloadArm::Proxied));
        let had = partial_len();
        for arm in &arms {
            let budget = arm_budget(arm, proxy_tried);
            tracing::warn!(
                %url,
                arm = arm.label(),
                budget_s = budget.as_secs(),
                "cloudflared binary missing; downloading now"
            );
            match download_binary(&url, arm, budget) {
                Ok(version) => {
                    let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
                    g.download_fails = 0;
                    tracing::info!(
                        bin = CF_BIN,
                        arm = arm.label(),
                        %version,
                        "cloudflared downloaded"
                    );
                    return BinaryState::Ready;
                }
                Err(e) => {
                    tracing::warn!(?e, %url, arm = arm.label(), "cloudflared download failed")
                }
            }
        }

        let progressed = partial_len() > had;
        let next = {
            let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
            g.download_fails = if progressed {
                0
            } else {
                g.download_fails.saturating_add(1)
            };
            download_backoff(g.download_fails)
        };
        tracing::warn!(
            arms = arms.len(),
            progressed,
            bytes = partial_len(),
            retry_secs = next.as_secs(),
            "cloudflared download did not finish; will retry"
        );
        BinaryState::DownloadFailed
    }

    fn throttle(&self, healthy: bool) -> Result<(), BinaryState> {
        let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
        let retry = download_backoff(g.download_fails);
        if !healthy {
            g.link_ok = false;
            let down_for = g
                .egress_down_since
                .get_or_insert_with(Instant::now)
                .elapsed();
            let forced = down_for >= EGRESS_DOWN_FORCE_AFTER
                && g.last_download.is_none_or(|t| t.elapsed() >= retry);
            if !forced {
                tracing::debug!("cloudflared: egress not usable yet; skip the download attempt");
                return Err(BinaryState::EgressDown);
            }
            tracing::warn!(
                down_s = down_for.as_secs(),
                "cloudflared: no egress passed the probe for a long time; \
                 trying the download anyway (the probe itself may be wrong)"
            );
        } else {
            g.egress_down_since = None;
            let just_became_usable = !g.link_ok;
            g.link_ok = true;
            if just_became_usable {
                g.download_fails = 0;
            } else if let Some(last) = g.last_download
                && last.elapsed() < retry
            {
                return Err(BinaryState::DownloadFailed);
            }
        }
        g.last_download = Some(Instant::now());
        Ok(())
    }

    fn download_arms(&self, force: bool) -> Vec<DownloadArm> {
        let url = download_url();
        let mut arms = Vec::new();
        if self.proxy_chores_possible() && (force || probe_download(&url, HEALTH_SOCKS5, None).0) {
            arms.push(DownloadArm::Proxied);
        }
        if let Some(arm) = direct_arm(&url) {
            arms.push(arm);
        }
        arms
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

fn download_backoff(fails: u32) -> Duration {
    let last = DOWNLOAD_BACKOFF.len() - 1;
    DOWNLOAD_BACKOFF[(fails.saturating_sub(1) as usize).min(last)]
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

fn why_now(running: Option<Protocol>, at_spawn: ProtocolWhy, egress: Egress) -> ProtocolWhy {
    let Some(running) = running else {
        return at_spawn;
    };
    match crate::cf_quality::fresh_verdict(egress) {
        Some((p, src)) if p == running => src.into(),
        _ => at_spawn,
    }
}

static SCORING_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

fn stamp_with(base: &str, proto: Protocol) -> String {
    format!("{base}#proto={}", proto.as_str())
}

fn block_on_scoring(egress: Egress) -> Option<Protocol> {
    match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(crate::cf_quality::pick(egress)),
        Err(_) => None,
    }
}

fn ladder_for(
    policy: CfProtocol,
    remembered: Option<(Protocol, crate::cf_quality::VerdictSource)>,
) -> Vec<(Protocol, ProtocolWhy, bool)> {
    let CfProtocol::Auto = policy else {
        return vec![(policy.initial(), ProtocolWhy::Locked, true)];
    };
    let skip_quic = remembered.map(|(p, _)| p) == Some(Protocol::Http2);
    let first_why = match remembered {
        Some((_, src)) => src.into(),
        None => ProtocolWhy::Initial,
    };
    let mut out = Vec::with_capacity(LADDER.len());
    for rung in LADDER.iter() {
        if skip_quic && rung.proto == Protocol::Quic {
            continue;
        }
        let why = if out.is_empty() {
            first_why
        } else {
            ProtocolWhy::Fallback
        };
        out.push((rung.proto, why, rung.pin_edges));
    }
    out
}

fn wait_ready(egress: Egress, timeout: Duration) -> bool {
    let Ok(addr) = egress.metrics_addr().parse() else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    loop {
        if crate::cf_metrics::ready(addr).unwrap_or(0) >= 1 {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn block_on_edges_proto(egress: Egress, proto: Protocol) -> Vec<crate::cf_edge::EdgeRtt> {
    match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(crate::cf_edge::pick_edges_proto(egress, proto)),
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

pub(crate) fn prepare_home(egress: Egress) -> io::Result<()> {
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

pub(crate) fn chown_cf(path: &str, egress: Egress) -> io::Result<()> {
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
    proto: Protocol,
    edges: &[String],
    logs: &Arc<sb_web::LineHistory>,
) -> io::Result<u32> {

    if let Err(e) = prepare_home(egress) {
        tracing::debug!(?e, dir = egress.home(), "cloudflared home prepare failed");
    }
    let mut argv: Vec<String> = vec![
        "tunnel".into(),
        "--no-autoupdate".into(),
        "--protocol".into(),
        proto.as_str().into(),
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
            if text.is_empty() || is_noise(&text) {
                continue;
            }
            let text = format!("{tag} {text}");
            println!("{text}");
            logs.push_lines(&[text]);
        }
    });
}

fn is_noise(line: &str) -> bool {
    (line.contains("Collection started collector=")
        || line.contains("Collection finished collector="))
        && line.contains(" INF ")
}

pub(crate) fn drop_to_cf(uid: u32, gid: u32) -> io::Result<()> {

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum DownloadArm {

    Proxied,

    Direct { url: String, ips: Vec<IpAddr> },
}

impl DownloadArm {
    fn label(&self) -> &'static str {
        match self {
            DownloadArm::Proxied => "proxy",
            DownloadArm::Direct { .. } => "direct",
        }
    }
}

fn download_url() -> String {
    format!("{CF_RELEASE_BASE}{}", cf_asset())
}

fn probe_download(url: &str, proxy: &str, pin: Option<IpAddr>) -> (bool, Option<String>) {
    match sb_ppgw::httpcli::head_status_via_blocking(url, proxy, pin, READY_TIMEOUT) {
        Ok((code, location)) => {
            let ok = sb_ppgw::httpcli::status_ok(code, READY_EXPECT);
            if ok {
                tracing::debug!(code, proxy, "cloudflared: the download URL is reachable");
            } else {
                tracing::debug!(code, proxy, "cloudflared: download probe got a bad status");
            }
            (ok, location.filter(|_| ok))
        }
        Err(e) => {
            tracing::debug!(?e, proxy, "cloudflared: download probe failed");
            (false, None)
        }
    }
}

fn download_host() -> &'static str {
    "github.com"
}

fn arm_budget(arm: &DownloadArm, proxy_tried: bool) -> Duration {
    match arm {
        DownloadArm::Direct { .. } if !proxy_tried => DOWNLOAD_TIMEOUT_PROBATION,
        _ => DOWNLOAD_TIMEOUT,
    }
}

fn direct_arm(url: &str) -> Option<DownloadArm> {
    let ips = sb_ppgw::download::resolve_all(download_host());
    let first = *ips.first()?;
    let (ok, location) = probe_download(url, "", Some(first));
    if !ok {
        tracing::debug!("cloudflared: the direct path cannot even HEAD the asset; skipping it");
        return None;
    }
    let Some(loc) = location else {
        return Some(DownloadArm::Direct {
            url: url.to_string(),
            ips,
        });
    };
    let host = sb_ppgw::dnsutil::url_hostname(&loc);
    let cdn = sb_ppgw::download::resolve_all(&host);
    if cdn.is_empty() {
        tracing::debug!(%host, "cloudflared: cannot resolve the redirect target; direct arm skipped");
        return None;
    }
    tracing::debug!(%host, n = cdn.len(), "cloudflared: direct arm will race the redirect target");
    Some(DownloadArm::Direct { url: loc, ips: cdn })
}

fn download_binary(url: &str, arm: &DownloadArm, budget: Duration) -> io::Result<String> {

    #[cfg(test)]
    {
        let _ = (url, arm, budget);
        Err(io::Error::other("downloads are disabled in unit tests"))
    }
    #[cfg(not(test))]
    {
        download_binary_inner(url, arm, budget)
    }
}

#[cfg(not(test))]
fn download_binary_inner(url: &str, arm: &DownloadArm, budget: Duration) -> io::Result<String> {
    let tmp = partial_path();
    discard_stale_partial(&tmp);
    let (url, proxy, ips): (&str, &str, &[IpAddr]) = match arm {
        DownloadArm::Proxied => (url, HEALTH_SOCKS5, &[]),

        DownloadArm::Direct { url, ips } => (url, "", ips),
    };
    sb_ppgw::download::Downloader::new(url, &tmp)
        .timeout(budget)
        .stream_to_file_blocking(proxy, ips)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let verdict = verify_elf(&tmp).and_then(|()| {
        set_mode(&tmp, 0o755)?;
        verify_runs(&tmp)
    });
    let version = match verdict {
        Ok(v) => v,
        Err(e) => {

            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    std::fs::rename(&tmp, CF_BIN)?;
    Ok(version)
}

fn partial_path() -> String {
    format!("{CF_BIN}.download")
}

fn partial_len() -> u64 {
    std::fs::metadata(partial_path())
        .map(|m| m.len())
        .unwrap_or(0)
}

fn discard_stale_partial(tmp: &str) {
    if !Path::new(tmp).exists() {
        return;
    }
    let fresh = std::fs::metadata(tmp)
        .and_then(|m| m.modified())
        .map(|t| t.elapsed().map(|age| age < PARTIAL_MAX_AGE).unwrap_or(true))
        .unwrap_or(false);
    if !fresh {
        tracing::info!(tmp, "cloudflared: discarding a stale partial download");
        let _ = std::fs::remove_file(tmp);
    }
}

fn sweep_partial() {
    let tmp = partial_path();
    if Path::new(&tmp).exists() {
        let bytes = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
        tracing::info!(
            tmp,
            bytes,
            "cloudflared: binary is in place; removing the leftover partial download"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}

fn verify_runs(path: &str) -> io::Result<String> {

    let root = unsafe { libc::geteuid() } == 0;
    run_version(path, root.then(|| Egress::Direct.uid_gid()))
}

fn run_version(path: &str, drop: Option<(u32, u32)>) -> io::Result<String> {
    let mut cmd = Command::new(path);
    cmd.arg("--version")
        .current_dir("/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some((uid, gid)) = drop {

        unsafe {
            cmd.pre_exec(move || drop_to_cf(uid, gid));
        }
    }
    let mut child = cmd.spawn()?;
    let deadline = Instant::now() + VERSION_TIMEOUT;
    let status = loop {
        match child.try_wait()? {
            Some(st) => break st,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(io::ErrorKind::TimedOut, "--version"));
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    if !status.success() {
        return Err(io::Error::other(format!("--version exited {status}")));
    }

    let mut out = String::new();
    if let Some(mut o) = child.stdout.take() {
        use std::io::Read;
        let _ = o.read_to_string(&mut out);
    }
    let line = out.lines().next().unwrap_or("").trim().to_string();
    if line.is_empty() {
        return Err(io::Error::other("--version printed nothing"));
    }
    Ok(line)
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

pub(crate) fn find_cf_pids() -> Vec<u32> {
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

    let reaped = crate::cf_probe::reap_strays();
    if reaped > 0 {
        tracing::info!(n = reaped, "cloudflared: reaped leaked probe tunnels");
    }

    if sup.load_cf_cfg().protocol.adaptive() {
        crate::cf_quality::spawn_rescoring(Arc::clone(&sup), shutdown.clone());
    }
    tokio::spawn(async move {
        loop {

            let nap = sup.next_tick_delay();
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep(nap) => {
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
    }

    #[test]
    fn the_download_backoff_is_a_ladder() {
        let s = |n| Duration::from_secs(n);
        assert_eq!(
            DOWNLOAD_BACKOFF.to_vec(),
            vec![s(10), s(20), s(30), s(60), s(120), s(180), s(240), s(300)]
        );

        assert_eq!(download_backoff(0), s(10));
        assert_eq!(download_backoff(1), s(10));
        assert_eq!(download_backoff(4), s(60));
        assert_eq!(download_backoff(8), s(300));

        assert_eq!(download_backoff(9), s(300));
        assert_eq!(download_backoff(u32::MAX), s(300));
        assert!(
            DOWNLOAD_BACKOFF.windows(2).all(|w| w[0] <= w[1]),
            "the ladder must be monotonic"
        );

        let early: Duration = DOWNLOAD_BACKOFF[..4].iter().sum();
        assert!(early <= s(120), "the first four retries took {early:?}");
    }

    #[test]
    fn the_monitor_tightens_its_period_while_the_binary_is_missing() {
        assert!(
            MONITOR_INTERVAL_PENDING < DOWNLOAD_BACKOFF[0],
            "the tick must be finer than the first rung, else the rung is unobservable"
        );
        let s = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Free, None);
        let want = if Path::new(CF_BIN).is_file() {
            MONITOR_INTERVAL
        } else {
            MONITOR_INTERVAL_PENDING
        };
        assert_eq!(s.next_tick_delay(), want);

        {
            let mut g = s.global.lock().unwrap();
            g.last_download = Some(Instant::now());
            g.download_fails = 8;
        }
        let d = s.next_tick_delay();
        assert!(d <= MONITOR_INTERVAL, "never nap longer than usual: {d:?}");
        assert!(d >= MONITOR_INTERVAL_PENDING);
    }

    #[test]
    fn the_backoff_only_counts_real_attempts() {
        let s = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Free, None);

        assert_eq!(s.throttle(false), Err(BinaryState::EgressDown));
        {
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

        assert_eq!(s.throttle(true), Ok(()));
        {
            let g = s.global.lock().unwrap();
            assert!(g.last_download.is_some());
            assert!(g.link_ok);
        }

        assert_eq!(s.throttle(true), Err(BinaryState::DownloadFailed));

        assert_eq!(s.throttle(false), Err(BinaryState::EgressDown));
        s.global.lock().unwrap().download_fails = 5;
        assert_eq!(s.throttle(true), Ok(()));
        assert_eq!(
            s.global.lock().unwrap().download_fails,
            0,
            "a recovered link starts a fresh ladder"
        );
    }

    #[test]
    fn gateway_reload_generation_restamps_both_replicas() {
        let saved = std::fs::read_to_string(RELOAD_MARKER).ok();
        let s = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Free, None);

        std::fs::write(RELOAD_MARKER, "1000000001\n").expect("write marker");
        let first: Vec<String> = Egress::ALL
            .iter()
            .map(|&e| {
                s.stamp(e, &CloudflaredCfg::default())
                    .expect("free mode always has a stamp")
            })
            .collect();
        assert!(
            first.iter().all(|st| st.contains("#reload=1000000001")),
            "both replicas must carry the reload generation: {first:?}"
        );

        std::fs::write(RELOAD_MARKER, "1000000002\n").expect("write marker");
        for (i, &e) in Egress::ALL.iter().enumerate() {
            assert_ne!(
                s.stamp(e, &CloudflaredCfg::default()).unwrap(),
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
    fn the_probe_hits_the_exact_url_we_download() {
        let url = download_url();
        assert_eq!(url, format!("{CF_RELEASE_BASE}{}", cf_asset()));
        assert!(url.contains(download_host()), "{url}");
        assert!(url.starts_with("https://"), "TLS or it proves nothing");
        assert!(url.ends_with(cf_asset()), "the arch-specific asset: {url}");
        assert_eq!(READY_TIMEOUT, Duration::from_secs(5));

        for code in [200u16, 204, 301, 302, 307, 399] {
            assert!(sb_ppgw::httpcli::status_ok(code, READY_EXPECT), "{code}");
        }
        for code in [400u16, 403, 404, 500, 502] {
            assert!(!sb_ppgw::httpcli::status_ok(code, READY_EXPECT), "{code}");
        }
    }

    #[test]
    fn the_direct_arm_downloads_from_the_redirect_target() {
        let cdn = "https://objects.githubusercontent.com/release-assets/cloudflared";
        let arm = DownloadArm::Direct {
            url: cdn.to_string(),
            ips: vec!["203.0.113.7".parse().unwrap()],
        };
        let DownloadArm::Direct { url, ips } = &arm else {
            panic!("built a direct arm");
        };
        assert_eq!(
            url, cdn,
            "the arm carries the redirect target, not the origin"
        );
        assert_ne!(
            sb_ppgw::dnsutil::url_hostname(url),
            download_host(),
            "the CDN host is a different host — that is the whole point"
        );
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn the_direct_arm_requires_a_working_head() {
        let src = include_str!("cf_ctl.rs");
        let direct = src
            .split("\nfn direct_arm(url: &str)")
            .nth(1)
            .and_then(|s| s.split("\n}\n").next())
            .expect("direct_arm exists");
        assert!(
            !direct.contains("force"),
            "force must never reach the direct arm; body was:\n{direct}"
        );
        assert!(
            direct.contains("if !ok {") && direct.contains("return None;"),
            "a failed HEAD must skip the arm entirely; body was:\n{direct}"
        );

        let arms = method_body(src, "fn download_arms(&self, force: bool)");
        assert!(
            arms.contains("force || probe_download(&url, HEALTH_SOCKS5, None).0"),
            "the proxy arm keeps its escape hatch; body was:\n{arms}"
        );
    }

    #[test]
    fn the_stall_guard_fires_well_before_the_total_timeout() {
        let stall = sb_ppgw::httpcli::BODY_STALL;
        assert!(
            stall * 3 <= DOWNLOAD_TIMEOUT,
            "stall {stall:?} vs total {DOWNLOAD_TIMEOUT:?}"
        );
        assert!(READY_TIMEOUT < stall);

        const SLOW_LINK_BPS: u64 = 70 * 1024;
        const ASSET_BYTES: u64 = 40 * 1024 * 1024;
        assert!(
            DOWNLOAD_TIMEOUT.as_secs() * SLOW_LINK_BPS >= ASSET_BYTES,
            "a {}s budget only covers {} MB at 70 KB/s",
            DOWNLOAD_TIMEOUT.as_secs(),
            DOWNLOAD_TIMEOUT.as_secs() * SLOW_LINK_BPS / 1_048_576
        );
    }

    #[test]
    fn the_two_download_arms_are_named_apart() {
        assert_eq!(DownloadArm::Proxied.label(), "proxy");
        let direct = DownloadArm::Direct {
            url: download_url(),
            ips: Vec::new(),
        };
        assert_eq!(direct.label(), "direct");
    }

    #[test]
    fn a_stale_partial_is_dropped_and_a_fresh_one_is_kept() {
        let dir = std::env::temp_dir().join(format!("cfpartial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fresh = dir.join("fresh.download");
        let stale = dir.join("stale.download");
        std::fs::write(&fresh, b"partial").expect("write");
        std::fs::write(&stale, b"partial").expect("write");
        backdate(&stale, PARTIAL_MAX_AGE + Duration::from_secs(60));

        discard_stale_partial(fresh.to_str().unwrap());
        assert!(fresh.exists(), "a fresh partial is what resume runs on");
        discard_stale_partial(stale.to_str().unwrap());
        assert!(!stale.exists(), "a stale partial must be dropped");

        discard_stale_partial(dir.join("nope").to_str().unwrap());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn backdate(path: &std::path::Path, age: Duration) {
        let when = std::time::SystemTime::now() - age;
        let secs = when
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs() as i64;
        let tv = [
            libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
        ];
        let c = std::ffi::CString::new(path.to_str().expect("utf-8")).expect("no NUL");

        let rc = unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()) };
        assert_eq!(rc, 0, "utimes failed: {}", io::Error::last_os_error());
    }

    #[test]
    fn a_downloaded_binary_must_actually_run() {
        let dir = std::env::temp_dir().join(format!("cfverify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");

        set_mode(dir.to_str().unwrap(), 0o755).expect("chmod dir");
        let mk = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).expect("write");
            set_mode(p.to_str().unwrap(), 0o755).expect("chmod");
            p
        };

        let good = mk("good", "#!/bin/sh\necho 'cloudflared version 1.2.3'\n");
        assert_eq!(
            verify_runs(good.to_str().unwrap()).expect("must run"),
            "cloudflared version 1.2.3"
        );

        let mute = mk("mute", "#!/bin/sh\nexit 0\n");
        assert!(verify_runs(mute.to_str().unwrap()).is_err());

        let angry = mk("angry", "#!/bin/sh\necho nope\nexit 3\n");
        assert!(verify_runs(angry.to_str().unwrap()).is_err());

        let junk = mk("junk", "\x7fELF not really\n");
        assert!(verify_runs(junk.to_str().unwrap()).is_err());

        assert!(verify_runs(dir.join("absent").to_str().unwrap()).is_err());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn downloads_are_disabled_in_unit_tests() {
        let arm = DownloadArm::Direct {
            url: download_url(),
            ips: vec!["203.0.113.7".parse().unwrap()],
        };
        let err =
            download_binary(&download_url(), &arm, DOWNLOAD_TIMEOUT).expect_err("must be refused");
        assert!(err.to_string().contains("disabled"), "{err}");
        let err = download_binary(&download_url(), &DownloadArm::Proxied, DOWNLOAD_TIMEOUT)
            .expect_err("ditto");
        assert!(err.to_string().contains("disabled"), "{err}");
    }

    #[test]
    fn a_stand_in_direct_arm_only_gets_a_short_lease() {
        let direct = DownloadArm::Direct {
            url: download_url(),
            ips: vec!["203.0.113.7".parse().unwrap()],
        };

        assert_eq!(
            arm_budget(&direct, false),
            DOWNLOAD_TIMEOUT_PROBATION,
            "a stand-in must hand control back so the proxy can take over"
        );

        assert_eq!(arm_budget(&direct, true), DOWNLOAD_TIMEOUT);

        assert_eq!(arm_budget(&DownloadArm::Proxied, true), DOWNLOAD_TIMEOUT);
        assert!(
            DOWNLOAD_TIMEOUT_PROBATION < DOWNLOAD_TIMEOUT,
            "a lease that is not shorter is not a lease"
        );

        assert!(DOWNLOAD_TIMEOUT_PROBATION > sb_ppgw::httpcli::BODY_STALL);

        assert!(DOWNLOAD_TIMEOUT_PROBATION.as_secs() * 51 * 1024 >= 1024 * 1024);
    }

    #[test]
    fn making_progress_does_not_climb_the_backoff_ladder() {

        let slices = 39_278_667u64.div_ceil(DOWNLOAD_TIMEOUT_PROBATION.as_secs() * 51 * 1024);
        let punished: u64 = (1..slices)
            .map(|n| download_backoff(n as u32).as_secs())
            .sum();
        let forgiven: u64 = (1..slices).map(|_| DOWNLOAD_BACKOFF[0].as_secs()).sum();
        assert!(
            punished > 3 * forgiven,
            "punishing progress costs {punished}s of waiting vs {forgiven}s — that is the trap"
        );

        let s = CloudflaredSupervisor::new(ConfigSource::Production, OutboundMode::Free, None);
        let bump = |progressed: bool| {
            let mut g = s.global.lock().unwrap();
            g.download_fails = if progressed {
                0
            } else {
                g.download_fails.saturating_add(1)
            };
            g.download_fails
        };
        assert_eq!(bump(false), 1);
        assert_eq!(bump(false), 2);
        assert_eq!(bump(true), 0, "a slice that moved bytes is not a failure");
        assert_eq!(bump(false), 1);
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

    #[test]
    fn the_binary_download_is_not_held_back_by_the_startup_grace() {
        let src = include_str!("cf_ctl.rs");
        let body = method_body(src, "fn tick_locked(&self)");

        let download = body
            .find("let state = self.ensure_binary();")
            .expect("tick_locked downloads the binary when it is missing");
        let grace = body
            .find("self.started.elapsed() < STARTUP_GRACE")
            .expect("tick_locked defers starts during the grace period");
        assert!(
            download < grace,
            "the download must not sit behind the startup grace"
        );
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
                && tick.contains("let state = self.ensure_binary();"),
            "tick_locked must still download the binary when it is missing"
        );
        assert_eq!(
            tick.matches("proxy_chores_possible").count(),
            2,
            "only the two update checks may gate on the proxy; the download must not"
        );

        let arms = method_body(src, "fn download_arms(&self, force: bool)");
        assert!(
            arms.contains("self.proxy_chores_possible()"),
            "the proxy arm is offered only when the proxy is ready"
        );
        assert!(
            arms.contains("direct_arm(&url)"),
            "the direct arm must not be conditioned on the proxy; body was:\n{arms}"
        );
        let direct = src
            .split("\nfn direct_arm(url: &str)")
            .nth(1)
            .and_then(|s| s.split("\n}\n").next())
            .expect("direct_arm exists");
        assert!(
            !direct.contains("proxy_chores_possible") && !direct.contains("proxy_stamp"),
            "the direct arm waits for nothing; body was:\n{direct}"
        );
        let start = method_body(src, "fn start_replica(&self");
        assert!(
            !start.contains("proxy_chores_possible") && !start.contains("proxy_stamp"),
            "picking edges and spawning must never wait on the proxy; body was:\n{start}"
        );

        assert!(
            start.contains("block_on_edges_proto(egress, proto)") && start.contains("spawn_cf(")
        );
        assert!(
            !start.contains("fn "),
            "extraction must stop at the next fn"
        );
    }

    #[test]
    fn only_the_self_inflicted_diagnostic_chatter_is_filtered() {
        for noisy in [
            "2026-08-07T17:50:41Z INF Collection finished collector=tunnelState",
            "2026-08-07T17:50:42Z INF Collection started collector=tunnelState",
            "2026-08-07T17:50:42Z INF Collection started collector=systemInformation",
        ] {
            assert!(is_noise(noisy), "must be filtered: {noisy}");
        }
        for keep in [
            "2026-08-07T17:46:42Z INF Registered tunnel connection connIndex=0 location=hkg10 protocol=http2",
            "2026-08-07T17:46:48Z INF precheck complete hard_fail=false suggested_protocol=http2",
            "2026-08-07T17:46:42Z WRN ICMP proxy feature is disabled",
            "2026-08-07T17:46:37Z INF Requesting new quick Tunnel on trycloudflare.com...",

            "2026-08-07T17:50:41Z ERR Collection finished collector=tunnelState error=boom",
        ] {
            assert!(!is_noise(keep), "must be kept: {keep}");
        }
    }

    #[test]
    fn a_locked_protocol_has_no_ladder() {
        for p in [Protocol::Quic, Protocol::Http2] {
            let rungs = ladder_for(CfProtocol::Fixed(p), None);
            assert_eq!(rungs.len(), 1);
            assert_eq!(rungs[0].0, p);
            assert_eq!(rungs[0].1, ProtocolWhy::Locked);
            assert!(rungs[0].2, "a locked transport still pins its own edges");

            let with_memory = ladder_for(
                CfProtocol::Fixed(p),
                Some((p.other(), VerdictSource::Scored)),
            );
            assert_eq!(with_memory.len(), 1);
            assert_eq!(with_memory[0].0, p);
        }
    }

    #[test]
    fn auto_climbs_the_full_ladder_without_memory() {
        let rungs = ladder_for(CfProtocol::Auto, None);
        assert_eq!(
            rungs
                .iter()
                .map(|(p, _, pin)| (p.as_str(), *pin))
                .collect::<Vec<_>>(),
            vec![("quic", true), ("http2", true), ("http2", false)]
        );
        assert_eq!(rungs[0].1, ProtocolWhy::Initial);
        assert_eq!(rungs[1].1, ProtocolWhy::Fallback);
        assert_eq!(rungs[2].1, ProtocolWhy::Fallback);
    }

    #[test]
    fn a_remembered_http2_skips_the_quic_rung() {
        let rungs = ladder_for(
            CfProtocol::Auto,
            Some((Protocol::Http2, VerdictSource::Scored)),
        );
        assert!(
            rungs.iter().all(|(p, _, _)| *p == Protocol::Http2),
            "the quic rung must be skipped, got {:?}",
            rungs.iter().map(|r| r.0.as_str()).collect::<Vec<_>>()
        );

        let quic = ladder_for(
            CfProtocol::Auto,
            Some((Protocol::Quic, VerdictSource::Scored)),
        );
        assert_eq!(quic.len(), LADDER.len());
        assert_eq!(quic[0].0, Protocol::Quic);
    }

    #[test]
    fn a_confirmed_verdict_updates_what_the_panel_says() {

        let e = Egress::Proxied;
        crate::cf_quality::forget(e);

        assert_eq!(
            why_now(Some(Protocol::Quic), ProtocolWhy::Initial, e),
            ProtocolWhy::Initial
        );

        crate::cf_quality::remember_verdict(e, Protocol::Quic, VerdictSource::Scored);
        assert_eq!(
            why_now(Some(Protocol::Quic), ProtocolWhy::Initial, e),
            ProtocolWhy::Scored
        );

        crate::cf_quality::remember_verdict(e, Protocol::Http2, VerdictSource::Fallback);
        assert_eq!(
            why_now(Some(Protocol::Http2), ProtocolWhy::Initial, e),
            ProtocolWhy::Fallback
        );

        assert_eq!(
            why_now(Some(Protocol::Quic), ProtocolWhy::Initial, e),
            ProtocolWhy::Initial
        );

        assert_eq!(why_now(None, ProtocolWhy::Unknown, e), ProtocolWhy::Unknown);
        crate::cf_quality::forget(e);
    }

    #[test]
    fn the_first_rung_reports_how_the_memory_was_made() {
        let scored = ladder_for(
            CfProtocol::Auto,
            Some((Protocol::Quic, VerdictSource::Scored)),
        );
        assert_eq!(scored[0].1, ProtocolWhy::Scored);
        let fell_back = ladder_for(
            CfProtocol::Auto,
            Some((Protocol::Http2, VerdictSource::Fallback)),
        );
        assert_eq!(fell_back[0].1, ProtocolWhy::Fallback);

        assert_eq!(
            ladder_for(CfProtocol::Auto, None)[0].1,
            ProtocolWhy::Initial
        );

        for why in [
            ProtocolWhy::Locked,
            ProtocolWhy::Initial,
            ProtocolWhy::Scored,
            ProtocolWhy::Fallback,
        ] {
            assert!(!why.as_str().is_empty());
        }
    }

    #[test]
    fn the_protocol_is_part_of_the_stamp() {
        let base = "direct-egress#reload=1000000001";
        let q = stamp_with(base, Protocol::Quic);
        let h = stamp_with(base, Protocol::Http2);
        assert_ne!(q, h);
        assert!(q.ends_with("#proto=quic") && h.ends_with("#proto=http2"));
        assert_eq!(q, stamp_with(base, Protocol::Quic), "must be stable");

        assert_eq!(q.split_once("#proto=").unwrap().0, base);
    }

    #[test]
    fn desired_protocol_follows_the_policy() {
        let s = sup();
        let locked = CloudflaredCfg {
            protocol: CfProtocol::Fixed(Protocol::Http2),
            ..Default::default()
        };
        assert_eq!(s.desired_protocol(Egress::Direct, &locked), Protocol::Http2);

        crate::cf_quality::forget(Egress::Direct);
        assert_eq!(
            s.desired_protocol(Egress::Direct, &CloudflaredCfg::default()),
            Protocol::Quic
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
        if s.load_cf_cfg().token.is_some() {
            return;
        }
        s.tick();
        assert!(Egress::ALL.iter().all(|&e| !s.running(e)));
    }

    #[test]
    fn status_and_restart_without_token() {
        let s = sup();
        if s.load_cf_cfg().token.is_some() {
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

        for e in Egress::ALL {
            s.with_proc(e, |p| {
                p.ready_misses = 2;
                p.unready_since = Some(Instant::now());
            });
        }

        let t0 = Instant::now();
        s.tick();
        assert!(t0.elapsed() < Duration::from_secs(1), "tick must not block");

        for e in Egress::ALL {
            let (misses, since) = s.with_proc(e, |p| (p.ready_misses, p.unready_since));
            assert_eq!(misses, 0, "{} ready misses must be cleared", e.as_str());
            assert!(since.is_none(), "{} downtime must restart", e.as_str());
        }
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
