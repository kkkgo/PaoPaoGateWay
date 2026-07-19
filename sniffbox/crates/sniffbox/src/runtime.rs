// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::config::{CidrAcl, Config, OutboundMode, RouteCfg};
use crate::outbound::Outbound;
use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use sb_dns::{FakeIpConfig, FakeIpPool};
use sb_outbound::PoolCfg;
use sb_sniff::{PeekBufPool, SniffNegCache};
use sb_stats::{
    AggTable, ConnId, ConnIdGen, ConnRecord, ConnTable, InboundKind, NodeDist, RecordKind,
    TrafficCache,
};
use sb_web::{AdminAcl, AdminHandle, TokenHandle, admin_handle, derive_secret, token_handle};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

pub const TRAFFIC_DEMAND_WINDOW_MS: u64 = 30_000;

pub struct AtomicRoute(AtomicU8);

#[derive(Copy, Clone, Debug)]
pub struct RouteFlags {
    pub block_bittorrent: bool,
    pub block_quic: bool,
    pub block_unknown: bool,
    pub log_sniffed: bool,
}

impl AtomicRoute {
    const BT: u8 = 1 << 0;
    const QUIC: u8 = 1 << 1;
    const UNKNOWN: u8 = 1 << 2;
    const LOG: u8 = 1 << 3;

    fn pack(c: &RouteCfg) -> u8 {
        (if c.block_bittorrent { Self::BT } else { 0 })
            | (if c.block_quic { Self::QUIC } else { 0 })
            | (if c.block_unknown { Self::UNKNOWN } else { 0 })
            | (if c.log_sniffed { Self::LOG } else { 0 })
    }

    pub fn new(c: &RouteCfg) -> Self {
        Self(AtomicU8::new(Self::pack(c)))
    }

    pub fn store(&self, c: &RouteCfg) {
        self.0.store(Self::pack(c), Ordering::Release);
    }

    pub fn load(&self) -> RouteFlags {
        let b = self.0.load(Ordering::Acquire);
        RouteFlags {
            block_bittorrent: b & Self::BT != 0,
            block_quic: b & Self::QUIC != 0,
            block_unknown: b & Self::UNKNOWN != 0,
            log_sniffed: b & Self::LOG != 0,
        }
    }
}

pub struct SharedState {

    pub route: AtomicRoute,

    pub outbound: Arc<Outbound>,

    outbound_mode: crate::config::OutboundMode,

    pub listen_addr: SocketAddr,

    pub id_gen: ConnIdGen,

    pub conn_table: ConnTable,

    pub traffic: Arc<TrafficCache>,

    pub agg: Arc<AggTable>,

    pub pplog: Option<crate::pplog::PplogHandle>,

    pub peek_pool: Arc<PeekBufPool>,

    pub sniff_neg: Arc<SniffNegCache>,

    pub fakeip: Option<Arc<FakeIpPool>>,

    proxy_acl: ArcSwap<CidrAcl>,

    splice_copy: AtomicBool,

    splice_threshold: AtomicU64,

    sniff_timeout_ms: AtomicU64,

    max_rec: AtomicUsize,

    net_cleanday: AtomicU8,

    web_admin: AdminHandle,

    web_token: TokenHandle,

    openport_auth: ArcSwap<Option<Arc<(String, String)>>>,

    pub node_dist: Arc<NodeDist>,

    pub socks_src_index: DashMap<u16, SocksSrc>,

    pub close_registry: DashMap<ConnId, tokio::sync::oneshot::Sender<()>>,

    pub clash_conns_cache: ArcSwapOption<String>,

    pub clash_conns_last_access: AtomicU64,

    pub traffic_last_access: AtomicU64,
}

#[derive(Clone, Copy)]
pub struct SocksSrc {
    pub ip: IpAddr,
    pub port: u16,
    pub inbound: InboundKind,
}

impl SharedState {
    pub fn new(cfg: &Config) -> Self {
        let outbound = Outbound::build(cfg);
        let fakeip = build_fakeip(cfg);
        Self {
            route: AtomicRoute::new(&cfg.route),
            outbound,
            outbound_mode: cfg.outbound.mode,
            listen_addr: cfg.inbound.listen,
            id_gen: ConnIdGen::new(),
            conn_table: ConnTable::new(),
            traffic: Arc::new(TrafficCache::new()),
            agg: Arc::new(AggTable::new(agg_window(cfg))),
            pplog: None,
            peek_pool: Arc::new(PeekBufPool::with_defaults()),
            sniff_neg: Arc::new(SniffNegCache::default()),
            fakeip,
            proxy_acl: ArcSwap::from_pointee(cfg.acl.proxy_cidr.clone()),
            splice_copy: AtomicBool::new(cfg.inbound.splice_copy),
            splice_threshold: AtomicU64::new(cfg.inbound.splice_threshold),
            sniff_timeout_ms: AtomicU64::new(cfg.inbound.sniff_timeout.as_millis() as u64),
            max_rec: AtomicUsize::new(stats_max_rec(cfg)),
            net_cleanday: AtomicU8::new(stats_net_cleanday(cfg)),
            web_admin: admin_handle(AdminAcl::new(cfg.web.admin_cidr.nets().to_vec())),
            web_token: token_handle(derive_secret(&cfg.web.password)),
            openport_auth: ArcSwap::from_pointee(cfg.inbound_proxy.auth.clone().map(Arc::new)),
            node_dist: Arc::new(NodeDist::new()),
            socks_src_index: DashMap::new(),
            close_registry: DashMap::new(),
            clash_conns_cache: ArcSwapOption::empty(),
            clash_conns_last_access: AtomicU64::new(0),
            traffic_last_access: AtomicU64::new(0),
        }
    }

    pub fn splice_copy(&self) -> bool {
        self.splice_copy.load(Ordering::Relaxed)
    }

    pub fn splice_threshold(&self) -> u64 {
        self.splice_threshold.load(Ordering::Relaxed)
    }

    pub fn sniff_timeout(&self) -> Duration {
        Duration::from_millis(self.sniff_timeout_ms.load(Ordering::Relaxed))
    }

    pub fn max_rec(&self) -> usize {
        self.max_rec.load(Ordering::Relaxed)
    }

    pub fn net_cleanday(&self) -> u8 {
        self.net_cleanday.load(Ordering::Relaxed)
    }

    pub fn web_admin(&self) -> AdminHandle {
        self.web_admin.clone()
    }

    pub fn web_token(&self) -> TokenHandle {
        self.web_token.clone()
    }

    pub fn openport_auth(&self) -> Option<Arc<(String, String)>> {
        (**self.openport_auth.load()).clone()
    }

    pub fn proxy_allowed(&self, ip: std::net::IpAddr) -> bool {
        ip.is_loopback() || self.proxy_acl.load().allows(ip)
    }

    pub fn proxy_cidr(&self) -> Vec<String> {
        self.proxy_acl
            .load()
            .nets()
            .iter()
            .map(|n| n.to_string())
            .collect()
    }

    pub fn admin_cidr(&self) -> Vec<String> {
        self.web_admin
            .load()
            .nets()
            .iter()
            .map(|n| n.to_string())
            .collect()
    }

    pub fn reload(&self, new_cfg: &Config) {
        self.route.store(&new_cfg.route);

        self.splice_copy
            .store(new_cfg.inbound.splice_copy, Ordering::Relaxed);
        self.splice_threshold
            .store(new_cfg.inbound.splice_threshold, Ordering::Relaxed);
        self.sniff_timeout_ms.store(
            new_cfg.inbound.sniff_timeout.as_millis() as u64,
            Ordering::Relaxed,
        );

        self.proxy_acl
            .store(Arc::new(new_cfg.acl.proxy_cidr.clone()));

        self.max_rec
            .store(stats_max_rec(new_cfg), Ordering::Relaxed);
        self.net_cleanday
            .store(stats_net_cleanday(new_cfg), Ordering::Relaxed);

        self.web_admin.store(Arc::new(AdminAcl::new(
            new_cfg.web.admin_cidr.nets().to_vec(),
        )));
        self.openport_auth
            .store(Arc::new(new_cfg.inbound_proxy.auth.clone().map(Arc::new)));

        self.web_token
            .store(Arc::new(derive_secret(&new_cfg.web.password)));

        self.outbound.reload(new_cfg);

        if let Some(pool) = self.outbound.socks5_pool() {
            pool.resize(PoolCfg {
                min: new_cfg.socks5.pool_min,
                max: new_cfg.socks5.pool_max,
                idle_timeout: new_cfg.socks5.pool_idle,
            });
        }
        if new_cfg.outbound.mode != self.outbound_mode {
            tracing::warn!(
                current = ?self.outbound_mode, new = ?new_cfg.outbound.mode,
                "outbound mode changed on reload — restart required to take effect"
            );
        }
        if new_cfg.inbound.listen != self.listen_addr {
            tracing::warn!(
                current = %self.listen_addr, new = %new_cfg.inbound.listen,
                "listen address changed on reload — restart required to take effect"
            );
        }
    }
}

pub struct WebTraffic {
    pub shared: Arc<SharedState>,
}

impl sb_web::TrafficSource for WebTraffic {
    fn snapshot_json(&self) -> String {

        let now = sb_stats::now_epoch_ms();
        let prev = self.shared.traffic_last_access.swap(now, Ordering::Relaxed);
        if prev == 0 || now.saturating_sub(prev) > TRAFFIC_DEMAND_WINDOW_MS {
            self.shared.agg.rebuild(self.shared.max_rec());
        }
        self.shared.agg.snapshot_json()
    }
    fn totals(&self) -> (u64, u64) {
        self.shared.traffic.totals()
    }
    fn clear(&self) {
        self.shared.conn_table.clear();
        self.shared.traffic.clear();
        self.shared.agg.clear();
    }
}

pub struct WebConnections {
    pub shared: Arc<SharedState>,
}

impl sb_web::ConnectionsSource for WebConnections {
    fn connections_json(&self) -> String {
        connections_snapshot(&self.shared)
    }
    fn close_all(&self) {

        self.shared.close_registry.clear();
    }
    fn close_one(&self, id: &str) -> bool {
        let Ok(n) = id.parse::<u64>() else {
            return false;
        };
        self.shared.close_registry.remove(&ConnId(n)).is_some()
    }
}

pub struct WebClashConnections {
    pub shared: Arc<SharedState>,
}

impl sb_web::ConnectionsSource for WebClashConnections {
    fn connections_json(&self) -> String {

        self.shared
            .clash_conns_last_access
            .store(sb_stats::now_epoch_ms(), Ordering::Relaxed);
        match self.shared.clash_conns_cache.load_full() {
            Some(blob) => (*blob).clone(),

            None => r#"{"downloadTotal":0,"uploadTotal":0,"connections":[]}"#.to_string(),
        }
    }
}

pub struct WebNodes {
    pub shared: Arc<SharedState>,
}

impl sb_web::NodesSource for WebNodes {
    fn nodes_json(&self) -> String {
        self.shared.node_dist.snapshot_json()
    }
    fn clear(&self) {
        self.shared.node_dist.clear();
    }
}

pub struct InfoStatic {
    pub mode: OutboundMode,
    pub openport_enabled: bool,
    pub openport_port: u16,
    pub udp_enable: bool,

    pub net_rec: bool,
    pub pplog: Option<SocketAddr>,

    pub dns_resolver: Option<SocketAddr>,

    pub clash_sock: std::path::PathBuf,
}

impl InfoStatic {
    pub fn from_cfg(cfg: &Config) -> Self {
        Self {
            mode: cfg.outbound.mode,
            openport_enabled: cfg.inbound_proxy.enabled,
            openport_port: cfg.inbound_proxy.listen_port,
            udp_enable: cfg.inbound_proxy.udp,
            net_rec: cfg.stats.as_ref().is_some_and(|s| s.enabled),
            pplog: cfg.report.pplog,
            dns_resolver: cfg.outbound.resolver.server,
            clash_sock: cfg.web.clash_sock.clone(),
        }
    }
}

#[derive(Default)]
struct InfoSample {

    cpu: Option<(u64, u64)>,

    cpu_cores: Vec<(u64, u64)>,

    proc_self: Option<u64>,

    proc_clash: Option<(u32, u64)>,

    proc_ovpn: Option<(u32, u64)>,
}

pub struct WebInfo {
    pub shared: Arc<SharedState>,
    pub stat: InfoStatic,
    sample: std::sync::Mutex<InfoSample>,
}

impl WebInfo {
    pub fn new(shared: Arc<SharedState>, stat: InfoStatic) -> Self {
        Self {
            shared,
            stat,
            sample: std::sync::Mutex::new(InfoSample::default()),
        }
    }

    fn mode_string(&self) -> String {
        match std::env::var("mode") {
            Ok(m) if !m.trim().is_empty() => m.trim().to_string(),
            _ => match self.stat.mode {
                OutboundMode::Free => "free",
                OutboundMode::Socks5 => "socks5",
                OutboundMode::Ovpn => "ovpn",
                OutboundMode::Yaml => "yaml",
                OutboundMode::Suburl => "suburl",
            }
            .to_string(),
        }
    }

    fn is_ppsub(&self) -> bool {
        if self.mode_string() != "suburl" {
            return false;
        }
        let suburl = env_or_ini("suburl");
        is_ppsub_suburl(suburl.as_deref())
    }
}

pub fn ppsub_active() -> bool {
    env_or_ini("mode")
        .as_deref()
        .map(|s| s.trim().trim_matches('"'))
        == Some("suburl")
        && is_ppsub_suburl(env_or_ini("suburl").as_deref())
}

fn is_ppsub_suburl(suburl: Option<&str>) -> bool {
    suburl
        .map(str::trim)
        .and_then(|s| s.strip_prefix("ppsub@"))
        .is_some_and(|url| !url.trim().is_empty())
}

fn env_or_ini(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| crate::production::ini_value(key))
}

fn env_bool(key: &str) -> bool {
    matches!(
        env_or_ini(key)
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

impl WebInfo {

    fn static_value(&self) -> serde_json::Value {
        use crate::sysinfo;
        let (mem_total, _) = sysinfo::meminfo();
        let (cpu_model, cpu_cores) = sysinfo::cpu_model_cores();

        let ifaces: Vec<serde_json::Value> = sysinfo::interfaces()
            .into_iter()
            .map(|i| {
                serde_json::json!({
                    "name": i.name,
                    "ipv4": i.ipv4,
                    "ipv6": i.ipv6,
                    "mac": i.mac,
                    "gateway": i.gateway,
                })
            })
            .collect();

        let trusted = {
            let ip = env_or_ini("dns_ip").unwrap_or_default();
            let ip = ip.trim();
            if !ip.is_empty() {
                let port: u16 = env_or_ini("dns_port")
                    .and_then(|p| p.trim().parse().ok())
                    .unwrap_or(53);
                serde_json::json!({ "ip": ip, "port": port })
            } else if let Some(s) = self.stat.dns_resolver {
                serde_json::json!({ "ip": s.ip().to_string(), "port": s.port() })
            } else {
                serde_json::Value::Null
            }
        };
        let ex_dns: Vec<String> = env_or_ini("ex_dns")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let clash_version = self
            .stat
            .mode
            .via_clash()
            .then(|| sysinfo::clash_version(&self.stat.clash_sock))
            .flatten();

        let fakeip_cidr = self.shared.fakeip.as_ref().map(|p| p.cidr().to_string());
        let route = self.shared.route.load();

        serde_json::json!({
            "version": crate::SNIFFBOX_VERSION,
            "clash_version": clash_version.as_ref().map(|v| &v.version),
            "clash_meta": clash_version.as_ref().map(|v| v.meta).unwrap_or(false),
            "mode": self.mode_string(),
            "ppsub": self.is_ppsub(),
            "kernel": sysinfo::kernel_version(),
            "memory": { "total": mem_total },
            "cpu": { "model": cpu_model, "cores": cpu_cores },
            "interfaces": ifaces,
            "dns": {
                "trusted": trusted,
                "ex_dns": ex_dns,
                "system": sysinfo::resolv_nameservers(),
            },
            "features": {
                "dns_burn": env_bool("dns_burn"),
                "net_rec": self.stat.net_rec,
                "openport": self.stat.openport_enabled,
                "openport_port": self.stat.openport_port,
                "udp_enable": self.stat.udp_enable,
                "max_rec": self.shared.max_rec(),
                "net_cleanday": self.shared.net_cleanday(),
            },

            "route": {
                "block_bittorrent": route.block_bittorrent,
                "block_quic": route.block_quic,
                "block_unknown": route.block_unknown,
            },

            "acl": {
                "admin_cidr": self.shared.admin_cidr(),
                "proxy_cidr": self.shared.proxy_cidr(),
            },
            "fakeip": { "cidr": fakeip_cidr },
            "pplog": self.stat.pplog.map(|s| s.to_string()),
        })
    }

    fn dynamic_value(&self) -> serde_json::Value {
        use crate::sysinfo;

        let now_cpu = sysinfo::cpu_jiffies();
        let now_cpu_cores = sysinfo::cpu_jiffies_per_core();
        let now_self = sysinfo::self_cpu_jiffies();

        let clash_pid = self
            .stat
            .mode
            .via_clash()
            .then(|| sysinfo::find_pid_by_name(&["clash", "mihomo", "clash-meta"]))
            .flatten();
        let now_clash = clash_pid.and_then(|p| sysinfo::process_cpu_jiffies(p).map(|j| (p, j)));

        let ovpn_pid = (self.stat.mode == OutboundMode::Ovpn)
            .then(|| sysinfo::find_pid_by_name(&["openvpn"]))
            .flatten();
        let now_ovpn = ovpn_pid.and_then(|p| sysinfo::process_cpu_jiffies(p).map(|j| (p, j)));

        let mut cpu_pct = 0.0;
        let mut cpu_cores = Vec::new();
        let mut self_pct = 0.0;
        let mut clash_pct = 0.0;
        let mut clash_rss = None;
        let mut clash_uptime = None;
        let mut ovpn_pct = 0.0;
        let mut ovpn_rss = None;
        let mut ovpn_uptime = None;

        {
            let mut s = self.sample.lock().unwrap();
            let total_delta = match (s.cpu, now_cpu) {
                (Some(prev), Some(cur)) => cur.0.saturating_sub(prev.0),
                _ => 0,
            };

            if let (Some(prev), Some(cur)) = (s.cpu, now_cpu) {
                cpu_pct = sysinfo::cpu_usage_pct(prev, cur);
            }

            if s.cpu_cores.len() == now_cpu_cores.len() {
                cpu_cores = s
                    .cpu_cores
                    .iter()
                    .zip(now_cpu_cores.iter())
                    .map(|(&prev, &cur)| (sysinfo::cpu_usage_pct(prev, cur) * 10.0).round() / 10.0)
                    .collect();
            }

            if let (Some(prev), Some(cur)) = (s.proc_self, now_self) {
                self_pct = sysinfo::process_cpu_pct(cur.saturating_sub(prev), total_delta);
            }

            if let (Some((pp, prev)), Some((cp, cur))) = (s.proc_clash, now_clash) {
                if pp == cp {
                    clash_pct = sysinfo::process_cpu_pct(cur.saturating_sub(prev), total_delta);
                }
            }

            if let (Some((pp, prev)), Some((cp, cur))) = (s.proc_ovpn, now_ovpn) {
                if pp == cp {
                    ovpn_pct = sysinfo::process_cpu_pct(cur.saturating_sub(prev), total_delta);
                }
            }

            s.cpu = now_cpu;
            s.cpu_cores = now_cpu_cores;
            s.proc_self = now_self;
            s.proc_clash = now_clash;
            s.proc_ovpn = now_ovpn;
        }

        if let Some(pid) = clash_pid {
            clash_rss = Some(sysinfo::process_rss(pid));
            clash_uptime = sysinfo::process_uptime(pid);
        }

        if let Some(pid) = ovpn_pid {
            ovpn_rss = Some(sysinfo::process_rss(pid));
            ovpn_uptime = sysinfo::process_uptime(pid);
        }

        let (_, mem_avail) = sysinfo::meminfo();

        let all = self.shared.conn_table.snapshot();
        let (down_total, up_total) = live_totals(&self.shared, &all);
        let conns = self.conn_stats(&all);
        let mapped = self.shared.fakeip.as_ref().map(|p| p.len());

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let r1 = |v: f64| (v * 10.0).round() / 10.0;
        serde_json::json!({
            "timestamp": ts,
            "uptime": sysinfo::uptime_secs(),
            "memory": {
                "available": mem_avail,
                "sniffbox_rss": sysinfo::self_rss(),
                "sniffbox_uptime": sysinfo::self_uptime(),
                "clash_rss": clash_rss,
                "clash_uptime": clash_uptime,
                "ovpn_rss": ovpn_rss,
                "ovpn_uptime": ovpn_uptime,
            },
            "cpu": {
                "usage": r1(cpu_pct),
                "per_core": cpu_cores,
                "sniffbox": r1(self_pct),
                "clash": clash_pid.map(|_| r1(clash_pct)),
                "ovpn": ovpn_pid.map(|_| r1(ovpn_pct)),
            },
            "traffic": {
                "downloadTotal": down_total,
                "uploadTotal": up_total,
            },
            "fakeip": { "mapped": mapped },
            "connections": conns,
        })
    }

    fn conn_stats(&self, all: &[Arc<ConnRecord>]) -> serde_json::Value {
        let mut total = 0u64;
        let mut tcp = 0u64;
        let mut udp = 0u64;
        let mut fake = 0u64;
        let mut real = 0u64;
        let mut clients: std::collections::HashSet<std::net::IpAddr> =
            std::collections::HashSet::new();
        for r in all.iter() {
            if r.closed_ms.load(Ordering::Relaxed) != 0 {
                continue;
            }
            total += 1;
            match r.transport {
                sb_stats::Transport::Tcp => tcp += 1,
                sb_stats::Transport::Udp => udp += 1,
            }
            if r.kind == RecordKind::Internal {
                continue;
            }
            clients.insert(r.src.0);
            let is_fake = self
                .shared
                .fakeip
                .as_ref()
                .is_some_and(|p| p.contains(r.dst.0));
            if is_fake {
                fake += 1;
            } else {
                real += 1;
            }
        }
        serde_json::json!({
            "active": total,
            "tcp": tcp,
            "udp": udp,
            "clients": clients.len(),
            "fakeip": fake,
            "realip": real,
        })
    }
}

fn merge_json(a: &mut serde_json::Value, b: serde_json::Value) {
    match (a, b) {
        (serde_json::Value::Object(am), serde_json::Value::Object(bm)) => {
            for (k, bv) in bm {
                merge_json(am.entry(k).or_insert(serde_json::Value::Null), bv);
            }
        }
        (a, b) => *a = b,
    }
}

impl sb_web::InfoSource for WebInfo {
    fn info_json(&self, scope: sb_web::InfoScope) -> String {
        let v = match scope {
            sb_web::InfoScope::Static => self.static_value(),
            sb_web::InfoScope::Dynamic => self.dynamic_value(),
            sb_web::InfoScope::All => {
                let mut s = self.static_value();
                merge_json(&mut s, self.dynamic_value());
                s
            }
        };
        v.to_string()
    }
}

fn live_totals(shared: &SharedState, all: &[Arc<ConnRecord>]) -> (u64, u64) {
    let (mut down, mut up) = shared.traffic.totals();
    for r in all {
        up += r
            .upload
            .load(Ordering::Relaxed)
            .saturating_sub(r.last_drained_up.load(Ordering::Relaxed));
        down += r
            .download
            .load(Ordering::Relaxed)
            .saturating_sub(r.last_drained_down.load(Ordering::Relaxed));
    }
    (down, up)
}

fn connections_snapshot(shared: &SharedState) -> String {
    let all = shared.conn_table.snapshot();
    let (down, up) = live_totals(shared, &all);
    let conns: Vec<serde_json::Value> = all
        .iter()
        .filter(|r| r.closed_ms.load(Ordering::Relaxed) == 0)
        .map(|r| conn_json(r))
        .collect();
    serde_json::json!({
        "downloadTotal": down,
        "uploadTotal": up,
        "connections": conns,
    })
    .to_string()
}

pub fn inbound_type_str(inbound: InboundKind) -> &'static str {
    match inbound {
        InboundKind::TProxy => "TProxy",
        InboundKind::Socks5 => "Socks5",
        InboundKind::Http => "HTTP",
        InboundKind::HealthCheck => "HealthCheck",

        InboundKind::Clash(label) => label,
    }
}

fn conn_json(r: &ConnRecord) -> serde_json::Value {

    let conn_type = if r.kind == RecordKind::Internal {
        "Inner"
    } else {
        inbound_type_str(r.inbound)
    };
    serde_json::json!({
        "id": r.id.0.to_string(),
        "metadata": {
            "network": r.transport.as_str(),
            "type": conn_type,
            "sourceIP": r.src.0.to_string(),
            "sourcePort": r.src.1.to_string(),
            "destinationIP": r.dst.0.to_string(),
            "destinationPort": r.dst.1.to_string(),
            "host": r.display_domain(),
            "dnsMode": "normal",
            "processPath": "",
            "specialProxy": "",
            "sniffHost": r.domain.clone().unwrap_or_default(),
        },
        "upload": r.upload.load(Ordering::Relaxed),
        "download": r.download.load(Ordering::Relaxed),
        "start": rfc3339_ms(r.created_epoch_ms),
        "chains": [],
        "rule": "",
        "rulePayload": "",
    })
}

fn rfc3339_ms(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let ms = epoch_ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{ms:03}Z")
}

fn stats_max_rec(cfg: &Config) -> usize {
    cfg.stats.as_ref().map(|s| s.max_rec).unwrap_or(5000)
}

fn stats_net_cleanday(cfg: &Config) -> u8 {
    cfg.stats.as_ref().map(|s| s.net_cleanday).unwrap_or(0)
}

fn agg_window(cfg: &Config) -> Duration {
    let min = cfg
        .stats
        .as_ref()
        .map(|s| s.traffic_window_min)
        .unwrap_or(60)
        .max(1);
    Duration::from_secs(min as u64 * 60)
}

fn build_fakeip(cfg: &Config) -> Option<Arc<FakeIpPool>> {
    let dns = cfg.dns.as_ref().filter(|d| d.enabled)?;
    let max_entries = match dns.max_entries {
        Some(n) => n,
        None => auto_max_entries(dns.max_mem_pct, sb_dns::usable_addrs(dns.fake_cidr)),
    };
    match FakeIpPool::new(FakeIpConfig {
        cidr: dns.fake_cidr,
        max_entries,
        ttl: dns.ttl,
        shards: dns.shards,
    }) {
        Ok(p) => Some(Arc::new(p)),
        Err(e) => {
            tracing::warn!(cidr = %dns.fake_cidr, ?e, "fakeip pool init failed; dns/fakeip disabled");
            None
        }
    }
}

fn auto_max_entries(mem_pct: u8, usable: u32) -> usize {
    const FALLBACK: usize = 65_536;
    const FLOOR: usize = 4_096;
    let ceil = usable as usize;
    let floor = FLOOR.min(ceil);
    match read_mem_available_bytes() {
        Some(bytes) => {
            let budget = bytes.saturating_mul(mem_pct as u64) / 100;
            let n = (budget / sb_dns::APPROX_BYTES_PER_ENTRY as u64) as usize;
            let n = n.clamp(floor, ceil);
            tracing::info!(
                mem_avail_mb = bytes / 1024 / 1024,
                mem_pct,
                usable,
                max_entries = n,
                "fakeip max_entries auto-sized (capped at cidr usable)"
            );
            n
        }
        None => {
            let n = FALLBACK.min(ceil);
            tracing::warn!(
                fallback = n,
                "MemAvailable unreadable; fakeip max_entries → fallback"
            );
            n
        }
    }
}

fn read_mem_available_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemAvailable:")?;
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        Some(kb * 1024)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InboundCfg, LogCfg, RouteCfg, SocksCfg};

    fn cfg(block_bt: bool) -> Config {
        Config {
            log: LogCfg::default(),
            inbound: InboundCfg::default(),
            socks5: SocksCfg::default(),
            route: RouteCfg {
                block_bittorrent: block_bt,
                ..Default::default()
            },
            stats: None,
            dns: None,
            ..Default::default()
        }
    }

    #[test]
    fn suburl_mode_detects_ppsub() {
        assert!(is_ppsub_suburl(Some("ppsub@http://10.10.10.8/ppsub.json")));
        assert!(is_ppsub_suburl(Some("  ppsub@https://x/y.json  ")));
        assert!(!is_ppsub_suburl(Some("https://sub.example/link")));
        assert!(!is_ppsub_suburl(Some("ppsub@")));
        assert!(!is_ppsub_suburl(None));
    }

    #[test]
    fn info_dynamic_traffic_totals_are_live_not_flush_lagged() {
        use sb_web::{InfoScope, InfoSource};
        use std::net::IpAddr;
        let c = cfg(false);
        let shared = Arc::new(SharedState::new(&c));
        let info = WebInfo::new(Arc::clone(&shared), InfoStatic::from_cfg(&c));

        let dyn_totals = || -> (u64, u64) {
            let v: serde_json::Value =
                serde_json::from_str(&info.info_json(InfoScope::Dynamic)).unwrap();
            (
                v["traffic"]["downloadTotal"].as_u64().unwrap(),
                v["traffic"]["uploadTotal"].as_u64().unwrap(),
            )
        };
        assert_eq!(dyn_totals(), (0, 0));

        let rec = Arc::new(
            ConnRecord::new(
                shared.id_gen.next_id(),
                ("10.0.0.9".parse::<IpAddr>().unwrap(), 5555),
                ("1.1.1.1".parse::<IpAddr>().unwrap(), 443),
                sb_stats::SniffedProto::Tls,
                Some("speed.test".into()),
            )
            .with_inbound(InboundKind::TProxy, sb_stats::Transport::Tcp),
        );
        shared.conn_table.insert(Arc::clone(&rec));

        rec.download.store(100_000_000, Ordering::Relaxed);
        rec.upload.store(2_000_000, Ordering::Relaxed);
        assert_eq!(shared.traffic.totals(), (0, 0), "flush loop has not settled yet");
        assert_eq!(
            dyn_totals(),
            (100_000_000, 2_000_000),
            "totals must reflect undrained increments"
        );

        rec.download.store(200_000_000, Ordering::Relaxed);
        assert_eq!(dyn_totals().0, 200_000_000);

        let (u, d) = rec.drain_delta();
        shared.traffic.add_totals(d, u);
        assert_eq!(shared.traffic.totals(), (200_000_000, 2_000_000));
        assert_eq!(
            dyn_totals(),
            (200_000_000, 2_000_000),
            "totals monotonically consistent before and after settlement"
        );
    }

    #[test]
    fn web_info_json_is_valid_and_complete() {
        use sb_web::{InfoScope, InfoSource};
        let c = cfg(true);
        let shared = Arc::new(SharedState::new(&c));
        let info = WebInfo::new(Arc::clone(&shared), InfoStatic::from_cfg(&c));

        let sv: serde_json::Value =
            serde_json::from_str(&info.info_json(InfoScope::Static)).expect("static valid JSON");
        for key in [
            "version",
            "mode",
            "ppsub",
            "kernel",
            "memory",
            "cpu",
            "interfaces",
            "dns",
            "features",
            "route",
            "acl",
            "fakeip",
        ] {
            assert!(sv.get(key).is_some(), "static missing {key}: {sv}");
        }

        assert!(
            !sv["mode"].as_str().unwrap().contains('@'),
            "mode must be bare: {sv}"
        );
        assert_eq!(
            sv["route"]["block_bittorrent"],
            serde_json::json!(true),
            "cfg(true) blocks BT"
        );
        assert_eq!(sv["route"]["block_quic"], serde_json::json!(false));
        assert!(
            sv["acl"]["admin_cidr"].as_array().unwrap().is_empty(),
            "no acl → allow all"
        );
        assert!(sv["acl"]["proxy_cidr"].as_array().unwrap().is_empty());

        assert_eq!(sv["features"]["net_rec"], serde_json::json!(false));
        assert!(sv["memory"]["total"].as_u64().unwrap() > 0);
        assert!(sv["cpu"]["cores"].as_u64().unwrap() >= 1);
        assert!(
            !sv["interfaces"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["name"] == "lo"),
            "lo should be filtered"
        );
        assert!(sv.get("timestamp").is_none(), "timestamp is dynamic-only");

        let _ = info.info_json(InfoScope::Dynamic);
        let dv: serde_json::Value =
            serde_json::from_str(&info.info_json(InfoScope::Dynamic)).expect("dynamic valid JSON");
        for key in [
            "timestamp",
            "uptime",
            "memory",
            "cpu",
            "traffic",
            "fakeip",
            "connections",
        ] {
            assert!(dv.get(key).is_some(), "dynamic missing {key}: {dv}");
        }
        assert!(dv["uptime"].as_u64().unwrap() > 0);

        assert!(
            dv["traffic"].get("downloadRate").is_none(),
            "rates are frontend-computed: {dv}"
        );
        for key in ["active", "tcp", "udp", "clients", "fakeip", "realip"] {
            assert!(
                dv["connections"].get(key).is_some(),
                "connections missing {key}: {dv}"
            );
        }
        assert!(dv.get("version").is_none(), "version is static-only");

        let av: serde_json::Value =
            serde_json::from_str(&info.info_json(InfoScope::All)).expect("all valid JSON");
        assert!(av["version"].is_string());
        assert!(av["memory"]["total"].as_u64().unwrap() > 0);
        assert!(av["memory"].get("available").is_some());
        assert!(av["cpu"].get("model").is_some() && av["cpu"].get("usage").is_some());
        assert!(av["fakeip"].get("cidr").is_some() && av["fakeip"].get("mapped").is_some());
        assert!(av["connections"].get("active").is_some());
    }

    #[test]
    fn connections_snapshot_empty_rule_and_live_totals() {
        use std::net::IpAddr;
        let shared = SharedState::new(&cfg(false));
        let id = shared.id_gen.next_id();
        let rec = Arc::new(
            ConnRecord::new(
                id,
                ("10.0.0.9".parse::<IpAddr>().unwrap(), 5555),
                ("1.1.1.1".parse::<IpAddr>().unwrap(), 443),
                sb_stats::SniffedProto::Tls,
                Some("example.com".into()),
            )
            .with_inbound(InboundKind::TProxy, sb_stats::Transport::Tcp),
        );

        rec.upload.store(100, Ordering::Relaxed);
        rec.download.store(200, Ordering::Relaxed);
        shared.conn_table.insert(Arc::clone(&rec));

        let v: serde_json::Value = serde_json::from_str(&connections_snapshot(&shared)).unwrap();
        assert_eq!(v["uploadTotal"], 100, "live upload total: {v}");
        assert_eq!(v["downloadTotal"], 200, "live download total: {v}");
        let conns = v["connections"].as_array().unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0]["rule"], "", "rule must be empty (no-clash)");
        assert_eq!(conns[0]["chains"].as_array().unwrap().len(), 0);
        assert_eq!(conns[0]["metadata"]["type"], "TProxy");
        assert_eq!(conns[0]["upload"], 100);
    }

    #[test]
    fn rfc3339_ms_formats_utc() {
        assert_eq!(super::rfc3339_ms(0), "1970-01-01T00:00:00.000Z");

        assert_eq!(
            super::rfc3339_ms(1_609_459_200_000),
            "2021-01-01T00:00:00.000Z"
        );

        assert_eq!(
            super::rfc3339_ms(1_609_459_323_456),
            "2021-01-01T00:02:03.456Z"
        );
    }

    #[test]
    fn reload_swaps_route_atomically() {
        let c1 = cfg(true);
        let state = SharedState::new(&c1);
        assert!(state.route.load().block_bittorrent);

        let c2 = cfg(false);
        state.reload(&c2);
        assert!(!state.route.load().block_bittorrent);
    }

    #[test]
    fn route_flags_pack_roundtrip() {
        let rc = RouteCfg {
            block_bittorrent: true,
            block_quic: false,
            block_unknown: true,
            log_sniffed: false,
        };
        let f = AtomicRoute::new(&rc).load();
        assert!(f.block_bittorrent && !f.block_quic && f.block_unknown && !f.log_sniffed);
    }

    #[test]
    fn auto_max_entries_capped_by_usable() {

        assert!(
            read_mem_available_bytes().is_some(),
            "MemAvailable readable on Linux host"
        );
        let big = sb_dns::usable_addrs("7.0.0.0/8".parse().unwrap());
        let small = sb_dns::usable_addrs("7.0.0.0/24".parse().unwrap());
        for pct in [1u8, 30, 100] {

            let n = auto_max_entries(pct, big);
            assert!(
                n <= big as usize && n >= 4096.min(big as usize),
                "big pct {pct} → {n}"
            );

            assert_eq!(
                auto_max_entries(pct, small),
                small as usize,
                "small cidr must cap at usable"
            );
        }
        assert!(auto_max_entries(50, big) >= auto_max_entries(1, big));
    }

    #[test]
    fn build_fakeip_auto_sizes_when_unset() {
        use crate::config::DnsCfg;
        let mut c = cfg(true);
        c.dns = Some(DnsCfg {
            max_entries: None,
            ..Default::default()
        });
        let state = SharedState::new(&c);

        let fk = state.fakeip.expect("fakeip built");
        let ip = fk.intern("example.com");
        assert!(fk.contains(std::net::IpAddr::V4(ip)));
    }

    #[test]
    fn reload_updates_splice_and_sniff_timeout() {
        let mut c = cfg(true);
        c.inbound.splice_copy = true;
        c.inbound.splice_threshold = 1024 * 1024;
        c.inbound.sniff_timeout = Duration::from_millis(300);
        let state = SharedState::new(&c);
        assert!(state.splice_copy());
        assert_eq!(state.splice_threshold(), 1024 * 1024);
        assert_eq!(state.sniff_timeout(), Duration::from_millis(300));

        c.inbound.splice_copy = false;
        c.inbound.splice_threshold = 4096;
        c.inbound.sniff_timeout = Duration::from_millis(150);
        state.reload(&c);
        assert!(!state.splice_copy());
        assert_eq!(state.splice_threshold(), 4096);
        assert_eq!(state.sniff_timeout(), Duration::from_millis(150));
    }

    #[test]
    fn reload_swaps_proxy_acl_and_stats() {
        use crate::config::{AclCfg, CidrAcl, StatsCfg};
        let ten: std::net::IpAddr = "10.0.0.5".parse().unwrap();

        let mut c = cfg(true);

        let state = SharedState::new(&c);
        assert!(state.proxy_allowed(ten));
        assert_eq!(state.max_rec(), 5000);
        assert_eq!(state.net_cleanday(), 0);

        c.acl = AclCfg {
            proxy_cidr: CidrAcl::parse("192.168.0.0/16").unwrap(),
        };
        c.stats = Some(StatsCfg {
            enabled: true,
            max_rec: 123,
            net_cleanday: 7,
            traffic_window_min: 30,
        });
        state.reload(&c);
        assert!(!state.proxy_allowed(ten));
        assert!(state.proxy_allowed("192.168.1.1".parse().unwrap()));
        assert!(state.proxy_allowed("127.0.0.1".parse().unwrap()));
        assert_eq!(state.max_rec(), 123);
        assert_eq!(state.net_cleanday(), 7);

        c.acl = AclCfg::default();
        c.stats = None;
        state.reload(&c);
        assert!(state.proxy_allowed(ten));
        assert_eq!(state.max_rec(), 5000);
        assert_eq!(state.net_cleanday(), 0);
    }

    #[test]
    fn info_reports_net_rec_and_acl_from_config() {
        use crate::config::{AclCfg, StatsCfg};
        use sb_web::{InfoScope, InfoSource};
        let mut c = cfg(true);
        c.stats = Some(StatsCfg {
            enabled: true,
            max_rec: 77,
            net_cleanday: 3,
            traffic_window_min: 30,
        });
        c.acl = AclCfg {
            proxy_cidr: CidrAcl::parse("192.168.0.0/16").unwrap(),
        };
        c.web.admin_cidr = CidrAcl::parse("10.10.10.0/24").unwrap();

        let shared = Arc::new(SharedState::new(&c));
        let info = WebInfo::new(Arc::clone(&shared), InfoStatic::from_cfg(&c));
        let sv: serde_json::Value =
            serde_json::from_str(&info.info_json(InfoScope::Static)).unwrap();

        assert_eq!(sv["features"]["net_rec"], serde_json::json!(true));
        assert_eq!(sv["features"]["max_rec"], serde_json::json!(77));
        assert_eq!(sv["features"]["net_cleanday"], serde_json::json!(3));
        assert_eq!(
            sv["acl"]["proxy_cidr"],
            serde_json::json!(["192.168.0.0/16"])
        );
        assert_eq!(
            sv["acl"]["admin_cidr"],
            serde_json::json!(["10.10.10.0/24"])
        );
    }

    #[test]
    fn reload_swaps_admin_cidr_and_openport_auth() {
        let lan: std::net::IpAddr = "10.10.10.50".parse().unwrap();
        let mut c = cfg(true);
        c.web.password = "old-pass".into();
        let state = SharedState::new(&c);

        assert!(state.web_admin().load().allows(lan));
        assert!(state.openport_auth().is_none());
        assert_eq!(**state.web_token().load(), derive_secret("old-pass"));

        c.web.admin_cidr = crate::config::CidrAcl::parse("192.168.0.0/16").unwrap();
        c.inbound_proxy.auth = Some(("u".into(), "pw".into()));
        c.web.password = "new-pass".into();
        state.reload(&c);
        assert!(!state.web_admin().load().allows(lan));
        assert_eq!(**state.web_token().load(), derive_secret("new-pass"));
        assert!(
            state
                .web_admin()
                .load()
                .allows("192.168.1.2".parse().unwrap())
        );
        assert!(
            state
                .web_admin()
                .load()
                .allows("127.0.0.1".parse().unwrap())
        );
        let auth = state.openport_auth().expect("auth set");
        assert_eq!(auth.as_ref(), &("u".into(), "pw".into()));

        c.web.admin_cidr = crate::config::CidrAcl::default();
        c.inbound_proxy.auth = None;
        state.reload(&c);
        assert!(state.web_admin().load().allows(lan));
        assert!(state.openport_auth().is_none());
    }
}
