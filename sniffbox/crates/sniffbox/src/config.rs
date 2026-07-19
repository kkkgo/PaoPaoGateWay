// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub log: LogCfg,
    pub inbound: InboundCfg,
    pub socks5: SocksCfg,
    pub route: RouteCfg,
    pub stats: Option<StatsCfg>,
    pub dns: Option<DnsCfg>,

    pub web: WebCfg,

    pub acl: AclCfg,

    pub inbound_proxy: InboundProxyCfg,

    pub outbound: OutboundCfg,

    pub report: ReportCfg,
}

#[derive(Debug, Clone)]
pub struct LogCfg {
    pub level: String,
    pub timestamp: bool,
}
impl Default for LogCfg {
    fn default() -> Self {
        Self {
            level: "info".into(),
            timestamp: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InboundCfg {
    pub listen: SocketAddr,

    pub listen6: Option<SocketAddr>,
    pub sniff_timeout: Duration,
    pub splice_copy: bool,

    pub splice_threshold: u64,
    pub udp: bool,
    pub udp_idle: Duration,

    pub udp_workers: usize,

    pub tcp_workers: usize,

    pub spoof_cache_cap: usize,

    pub tune_sysctl: bool,
}
impl Default for InboundCfg {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1081".parse().unwrap(),
            listen6: None,
            sniff_timeout: Duration::from_millis(300),
            splice_copy: true,
            splice_threshold: 1024 * 1024,
            udp: true,
            udp_idle: Duration::from_secs(60),
            udp_workers: default_udp_workers(),
            tcp_workers: default_udp_workers(),
            spoof_cache_cap: 1024,
            tune_sysctl: true,
        }
    }
}

fn default_udp_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8)
}

#[derive(Debug, Clone)]
pub struct SocksCfg {
    pub server: SocketAddr,
    pub pool_min: usize,
    pub pool_max: usize,
    pub pool_idle: Duration,
}
impl Default for SocksCfg {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:1080".parse().unwrap(),
            pool_min: 8,
            pool_max: 128,
            pool_idle: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteCfg {
    pub block_bittorrent: bool,
    pub block_quic: bool,
    pub block_unknown: bool,
    pub log_sniffed: bool,
}
impl Default for RouteCfg {
    fn default() -> Self {
        Self {
            block_bittorrent: true,
            block_quic: false,
            block_unknown: false,
            log_sniffed: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StatsCfg {
    pub enabled: bool,
    pub max_rec: usize,
    pub net_cleanday: u8,

    pub traffic_window_min: u32,
}
impl Default for StatsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            max_rec: 5000,
            net_cleanday: 0,
            traffic_window_min: 60,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsCfg {
    pub enabled: bool,

    pub listen: SocketAddr,

    pub fake_cidr: Ipv4Net,

    pub ttl: u32,

    pub max_entries: Option<usize>,

    pub max_mem_pct: u8,

    pub shards: u32,
}
impl Default for DnsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:1053".parse().unwrap(),
            fake_cidr: "7.0.0.0/8".parse().unwrap(),
            ttl: 3,
            max_entries: None,
            max_mem_pct: 30,
            shards: 16,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CidrAcl {
    nets: Vec<Ipv4Net>,
}

impl CidrAcl {

    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut nets = Vec::new();
        for item in raw.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            nets.push(parse_acl_item(item)?);
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn nets(&self) -> &[Ipv4Net] {
        &self.nets
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.nets.is_empty() {
            return true;
        }
        let v4 = match ip {
            IpAddr::V4(a) => a,
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(a) => a,
                None => return false,
            },
        };
        self.nets.iter().any(|n| n.contains(&v4))
    }
}

fn parse_acl_item(item: &str) -> Result<Ipv4Net, String> {
    if item.contains('/') {
        item.parse::<Ipv4Net>()
            .map_err(|e| format!("bad cidr {item:?}: {e}"))
    } else {
        let addr: Ipv4Addr = item.parse().map_err(|e| format!("bad ip {item:?}: {e}"))?;
        Ok(Ipv4Net::new(addr, 32).expect("/32 always valid"))
    }
}

#[derive(Debug, Clone)]
pub struct WebCfg {
    pub listen: SocketAddr,
    pub password: String,

    pub admin_cidr: CidrAcl,

    pub clash_sock: PathBuf,

    pub webroot: PathBuf,

    pub screen_dev: PathBuf,

    pub reload_cmd: Vec<String>,
}
impl Default for WebCfg {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:80".parse().unwrap(),
            password: "clashpass".into(),
            admin_cidr: CidrAcl::default(),
            clash_sock: PathBuf::from("/tmp/clash.sock"),
            webroot: PathBuf::from("/etc/config/clash/clash-dashboard"),
            screen_dev: PathBuf::from("/dev/vcs1"),
            reload_cmd: vec!["/usr/bin/ppg.sh".into(), "reload".into()],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AclCfg {
    pub proxy_cidr: CidrAcl,
}

#[derive(Debug, Clone)]
pub struct InboundProxyCfg {
    pub enabled: bool,
    pub listen_port: u16,

    pub auth: Option<(String, String)>,

    pub udp: bool,
}
impl Default for InboundProxyCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: 1080,
            auth: None,
            udp: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutboundMode {
    #[default]
    Free,
    Socks5,
    Ovpn,
    Yaml,
    Suburl,
}
impl OutboundMode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "socks5" => Self::Socks5,
            "ovpn" => Self::Ovpn,
            "yaml" => Self::Yaml,
            "suburl" => Self::Suburl,
            _ => Self::Free,
        }
    }

    pub fn via_clash(self) -> bool {
        matches!(self, Self::Yaml | Self::Suburl)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsResolverCfg {
    pub server: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct OutboundCfg {
    pub mode: OutboundMode,

    pub upstream: Option<SocketAddr>,

    pub auth: Option<(String, String)>,

    pub resolver: DnsResolverCfg,

    pub bind_device: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ReportCfg {
    pub pplog: Option<SocketAddr>,
    pub pplog_uuid: Option<[u8; 16]>,
}

pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hexs: String = s.chars().filter(|c| *c != '-').collect();
    if hexs.len() != 32 {
        return None;
    }
    hex::decode(hexs).ok()?.try_into().ok()
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigErr {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ini parse at line {line}: {msg}")]
    Parse { line: usize, msg: String },
    #[error("field {section}.{key} = {value:?} — {msg}")]
    Field {
        section: String,
        key: String,
        value: String,
        msg: String,
    },
    #[error("validation: {0}")]
    Validation(String),
}

type Section = HashMap<String, String>;
type Ini = HashMap<String, Section>;

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigErr> {
        let text = std::fs::read_to_string(path)?;
        Self::from_text(&text)
    }

    pub fn from_text(text: &str) -> Result<Self, ConfigErr> {
        let ini = parse_ini(text)?;
        Self::from_ini(ini)
    }

    pub fn from_ini(ini: Ini) -> Result<Self, ConfigErr> {
        let log = parse_log(ini.get("log"))?;
        let inbound = parse_inbound(ini.get("inbound"))?;
        let socks5 = parse_socks(ini.get("socks5"))?;
        let route = parse_route(ini.get("route"))?;
        let stats = parse_stats(ini.get("stats"))?;
        let dns = parse_dns(ini.get("dns"))?;
        let web = parse_web(ini.get("web"))?;
        let acl = parse_acl(ini.get("acl"))?;
        let inbound_proxy = parse_inbound_proxy(ini.get("inbound_proxy"))?;
        let outbound = parse_outbound(ini.get("outbound"))?;
        let report = parse_report(ini.get("report"))?;
        Ok(Self {
            log,
            inbound,
            socks5,
            route,
            stats,
            dns,
            web,
            acl,
            inbound_proxy,
            outbound,
            report,
        })
    }
}

fn parse_ini(text: &str) -> Result<Ini, ConfigErr> {
    let mut out: Ini = Ini::new();
    let mut current = String::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| ConfigErr::Parse {
                    line: line_no,
                    msg: "missing closing ']'".into(),
                })?
                .trim()
                .to_string();
            if name.is_empty() {
                return Err(ConfigErr::Parse {
                    line: line_no,
                    msg: "empty section name".into(),
                });
            }
            current = name;
            out.entry(current.clone()).or_default();
            continue;
        }
        let (k, v) = line.split_once('=').ok_or_else(|| ConfigErr::Parse {
            line: line_no,
            msg: "expected 'key = value'".into(),
        })?;
        if current.is_empty() {
            return Err(ConfigErr::Parse {
                line: line_no,
                msg: "key before any [section]".into(),
            });
        }
        out.get_mut(&current)
            .unwrap()
            .insert(k.trim().to_string(), v.trim().to_string());
    }
    Ok(out)
}

fn strip_comment(line: &str) -> &str {

    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return "";
    }
    line
}

fn get<'a>(sec: Option<&'a Section>, key: &str) -> Option<&'a str> {
    sec.and_then(|s| s.get(key)).map(|s| s.as_str())
}

fn err<T: std::fmt::Debug>(
    section: &str,
    key: &str,
    value: &str,
    msg: &str,
) -> impl FnOnce(T) -> ConfigErr + use<T> {
    let section = section.to_string();
    let key = key.to_string();
    let value = value.to_string();
    let msg = msg.to_string();
    move |_| ConfigErr::Field {
        section,
        key,
        value,
        msg,
    }
}

fn parse_bool(section: &str, key: &str, raw: &str) -> Result<bool, ConfigErr> {
    match raw.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(ConfigErr::Field {
            section: section.into(),
            key: key.into(),
            value: raw.into(),
            msg: "expected boolean (true/false/yes/no/on/off/1/0)".into(),
        }),
    }
}

fn parse_num<T: std::str::FromStr>(section: &str, key: &str, raw: &str) -> Result<T, ConfigErr>
where
    T::Err: std::fmt::Debug,
{
    raw.parse::<T>()
        .map_err(err::<T::Err>(section, key, raw, "expected integer"))
}

fn parse_socket(section: &str, key: &str, raw: &str) -> Result<SocketAddr, ConfigErr> {
    raw.parse::<SocketAddr>()
        .map_err(err(section, key, raw, "expected ip:port"))
}

fn parse_cidr(section: &str, key: &str, raw: &str) -> Result<Ipv4Net, ConfigErr> {
    raw.parse::<Ipv4Net>()
        .map_err(err(section, key, raw, "expected ipv4 cidr e.g. 7.0.0.0/8"))
}

fn parse_log(sec: Option<&Section>) -> Result<LogCfg, ConfigErr> {
    let mut c = LogCfg::default();
    if let Some(v) = get(sec, "level") {
        c.level = v.to_string();
    }
    if let Some(v) = get(sec, "timestamp") {
        c.timestamp = parse_bool("log", "timestamp", v)?;
    }
    Ok(c)
}

fn parse_inbound(sec: Option<&Section>) -> Result<InboundCfg, ConfigErr> {
    let mut c = InboundCfg::default();
    if let Some(v) = get(sec, "listen") {
        c.listen = parse_socket("inbound", "listen", v)?;
    }
    if let Some(v) = get(sec, "listen6") {
        let addr = parse_socket("inbound", "listen6", v)?;
        if !addr.is_ipv6() {
            return Err(ConfigErr::Field {
                section: "inbound".into(),
                key: "listen6".into(),
                value: v.into(),
                msg: "expected an IPv6 ip:port e.g. [::1]:1081".into(),
            });
        }
        c.listen6 = Some(addr);
    }
    if let Some(v) = get(sec, "sniff_timeout_ms") {
        c.sniff_timeout = Duration::from_millis(parse_num("inbound", "sniff_timeout_ms", v)?);
    }
    if let Some(v) = get(sec, "splice_copy") {
        c.splice_copy = parse_bool("inbound", "splice_copy", v)?;
    }
    if let Some(v) = get(sec, "splice_threshold") {
        c.splice_threshold = parse_num("inbound", "splice_threshold", v)?;
    }
    if let Some(v) = get(sec, "udp") {
        c.udp = parse_bool("inbound", "udp", v)?;
    }
    if let Some(v) = get(sec, "udp_idle_sec") {
        c.udp_idle = Duration::from_secs(parse_num("inbound", "udp_idle_sec", v)?);
    }
    if let Some(v) = get(sec, "udp_workers") {
        let n: usize = parse_num("inbound", "udp_workers", v)?;
        c.udp_workers = n.max(1);
    }
    if let Some(v) = get(sec, "tcp_workers") {
        let n: usize = parse_num("inbound", "tcp_workers", v)?;
        c.tcp_workers = n.clamp(1, 64);
    }
    if let Some(v) = get(sec, "spoof_cache_cap") {
        let n: usize = parse_num("inbound", "spoof_cache_cap", v)?;
        c.spoof_cache_cap = n.max(16);
    }
    if let Some(v) = get(sec, "tune_sysctl") {
        c.tune_sysctl = parse_bool("inbound", "tune_sysctl", v)?;
    }
    Ok(c)
}

fn parse_socks(sec: Option<&Section>) -> Result<SocksCfg, ConfigErr> {
    let mut c = SocksCfg::default();
    if let Some(v) = get(sec, "server") {
        c.server = parse_socket("socks5", "server", v)?;
    }
    if let Some(v) = get(sec, "pool_min") {
        c.pool_min = parse_num("socks5", "pool_min", v)?;
    }
    if let Some(v) = get(sec, "pool_max") {
        c.pool_max = parse_num("socks5", "pool_max", v)?;
    }
    if let Some(v) = get(sec, "pool_idle_sec") {
        c.pool_idle = Duration::from_secs(parse_num("socks5", "pool_idle_sec", v)?);
    }

    const POOL_HARD_CAP: usize = 65_536;
    if c.pool_max == 0 || c.pool_max > POOL_HARD_CAP {
        return Err(ConfigErr::Validation(format!(
            "socks5.pool_max must be in 1..={POOL_HARD_CAP}, got {}",
            c.pool_max
        )));
    }
    if c.pool_min > c.pool_max {
        return Err(ConfigErr::Validation(format!(
            "socks5.pool_min ({}) must be <= pool_max ({})",
            c.pool_min, c.pool_max
        )));
    }
    Ok(c)
}

fn parse_route(sec: Option<&Section>) -> Result<RouteCfg, ConfigErr> {
    let mut c = RouteCfg::default();
    if let Some(v) = get(sec, "block_bittorrent") {
        c.block_bittorrent = parse_bool("route", "block_bittorrent", v)?;
    }
    if let Some(v) = get(sec, "block_quic") {
        c.block_quic = parse_bool("route", "block_quic", v)?;
    }
    if let Some(v) = get(sec, "block_unknown") {
        c.block_unknown = parse_bool("route", "block_unknown", v)?;
    }
    if let Some(v) = get(sec, "log_sniffed") {
        c.log_sniffed = parse_bool("route", "log_sniffed", v)?;
    }
    Ok(c)
}

fn parse_stats(sec: Option<&Section>) -> Result<Option<StatsCfg>, ConfigErr> {
    let Some(s) = sec else { return Ok(None) };
    let mut c = StatsCfg::default();
    if let Some(v) = get(Some(s), "enabled") {
        c.enabled = parse_bool("stats", "enabled", v)?;
    }
    if !c.enabled {
        return Ok(Some(c));
    }
    if let Some(v) = get(Some(s), "max_rec") {
        c.max_rec = parse_num("stats", "max_rec", v)?;
    }
    if let Some(v) = get(Some(s), "net_cleanday") {
        c.net_cleanday = parse_num("stats", "net_cleanday", v)?;
    }
    if let Some(v) = get(Some(s), "traffic_window_min") {
        c.traffic_window_min = parse_num("stats", "traffic_window_min", v)?;
    }
    Ok(Some(c))
}

fn parse_dns(sec: Option<&Section>) -> Result<Option<DnsCfg>, ConfigErr> {
    let Some(s) = sec else { return Ok(None) };
    let mut c = DnsCfg::default();
    if let Some(v) = get(Some(s), "enabled") {
        c.enabled = parse_bool("dns", "enabled", v)?;
    }
    if !c.enabled {
        return Ok(Some(c));
    }
    if let Some(v) = get(Some(s), "listen") {
        c.listen = parse_socket("dns", "listen", v)?;
    }
    if let Some(v) = get(Some(s), "fake_cidr") {
        c.fake_cidr = parse_cidr("dns", "fake_cidr", v)?;
    }
    if let Some(v) = get(Some(s), "ttl") {
        c.ttl = parse_num("dns", "ttl", v)?;
    }
    if let Some(v) = get(Some(s), "max_entries") {
        c.max_entries = Some(parse_num("dns", "max_entries", v)?);
    }
    if let Some(v) = get(Some(s), "max_mem_pct") {
        c.max_mem_pct = parse_num("dns", "max_mem_pct", v)?;
    }
    if let Some(v) = get(Some(s), "shards") {
        c.shards = parse_num("dns", "shards", v)?;
    }
    if matches!(c.max_entries, Some(0)) {
        return Err(ConfigErr::Validation("dns.max_entries must be >= 1".into()));
    }
    if c.max_mem_pct == 0 || c.max_mem_pct > 100 {
        return Err(ConfigErr::Validation(
            "dns.max_mem_pct must be 1..=100".into(),
        ));
    }
    if c.shards == 0 {
        return Err(ConfigErr::Validation("dns.shards must be >= 1".into()));
    }
    Ok(Some(c))
}

fn parse_userpass(section: &str, key: &str, raw: &str) -> Result<(String, String), ConfigErr> {
    raw.split_once(':')
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .ok_or_else(|| ConfigErr::Field {
            section: section.into(),
            key: key.into(),
            value: raw.into(),
            msg: "expected user:pass".into(),
        })
}

fn parse_cidr_acl(section: &str, key: &str, raw: &str) -> Result<CidrAcl, ConfigErr> {
    CidrAcl::parse(raw).map_err(|msg| ConfigErr::Field {
        section: section.into(),
        key: key.into(),
        value: raw.into(),
        msg,
    })
}

fn parse_web(sec: Option<&Section>) -> Result<WebCfg, ConfigErr> {
    let mut c = WebCfg::default();
    if let Some(v) = get(sec, "password") {
        c.password = v.to_string();
    }
    if let Some(v) = get(sec, "admin_cidr") {
        c.admin_cidr = parse_cidr_acl("web", "admin_cidr", v)?;
    }
    if let Some(v) = get(sec, "clash_sock") {
        c.clash_sock = v.into();
    }
    if let Some(v) = get(sec, "webroot") {
        c.webroot = v.into();
    }
    if let Some(v) = get(sec, "screen_dev") {
        c.screen_dev = v.into();
    }

    if let Some(v) = get(sec, "reload_cmd") {
        c.reload_cmd = v.split_whitespace().map(str::to_string).collect();
    }
    Ok(c)
}

fn parse_acl(sec: Option<&Section>) -> Result<AclCfg, ConfigErr> {
    let mut c = AclCfg::default();
    if let Some(v) = get(sec, "proxy_cidr") {
        c.proxy_cidr = parse_cidr_acl("acl", "proxy_cidr", v)?;
    }
    Ok(c)
}

fn parse_inbound_proxy(sec: Option<&Section>) -> Result<InboundProxyCfg, ConfigErr> {
    let mut c = InboundProxyCfg::default();
    if let Some(v) = get(sec, "enabled") {
        c.enabled = parse_bool("inbound_proxy", "enabled", v)?;
    }
    if let Some(v) = get(sec, "listen_port") {
        c.listen_port = parse_num("inbound_proxy", "listen_port", v)?;
    }
    if let Some(v) = get(sec, "auth") {
        c.auth = Some(parse_userpass("inbound_proxy", "auth", v)?);
    }
    if let Some(v) = get(sec, "udp") {
        c.udp = parse_bool("inbound_proxy", "udp", v)?;
    }
    Ok(c)
}

fn parse_outbound(sec: Option<&Section>) -> Result<OutboundCfg, ConfigErr> {
    let mut c = OutboundCfg::default();
    if let Some(v) = get(sec, "mode") {
        c.mode = OutboundMode::parse(v);
    }
    if let Some(v) = get(sec, "server") {
        c.upstream = Some(parse_socket("outbound", "server", v)?);
    }
    if let Some(user) = get(sec, "username") {
        let pass = get(sec, "password").unwrap_or("");
        c.auth = Some((user.to_string(), pass.to_string()));
    }
    if let Some(v) = get(sec, "dns_server") {
        c.resolver.server = Some(parse_socket("outbound", "dns_server", v)?);
    }
    if let Some(v) = get(sec, "bind_device") {
        c.bind_device = Some(v.to_string());
    }
    Ok(c)
}

fn parse_report(sec: Option<&Section>) -> Result<ReportCfg, ConfigErr> {
    let mut c = ReportCfg::default();
    if let Some(v) = get(sec, "pplog") {
        c.pplog = Some(parse_socket("report", "pplog", v)?);
    }
    if let Some(v) = get(sec, "uuid") {
        c.pplog_uuid = Some(parse_uuid(v).ok_or_else(|| ConfigErr::Field {
            section: "report".into(),
            key: "uuid".into(),
            value: v.into(),
            msg: "expected uuid (32 hex digits, dashes optional)".into(),
        })?);
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN_INI: &str = r#"
        [inbound]
        listen = 127.0.0.1:1081

        [socks5]
        server = 127.0.0.1:1080

        [route]
        block_bittorrent = true
    "#;

    #[test]
    fn parse_min() {
        let ini = parse_ini(MIN_INI).unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        assert_eq!(cfg.inbound.listen, "127.0.0.1:1081".parse().unwrap());
        assert!(cfg.route.block_bittorrent);
        assert!(!cfg.route.block_quic);
        assert!(cfg.route.log_sniffed);
        assert!(cfg.stats.is_none());
    }

    #[test]
    fn listen6_parsed_and_validated() {

        let cfg = Config::from_ini(parse_ini(MIN_INI).unwrap()).unwrap();
        assert!(cfg.inbound.listen6.is_none());

        let ini = parse_ini(
            "[inbound]\nlisten = 127.0.0.1:1081\nlisten6 = [::1]:1081\n\n[socks5]\nserver = 127.0.0.1:1080\n\n[route]\nblock_bittorrent = true\n",
        )
        .unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        assert_eq!(cfg.inbound.listen6, Some("[::1]:1081".parse().unwrap()));

        let ini =
            parse_ini("[inbound]\nlisten = 127.0.0.1:1081\nlisten6 = 127.0.0.1:1081\n").unwrap();
        assert!(Config::from_ini(ini).is_err());
    }

    #[test]
    fn defaults_kick_in() {
        let ini = parse_ini("").unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.inbound.sniff_timeout, Duration::from_millis(300));
        assert!(cfg.inbound.splice_copy);
        assert_eq!(cfg.inbound.splice_threshold, 1024 * 1024);
        assert_eq!(cfg.socks5.pool_min, 8);
    }

    #[test]
    fn parse_splice_threshold() {
        let ini = parse_ini("[inbound]\nsplice_threshold = 4096\n").unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        assert_eq!(cfg.inbound.splice_threshold, 4096);
    }

    #[test]
    fn comments_and_blank_lines_ok() {
        let ini = parse_ini("# top comment\n\n[log]\n; semi comment\nlevel = debug\n").unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        assert_eq!(cfg.log.level, "debug");
    }

    #[test]
    fn tune_sysctl_defaults_true_and_parses() {
        let cfg = Config::from_ini(parse_ini("").unwrap()).unwrap();
        assert!(cfg.inbound.tune_sysctl);
        let off = Config::from_ini(parse_ini("[inbound]\ntune_sysctl = false\n").unwrap()).unwrap();
        assert!(!off.inbound.tune_sysctl);
    }

    #[test]
    fn bool_synonyms() {
        let ini = parse_ini("[route]\nblock_quic = yes\nlog_sniffed = off\n").unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        assert!(cfg.route.block_quic);
        assert!(!cfg.route.log_sniffed);
    }

    #[test]
    fn rejects_bad_bool() {
        let ini = parse_ini("[route]\nblock_quic = maybe\n").unwrap();
        let e = Config::from_ini(ini).unwrap_err();
        assert!(matches!(e, ConfigErr::Field { .. }));
    }

    #[test]
    fn rejects_bad_socket() {
        let ini = parse_ini("[inbound]\nlisten = notanaddr\n").unwrap();
        let e = Config::from_ini(ini).unwrap_err();
        assert!(matches!(e, ConfigErr::Field { .. }));
    }

    #[test]
    fn rejects_key_before_section() {
        let e = parse_ini("foo = bar\n").unwrap_err();
        assert!(matches!(e, ConfigErr::Parse { .. }));
    }

    #[test]
    fn stats_disabled_skips_other_fields() {
        let ini = parse_ini("[stats]\nenabled = false\nmax_rec = 999\n").unwrap();
        let s = Config::from_ini(ini).unwrap().stats.unwrap();
        assert!(!s.enabled);

        assert_eq!(s.max_rec, 5000);
    }

    #[test]
    fn rejects_pool_min_gt_max() {
        let ini = parse_ini("[socks5]\npool_min = 10\npool_max = 4\n").unwrap();
        let e = Config::from_ini(ini).unwrap_err();
        assert!(matches!(e, ConfigErr::Validation(_)));
    }

    #[test]
    fn rejects_absurd_pool_max() {
        let ini = parse_ini("[socks5]\npool_max = 999999999\n").unwrap();
        let e = Config::from_ini(ini).unwrap_err();
        assert!(matches!(e, ConfigErr::Validation(_)));
    }

    #[test]
    fn dns_absent_is_none() {
        let cfg = Config::from_ini(parse_ini(MIN_INI).unwrap()).unwrap();
        assert!(cfg.dns.is_none());
    }

    #[test]
    fn dns_defaults_and_parse() {
        let ini = parse_ini("[dns]\nfake_cidr = 28.0.0.0/8\n").unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        let d = cfg.dns.unwrap();
        assert!(d.enabled);
        assert_eq!(d.listen, "127.0.0.1:1053".parse().unwrap());
        assert_eq!(d.fake_cidr, "28.0.0.0/8".parse().unwrap());
        assert_eq!(d.ttl, 3);
        assert_eq!(d.max_entries, None);
        assert_eq!(d.max_mem_pct, 30);
        assert_eq!(d.shards, 16);
    }

    #[test]
    fn dns_full_parse() {
        let ini = parse_ini(
            "[dns]\nenabled = true\nlisten = 0.0.0.0:53\nfake_cidr = 198.18.0.0/15\nttl = 10\nmax_entries = 1024\nmax_mem_pct = 50\nshards = 32\n",
        )
        .unwrap();
        let d = Config::from_ini(ini).unwrap().dns.unwrap();
        assert_eq!(d.listen, "0.0.0.0:53".parse().unwrap());
        assert_eq!(d.fake_cidr, "198.18.0.0/15".parse().unwrap());
        assert_eq!(d.ttl, 10);
        assert_eq!(d.max_entries, Some(1024));
        assert_eq!(d.max_mem_pct, 50);
        assert_eq!(d.shards, 32);
    }

    #[test]
    fn dns_rejects_zero_shards() {
        let ini = parse_ini("[dns]\nshards = 0\n").unwrap();
        assert!(matches!(
            Config::from_ini(ini).unwrap_err(),
            ConfigErr::Validation(_)
        ));
    }

    #[test]
    fn dns_rejects_bad_mem_pct() {
        for bad in ["0", "101", "200"] {
            let ini = parse_ini(&format!("[dns]\nmax_mem_pct = {bad}\n")).unwrap();
            assert!(
                matches!(Config::from_ini(ini).unwrap_err(), ConfigErr::Validation(_)),
                "pct {bad}"
            );
        }
    }

    #[test]
    fn dns_disabled_skips_fields() {
        let ini = parse_ini("[dns]\nenabled = false\nfake_cidr = garbage\n").unwrap();

        let d = Config::from_ini(ini).unwrap().dns.unwrap();
        assert!(!d.enabled);
    }

    #[test]
    fn dns_rejects_bad_cidr() {
        let ini = parse_ini("[dns]\nfake_cidr = not-a-cidr\n").unwrap();
        assert!(matches!(
            Config::from_ini(ini).unwrap_err(),
            ConfigErr::Field { .. }
        ));
    }

    #[test]
    fn dns_rejects_zero_max_entries() {
        let ini = parse_ini("[dns]\nmax_entries = 0\n").unwrap();
        assert!(matches!(
            Config::from_ini(ini).unwrap_err(),
            ConfigErr::Validation(_)
        ));
    }

    #[test]
    fn web_defaults_when_absent() {
        let cfg = Config::from_ini(parse_ini(MIN_INI).unwrap()).unwrap();
        assert_eq!(cfg.web.listen, "0.0.0.0:80".parse().unwrap());
        assert_eq!(cfg.web.clash_sock, PathBuf::from("/tmp/clash.sock"));
        assert_eq!(cfg.web.screen_dev, PathBuf::from("/dev/vcs1"));
        assert!(cfg.web.admin_cidr.is_empty());
        assert!(cfg.acl.proxy_cidr.is_empty());
        assert!(!cfg.inbound_proxy.enabled);
        assert_eq!(cfg.inbound_proxy.listen_port, 1080);
        assert_eq!(cfg.outbound.mode, OutboundMode::Free);
        assert!(cfg.report.pplog.is_none());
    }

    #[test]
    fn cidr_acl_empty_allows_all() {
        let acl = CidrAcl::parse("").unwrap();
        assert!(acl.is_empty());
        assert!(acl.allows("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_acl_single_ip_and_cidr() {
        let acl = CidrAcl::parse("10.10.10.123, 192.168.0.0/16").unwrap();
        assert!(!acl.is_empty());
        assert!(acl.allows("10.10.10.123".parse().unwrap()));
        assert!(!acl.allows("10.10.10.124".parse().unwrap()));
        assert!(acl.allows("192.168.5.5".parse().unwrap()));
        assert!(!acl.allows("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_acl_rejects_garbage() {
        assert!(CidrAcl::parse("not-an-ip").is_err());
        assert!(CidrAcl::parse("10.0.0.0/99").is_err());
    }

    #[test]
    fn web_acl_parsed_from_section() {
        let ini =
            parse_ini("[web]\nadmin_cidr = 10.10.10.123\n[acl]\nproxy_cidr = 10.10.10.0/24\n")
                .unwrap();
        let cfg = Config::from_ini(ini).unwrap();
        assert!(cfg.web.admin_cidr.allows("10.10.10.123".parse().unwrap()));
        assert!(!cfg.web.admin_cidr.allows("10.10.10.1".parse().unwrap()));
        assert!(cfg.acl.proxy_cidr.allows("10.10.10.55".parse().unwrap()));
        assert!(!cfg.acl.proxy_cidr.allows("10.10.11.1".parse().unwrap()));
    }

    #[test]
    fn outbound_mode_parse() {
        assert_eq!(OutboundMode::parse("socks5"), OutboundMode::Socks5);
        assert_eq!(OutboundMode::parse("OVPN"), OutboundMode::Ovpn);
        assert_eq!(OutboundMode::parse("yaml"), OutboundMode::Yaml);
        assert_eq!(OutboundMode::parse("suburl"), OutboundMode::Suburl);
        assert_eq!(OutboundMode::parse("free"), OutboundMode::Free);
        assert_eq!(OutboundMode::parse("whatever"), OutboundMode::Free);
        assert!(OutboundMode::Yaml.via_clash() && OutboundMode::Suburl.via_clash());
        assert!(!OutboundMode::Free.via_clash() && !OutboundMode::Socks5.via_clash());
    }

    #[test]
    fn outbound_section_parse() {
        let ini = parse_ini(
            "[outbound]\nmode = socks5\nserver = 1.2.3.4:1080\nusername = u\npassword = pw\nbind_device = tun114\n",
        )
        .unwrap();
        let o = Config::from_ini(ini).unwrap().outbound;
        assert_eq!(o.mode, OutboundMode::Socks5);
        assert_eq!(o.upstream, Some("1.2.3.4:1080".parse().unwrap()));
        assert_eq!(o.auth, Some(("u".into(), "pw".into())));
        assert_eq!(o.bind_device.as_deref(), Some("tun114"));
    }

    #[test]
    fn inbound_proxy_auth_parse() {
        let ini =
            parse_ini("[inbound_proxy]\nenabled = yes\nauth = alice:secret\nudp = yes\n").unwrap();
        let p = Config::from_ini(ini).unwrap().inbound_proxy;
        assert!(p.enabled && p.udp);
        assert_eq!(p.auth, Some(("alice".into(), "secret".into())));
    }

    #[test]
    fn inbound_proxy_rejects_bad_auth() {
        let ini = parse_ini("[inbound_proxy]\nauth = noseparator\n").unwrap();
        assert!(matches!(
            Config::from_ini(ini).unwrap_err(),
            ConfigErr::Field { .. }
        ));
    }

    #[test]
    fn report_pplog_parse() {
        let ini = parse_ini(
            "[report]\npplog = 10.10.10.200:9000\nuuid = 990c7c49-dbb2-470b-bb05-2f8260281759\n",
        )
        .unwrap();
        let r = Config::from_ini(ini).unwrap().report;
        assert_eq!(r.pplog, Some("10.10.10.200:9000".parse().unwrap()));
        assert_eq!(r.pplog_uuid.unwrap()[0], 0x99);
        assert_eq!(r.pplog_uuid.unwrap()[15], 0x59);
    }

    #[test]
    fn report_rejects_bad_uuid() {
        let ini = parse_ini("[report]\nuuid = not-a-uuid\n").unwrap();
        assert!(matches!(
            Config::from_ini(ini).unwrap_err(),
            ConfigErr::Field { .. }
        ));
    }

    #[test]
    fn parse_uuid_with_and_without_dashes() {
        let a = parse_uuid("990c7c49-dbb2-470b-bb05-2f8260281759").unwrap();
        let b = parse_uuid("990c7c49dbb2470bbb052f8260281759").unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0], 0x99);
        assert!(parse_uuid("short").is_none());
        assert!(parse_uuid("zz0c7c49dbb2470bbb052f8260281759").is_none());
    }
}
