// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::config::{
    AclCfg, CidrAcl, Config, DnsCfg, DnsResolverCfg, InboundCfg, InboundProxyCfg, LogCfg,
    OutboundCfg, OutboundMode, ReportCfg, RouteCfg, SocksCfg, StatsCfg, WebCfg,
};
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

pub const PPGW_INI: &str = "/tmp/ppgw.ini";

pub const RUNNING_SNAPSHOT: &str = "/tmp/sniffbox_running.ini";

const CLASH_PW_ENV: &str = "clash_web_password";

pub fn build_production() -> Config {
    let ppgw = PpgwIni::load(PPGW_INI);
    build(&ppgw)
}

fn build(p: &PpgwIni) -> Config {
    let workers = auto_workers();
    let (pool_min, pool_max) = auto_pool();

    let log = LogCfg {
        level: "info".into(),
        timestamp: true,
    };

    let inbound = InboundCfg {
        listen: "127.0.0.1:1081".parse().unwrap(),

        listen6: ipv6_enabled().then(|| "[::1]:1081".parse().unwrap()),
        sniff_timeout: Duration::from_millis(300),
        splice_copy: true,
        splice_threshold: p.num("splice_threshold").unwrap_or(1024 * 1024),
        udp: p.bool("udp_enable").unwrap_or(false),
        udp_idle: Duration::from_secs(60),
        udp_workers: workers,
        tcp_workers: workers,
        spoof_cache_cap: auto_spoof_cache_cap(),
        tune_sysctl: true,
    };

    let socks5 = SocksCfg {
        server: "127.0.0.1:1080".parse().unwrap(),
        pool_min,
        pool_max,
        pool_idle: Duration::from_secs(300),
    };

    let route = p.route();

    let stats = Some(StatsCfg {
        enabled: p.bool("net_rec").unwrap_or(false),
        max_rec: p.num("max_rec").unwrap_or(5000),
        net_cleanday: p.num("net_cleanday").unwrap_or(0),
        traffic_window_min: p.num("traffic_window_min").unwrap_or(60),
    });

    let dns = Some(DnsCfg {
        enabled: true,
        listen: "0.0.0.0:53".parse().unwrap(),
        fake_cidr: p
            .cidr("fake_cidr")
            .unwrap_or_else(|| "7.0.0.0/8".parse().unwrap()),
        ttl: 3,
        max_entries: None,
        max_mem_pct: 30,
        shards: 16,
    });

    let web = WebCfg {
        listen: "0.0.0.0:80".parse().unwrap(),
        password: web_password(p),
        admin_cidr: p.acl("admin_cidr"),
        clash_sock: "/tmp/clash.sock".into(),
        webroot: "/etc/config/clash/clash-dashboard".into(),
        screen_dev: "/dev/vcs1".into(),
        reload_cmd: vec!["/usr/bin/ppg.sh".into(), "reload".into()],
    };

    let acl = AclCfg {
        proxy_cidr: p.acl("proxy_cidr"),
    };

    let inbound_proxy = InboundProxyCfg {

        enabled: true,
        listen_port: 1080,
        auth: p.userpass("openport_auth"),
        udp: p.bool("udp_enable").unwrap_or(false),
    };

    let mode = p.str("mode").map(OutboundMode::parse).unwrap_or_default();
    let outbound = OutboundCfg {
        mode,
        upstream: p.socks5_upstream(),
        auth: p.socks5_auth(),
        resolver: DnsResolverCfg {
            server: p.dns_resolver(),
        },
        bind_device: (mode == OutboundMode::Ovpn).then(|| "tun114".to_string()),
    };

    let report = ReportCfg {
        pplog: p.socket("pplog"),
        pplog_uuid: p.str("pplog_uuid").and_then(crate::config::parse_uuid),
    };

    Config {
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
    }
}

fn web_password(p: &PpgwIni) -> String {
    std::env::var(CLASH_PW_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| p.str("clash_web_password").map(String::from))
        .unwrap_or_else(|| "clashpass".into())
}

fn cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn auto_workers() -> usize {
    cpus().min(8)
}

fn auto_pool() -> (usize, usize) {
    let c = cpus();
    let min = (c * 4).clamp(8, 64);
    let max = (c * 32).clamp(64, 1024);
    (min, max)
}

fn auto_spoof_cache_cap() -> usize {
    (cpus() * 512).clamp(1024, 8192)
}

fn ipv6_enabled() -> bool {
    std::fs::read_to_string("/etc/config/network")
        .map(|s| s.contains("eth06"))
        .unwrap_or(false)
}

pub fn ini_value(key: &str) -> Option<String> {
    PpgwIni::load(PPGW_INI).str(key).map(str::to_string)
}

#[derive(Default)]
struct PpgwIni {
    kv: HashMap<String, String>,
}

impl PpgwIni {
    fn load(path: &str) -> Self {
        let kv = std::fs::read_to_string(path)
            .map(|t| parse_ppgw(&t))
            .unwrap_or_default();
        Self { kv }
    }

    fn str(&self, key: &str) -> Option<&str> {
        self.kv
            .get(key)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
    }

    fn bool(&self, key: &str) -> Option<bool> {
        self.str(key).and_then(parse_yesno)
    }

    fn num<T: FromStr>(&self, key: &str) -> Option<T> {
        self.str(key).and_then(|s| s.parse().ok())
    }

    fn cidr(&self, key: &str) -> Option<Ipv4Net> {
        self.str(key).and_then(|s| s.parse().ok())
    }

    fn socket(&self, key: &str) -> Option<SocketAddr> {
        self.str(key).and_then(|s| s.parse().ok())
    }

    fn acl(&self, key: &str) -> CidrAcl {
        self.str(key)
            .and_then(|s| CidrAcl::parse(s).ok())
            .unwrap_or_default()
    }

    fn userpass(&self, key: &str) -> Option<(String, String)> {
        self.str(key).and_then(|s| {
            s.split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        })
    }

    fn socks5_upstream(&self) -> Option<SocketAddr> {
        let ip = self.str("socks5_ip")?;
        let port: u16 = self.num("socks5_port").unwrap_or(7890);
        format!("{ip}:{port}").parse().ok()
    }

    fn socks5_auth(&self) -> Option<(String, String)> {
        let user = self.str("socks5_username")?;
        let pass = self.str("socks5_password").unwrap_or("");
        Some((user.to_string(), pass.to_string()))
    }

    fn dns_resolver(&self) -> Option<SocketAddr> {
        let ip = self.str("dns_ip")?;
        let port: u16 = self.num("dns_port").unwrap_or(53);
        format!("{ip}:{port}").parse().ok()
    }

    fn route(&self) -> RouteCfg {
        let mut c = RouteCfg {
            block_bittorrent: true,
            block_quic: true,
            block_unknown: false,
            log_sniffed: true,
        };
        if let Some(box_val) = self.str("box") {
            for part in box_val.split(',') {
                let Some((k, v)) = part.split_once('=') else {
                    continue;
                };
                let Some(b) = parse_yesno(v.trim()) else {
                    continue;
                };
                match k.trim() {
                    "route.block_bittorrent" => c.block_bittorrent = b,
                    "route.block_quic" => c.block_quic = b,
                    "route.block_unknown" => c.block_unknown = b,
                    _ => {}
                }
            }
        }
        c
    }
}

fn parse_ppgw(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };

        let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
        out.insert(k.trim().to_string(), v);
    }
    out
}

fn parse_yesno(s: &str) -> Option<bool> {
    match s.trim().trim_matches('"').to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Some(true),
        "no" | "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ppgw(text: &str) -> PpgwIni {
        PpgwIni {
            kv: parse_ppgw(text),
        }
    }

    #[test]
    fn fixed_defaults_hold() {
        let cfg = build(&PpgwIni::default());
        assert_eq!(cfg.log.level, "info");
        assert!(cfg.log.timestamp);
        assert_eq!(cfg.inbound.listen, "127.0.0.1:1081".parse().unwrap());
        assert_eq!(cfg.inbound.sniff_timeout, Duration::from_millis(300));
        assert!(cfg.inbound.splice_copy);
        assert_eq!(cfg.inbound.udp_idle, Duration::from_secs(60));
        assert!(cfg.inbound.tune_sysctl);
        assert_eq!(cfg.socks5.server, "127.0.0.1:1080".parse().unwrap());
        let dns = cfg.dns.unwrap();
        assert!(dns.enabled);
        assert_eq!(dns.listen, "0.0.0.0:53".parse().unwrap());
        assert_eq!(dns.ttl, 3);
        assert_eq!(dns.max_entries, None);
        assert_eq!(dns.max_mem_pct, 30);
        assert_eq!(dns.shards, 16);
    }

    #[test]
    fn missing_ppgw_uses_defaults() {

        let cfg = build(&PpgwIni::load("/nonexistent/ppgw.ini"));
        assert!(!cfg.inbound.udp);
        let s = cfg.stats.unwrap();
        assert!(!s.enabled);
        assert_eq!(s.max_rec, 5000);
        assert_eq!(s.net_cleanday, 0);
        assert_eq!(cfg.dns.unwrap().fake_cidr, "7.0.0.0/8".parse().unwrap());

        assert!(cfg.route.block_bittorrent);
        assert!(cfg.route.block_quic);
        assert!(!cfg.route.block_unknown);
        assert!(cfg.route.log_sniffed);
    }

    #[test]
    fn reads_ppgw_variable_fields() {
        let p = ppgw(
            "#paopao-gateway\n\
             udp_enable=yes\n\
             net_rec=yes\n\
             max_rec=12000\n\
             net_cleanday=15\n\
             fake_cidr=28.0.0.0/8\n",
        );
        let cfg = build(&p);
        assert!(cfg.inbound.udp);
        let s = cfg.stats.unwrap();
        assert!(s.enabled);
        assert_eq!(s.max_rec, 12000);
        assert_eq!(s.net_cleanday, 15);
        assert_eq!(cfg.dns.unwrap().fake_cidr, "28.0.0.0/8".parse().unwrap());
    }

    #[test]
    fn box_overrides_route() {
        let p = ppgw(
            "box=\"route.block_bittorrent=false,route.block_quic=false,route.block_unknown=true\"\n",
        );
        let r = p.route();
        assert!(!r.block_bittorrent);
        assert!(!r.block_quic);
        assert!(r.block_unknown);
    }

    #[test]
    fn box_partial_override_keeps_other_defaults() {
        let p = ppgw("box=route.block_quic=false\n");
        let r = p.route();
        assert!(r.block_bittorrent);
        assert!(!r.block_quic);
        assert!(!r.block_unknown);
    }

    #[test]
    fn quotes_stripped() {
        let p = ppgw("clash_web_password=\"hunter2\"\nudp_enable=\"no\"\n");
        assert_eq!(p.str("clash_web_password"), Some("hunter2"));
        assert_eq!(p.bool("udp_enable"), Some(false));
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let p = ppgw("# comment\n\n; semi\nmax_rec=42\n");
        assert_eq!(p.num::<usize>("max_rec"), Some(42));
    }

    #[test]
    fn auto_values_within_bounds() {
        let (min, max) = auto_pool();
        assert!(min >= 8 && min <= max);
        assert!(max <= 1024);
        assert!(auto_workers() >= 1 && auto_workers() <= 8);
        assert!(auto_spoof_cache_cap() >= 1024);
    }

    #[test]
    fn web_fixed_listen_and_defaults() {
        let cfg = build(&PpgwIni::default());
        assert_eq!(cfg.web.listen, "0.0.0.0:80".parse().unwrap());
        assert_eq!(
            cfg.web.clash_sock,
            std::path::PathBuf::from("/tmp/clash.sock")
        );
        assert!(cfg.web.admin_cidr.is_empty());
        assert!(cfg.acl.proxy_cidr.is_empty());
        assert!(cfg.inbound_proxy.enabled);
        assert_eq!(cfg.inbound_proxy.listen_port, 1080);
        assert_eq!(cfg.outbound.mode, OutboundMode::Free);
        assert!(cfg.outbound.bind_device.is_none());
        assert!(cfg.report.pplog.is_none());
    }

    #[test]
    fn reads_admin_and_proxy_cidr() {
        let p = ppgw("admin_cidr=10.10.10.123\nproxy_cidr=10.10.10.0/24\n");
        let cfg = build(&p);
        assert!(cfg.web.admin_cidr.allows("10.10.10.123".parse().unwrap()));
        assert!(!cfg.web.admin_cidr.allows("10.10.10.124".parse().unwrap()));
        assert!(cfg.acl.proxy_cidr.allows("10.10.10.55".parse().unwrap()));
        assert!(!cfg.acl.proxy_cidr.allows("10.10.11.1".parse().unwrap()));
    }

    #[test]
    fn reads_openport_keys() {

        let p = ppgw("openport=no\nopenport_auth=alice:secret\nudp_enable=yes\n");
        let cfg = build(&p);
        assert!(cfg.inbound_proxy.enabled);
        assert!(cfg.inbound_proxy.udp);
        assert_eq!(
            cfg.inbound_proxy.auth,
            Some(("alice".into(), "secret".into()))
        );
    }

    #[test]
    fn reads_socks5_outbound_keys() {
        let p = ppgw(
            "mode=socks5\nsocks5_ip=1.2.3.4\nsocks5_port=1080\nsocks5_username=u\nsocks5_password=pw\n",
        );
        let cfg = build(&p);
        assert_eq!(cfg.outbound.mode, OutboundMode::Socks5);
        assert_eq!(cfg.outbound.upstream, Some("1.2.3.4:1080".parse().unwrap()));
        assert_eq!(cfg.outbound.auth, Some(("u".into(), "pw".into())));
        assert!(cfg.outbound.bind_device.is_none());
    }

    #[test]
    fn ovpn_mode_binds_tun114_and_resolver() {
        let p = ppgw("mode=ovpn\ndns_ip=10.10.10.3\n");
        let cfg = build(&p);
        assert_eq!(cfg.outbound.mode, OutboundMode::Ovpn);
        assert_eq!(cfg.outbound.bind_device.as_deref(), Some("tun114"));
        assert_eq!(
            cfg.outbound.resolver.server,
            Some("10.10.10.3:53".parse().unwrap())
        );
    }

    #[test]
    fn socks5_port_defaults_when_only_ip() {
        let p = ppgw("mode=socks5\nsocks5_ip=9.9.9.9\n");
        let cfg = build(&p);
        assert_eq!(cfg.outbound.upstream, Some("9.9.9.9:7890".parse().unwrap()));
    }

    #[test]
    fn reads_pplog() {
        let p = ppgw("pplog=10.10.10.200:9000\npplog_uuid=990c7c49-dbb2-470b-bb05-2f8260281759\n");
        let report = build(&p).report;
        assert_eq!(report.pplog, Some("10.10.10.200:9000".parse().unwrap()));
        assert_eq!(report.pplog_uuid.unwrap()[0], 0x99);

        assert!(
            build(&ppgw("pplog=10.10.10.200:9000\n"))
                .report
                .pplog_uuid
                .is_none()
        );
    }

    #[test]
    fn web_password_from_ppgw_when_env_absent() {
        if std::env::var(CLASH_PW_ENV).is_ok() {
            return;
        }
        let p = ppgw("clash_web_password=hunter2\n");
        assert_eq!(build(&p).web.password, "hunter2");

        assert_eq!(build(&PpgwIni::default()).web.password, "clashpass");
    }
}
