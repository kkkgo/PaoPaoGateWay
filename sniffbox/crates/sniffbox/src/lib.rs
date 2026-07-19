// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub mod clash_ctl;
pub mod clash_pull;
pub mod config;
pub mod dns_server;
pub mod engine;
pub mod geo_cron;
pub mod inbound_proxy;
pub mod ip_rules;
pub mod logging;
pub mod outbound;
pub mod ovpn_ctl;
pub mod pplog;
pub mod probe;
pub mod production;
pub mod reload;
pub mod resolver;
pub mod runtime;
pub mod smart_speed;
pub mod sysinfo;
pub mod tasks;
pub mod udp_engine;
pub mod web_geo;
pub mod web_proxies;

use config::Config;
use runtime::SharedState;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

pub(crate) const SNIFFBOX_VERSION: &str = match option_env!("SNIFFBOX_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Clone)]
pub enum ConfigSource {
    File(PathBuf),
    Production,
}

impl ConfigSource {
    pub fn load(&self) -> Result<Config, config::ConfigErr> {
        match self {
            ConfigSource::File(p) => Config::load(p),
            ConfigSource::Production => Ok(production::build_production()),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            ConfigSource::File(p) => p.display().to_string(),
            ConfigSource::Production => format!("<production: fixed + {}>", production::PPGW_INI),
        }
    }

    pub fn write_running_snapshot(&self) {
        if let ConfigSource::Production = self {
            match std::fs::copy(production::PPGW_INI, production::RUNNING_SNAPSHOT) {
                Ok(_) => tracing::info!(
                    path = production::RUNNING_SNAPSHOT,
                    "wrote running-config snapshot"
                ),
                Err(e) => tracing::warn!(
                    ?e,
                    src = production::PPGW_INI,
                    "running-config snapshot write failed"
                ),
            }
        }
    }
}

pub fn cli_main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let parsed = match parse_args(&args) {
        Ok(ParsedArgs::Run(p)) => p,
        Ok(ParsedArgs::PrintAndExit(msg)) => {
            println!("{msg}");
            return ExitCode::SUCCESS;
        }
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };

    let mut cfg = match parsed.source.load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config load failed: {e}");
            return ExitCode::from(1);
        }
    };
    parsed.overrides.apply(&mut cfg);

    logging::init(&cfg.log.level, cfg.log.timestamp);

    parsed.source.write_running_snapshot();

    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".into());
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-str panic payload>".into());
        tracing::error!(location = %loc, payload = %msg, "panic occurred");
    }));
    tracing::info!(
        version = SNIFFBOX_VERSION,
        config = %parsed.source.describe(),
        "sniffbox starting"
    );
    raise_nofile();
    if cfg.inbound.tune_sysctl {
        tune_sysctls();
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    match rt.block_on(run(cfg, parsed.source)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(?e, "runtime error");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
struct RunArgs {
    source: ConfigSource,
    overrides: Overrides,
}

#[derive(Debug, Default)]
struct Overrides {
    listen: Option<std::net::SocketAddr>,
    log_level: Option<String>,
}

impl Overrides {
    fn apply(&self, cfg: &mut Config) {
        if let Some(l) = self.listen {
            cfg.inbound.listen = l;
        }
        if let Some(lvl) = &self.log_level {
            cfg.log.level = lvl.clone();
        }
    }
}

enum ParsedArgs {
    Run(RunArgs),
    PrintAndExit(String),
}

const NOFILE_TARGET: libc::rlim_t = 1_048_576;

fn raise_nofile() {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        tracing::warn!(err = ?std::io::Error::last_os_error(), "getrlimit(NOFILE) failed");
        return;
    }
    let (cur0, max0) = (rlim.rlim_cur, rlim.rlim_max);

    let want = NOFILE_TARGET.max(max0);
    rlim.rlim_cur = want;
    rlim.rlim_max = want;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } == 0 {
        tracing::info!(
            soft_before = cur0,
            hard_before = max0,
            soft_now = want,
            hard_now = want,
            "NOFILE raised (hard limit lifted)"
        );
        return;
    }

    if cur0 < max0 {
        rlim.rlim_cur = max0;
        rlim.rlim_max = max0;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } == 0 {
            tracing::info!(
                soft_before = cur0,
                soft_now = max0,
                hard = max0,
                "NOFILE soft raised to hard (no CAP_SYS_RESOURCE to lift hard cap)"
            );
            return;
        }
    }
    tracing::warn!(err = ?std::io::Error::last_os_error(), soft = cur0, hard = max0,
        "setrlimit(NOFILE) failed; keeping defaults");
}

fn tune_sysctls() {

    const RAISE: &[(&str, i64, &str)] = &[
        ("net.core.rmem_max", 16 * 1024 * 1024, "max recv socket buf"),
        ("net.core.wmem_max", 16 * 1024 * 1024, "max send socket buf"),
        ("net.core.somaxconn", 8192, "listen accept queue cap"),
        (
            "net.core.netdev_max_backlog",
            32768,
            "per-CPU ingress queue (high PPS)",
        ),
        ("net.ipv4.tcp_max_syn_backlog", 16384, "SYN half-open queue"),
        ("fs.file-max", 1_048_576, "system-wide max open fds"),
    ];
    for &(key, target, what) in RAISE {
        raise_sysctl(key, target, what);
    }
    enable_bbr_fq();
}

fn raise_sysctl(key: &str, target: i64, what: &str) {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    let current = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok());
    match current {
        Some(cur) if cur >= target => {
            tracing::debug!(key, current = cur, target, "sysctl already >= target; skip");
        }
        _ => match std::fs::write(&path, target.to_string()) {
            Ok(()) => tracing::info!(key, from = ?current, to = target, what, "sysctl raised"),
            Err(e) => tracing::warn!(
                key, target, err = ?e,
                "sysctl raise failed (read-only /proc or missing privilege); leaving kernel default"
            ),
        },
    }
}

fn enable_bbr_fq() {
    let qdisc = std::fs::read_to_string("/proc/sys/net/core/default_qdisc").unwrap_or_default();
    let qdisc = qdisc.trim();
    if !qdisc.starts_with("fq") {
        match std::fs::write("/proc/sys/net/core/default_qdisc", "fq") {
            Ok(()) => tracing::info!(
                from = qdisc,
                to = "fq",
                "default_qdisc set (fair-queue + pacing)"
            ),
            Err(e) => tracing::debug!(err = ?e, "set default_qdisc=fq failed"),
        }
    }

    let avail = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
        .unwrap_or_default();
    if !avail.split_whitespace().any(|a| a == "bbr") {
        tracing::debug!(
            available = avail.trim(),
            "bbr not compiled in kernel; skip congestion control tune"
        );
        return;
    }
    let cur =
        std::fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control").unwrap_or_default();
    let cur = cur.trim();
    if cur == "cubic" || cur == "reno" {
        match std::fs::write("/proc/sys/net/ipv4/tcp_congestion_control", "bbr") {
            Ok(()) => tracing::info!(from = cur, to = "bbr", "tcp_congestion_control set"),
            Err(e) => tracing::warn!(err = ?e, "set tcp_congestion_control=bbr failed"),
        }
    } else {
        tracing::debug!(
            current = cur,
            "tcp_congestion_control already non-default; leaving as-is"
        );
    }
}

fn usage() -> &'static str {
    concat!(
        "sniffbox — TPROXY sniff + SOCKS5 forwarder\n",
        "usage: sniffbox [-c <ini>] [--listen <ip:port>] [--log-level <lvl>]\n",
        "       sniffbox -h | -V\n",
        "without -c: production mode (fixed defaults + /tmp/ppgw.ini + auto-tuned)",
    )
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    let mut cfg_path: Option<PathBuf> = None;
    let mut overrides = Overrides::default();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--config" => {
                let v = it
                    .next()
                    .ok_or_else(|| "missing value for -c".to_string())?;
                cfg_path = Some(PathBuf::from(v));
            }
            "--listen" => {
                let v = it
                    .next()
                    .ok_or_else(|| "missing value for --listen".to_string())?;
                overrides.listen = Some(
                    v.parse()
                        .map_err(|e| format!("--listen: invalid socket addr: {e}"))?,
                );
            }
            "--log-level" => {
                let v = it
                    .next()
                    .ok_or_else(|| "missing value for --log-level".to_string())?;
                overrides.log_level = Some(v.clone());
            }
            "-h" | "--help" => return Ok(ParsedArgs::PrintAndExit(usage().to_string())),
            "-V" | "--version" => {
                return Ok(ParsedArgs::PrintAndExit(format!(
                    "sniffbox {}",
                    SNIFFBOX_VERSION
                )));
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    let source = match cfg_path {
        Some(p) => ConfigSource::File(p),
        None => ConfigSource::Production,
    };
    Ok(ParsedArgs::Run(RunArgs { source, overrides }))
}

async fn run(cfg: Config, source: ConfigSource) -> std::io::Result<()> {
    let listen_addr = cfg.inbound.listen;
    let udp_enabled = cfg.inbound.udp;
    let udp_idle = cfg.inbound.udp_idle;
    let udp_workers = cfg.inbound.udp_workers;
    let spoof_cache_cap = cfg.inbound.spoof_cache_cap;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let pplog = match (cfg.report.pplog, cfg.report.pplog_uuid) {
        (Some(addr), Some(uuid)) => Some(pplog::start(addr, uuid, shutdown_rx.clone())),
        (Some(_), None) => {
            tracing::warn!(
                "pplog set but pplog_uuid missing — reporting disabled (uuid is the encryption key seed)"
            );
            None
        }
        _ => {
            tracing::info!("pplog reporting disabled (no pplog= in ppgw.ini)");
            None
        }
    };

    let mut state = SharedState::new(&cfg);
    state.pplog = pplog;
    let shared = Arc::new(state);

    match shared.outbound.socks5_pool() {
        Some(pool) => {
            std::mem::drop(pool.spawn_warmer());
            tracing::info!(
                mode = ?cfg.outbound.mode, target = %pool.target(), cfg = ?pool.cfg(),
                "socks pool warmer started"
            );
        }
        None => {
            tracing::info!(
                mode = ?cfg.outbound.mode,
                resolver = ?cfg.outbound.resolver.server,
                bind_device = ?cfg.outbound.bind_device,
                "direct outbound (resolve + connect; no socks pool)"
            );

            if let Some(dev) = &cfg.outbound.bind_device
                && !sb_outbound::direct::device_exists(dev)
            {
                tracing::warn!(device = %dev,
                    "bind_device not found at startup; direct connects bound to it will fail until it appears");
            }
        }
    }

    let ovpn_sup = (cfg.outbound.mode == config::OutboundMode::Ovpn).then(|| {

        let tun_ready = shared.outbound.tun_ready();
        let sup = Arc::new(ovpn_ctl::OvpnSupervisor::new(tun_ready));
        ovpn_ctl::spawn_monitor(Arc::clone(&sup), shutdown_rx.clone());
        tracing::info!("openvpn supervisor started (mode=ovpn)");
        sup
    });

    let tcp_workers = cfg.inbound.tcp_workers.max(1);
    spawn_tcp_listeners(listen_addr, tcp_workers, &shared, &shutdown_rx, true)?;

    if let Some(listen6) = cfg.inbound.listen6 {
        if let Err(e) = spawn_tcp_listeners(listen6, tcp_workers, &shared, &shutdown_rx, false) {
            tracing::warn!(%listen6, ?e, "bind_tproxy_tcp (IPv6) failed; continuing IPv4-only");
        }
    }

    {
        let shared = Arc::clone(&shared);
        let source = source.clone();
        tokio::spawn(async move {
            reload::run_reload_loop(shared, source).await;
        });
    }

    let nodes_enabled = cfg.stats.as_ref().is_some_and(|s| s.enabled);

    let smart_stats = Arc::new(smart_speed::SmartStats::default());
    if nodes_enabled {
        start_stats_pipeline(&shared, shutdown_rx.clone());
    }

    if cfg.outbound.mode.via_clash() {
        clash_pull::spawn(
            Arc::clone(&shared),
            cfg.web.clash_sock.clone(),
            std::time::Duration::from_millis(900),
            nodes_enabled,
            shutdown_rx.clone(),
        );

        smart_speed::spawn(
            cfg.web.clash_sock.clone(),
            Arc::clone(&smart_stats),
            shutdown_rx.clone(),
        );
    } else {
        tracing::info!(mode = ?cfg.outbound.mode,
            "clash not the router; skipping /connections poll");
    }

    if let (Some(dns), Some(fakeip)) = (
        cfg.dns.as_ref().filter(|d| d.enabled),
        shared.fakeip.clone(),
    ) {
        match dns_server::bind_dns(dns.listen).await {
            Ok(sock) => {
                tracing::info!(
                    listen = %dns.listen, cidr = %fakeip.cidr(),
                    ttl = fakeip.ttl(), max_entries = dns.max_entries,
                    "fakeip dns server running"
                );
                let sd = shutdown_rx.clone();
                tokio::spawn(async move {
                    dns_server::run_dns_server(sock, fakeip, sd).await;
                });
            }
            Err(e) => {
                tracing::warn!(listen = %dns.listen, ?e, "dns bind failed; fakeip dns disabled");
            }
        }
    }

    {

        let clash_supervisor = cfg
            .outbound
            .mode
            .via_clash()
            .then(|| Arc::new(clash_ctl::ClashSupervisor::new()));

        let web_geo = clash_supervisor
            .clone()
            .map(|s| Arc::new(web_geo::WebGeo::new(s)));

        if let Some(g) = web_geo.clone() {
            geo_cron::spawn(g, shutdown_rx.clone());
        }

        let web_proxies = cfg.outbound.mode.via_clash().then(|| {
            let wp = web_proxies::WebProxies::new(
                cfg.web.clash_sock.clone(),
                Arc::clone(&smart_stats),
            );
            let wp2 = Arc::clone(&wp);
            let warm = wp.warm_signal();
            let mut sd = shutdown_rx.clone();
            tokio::spawn(async move {
                use std::time::{Duration, Instant};
                async fn refresh(w: &Arc<web_proxies::WebProxies>) -> bool {
                    let w = Arc::clone(w);
                    tokio::task::spawn_blocking(move || w.refresh())
                        .await
                        .unwrap_or(false)
                }

                loop {
                    if refresh(&wp2).await {
                        break;
                    }
                    tokio::select! {
                        _ = sd.changed() => { if *sd.borrow() { return; } }
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                    }
                }

                let start = Instant::now();
                for mark in [10u64, 30, 60, 90] {
                    let target = start + Duration::from_secs(mark);
                    if let Some(dur) = target.checked_duration_since(Instant::now()) {
                        tokio::select! {
                            _ = sd.changed() => { if *sd.borrow() { return; } }
                            _ = tokio::time::sleep(dur) => {}
                        }
                    }
                    refresh(&wp2).await;
                }

                let mut last = Instant::now();
                loop {
                    tokio::select! {
                        _ = sd.changed() => { if *sd.borrow() { break; } }
                        _ = warm.notified() => {
                            if last.elapsed() >= Duration::from_secs(5) {
                                refresh(&wp2).await;
                                last = Instant::now();
                            }
                        }
                    }
                }
            });
            wp
        });
        let web_cfg = Arc::new(sb_web::ServerConfig {
            listen: cfg.web.listen,
            token: shared.web_token(),
            admin: shared.web_admin(),
            clash_sock: cfg.web.clash_sock.clone(),

            clash_enabled: cfg.outbound.mode.via_clash(),
            webroot: cfg.web.webroot.clone(),
            screen_dev: cfg.web.screen_dev.clone(),

            screen_history: sb_web::ScreenHistory::new(5000),
            log_tx: logging::log_sender(),
            traffic: Some(Arc::new(runtime::WebTraffic {
                shared: Arc::clone(&shared),
            })),

            connections: Some(if cfg.outbound.mode.via_clash() {
                Arc::new(runtime::WebClashConnections {
                    shared: Arc::clone(&shared),
                }) as Arc<dyn sb_web::ConnectionsSource>
            } else {
                Arc::new(runtime::WebConnections {
                    shared: Arc::clone(&shared),
                }) as Arc<dyn sb_web::ConnectionsSource>
            }),

            nodes: cfg.outbound.mode.via_clash().then(|| {
                Arc::new(runtime::WebNodes {
                    shared: Arc::clone(&shared),
                }) as Arc<dyn sb_web::NodesSource>
            }),

            info: Some(Arc::new(runtime::WebInfo::new(
                Arc::clone(&shared),
                runtime::InfoStatic::from_cfg(&cfg),
            )) as Arc<dyn sb_web::InfoSource>),

            proxies: web_proxies
                .clone()
                .map(|wp| wp as Arc<dyn sb_web::ProxiesSource>),

            reload_cmd: (!cfg.web.reload_cmd.is_empty()).then(|| cfg.web.reload_cmd.clone()),
            reload_inflight: Arc::new(std::sync::atomic::AtomicBool::new(false)),

            probe: Some(Arc::new(probe::WebProbe::new()) as Arc<dyn sb_web::ProbeSource>),

            clash_control: clash_supervisor
                .clone()
                .map(|s| s as Arc<dyn sb_web::ClashControl>),

            geo: web_geo.clone().map(|g| g as Arc<dyn sb_web::GeoControl>),
        });
        let sd = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = sb_web::serve(web_cfg, sd).await {
                tracing::warn!(?e, "web server exited (bind :80 needs privilege)");
            }
        });
    }

    inbound_proxy::start_inbound_proxy(
        Arc::clone(&shared),
        inbound_proxy::InboundProxyParams {
            listen_port: cfg.inbound_proxy.listen_port,
            udp: cfg.inbound_proxy.udp,
            udp_idle: cfg.inbound.udp_idle,
        },
        shutdown_rx.clone(),
    );

    inbound_proxy::start_healthcheck_listener(Arc::clone(&shared), shutdown_rx.clone());

    if udp_enabled {
        match udp_engine::start_udp_engine(
            Arc::clone(&shared),
            listen_addr,
            udp_idle,
            udp_workers,
            spoof_cache_cap,
            shutdown_rx.clone(),
        ) {
            Ok(_engine) => {
                tracing::info!(%listen_addr, ?udp_idle, udp_workers, "udp engine running");
            }
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "udp engine bind failed (need CAP_NET_ADMIN); continuing TCP-only"
                );
            }
        }

        if let Some(listen6) = cfg.inbound.listen6 {
            match udp_engine::start_udp_engine(
                Arc::clone(&shared),
                listen6,
                udp_idle,
                udp_workers,
                spoof_cache_cap,
                shutdown_rx.clone(),
            ) {
                Ok(_engine) => {
                    tracing::info!(%listen6, ?udp_idle, udp_workers, "udp engine (IPv6) running");
                }
                Err(e) => {
                    tracing::warn!(%listen6, ?e, "udp engine (IPv6) bind failed; continuing without v6 UDP");
                }
            }
        }
    } else {
        tracing::info!("udp engine disabled by config");
    }

    let term = install_signals();
    let _ = term.await;
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    if let Some(sup) = ovpn_sup {
        let _ = tokio::task::spawn_blocking(move || sup.kill()).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(())
}

fn spawn_tcp_listeners(
    listen_addr: std::net::SocketAddr,
    workers: usize,
    shared: &Arc<SharedState>,
    shutdown_rx: &watch::Receiver<bool>,
    fatal: bool,
) -> std::io::Result<()> {
    let first = match sb_tproxy::tcp::bind_tproxy_tcp(listen_addr) {
        Ok(l) => l,
        Err(e) => {
            if fatal {
                tracing::error!(%listen_addr, ?e, "bind_tproxy_tcp failed (need CAP_NET_ADMIN)");
            }
            return Err(e);
        }
    };
    let mut listeners = vec![first];
    for _ in 1..workers {
        match sb_tproxy::tcp::bind_tproxy_tcp(listen_addr) {
            Ok(l) => listeners.push(l),
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "additional TCP REUSEPORT bind failed; fewer accept workers"
                );
                break;
            }
        }
    }
    tracing::info!(%listen_addr, workers = listeners.len(), "tproxy tcp listening (REUSEPORT)");

    for listener in listeners {
        let shared = Arc::clone(shared);
        let mut sd = shutdown_rx.clone();
        tokio::spawn(async move {
            accept_loop(listener, shared, &mut sd).await;
        });
    }
    Ok(())
}

async fn accept_loop(
    listener: tokio::net::TcpListener,
    shared: Arc<SharedState>,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
            res = listener.accept() => {
                match res {
                    Ok((stream, peer)) => {
                        let shared = Arc::clone(&shared);
                        tokio::spawn(async move {
                            if let Err(e) = engine::handle_conn(stream, peer, shared).await {
                                tracing::debug!(%peer, ?e, "conn ended with error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(?e, "accept error; backoff 100ms");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

fn start_stats_pipeline(shared: &Arc<SharedState>, shutdown_rx: watch::Receiver<bool>) {
    let shared_c = Arc::clone(shared);
    tokio::spawn(async move {
        tasks::run_flush_loop(shared_c, shutdown_rx).await;
    });
}

fn install_signals() -> tokio::sync::oneshot::Receiver<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "SIGTERM register failed; only SIGINT will trigger shutdown"
                );
                None
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(?e, "SIGINT register failed");
                None
            }
        };

        let term = async {
            match sigterm.as_mut() {
                Some(s) => {
                    let _ = s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let int = async {
            match sigint.as_mut() {
                Some(s) => {
                    let _ = s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = term => {}
            _ = int => {}
        }
        let _ = tx.send(());
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_production_when_no_c() {
        let args = vec!["sniffbox".into()];
        match parse_args(&args).unwrap() {
            ParsedArgs::Run(r) => assert!(matches!(r.source, ConfigSource::Production)),
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parse_args_custom_path() {
        let args = vec!["sniffbox".into(), "-c".into(), "/etc/x.ini".into()];
        match parse_args(&args).unwrap() {
            ParsedArgs::Run(r) => {
                assert!(
                    matches!(r.source, ConfigSource::File(p) if p == std::path::Path::new("/etc/x.ini"))
                );
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parse_args_listen_override() {
        let args = vec!["sniffbox".into(), "--listen".into(), "0.0.0.0:9999".into()];
        match parse_args(&args).unwrap() {
            ParsedArgs::Run(r) => {
                assert_eq!(r.overrides.listen.unwrap().port(), 9999);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parse_args_help() {
        assert!(matches!(
            parse_args(&["sniffbox".into(), "--help".into()]).unwrap(),
            ParsedArgs::PrintAndExit(_)
        ));
    }

    #[test]
    fn parse_args_version() {
        match parse_args(&["sniffbox".into(), "-V".into()]).unwrap() {
            ParsedArgs::PrintAndExit(s) => assert!(s.starts_with("sniffbox ")),
            _ => panic!("expected PrintAndExit"),
        }
    }
}
