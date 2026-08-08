// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::cf_ctl::Egress;
use crate::config::Protocol;

const PROBE_TIMEOUT: Duration = Duration::from_secs(40);
const POLL: Duration = Duration::from_millis(500);

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLVE_POLL: Duration = Duration::from_secs(2);

const WARMUP_TIMEOUT: Duration = Duration::from_secs(60);
const WARMUP_POLL: Duration = Duration::from_secs(2);

const PROBE_BYTES: usize = 1024 * 1024;

const MAX_PROBE_BYTES: usize = 4 * 1024 * 1024;

const SAMPLE_TIMEOUT: Duration = Duration::from_secs(20);

const HEALTH_SOCKS5: &str = "127.0.0.1:1079";

#[derive(Debug, Clone, Default)]
pub struct Sample {
    pub protocol: Option<Protocol>,

    pub ready: bool,

    pub ttfb: Vec<Duration>,

    pub rate: Vec<f64>,

    pub failures: u32,

    pub min_rtt_ms: Option<u64>,

    pub rate_limited: bool,

    pub stage: Stage,

    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {

    #[default]
    NotRegistered,

    Registered,

    Resolved,

    Warm,
}

impl Sample {
    fn new(protocol: Protocol) -> Self {
        Self {
            protocol: Some(protocol),
            ..Default::default()
        }
    }
}

pub struct Running {
    pid: u32,
    hostname: String,
    metrics: SocketAddr,
    log: std::path::PathBuf,
    egress: Egress,

    refused: bool,
}

static REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Running {

    pub async fn start(
        egress: Egress,
        proto: Protocol,
        edge: Option<IpAddr>,
        origin_url: &str,
    ) -> Option<Running> {
        let port = free_port()?;
        let metrics: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
        let log = std::path::PathBuf::from(format!("/tmp/sniffbox.cf.probe.{port}.log"));
        let _ = std::fs::remove_file(&log);
        let pid = spawn(egress, proto, edge, origin_url, metrics, &log)
            .map_err(|e| tracing::debug!(?e, "cf probe: spawn failed"))
            .ok()?;

        let mut running = Running {
            pid,
            hostname: String::new(),
            metrics,
            log,
            egress,
            refused: false,
        };
        if !wait_ready(metrics, PROBE_TIMEOUT).await {
            running.refused = refused_in_log(&running.log);

            tracing::warn!(
                egress = egress.as_str(),
                protocol = proto.as_str(),
                refused = running.refused,
                log = %log_tail(&running.log, 6),
                "cf probe: tunnel did not register"
            );
            return None;
        }
        let Some(host) = hostname_from_log(&running.log) else {

            tracing::warn!(
                egress = egress.as_str(),
                protocol = proto.as_str(),
                log = %log_tail(&running.log, 6),
                "cf probe: registered but no trycloudflare hostname in the log"
            );
            return None;
        };
        running.hostname = host;
        Some(running)
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn rate_limited_recently() -> bool {
        REFUSED.swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn min_rtt_ms(&self) -> Option<u64> {
        let addr = self.metrics;
        let body = tokio::task::spawn_blocking(move || crate::cf_metrics::metrics_text(addr))
            .await
            .ok()??;
        parse_min_rtt(&body)
    }

    fn egress(&self) -> Egress {
        self.egress
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.refused {
            REFUSED.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        kill(self.pid);
        let _ = std::fs::remove_file(&self.log);
    }
}

fn log_tail(log: &std::path::Path, n: usize) -> String {
    let Ok(text) = std::fs::read_to_string(log) else {
        return "<no log>".into();
    };
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|l| l.chars().take(200).collect::<String>())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn refused_in_log(log: &std::path::Path) -> bool {
    std::fs::read_to_string(log)
        .map(|t| t.contains("429 Too Many Requests") || t.contains("error code: 1015"))
        .unwrap_or(false)
}

pub fn reap_strays() -> usize {
    let mut killed = 0;
    for pid in crate::cf_ctl::find_cf_pids() {
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let argv = String::from_utf8_lossy(&raw).replace('\0', " ");
        if is_probe_argv(&argv) {
            tracing::info!(pid, "cf probe: reaping a leaked probe tunnel");
            kill(pid);
            killed += 1;
        }
    }

    killed + sweep_probe_logs()
}

fn sweep_probe_logs() -> usize {
    let live: Vec<String> = crate::cf_ctl::find_cf_pids()
        .into_iter()
        .filter_map(|pid| std::fs::read(format!("/proc/{pid}/cmdline")).ok())
        .map(|raw| String::from_utf8_lossy(&raw).replace('\0', " "))
        .collect();
    let Ok(rd) = std::fs::read_dir("/tmp") else {
        return 0;
    };
    let mut swept = 0;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(port) = probe_log_port(name) else {
            continue;
        };
        if live
            .iter()
            .any(|argv| argv.contains(&format!("127.0.0.1:{port}")))
        {
            continue;
        }
        if std::fs::remove_file(entry.path()).is_ok() {
            swept += 1;
        }
    }
    if swept > 0 {
        tracing::info!(n = swept, "cf probe: swept orphaned probe logs");
    }
    swept
}

fn probe_log_port(name: &str) -> Option<u16> {
    name.strip_prefix("sniffbox.cf.probe.")?
        .strip_suffix(".log")?
        .parse()
        .ok()
}

fn is_probe_argv(argv: &str) -> bool {
    argv.contains("--url http://127.0.0.1:")
        && argv.contains("--metrics 127.0.0.1:")
        && !argv.contains("--token")
}

fn free_port() -> Option<u16> {
    let sock = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let port = sock.local_addr().ok()?.port();
    drop(sock);
    Some(port)
}

fn probe_home(egress: Egress) -> String {
    format!("{}/probe", egress.home())
}

pub(crate) fn build_argv(
    proto: Protocol,
    edge: Option<IpAddr>,
    origin_url: &str,
    metrics: SocketAddr,
) -> Vec<String> {

    let mut argv: Vec<String> = vec![
        "tunnel".into(),
        "--no-autoupdate".into(),
        "--protocol".into(),
        proto.as_str().into(),
    ];
    if let Some(ip) = edge {
        argv.push("--edge".into());
        argv.push(format!("{ip}:{}", crate::cf_edge::EDGE_PORT));
    }
    argv.push("--metrics".into());
    argv.push(metrics.to_string());
    argv.push("--url".into());
    argv.push(origin_url.to_string());
    argv
}

fn spawn(
    egress: Egress,
    proto: Protocol,
    edge: Option<IpAddr>,
    origin_url: &str,
    metrics: SocketAddr,
    log: &std::path::Path,
) -> std::io::Result<u32> {
    let home = probe_home(egress);

    let _ = crate::cf_ctl::prepare_home(egress);
    if std::fs::create_dir_all(&home).is_ok() {
        let _ = crate::cf_ctl::chown_cf(&home, egress);
    }
    let argv = build_argv(proto, edge, origin_url, metrics);
    let out = std::fs::File::create(log)?;
    let err = out.try_clone()?;
    let mut cmd = Command::new(crate::cf_ctl::CF_BIN);
    cmd.args(&argv)
        .env("HOME", &home)
        .current_dir(&home)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    let (uid, gid) = egress.uid_gid();

    unsafe {
        cmd.pre_exec(move || crate::cf_ctl::drop_to_cf(uid, gid));
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

fn kill(pid: u32) {

    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

async fn wait_ready(metrics: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let ready = tokio::task::spawn_blocking(move || crate::cf_metrics::ready(metrics))
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        if ready >= 1 {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn resolve(egress: Egress, host: &str) -> Option<SocketAddr> {
    let deadline = Instant::now() + RESOLVE_TIMEOUT;
    loop {
        if let Some(ip) = crate::cf_edge::resolve_a(egress, host).await {
            return Some(SocketAddr::new(ip, 80));
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(RESOLVE_POLL).await;
    }
}

pub fn parse_min_rtt(metrics_body: &str) -> Option<u64> {
    metrics_body
        .lines()
        .filter(|l| l.starts_with("quic_client_min_rtt{"))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.trim().parse::<f64>().ok())
        .map(|v| v as u64)
        .min()
}

pub fn hostname_from_log_text(text: &str) -> Option<String> {
    text.match_indices("https://").find_map(|(at, _)| {
        let rest = &text[at + "https://".len()..];
        let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))?;
        let host = &rest[..end];
        host.ends_with(".trycloudflare.com")
            .then(|| host.to_string())
    })
}

fn hostname_from_log(log: &std::path::Path) -> Option<String> {
    hostname_from_log_text(&std::fs::read_to_string(log).ok()?)
}

pub async fn measure_pair(egress: Egress, rounds: usize) -> (Sample, Sample) {
    let (mut sa, mut sb) = (Sample::new(Protocol::Quic), Sample::new(Protocol::Http2));

    let (edge_a, edge_b) = (
        pick_edge(egress, Protocol::Quic).await,
        pick_edge(egress, Protocol::Http2).await,
    );
    let (Some(origin_a), Some(origin_b)) = (Origin::start().await, Origin::start().await) else {

        tracing::warn!(
            egress = egress.as_str(),
            "cf probe: could not start the loopback origin; skipping this round"
        );
        return (sa, sb);
    };
    if edge_a.is_none() || edge_b.is_none() {

        tracing::warn!(
            egress = egress.as_str(),
            quic = ?edge_a,
            http2 = ?edge_b,
            "cf probe: no edge answered on this egress; the probe will fall back to cloudflared's own discovery"
        );
    }
    let (url_a, url_b) = (origin_a.url(), origin_b.url());
    let (tun_a, tun_b) = tokio::join!(
        Running::start(egress, Protocol::Quic, edge_a, &url_a),
        Running::start(egress, Protocol::Http2, edge_b, &url_b),
    );

    let refused = Running::rate_limited_recently();
    sa.rate_limited = refused;
    sb.rate_limited = refused;
    let mut arm_a = Arm::prepare(tun_a, &mut sa).await;
    let mut arm_b = Arm::prepare(tun_b, &mut sb).await;
    for _ in 0..rounds {
        Arm::sample_tiny(&mut arm_a, &mut sa).await;
        Arm::sample_tiny(&mut arm_b, &mut sb).await;
        Arm::sample_sized(&mut arm_a, &mut sa).await;
        Arm::sample_sized(&mut arm_b, &mut sb).await;
    }
    (sa, sb)
}

async fn pick_edge(egress: Egress, proto: Protocol) -> Option<IpAddr> {
    crate::cf_edge::pick_edges_proto(egress, proto)
        .await
        .first()
        .map(|e| e.ip)
}

struct Arm {
    _tunnel: Running,
    addr: SocketAddr,
    host: String,
}

impl Arm {

    async fn prepare(tunnel: Option<Running>, s: &mut Sample) -> Option<Arm> {
        let tunnel = tunnel?;
        s.ready = true;
        s.stage = Stage::Registered;
        s.min_rtt_ms = tunnel.min_rtt_ms().await;
        let egress = tunnel.egress();
        let host = tunnel.hostname().to_string();

        let Some(addr) = resolve(egress, &host).await else {
            tracing::warn!(
                egress = egress.as_str(),
                host,
                timeout_s = RESOLVE_TIMEOUT.as_secs(),
                "cf probe: the freshly issued hostname never resolved on this egress"
            );
            return None;
        };
        s.stage = Stage::Resolved;
        if let Err(e) = warmup(addr, &host).await {
            s.detail = Some(e.as_text());
            tracing::warn!(
                egress = egress.as_str(),
                host,
                %addr,
                timeout_s = WARMUP_TIMEOUT.as_secs(),
                why = %e.as_text(),
                "cf probe: registered and resolved, but never got a 200 from the hostname"
            );
            return None;
        }
        s.stage = Stage::Warm;
        Some(Arm {
            _tunnel: tunnel,
            addr,
            host,
        })
    }

    async fn sample_tiny(arm: &mut Option<Arm>, s: &mut Sample) {
        let Some(arm) = arm else { return };
        match get(arm.addr, &arm.host, "/", 0).await {
            Ok((ttfb, _)) => s.ttfb.push(ttfb),
            Err(e) => {
                s.failures += 1;
                s.detail.get_or_insert_with(|| e.as_text());
            }
        }
    }

    async fn sample_sized(arm: &mut Option<Arm>, s: &mut Sample) {
        let Some(arm) = arm else { return };
        let path = format!("/b/{PROBE_BYTES}");
        match get(arm.addr, &arm.host, &path, PROBE_BYTES).await {
            Ok((_, body)) if !body.is_zero() => {
                s.rate.push(PROBE_BYTES as f64 / body.as_secs_f64())
            }

            Ok(_) => s.failures += 1,
            Err(e) => {
                s.failures += 1;
                s.detail.get_or_insert_with(|| e.as_text());
            }
        }
    }
}

async fn warmup(addr: SocketAddr, host: &str) -> Result<(), ProbeErr> {
    let deadline = Instant::now() + WARMUP_TIMEOUT;

    let mut last;
    loop {
        match get(addr, host, "/", 0).await {
            Ok(_) => return Ok(()),

            Err(e) => last = e,
        }
        if Instant::now() >= deadline {
            return Err(last);
        }
        tokio::time::sleep(WARMUP_POLL).await;
    }
}

#[derive(Debug, Clone)]
pub enum ProbeErr {

    Connect,

    Io,

    Status(String),

    Short { got: usize, want: usize },

    Timeout,
}

impl ProbeErr {
    pub fn as_text(&self) -> String {
        match self {
            Self::Connect => "cannot connect (proxy refused, or edge unreachable)".into(),
            Self::Io => "connection broke before a response".into(),
            Self::Status(line) => format!("edge answered {line:?}"),
            Self::Short { got, want } => format!("truncated body ({got}/{want} bytes)"),
            Self::Timeout => "timed out".into(),
        }
    }
}

async fn get(
    addr: SocketAddr,
    host: &str,
    path: &str,
    expect: usize,
) -> Result<(Duration, Duration), ProbeErr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let work = async {
        let mut s = connect(addr).await.ok_or(ProbeErr::Connect)?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let started = Instant::now();
        s.write_all(req.as_bytes())
            .await
            .map_err(|_| ProbeErr::Io)?;
        let mut buf = vec![0u8; 64 * 1024];
        let n = s.read(&mut buf).await.map_err(|_| ProbeErr::Io)?;
        if n == 0 {
            return Err(ProbeErr::Io);
        }
        let ttfb = started.elapsed();

        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        if !head.starts_with("HTTP/1.1 200") {
            return Err(ProbeErr::Status(status_line(&head)));
        }
        let body_start = head.find("\r\n\r\n").map(|i| n - (i + 4)).unwrap_or(0);
        let stream_started = Instant::now();
        let mut got = body_start;
        loop {
            let r = s.read(&mut buf).await.map_err(|_| ProbeErr::Io)?;
            if r == 0 {
                break;
            }
            got += r;
        }
        if got < expect {
            return Err(ProbeErr::Short { got, want: expect });
        }
        Ok((ttfb, stream_started.elapsed()))
    };
    match tokio::time::timeout(SAMPLE_TIMEOUT, work).await {
        Ok(r) => r,
        Err(_) => Err(ProbeErr::Timeout),
    }
}

fn status_line(head: &str) -> String {
    head.lines()
        .next()
        .unwrap_or_default()
        .trim_end()
        .chars()
        .take(80)
        .collect()
}

async fn connect(addr: SocketAddr) -> Option<tokio::net::TcpStream> {
    if let Some(s) = connect_via_health_socks5(addr).await {
        return Some(s);
    }
    tokio::net::TcpStream::connect(addr).await.ok()
}

async fn connect_via_health_socks5(addr: SocketAddr) -> Option<tokio::net::TcpStream> {
    let mut s = tokio::net::TcpStream::connect(HEALTH_SOCKS5).await.ok()?;

    sb_outbound::socks5::handshake_no_auth(&mut s).await.ok()?;
    sb_outbound::socks5::send_connect(&mut s, addr, None)
        .await
        .ok()?;
    Some(s)
}

pub struct Origin {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Origin {
    pub async fn start() -> Option<Origin> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
        let port = listener.local_addr().ok()?.port();
        let task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let path = req.split(' ').nth(1).unwrap_or("/");
                    let len = body_len(path);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nContent-Type: \
                         application/octet-stream\r\nConnection: close\r\n\r\n"
                    );
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let chunk = vec![0u8; 32 * 1024];
                    let mut left = len;
                    while left > 0 {
                        let take = left.min(chunk.len());
                        if sock.write_all(&chunk[..take]).await.is_err() {
                            return;
                        }
                        left -= take;
                    }
                });
            }
        });
        Some(Origin { port, task })
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn body_len(path: &str) -> usize {
    path.strip_prefix("/b/")
        .and_then(|n| n.parse::<usize>().ok())
        .map(|n| n.min(MAX_PROBE_BYTES))
        .unwrap_or(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_assigned_hostname_past_the_banner() {
        let log = "\
2026-08-07T10:00:00Z INF Thank you for trying Cloudflare Tunnel.
2026-08-07T10:00:00Z INF https://developers.cloudflare.com/cloudflare-one/
2026-08-07T10:00:01Z INF +----------------------------------------+
2026-08-07T10:00:01Z INF |  https://four-word-name-here.trycloudflare.com  |
2026-08-07T10:00:01Z INF +----------------------------------------+
";
        assert_eq!(
            hostname_from_log_text(log).as_deref(),
            Some("four-word-name-here.trycloudflare.com")
        );
    }

    #[test]
    fn no_trycloudflare_hostname_is_none() {
        assert_eq!(
            hostname_from_log_text("INF https://developers.cloudflare.com/x\n"),
            None
        );
        assert_eq!(hostname_from_log_text(""), None);
    }

    #[test]
    fn rate_limit_is_recognised_from_either_wording() {
        let dir = std::env::temp_dir().join(format!("sniffbox-probe-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.log");
        std::fs::write(
            &a,
            "ERR failed to request quick tunnel: 429 Too Many Requests\n",
        )
        .unwrap();
        assert!(refused_in_log(&a));
        let b = dir.join("b.log");
        std::fs::write(&b, "<title>Access denied</title> error code: 1015").unwrap();
        assert!(refused_in_log(&b));
        let c = dir.join("c.log");
        std::fs::write(&c, "INF Registered tunnel connection\n").unwrap();
        assert!(!refused_in_log(&c));

        assert!(!refused_in_log(&dir.join("missing.log")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_numbered_probe_logs_are_sweepable() {
        assert_eq!(probe_log_port("sniffbox.cf.probe.44513.log"), Some(44513));
        for keep in [
            "sniffbox.cf.probe.proxy",
            "sniffbox.cf.probe.direct",
            "sniffbox.cf.proto.proxy",
            "sniffbox.cf.history.proxy",
            "sniffbox_running.ini",
            "sniffbox.cf.probe.log",
            "sniffbox.cf.probe.99999999.log",
            "ppgw.ini",
        ] {
            assert_eq!(probe_log_port(keep), None, "must not be swept: {keep}");
        }
    }

    #[test]
    fn only_our_own_probe_argv_matches() {
        assert!(is_probe_argv(
            "cloudflared tunnel --no-autoupdate --protocol quic --metrics 127.0.0.1:34567 --url http://127.0.0.1:45678"
        ));
        assert!(!is_probe_argv(
            "cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:20241 --edge 198.41.192.7:7844 run --token eyJhIjoi"
        ));

        assert!(!is_probe_argv(
            "cloudflared tunnel --url http://127.0.0.1:8080"
        ));
    }

    #[test]
    fn probe_argv_shape() {
        let argv = build_argv(
            Protocol::Http2,
            Some("198.41.192.7".parse().unwrap()),
            "http://127.0.0.1:45678",
            "127.0.0.1:34567".parse().unwrap(),
        );
        let joined = argv.join(" ");
        assert_eq!(
            joined,
            "tunnel --no-autoupdate --protocol http2 --edge 198.41.192.7:7844 \
             --metrics 127.0.0.1:34567 --url http://127.0.0.1:45678"
        );
        assert!(is_probe_argv(&joined));
        assert!(
            !joined.contains("--token"),
            "a probe must never carry the production token"
        );

        let bare = build_argv(
            Protocol::Quic,
            None,
            "http://127.0.0.1:1",
            "127.0.0.1:2".parse().unwrap(),
        );
        assert!(!bare.contains(&"--edge".to_string()));
        assert_eq!(bare[3], "quic");
    }

    #[test]
    fn origin_supplies_the_requested_size_up_to_a_cap() {
        assert_eq!(body_len("/b/1048576"), 1024 * 1024);
        assert_eq!(body_len("/b/999999999"), MAX_PROBE_BYTES);
        assert_eq!(body_len("/"), 2);
        assert_eq!(body_len("/b/notanumber"), 2);
    }

    #[tokio::test]
    async fn origin_serves_loopback_only() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let origin = Origin::start().await.unwrap();
        let url = origin.url();
        assert!(url.starts_with("http://127.0.0.1:"));
        let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(b"GET /b/4096 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut all = Vec::new();
        s.read_to_end(&mut all).await.unwrap();
        let head_end = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(all.starts_with(b"HTTP/1.1 200 OK"));
        assert_eq!(all.len() - head_end, 4096);
    }

    #[tokio::test]
    #[ignore = "spawns a real quick tunnel; needs root + cloudflared + internet"]
    async fn probe_debug() {
        let egress = Egress::Direct;
        let proto = Protocol::Quic;
        let origin = Origin::start().await.expect("origin");
        println!("origin  : {}", origin.url());
        let edge = pick_edge(egress, proto).await;
        println!("edge    : {edge:?}");
        let tun = Running::start(egress, proto, edge, &origin.url()).await;
        println!(
            "spawn   : {}",
            if tun.is_some() {
                "registered"
            } else if Running::rate_limited_recently() {
                "REFUSED (429 / error 1015)"
            } else {
                "did not register"
            }
        );
        let Some(tun) = tun else { return };
        println!("hostname: {}", tun.hostname());
        println!("min_rtt : {:?}", tun.min_rtt_ms().await);
        let addr = resolve(egress, tun.hostname()).await;
        println!("resolve : {addr:?}");
        let Some(addr) = addr else { return };
        println!("warmup  : {:?}", warmup(addr, tun.hostname()).await);
        println!(
            "get     : {:?}",
            get(addr, tun.hostname(), "/b/1048576", PROBE_BYTES).await
        );
    }

    #[tokio::test]
    #[ignore = "spawns two real quick tunnels (~8 MB); needs root + cloudflared + internet"]
    async fn real_scoring_round() {
        let (quic, http2) = measure_pair(Egress::Direct, crate::cf_quality::ROUNDS).await;
        println!("quic  : {quic:?}");
        println!("http2 : {http2:?}");
        println!("score quic  : {:?}", crate::cf_quality::score(&quic));
        println!("score http2 : {:?}", crate::cf_quality::score(&http2));
    }

    #[test]
    fn log_tail_takes_the_end_and_truncates() {
        let dir = std::env::temp_dir().join(format!("sniffbox-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("probe.log");

        std::fs::write(&p, "a\n\n  b  \nc\nd\n").unwrap();
        assert_eq!(log_tail(&p, 3), "b | c | d", "tail only, blanks dropped");
        assert_eq!(log_tail(&p, 99), "a | b | c | d", "fewer lines than asked");

        std::fs::write(&p, format!("{}\n", "x".repeat(5000))).unwrap();
        assert_eq!(log_tail(&p, 1).len(), 200, "each line is capped");

        assert_eq!(log_tail(&dir.join("gone.log"), 3), "<no log>");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn min_rtt_takes_the_lowest_connection() {
        let body = "\
quic_client_min_rtt{conn_index=\"0\"} 163
quic_client_min_rtt{conn_index=\"1\"} 155
quic_client_latest_rtt{conn_index=\"0\"} 200
";
        assert_eq!(parse_min_rtt(body), Some(155));

        assert_eq!(parse_min_rtt("go_goroutines 38\n"), None);
    }
}
