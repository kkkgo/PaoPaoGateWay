// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::acl::AdminAcl;
use crate::events::LogTx;
use crate::screen::ScreenHistory;
use crate::traffic::TrafficSource;
use crate::{
    auth, clash_logs, connections, http, native, proxy_unix, respond, router, screen_poll,
    static_files,
};
use arc_swap::ArcSwap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

pub struct ServerConfig {
    pub listen: SocketAddr,

    pub token: crate::auth::TokenHandle,

    pub admin: Arc<ArcSwap<AdminAcl>>,
    pub clash_sock: PathBuf,

    pub clash_enabled: bool,
    pub webroot: PathBuf,

    pub screen_dev: PathBuf,

    pub screen_history: Arc<ScreenHistory>,

    pub log_tx: Option<LogTx>,

    pub traffic: Option<Arc<dyn TrafficSource>>,

    pub connections: Option<Arc<dyn crate::connections::ConnectionsSource>>,

    pub nodes: Option<Arc<dyn crate::nodes::NodesSource>>,

    pub info: Option<Arc<dyn crate::info::InfoSource>>,

    pub proxies: Option<Arc<dyn crate::proxies::ProxiesSource>>,

    pub reload_cmd: Option<Vec<String>>,

    pub reload_inflight: Arc<AtomicBool>,

    pub probe: Option<Arc<dyn crate::probe::ProbeSource>>,

    pub clash_control: Option<Arc<dyn crate::clash_ctl::ClashControl>>,

    pub geo: Option<Arc<dyn crate::geo::GeoControl>>,
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

const MAX_NATIVE_BODY: usize = 32 * 1024;

pub async fn serve(cfg: Arc<ServerConfig>, shutdown: watch::Receiver<bool>) -> io::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    run(listener, cfg, shutdown).await
}

pub async fn run(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    tracing::info!(
        listen = %cfg.listen,
        clash_sock = %cfg.clash_sock.display(),
        webroot = %cfg.webroot.display(),
        "web server listening"
    );

    if cfg.clash_enabled {
        if let Some(tx) = cfg.log_tx.clone() {
            clash_logs::spawn(cfg.clash_sock.clone(), tx, shutdown.clone());
        }
    } else {
        tracing::info!(
            "clash not running (outbound mode bypasses it); /logs consumer + clash reverse-proxy disabled"
        );
    }

    screen_poll::spawn(
        cfg.screen_dev.clone(),
        cfg.screen_history.clone(),
        shutdown.clone(),
    );
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => { tracing::warn!(%e, "web accept failed"); continue; }
                };
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, cfg).await {
                        tracing::debug!(%peer, %e, "web conn closed with error");
                    }
                });
            }
        }
    }
    tracing::info!("web server shutting down");
    Ok(())
}

async fn handle_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
) -> io::Result<()> {

    if !cfg.admin.load().allows(peer.ip()) {
        return Ok(());
    }
    let _ = stream.set_nodelay(true);

    let mut carry: Vec<u8> = Vec::new();
    loop {
        let head_len = match tokio::time::timeout(
            IDLE_TIMEOUT,
            http::read_head(&mut stream, &mut carry),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        let body_prefix = carry.split_off(head_len);
        let req = match http::parse_request(&carry) {
            Ok(r) => r,
            Err(_) => {
                let _ = respond::send(
                    &mut stream,
                    400,
                    "Bad Request",
                    &[],
                    b"bad request\n",
                    false,
                )
                .await;
                return Ok(());
            }
        };
        carry.clear();

        let route = router::classify(&req.method, req.path_only());
        let ka = req.keep_alive();

        let local_ctl = req.path_only() == "/sniffbox/clash/up";
        if local_ctl && !peer.ip().is_loopback() {
            respond::forbidden(&mut stream, "loopback only\n", ka).await?;
            carry = consume_body(&mut stream, req.framing()?, body_prefix).await?;
            if !ka {
                return Ok(());
            }
            continue;
        }

        if route.needs_auth()
            && !local_ctl
            && !auth::check_bearer(req.header("authorization"), cfg.token.load().as_str())
        {
            respond::unauthorized(&mut stream, ka).await?;
            carry = consume_body(&mut stream, req.framing()?, body_prefix).await?;
            if !ka {
                return Ok(());
            }
            continue;
        }

        match route {
            router::Route::ProxyClash => {

                let path = req.path_only();
                let is_conn = path == "/connections" || path.starts_with("/connections/");
                let is_delete = req.method.eq_ignore_ascii_case("DELETE");
                let self_serve = is_conn && !(cfg.clash_enabled && is_delete);
                if let Some(src) = cfg.connections.as_ref().filter(|_| self_serve) {
                    match connections::handle(&mut stream, &req, path, src, ka).await? {
                        connections::Outcome::KeepAlive => {
                            carry = Vec::new();
                            continue;
                        }
                        connections::Outcome::Close => return Ok(()),
                    }
                } else if !cfg.clash_enabled {

                    respond::send(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        &[("Content-Type", "text/plain")],
                        b"clash not running (sniffbox outbound mode bypasses it)\n",
                        ka,
                    )
                    .await?;
                } else {

                    match proxy_unix::proxy(&mut stream, &req, &body_prefix, &cfg.clash_sock)
                        .await?
                    {
                        proxy_unix::ProxyOutcome::KeepAlive => {
                            carry = Vec::new();
                            continue;
                        }
                        proxy_unix::ProxyOutcome::Close => return Ok(()),
                    }
                }
            }
            router::Route::RedirectRoot => {
                respond::redirect(&mut stream, "/ui", ka).await?;
            }
            router::Route::Static => {
                let ui_root = cfg.webroot.join("ui");
                serve_static(&mut stream, &ui_root, req.path_only(), "/ui", ka).await?;
            }
            router::Route::DataFiles => {

                let root = cfg.webroot.join("data");
                serve_static(&mut stream, &root, req.path_only(), "/data", ka).await?;
            }
            router::Route::Blocked => {
                tracing::info!(%peer, method = %req.method, path = %req.path_only(), "blocked dangerous clash API");
                respond::forbidden(&mut stream, "blocked by sniffbox\n", ka).await?;
            }
            router::Route::GeoUpdate => {
                geo_update(&mut stream, &cfg, ka).await?;
            }
            router::Route::ConfigPatch => {

                let (body, leftover) = match http::read_body_bounded(
                    &mut stream,
                    req.framing()?,
                    body_prefix,
                    MAX_NATIVE_BODY,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                        respond::send(
                            &mut stream,
                            413,
                            "Payload Too Large",
                            &[],
                            b"body too large\n",
                            false,
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };
                if !router::configs_patch_mode_only(&body) {
                    tracing::info!(%peer, path = %req.path_only(), "blocked clash PATCH /configs (only mode change allowed)");
                    respond::forbidden(&mut stream, "only mode change allowed\n", ka).await?;
                } else if !cfg.clash_enabled {
                    respond::send(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        &[("Content-Type", "text/plain")],
                        b"clash not running (sniffbox outbound mode bypasses it)\n",
                        ka,
                    )
                    .await?;
                } else {

                    match proxy_unix::proxy(&mut stream, &req, &body, &cfg.clash_sock).await? {
                        proxy_unix::ProxyOutcome::KeepAlive => {}
                        proxy_unix::ProxyOutcome::Close => return Ok(()),
                    }
                }
                carry = leftover;
                if !ka {
                    return Ok(());
                }
                continue;
            }
            router::Route::ConfigGet => {

                if let Some(src) = cfg.proxies.clone() {
                    let body = tokio::task::spawn_blocking(move || src.mode_json())
                        .await
                        .unwrap_or_else(|_| r#"{"mode":"rule"}"#.to_string());
                    respond::send(
                        &mut stream,
                        200,
                        "OK",
                        &[("Content-Type", "application/json")],
                        body.as_bytes(),
                        ka,
                    )
                    .await?;
                } else {

                    respond::send(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        &[("Content-Type", "text/plain")],
                        b"clash not running (sniffbox outbound mode bypasses it)\n",
                        ka,
                    )
                    .await?;
                }
            }
            router::Route::Native => {

                let (body, leftover) = match http::read_body_bounded(
                    &mut stream,
                    req.framing()?,
                    body_prefix,
                    MAX_NATIVE_BODY,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                        respond::send(
                            &mut stream,
                            413,
                            "Payload Too Large",
                            &[],
                            b"body too large\n",
                            false,
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };

                if native::handle(&mut stream, &req, &cfg, ka, &body).await? {
                    carry = leftover;
                    if !ka {
                        return Ok(());
                    }
                    continue;
                }
                return Ok(());
            }
        }

        carry = consume_body(&mut stream, req.framing()?, body_prefix).await?;
        if !ka {
            return Ok(());
        }
    }
}

async fn geo_update(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.geo.clone() else {
        return respond::not_found(stream, ka).await;
    };
    match tokio::task::spawn_blocking(move || src.update()).await {
        Ok(json) => {
            respond::send(
                stream,
                200,
                "OK",
                &[("Content-Type", "application/json")],
                json.as_bytes(),
                ka,
            )
            .await
        }
        Err(e) => {
            tracing::warn!(%e, "geo update task panicked");
            respond::send(
                stream,
                500,
                "Internal Server Error",
                &[("Content-Type", "application/json")],
                br#"{"error":"geo update failed"}"#,
                ka,
            )
            .await
        }
    }
}

async fn serve_static(
    stream: &mut TcpStream,
    webroot: &Path,
    path: &str,
    prefix: &str,
    ka: bool,
) -> io::Result<()> {
    let Some(file_path) = static_files::resolve_prefixed(webroot, path, prefix) else {
        return respond::forbidden(stream, "bad path\n", ka).await;
    };
    match tokio::fs::read(&file_path).await {
        Ok(bytes) => {
            let ct = static_files::content_type(&file_path);
            let cc = static_files::cache_control(&file_path);
            respond::file(stream, ct, cc, &bytes, ka).await
        }
        Err(_) => respond::not_found(stream, ka).await,
    }
}

async fn consume_body(
    stream: &mut TcpStream,
    framing: http::Framing,
    prefix: Vec<u8>,
) -> io::Result<Vec<u8>> {
    use http::Framing;
    match framing {
        Framing::None => Ok(prefix),
        Framing::Length(n) => {
            let n = n as usize;
            if prefix.len() >= n {
                Ok(prefix[n..].to_vec())
            } else {
                let mut need = n - prefix.len();
                let mut sink = [0u8; 8192];
                while need > 0 {
                    let r = stream.read(&mut sink[..need.min(8192)]).await?;
                    if r == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "eof draining body",
                        ));
                    }
                    need -= r;
                }
                Ok(Vec::new())
            }
        }
        Framing::Chunked => {
            let mut sink = tokio::io::sink();
            http::relay_body(stream, &mut sink, Framing::Chunked, &prefix).await?;
            Ok(Vec::new())
        }
        Framing::Eof => Ok(Vec::new()),
    }
}
