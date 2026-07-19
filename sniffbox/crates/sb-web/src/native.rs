// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::http::ReqHead;
use crate::server::ServerConfig;
use crate::{respond, screen, sse};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::RecvError;

const JSON: (&str, &str) = ("Content-Type", "application/json");

pub async fn handle(
    stream: &mut TcpStream,
    req: &ReqHead,
    cfg: &ServerConfig,
    ka: bool,
    body: &[u8],
) -> io::Result<bool> {
    match req.path_only() {
        "/sniffbox/probe" => {
            probe(stream, req, cfg, ka, body).await?;
            Ok(ka)
        }
        "/sniffbox/logs/sse" => {
            logs_sse(stream, cfg).await?;
            Ok(false)
        }
        "/sniffbox/screen" => {
            screen_snapshot(stream, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/screen/sse" => {
            screen_sse(stream, cfg).await?;
            Ok(false)
        }
        "/sniffbox/traffic/total" => {
            traffic_total(stream, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/traffic/clear" => {
            traffic_clear(stream, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/traffic/sse" => {
            traffic_sse(stream, cfg).await?;
            Ok(false)
        }
        "/sniffbox/nodes" => {
            nodes_get(stream, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/proxies" => {
            proxies_get(stream, req, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/proxy" => {
            proxy_detail_get(stream, req, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/nodes/clear" => {
            nodes_clear(stream, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/info" => {
            info_get(stream, cfg, crate::info::InfoScope::All, ka).await?;
            Ok(ka)
        }
        "/sniffbox/info/static" => {
            info_get(stream, cfg, crate::info::InfoScope::Static, ka).await?;
            Ok(ka)
        }
        "/sniffbox/info/dynamic" => {
            info_get(stream, cfg, crate::info::InfoScope::Dynamic, ka).await?;
            Ok(ka)
        }
        "/sniffbox/geo" => {
            geo_status(stream, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/reload" => {
            reload(stream, cfg, ka).await?;
            Ok(ka)
        }
        "/sniffbox/clash/up" => {
            clash_up(stream, cfg, ka).await?;
            Ok(ka)
        }
        _ => {
            respond::not_found(stream, ka).await?;
            Ok(ka)
        }
    }
}

async fn probe(stream: &mut TcpStream, req: &ReqHead, cfg: &ServerConfig, ka: bool, body: &[u8]) -> io::Result<()> {
    let Some(src) = cfg.probe.as_ref() else {
        return respond::not_found(stream, ka).await;
    };
    if !req.method.eq_ignore_ascii_case("POST") {
        return respond::send(stream, 405, "Method Not Allowed", &[JSON, ("Allow", "POST")], b"", ka).await;
    }
    let Ok(body) = std::str::from_utf8(body) else {
        let msg = br#"{"ok":false,"denied":true,"error":"body must be utf-8"}"#;
        return respond::send(stream, 400, "Bad Request", &[JSON], msg, ka).await;
    };
    let (src, body) = (Arc::clone(src), body.to_string());

    match tokio::task::spawn_blocking(move || src.probe(&body)).await {
        Ok(Ok(out)) => respond::send(stream, 200, "OK", &[JSON], out.as_bytes(), ka).await,

        Ok(Err(_busy)) => {
            let msg = br#"{"ok":false,"busy":true,"error":"too many concurrent probes"}"#;
            respond::send(stream, 429, "Too Many Requests", &[JSON, ("Retry-After", "1")], msg, ka).await
        }
        Err(e) => {
            tracing::warn!(%e, "probe task panicked");
            let msg = br#"{"ok":false,"error":"probe task failed"}"#;
            respond::send(stream, 500, "Internal Server Error", &[JSON], msg, ka).await
        }
    }
}

async fn geo_status(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.geo.as_ref() else {
        return respond::not_found(stream, ka).await;
    };
    let body = src.status_json();
    respond::send(stream, 200, "OK", &[JSON], body.as_bytes(), ka).await
}

async fn traffic_total(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.traffic.as_ref() else {
        return respond::not_found(stream, ka).await;
    };
    let (d, u) = src.totals();
    let body = format!(r#"{{"downloadTotal":{d},"uploadTotal":{u}}}"#);
    respond::send(stream, 200, "OK", &[("Content-Type", "application/json")], body.as_bytes(), ka).await
}

async fn nodes_get(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.nodes.as_ref() else {
        return respond::not_found(stream, ka).await;
    };
    let body = src.nodes_json();
    respond::send(stream, 200, "OK", &[("Content-Type", "application/json")], body.as_bytes(), ka).await
}

async fn proxies_get(stream: &mut TcpStream, req: &ReqHead, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.proxies.as_ref() else {
        return respond::not_found(stream, ka).await;
    };

    let fresh = req.path.contains("fresh=1");
    let src = Arc::clone(src);
    let body = tokio::task::spawn_blocking(move || if fresh { src.proxies_json_fresh() } else { src.proxies_json() })
        .await
        .unwrap_or_else(|_| "{}".to_string());
    respond::send(stream, 200, "OK", &[JSON], body.as_bytes(), ka).await
}

async fn proxy_detail_get(stream: &mut TcpStream, req: &ReqHead, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.proxies.as_ref() else {
        return respond::not_found(stream, ka).await;
    };
    let Some(name) = query_param(&req.path, "name").filter(|n| !n.is_empty()) else {
        return respond::send(stream, 400, "Bad Request", &[JSON], br#"{"message":"missing name"}"#, ka).await;
    };
    let src = Arc::clone(src);
    let (status, body) = tokio::task::spawn_blocking(move || src.proxy_detail(&name))
        .await
        .unwrap_or((500, r#"{"message":"internal"}"#.to_string()));
    let reason = if status == 200 { "OK" } else { "Not Found" };
    respond::send(stream, status, reason, &[JSON], body.as_bytes(), ka).await
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let q = path.split_once('?').map(|(_, q)| q)?;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| pct_decode(v))
    })
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn nodes_clear(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.nodes.as_ref() else {
        return respond::not_found(stream, ka).await;
    };
    src.clear();
    respond::send(stream, 200, "OK", &[("Content-Type", "application/json")], br#"{"cleared":true}"#, ka).await
}

async fn info_get(
    stream: &mut TcpStream,
    cfg: &ServerConfig,
    scope: crate::info::InfoScope,
    ka: bool,
) -> io::Result<()> {
    let Some(src) = cfg.info.as_ref() else {
        return respond::not_found(stream, ka).await;
    };

    if scope != crate::info::InfoScope::Dynamic {
        if let Some(p) = cfg.proxies.as_ref() {
            p.warm();
        }
    }

    let src = src.clone();
    let body = tokio::task::spawn_blocking(move || src.info_json(scope))
        .await
        .unwrap_or_else(|_| "{}".to_string());
    respond::send(stream, 200, "OK", &[("Content-Type", "application/json")], body.as_bytes(), ka).await
}

async fn reload(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(argv) = cfg.reload_cmd.as_ref().filter(|a| !a.is_empty()) else {

        return respond::send(
            stream,
            501,
            "Not Implemented",
            &[("Content-Type", "application/json")],
            br#"{"reloading":false,"error":"disabled"}"#,
            ka,
        )
        .await;
    };
    use std::sync::atomic::Ordering;

    if cfg
        .reload_inflight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return respond::send(
            stream,
            409,
            "Conflict",
            &[("Content-Type", "application/json")],
            br#"{"reloading":true,"already":true}"#,
            ka,
        )
        .await;
    }
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let spawned = cmd.spawn();
    match spawned {
        Ok(mut child) => {
            tracing::info!(cmd = %argv.join(" "), "gateway reload triggered");

            let flag = cfg.reload_inflight.clone();
            tokio::spawn(async move {
                let _ = child.wait().await;
                flag.store(false, Ordering::Release);
            });
            respond::send(
                stream,
                200,
                "OK",
                &[("Content-Type", "application/json")],
                br#"{"reloading":true}"#,
                ka,
            )
            .await
        }
        Err(e) => {

            cfg.reload_inflight.store(false, Ordering::Release);
            tracing::warn!(cmd = %argv.join(" "), %e, "gateway reload spawn failed");
            respond::send(
                stream,
                500,
                "Internal Server Error",
                &[("Content-Type", "application/json")],
                br#"{"reloading":false,"error":"spawn failed"}"#,
                ka,
            )
            .await
        }
    }
}

async fn clash_up(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(ctl) = cfg.clash_control.clone() else {
        return respond::send(
            stream, 503, "Service Unavailable", &[JSON],
            br#"{"running":false,"error":"clash disabled in this mode"}"#, ka,
        ).await;
    };

    match tokio::task::spawn_blocking(move || ctl.ensure_up()).await {
        Ok(Ok(spawned)) => {
            let body: &[u8] = if spawned {
                br#"{"running":true,"spawned":true}"#
            } else {
                br#"{"running":true,"spawned":false}"#
            };
            respond::send(stream, 200, "OK", &[JSON], body, ka).await
        }
        Ok(Err(e)) => {
            tracing::warn!(%e, "clash ensure_up failed");
            respond::send(stream, 500, "Internal Server Error", &[JSON], br#"{"running":false,"error":"spawn failed"}"#, ka).await
        }
        Err(e) => {
            tracing::warn!(%e, "clash ensure_up task join failed");
            respond::send(stream, 500, "Internal Server Error", &[JSON], br#"{"running":false,"error":"internal"}"#, ka).await
        }
    }
}

async fn traffic_clear(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(src) = cfg.traffic.as_ref() else {
        return respond::not_found(stream, ka).await;
    };
    src.clear();
    respond::send(stream, 200, "OK", &[("Content-Type", "application/json")], br#"{"cleared":true}"#, ka).await
}

async fn traffic_sse(stream: &mut TcpStream, cfg: &ServerConfig) -> io::Result<()> {
    let Some(src) = cfg.traffic.as_ref() else {
        return respond::not_found(stream, false).await;
    };
    sse::write_headers(stream).await?;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let snap = src.snapshot_json();
        sse::event(stream, &snap).await?;
    }
}

async fn logs_sse(stream: &mut TcpStream, cfg: &ServerConfig) -> io::Result<()> {
    let Some(tx) = cfg.log_tx.as_ref() else {
        return respond::not_found(stream, false).await;
    };
    let mut rx = tx.subscribe();
    sse::write_headers(stream).await?;
    let mut hb = tokio::time::interval(Duration::from_secs(15));
    hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(ev) => sse::event(stream, &ev.to_json()).await?,
                Err(RecvError::Lagged(n)) => sse::comment(stream, &format!("lagged {n}")).await?,
                Err(RecvError::Closed) => return Ok(()),
            },
            _ = hb.tick() => sse::comment(stream, "ping").await?,
        }
    }
}

async fn screen_snapshot(stream: &mut TcpStream, cfg: &ServerConfig, ka: bool) -> io::Result<()> {
    let Some(current) = read_screen_async(cfg.screen_dev.clone()).await else {
        return respond::send(
            stream,
            200,
            "OK",
            &[("Content-Type", "text/plain; charset=utf-8"), ("X-Screen-Status", "unavailable")],
            b"",
            ka,
        )
        .await;
    };
    let history = cfg.screen_history.snapshot_text();
    let body = if history.is_empty() { current } else { history };
    respond::send(stream, 200, "OK", &[("Content-Type", "text/plain; charset=utf-8")], body.as_bytes(), ka).await
}

async fn screen_sse(stream: &mut TcpStream, cfg: &ServerConfig) -> io::Result<()> {
    let mut rx = cfg.screen_history.subscribe();
    sse::write_headers(stream).await?;
    let mut hb = tokio::time::interval(Duration::from_secs(15));
    hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(chunk) => sse::event(stream, &chunk).await?,
                Err(RecvError::Lagged(n)) => sse::comment(stream, &format!("lagged {n}")).await?,
                Err(RecvError::Closed) => return Ok(()),
            },
            _ = hb.tick() => sse::comment(stream, "ping").await?,
        }
    }
}

async fn read_screen_async(dev: PathBuf) -> Option<String> {
    tokio::task::spawn_blocking(move || screen::read_screen(&dev).ok()).await.ok().flatten()
}
#[cfg(test)]
mod tests {
    use super::{pct_decode, query_param};
    #[test]
    fn pct_decode_basic() {
        assert_eq!(pct_decode("abc"), "abc");
        assert_eq!(pct_decode("a+b"), "a b");
        assert_eq!(pct_decode("%2Fx"), "/x");

        assert_eq!(pct_decode("%55%6E%69%74%65%64%20%53%74%61%74%65%73"), "United States");

        assert_eq!(pct_decode("%zz"), "%zz");
        assert_eq!(pct_decode("%4"), "%4");
    }
    #[test]
    fn query_param_extract() {
        assert_eq!(query_param("/sniffbox/proxy?name=abc", "name").as_deref(), Some("abc"));
        assert_eq!(
            query_param("/sniffbox/proxy?name=%55%6E%69%74%65%64%20%53%74%61%74%65%73", "name").as_deref(),
            Some("United States")
        );
        assert_eq!(query_param("/sniffbox/proxy?x=1&name=n", "name").as_deref(), Some("n"));
        assert_eq!(query_param("/sniffbox/proxy", "name"), None);
        assert_eq!(query_param("/sniffbox/proxy?other=1", "name"), None);
    }
}
