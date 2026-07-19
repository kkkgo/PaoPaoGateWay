// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::web_geo::WebGeo;
use std::sync::Arc;
use std::time::Duration;

pub(crate) const PPSUB_JSON: &str = "/etc/config/clash/clash-dashboard/data/ppsub.json";

const MARKER: &str = "/tmp/sniffbox_georestart.last";

pub fn spawn(geo: Arc<WebGeo>, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
            tick(&geo).await;
        }
    });
}

async fn tick(geo: &Arc<WebGeo>) {

    if !crate::runtime::ppsub_active() {
        return;
    }
    let Ok(json) = std::fs::read_to_string(PPSUB_JSON) else {
        return;
    };
    let Some(hour) = parse_restart_hour(&json) else {
        return;
    };
    let (now_hour, today) = local_hour_date();
    let marker = std::fs::read_to_string(MARKER).ok();
    if !should_fire(hour, now_hour, &today, marker.as_deref()) {
        return;
    }

    if let Err(e) = std::fs::write(MARKER, &today) {
        tracing::warn!(%e, "restart_cron: marker write failed, skip to avoid restart loop");
        return;
    }
    tracing::info!(hour, "restart_cron: geo update + clash cold-restart");
    let g = Arc::clone(geo);
    match tokio::task::spawn_blocking(move || g.update_then_restart()).await {
        Ok(report) => tracing::info!(%report, "restart_cron done"),
        Err(e) => tracing::warn!(%e, "restart_cron task panicked"),
    }
}

fn parse_restart_hour(json: &str) -> Option<u8> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let rc = v.get("restart_cron")?;
    if !rc.get("enable").and_then(|b| b.as_bool()).unwrap_or(false) {
        return None;
    }
    let hour = rc.get("hour")?.as_u64()?;
    (hour < 24).then_some(hour as u8)
}

fn should_fire(cfg_hour: u8, now_hour: u8, today: &str, marker: Option<&str>) -> bool {
    now_hour == cfg_hour && marker.map(str::trim) != Some(today)
}

fn local_hour_date() -> (u8, String) {

    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        (
            tm.tm_hour as u8,
            format!(
                "{:04}-{:02}-{:02}",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enabled_hour() {
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":true,"hour":4}}"#),
            Some(4)
        );
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":true,"hour":0}}"#),
            Some(0)
        );
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":true,"hour":23}}"#),
            Some(23)
        );
    }

    #[test]
    fn parse_rejects_disabled_missing_invalid() {
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":false,"hour":4}}"#),
            None
        );
        assert_eq!(parse_restart_hour(r#"{"restart_cron":{"hour":4}}"#), None);
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":true,"hour":24}}"#),
            None
        );
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":true,"hour":-1}}"#),
            None
        );
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":true,"hour":"4"}}"#),
            None
        );
        assert_eq!(
            parse_restart_hour(r#"{"restart_cron":{"enable":true}}"#),
            None
        );
        assert_eq!(
            parse_restart_hour(r#"{"global_monitor":{"enable":true}}"#),
            None
        );
        assert_eq!(parse_restart_hour("not json"), None);
    }

    #[test]
    fn fire_once_per_day_at_hour() {

        assert!(should_fire(4, 4, "2026-07-16", None));
        assert!(should_fire(4, 4, "2026-07-16", Some("2026-07-15")));

        assert!(!should_fire(4, 4, "2026-07-16", Some("2026-07-16")));
        assert!(!should_fire(4, 4, "2026-07-16", Some("2026-07-16\n")));

        assert!(!should_fire(4, 3, "2026-07-16", None));
        assert!(!should_fire(4, 5, "2026-07-16", None));
    }
}
