// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::clash_ctl::ClashSupervisor;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

const CLASH_DIR: &str = "/etc/config/clash";

pub struct WebGeo {
    dir: PathBuf,
    clash: Arc<ClashSupervisor>,
    updating: Mutex<()>,
}

impl WebGeo {

    pub fn new(clash: Arc<ClashSupervisor>) -> Self {
        Self {
            dir: PathBuf::from(CLASH_DIR),
            clash,
            updating: Mutex::new(()),
        }
    }
}

impl WebGeo {

    pub async fn update_then_restart(&self) -> String {
        let _guard = self.updating.lock().await;
        let report = sb_ppgw::geo::update(&self.dir).await;
        self.restart_clash("scheduled clash cold-restart failed")
            .await;
        report.to_json()
    }

    async fn restart_clash(&self, what: &'static str) {
        let clash = Arc::clone(&self.clash);
        let r = tokio::task::spawn_blocking(move || clash.restart()).await;
        match r {
            Ok(Err(e)) => tracing::warn!(%e, "{what}"),
            Err(e) => tracing::warn!(%e, "{what}"),
            Ok(Ok(())) => {}
        }
    }
}

impl sb_web::GeoControl for WebGeo {
    fn status_json(&self) -> String {
        sb_ppgw::geo::status(&self.dir).to_json()
    }

    fn update(&self) -> sb_web::GeoFut<'_> {
        Box::pin(async move {

            let _guard = self.updating.lock().await;
            let report = sb_ppgw::geo::update(&self.dir).await;
            if report.changed {

                self.restart_clash("clash cold-restart after geo update failed")
                    .await;
            }
            report.to_json()
        })
    }
}
