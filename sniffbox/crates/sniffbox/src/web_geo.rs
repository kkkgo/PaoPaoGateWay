// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::clash_ctl::ClashSupervisor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

    pub fn update_then_restart(&self) -> String {
        let _guard = self.updating.lock().unwrap_or_else(|e| e.into_inner());
        let report = sb_ppgw::geo::update(&self.dir);
        if let Err(e) = self.clash.restart() {
            tracing::warn!(%e, "scheduled clash cold-restart failed");
        }
        report.to_json()
    }
}

impl sb_web::GeoControl for WebGeo {
    fn status_json(&self) -> String {
        sb_ppgw::geo::status(&self.dir).to_json()
    }

    fn update(&self) -> String {

        let _guard = self.updating.lock().unwrap_or_else(|e| e.into_inner());
        let report = sb_ppgw::geo::update(&self.dir);
        if report.changed {

            if let Err(e) = self.clash.restart() {
                tracing::warn!(%e, "clash cold-restart after geo update failed");
            }
        }
        report.to_json()
    }
}
