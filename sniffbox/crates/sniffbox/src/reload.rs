// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::ConfigSource;
use crate::runtime::SharedState;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};

pub async fn run_reload_loop(shared: Arc<SharedState>, source: ConfigSource) {
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(?e, "failed to register SIGHUP handler");
            return;
        }
    };
    while sighup.recv().await.is_some() {
        tracing::info!(source = %source.describe(), "SIGHUP — reloading config");
        match source.load() {
            Ok(new) => {
                shared.reload(&new);
                tracing::info!("config reloaded");
            }
            Err(e) => {
                tracing::warn!(?e, "reload failed; keep old config");
            }
        }
    }
}
