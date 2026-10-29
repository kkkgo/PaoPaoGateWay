// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::runtime::SharedState;
use sb_stats::cleanup::{CleanState, maybe_clean};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::watch;

const FLUSH_INTERVAL: Duration = Duration::from_secs(3);

pub async fn run_housekeeping(shared: Arc<SharedState>, mut shutdown: watch::Receiver<bool>) {
    let mut clean_state = CleanState::default();
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::info!(
        ?FLUSH_INTERVAL,
        max_rec = shared.max_rec(),
        stats = shared.stats_enabled(),
        "housekeeping loop started"
    );

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    flush_once(&shared, &mut clean_state);
                    break;
                }
            }
            _ = ticker.tick() => flush_once(&shared, &mut clean_state),
        }
    }
    tracing::info!("housekeeping loop exited");
}

fn flush_once(shared: &SharedState, clean_state: &mut CleanState) {
    let max_rec = shared.max_rec();
    let net_cleanday = shared.net_cleanday();
    drain_local(shared);

    let _ = shared
        .conn_table
        .sweep_recency(0, Duration::from_secs(86_400));

    maybe_clean(net_cleanday, clean_state, || {
        shared.conn_table.clear();
        shared.traffic.clear();
        shared.agg.clear();
        shared.node_dist.clear();
        shared.cf_traffic.clear();
    });

    shared.sniff_neg.gc();

    let demand = {
        let last = shared.traffic_last_access.load(Ordering::Relaxed);
        last != 0
            && sb_stats::now_epoch_ms().saturating_sub(last)
                <= crate::runtime::TRAFFIC_DEMAND_WINDOW_MS
    };
    if !shared.stats_enabled() {
        return;
    }
    if demand {
        shared.agg.rebuild(max_rec);
    } else {
        shared.agg.prune(max_rec);
    }
}

fn drain_local(shared: &SharedState) {
    for rec in shared.conn_table.snapshot() {

        let (du, dd) = rec.drain_delta();
        if du != 0 || dd != 0 {

            shared.conn_table.touch(rec.id);

            shared.account_delta(&rec, dd, du);

            if let Some(p) = &shared.pplog
                && rec.closed_ms.load(Ordering::Relaxed) == 0
            {
                p.emit(crate::pplog::Event::Update {
                    id: rec.id.0,
                    up: rec.upload.load(Ordering::Relaxed),
                    down: rec.download.load(Ordering::Relaxed),
                });
            }
        }

        if shared.stats_enabled() {
            let (fu, fd) = rec.fold_delta();
            if fu != 0 || fd != 0 {
                shared.agg.fold(&rec, fu, fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, StatsCfg};
    use sb_stats::types::{ConnRecord, SniffedProto};

    fn shared_net_rec_off() -> Arc<SharedState> {
        Arc::new(SharedState::new(&Config::default()))
    }

    fn shared_net_rec_on() -> Arc<SharedState> {
        let cfg = Config {
            stats: Some(StatsCfg {
                enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        Arc::new(SharedState::new(&cfg))
    }

    fn rec_with_bytes(id: u64, up: u64, down: u64) -> Arc<ConnRecord> {
        let r = Arc::new(ConnRecord::new(
            sb_stats::ConnId(id),
            ("10.0.0.9".parse().unwrap(), 40000 + id as u16),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            Some("leak.example".into()),
        ));
        r.add_up(up);
        r.add_down(down);
        r
    }

    #[test]
    fn housekeeping_reclaims_closed_records_when_net_rec_is_off() {
        let shared = shared_net_rec_off();
        assert!(!shared.stats_enabled());
        let mut clean = CleanState::default();
        for id in 1..=50 {
            let r = rec_with_bytes(id, 100, 200);
            shared.conn_table.insert(Arc::clone(&r));
            shared.conn_table.close(r.id);
        }
        assert_eq!(shared.conn_table.len(), 50);
        flush_once(&shared, &mut clean);
        assert_eq!(
            shared.conn_table.len(),
            0,
            "closed records must be reclaimed even with net_rec off"
        );
        assert_eq!(shared.traffic.totals(), (50 * 200, 50 * 100));
        assert_eq!(
            shared.agg.len(),
            0,
            "net_rec off must not build time-window aggregate rows"
        );
    }

    #[test]
    fn net_rec_off_skips_the_aggregate_but_keeps_live_records() {
        let shared = shared_net_rec_off();
        let mut clean = CleanState::default();
        let r = rec_with_bytes(1, 7, 11);
        shared.conn_table.insert(Arc::clone(&r));
        flush_once(&shared, &mut clean);
        assert_eq!(shared.conn_table.len(), 1, "active record stays");
        assert_eq!(shared.traffic.totals(), (11, 7));
        assert_eq!(shared.agg.len(), 0);
    }

    #[test]
    fn net_rec_on_still_folds_the_aggregate() {
        let shared = shared_net_rec_on();
        assert!(shared.stats_enabled());
        let mut clean = CleanState::default();
        let r = rec_with_bytes(1, 7, 11);
        shared.conn_table.insert(Arc::clone(&r));
        flush_once(&shared, &mut clean);
        assert_eq!(shared.agg.len(), 1, "net_rec on must fold into agg");
        assert_eq!(shared.traffic.totals(), (11, 7));
    }

    #[test]
    fn housekeeping_is_spawned_unconditionally_in_run() {
        let src = include_str!("lib.rs");
        let body = src.split_once("async fn run(").expect("run() must exist").1;
        let body = body.split("\nfn ").next().unwrap();
        let line = body
            .lines()
            .find(|l| l.contains("start_housekeeping("))
            .expect("run() must start the housekeeping loop");
        assert!(
            line.starts_with("    start_housekeeping(") && !line.starts_with("     "),
            "housekeeping must be a top-level statement of run(), not gated on net_rec; got: {line:?}"
        );
    }

    #[test]
    fn drain_accumulates_totals_then_zero_on_idle() {
        let shared = Arc::new(SharedState::new(&Config::default()));
        let r = Arc::new(ConnRecord::new(
            sb_stats::ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            Some("example.com".into()),
        ));
        shared.conn_table.insert(Arc::clone(&r));
        r.upload.store(500, Ordering::Relaxed);
        r.download.store(1000, Ordering::Relaxed);
        drain_local(&shared);
        assert_eq!(shared.traffic.totals(), (1000, 500));

        drain_local(&shared);
        assert_eq!(shared.traffic.totals(), (1000, 500));
    }

    #[test]
    fn close_path_tail_bytes_counted_in_totals() {
        let shared = Arc::new(SharedState::new(&Config::default()));
        let r = Arc::new(ConnRecord::new(
            sb_stats::ConnId(7),
            ("10.0.0.7".parse().unwrap(), 55555),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            Some("ex.com".into()),
        ));
        shared.conn_table.insert(Arc::clone(&r));
        r.add_up(900);
        r.add_down(1_073_741_824);

        let (du, dd) = r.drain_delta();
        shared.traffic.add_totals(dd, du);
        shared.conn_table.close(r.id);

        drain_local(&shared);
        assert_eq!(shared.traffic.totals(), (1_073_741_824, 900));
    }
}
