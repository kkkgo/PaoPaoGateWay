// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::runtime::SharedState;
use sb_stats::cleanup::{CleanState, maybe_clean};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::watch;

const FLUSH_INTERVAL: Duration = Duration::from_secs(3);

pub async fn run_flush_loop(shared: Arc<SharedState>, mut shutdown: watch::Receiver<bool>) {
    let mut clean_state = CleanState::default();
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::info!(
        ?FLUSH_INTERVAL,
        max_rec = shared.max_rec(),
        "flush loop started"
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
    tracing::info!("flush loop exited");
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
    });

    shared.sniff_neg.gc();

    let demand = {
        let last = shared.traffic_last_access.load(Ordering::Relaxed);
        last != 0
            && sb_stats::now_epoch_ms().saturating_sub(last)
                <= crate::runtime::TRAFFIC_DEMAND_WINDOW_MS
    };
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

            shared.traffic.add_totals(dd, du);

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

        let (fu, fd) = rec.fold_delta();
        if fu != 0 || fd != 0 {
            shared.agg.fold(&rec, fu, fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sb_stats::types::{ConnRecord, SniffedProto};

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
