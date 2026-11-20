// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    Sniffbox,
    Clash,
}

impl LogSource {
    pub fn as_str(self) -> &'static str {
        match self {
            LogSource::Sniffbox => "sniffbox",
            LogSource::Clash => "clash",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEvent {

    pub seq: u64,
    pub ts_ms: u64,
    pub source: LogSource,
    pub level: String,
    pub msg: String,
}

impl LogEvent {
    pub fn new(source: LogSource, level: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            seq: 0,
            ts_ms: now_ms(),
            source,
            level: level.into(),
            msg: msg.into(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::json!({
            "source": self.source.as_str(),
            "level": self.level,
            "ts": self.ts_ms,
            "msg": self.msg,
            "seq": self.seq,
        })
        .to_string()
    }

    fn cost(&self) -> usize {
        self.msg.len() + self.level.len() + 64
    }
}

pub type LogTx = Arc<LogHub>;

const MAX_MSG: usize = 4096;

pub struct LogHub {
    tx: broadcast::Sender<Arc<LogEvent>>,
    hist: Mutex<History>,

    epoch: u64,
    max_events: usize,
    max_bytes: usize,
}

struct History {
    q: VecDeque<Arc<LogEvent>>,
    bytes: usize,
    next_seq: u64,
}

impl LogHub {

    pub fn new(broadcast_cap: usize, max_events: usize, max_bytes: usize) -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(broadcast_cap.max(1));
        Arc::new(Self {
            tx,
            hist: Mutex::new(History {
                q: VecDeque::new(),
                bytes: 0,
                next_seq: 1,
            }),
            epoch: now_ms(),
            max_events,
            max_bytes,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LogEvent>> {
        self.tx.subscribe()
    }

    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    pub fn publish(&self, mut ev: LogEvent) {
        let keep = !matches!(ev.level.as_str(), "debug" | "trace");
        let listening = self.tx.receiver_count() > 0;
        if !keep && !listening {
            return;
        }
        if keep && ev.msg.len() > MAX_MSG {
            let mut cut = MAX_MSG;
            while !ev.msg.is_char_boundary(cut) {
                cut -= 1;
            }
            ev.msg.truncate(cut);
            ev.msg.push('…');
        }
        let mut h = self.hist.lock().unwrap_or_else(|e| e.into_inner());
        ev.seq = h.next_seq;
        h.next_seq += 1;
        let ev = Arc::new(ev);
        if keep && self.max_events > 0 {
            h.bytes += ev.cost();
            h.q.push_back(ev.clone());
            while h.q.len() > self.max_events || (h.bytes > self.max_bytes && h.q.len() > 1) {
                if let Some(old) = h.q.pop_front() {
                    h.bytes -= old.cost();
                }
            }
        }
        if listening {
            let _ = self.tx.send(ev);
        }
    }

    pub fn emit(&self, source: LogSource, level: impl Into<String>, msg: impl Into<String>) {
        self.publish(LogEvent::new(source, level, msg));
    }

    pub fn since(&self, since: u64) -> Vec<Arc<LogEvent>> {
        let h = self.hist.lock().unwrap_or_else(|e| e.into_inner());

        let start = h.q.partition_point(|e| e.seq <= since);
        h.q.range(start..).cloned().collect()
    }

    #[doc(hidden)]
    pub fn history_bytes(&self) -> usize {
        self.hist.lock().unwrap_or_else(|e| e.into_inner()).bytes
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape_and_escaping() {
        let ev = LogEvent {
            seq: 42,
            ts_ms: 1700000000000,
            source: LogSource::Clash,
            level: "info".into(),
            msg: "a\"b\nc".into(),
        };
        let v: serde_json::Value = serde_json::from_str(&ev.to_json()).unwrap();
        assert_eq!(v["source"], "clash");
        assert_eq!(v["level"], "info");
        assert_eq!(v["ts"], 1700000000000u64);
        assert_eq!(v["msg"], "a\"b\nc");
        assert_eq!(v["seq"], 42);
    }

    fn msgs(evs: &[Arc<LogEvent>]) -> Vec<String> {
        evs.iter().map(|e| e.msg.clone()).collect()
    }

    #[test]
    fn history_is_kept_without_subscribers_and_numbered_in_order() {
        let hub = LogHub::new(8, 100, 1 << 20);
        assert_eq!(hub.receiver_count(), 0);
        for i in 0..5 {
            hub.emit(LogSource::Sniffbox, "info", format!("m{i}"));
        }
        let all = hub.since(0);
        assert_eq!(msgs(&all), ["m0", "m1", "m2", "m3", "m4"]);
        let seqs: Vec<u64> = all.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5]);
        assert_eq!(msgs(&hub.since(3)), ["m3", "m4"], "since() is exclusive");
        assert!(hub.since(5).is_empty());
        assert!(hub.since(u64::MAX).is_empty());
    }

    #[test]
    fn history_respects_event_and_byte_caps() {
        let hub = LogHub::new(8, 3, 1 << 20);
        for i in 0..10 {
            hub.emit(LogSource::Sniffbox, "warn", format!("m{i}"));
        }
        assert_eq!(
            msgs(&hub.since(0)),
            ["m7", "m8", "m9"],
            "count cap keeps the newest"
        );

        let hub = LogHub::new(8, 1000, 4096);
        for i in 0..20 {
            hub.emit(
                LogSource::Sniffbox,
                "info",
                format!("{i:04}{}", "x".repeat(1020)),
            );
        }
        let kept = hub.since(0);
        assert!(
            !kept.is_empty() && kept.len() <= 4,
            "byte cap bounds history, kept {}",
            kept.len()
        );
        assert!(hub.history_bytes() <= 4096, "bytes {}", hub.history_bytes());
        assert!(
            kept.last().unwrap().msg.starts_with("0019"),
            "newest survives"
        );
    }

    #[test]
    fn oversized_message_is_truncated_on_a_char_boundary() {
        let hub = LogHub::new(8, 10, 1 << 20);
        hub.emit(LogSource::Sniffbox, "error", "€".repeat(3000));
        let ev = &hub.since(0)[0];
        assert!(ev.msg.len() <= MAX_MSG + '…'.len_utf8());
        assert!(ev.msg.ends_with('…'));

        assert!(ev.msg.trim_end_matches('…').chars().all(|c| c == '€'));
    }

    #[test]
    fn debug_is_broadcast_live_but_not_kept() {
        let hub = LogHub::new(8, 100, 1 << 20);
        hub.emit(LogSource::Sniffbox, "debug", "nobody listening");
        let mut rx = hub.subscribe();
        hub.emit(LogSource::Sniffbox, "debug", "live only");
        hub.emit(LogSource::Clash, "info", "kept");
        assert_eq!(rx.try_recv().unwrap().msg, "live only");
        assert_eq!(rx.try_recv().unwrap().msg, "kept");
        assert_eq!(msgs(&hub.since(0)), ["kept"]);
    }

    #[test]
    fn broadcast_order_matches_seq_under_concurrency() {
        let hub = LogHub::new(100_000, 100_000, 1 << 26);
        let mut rx = hub.subscribe();
        std::thread::scope(|s| {
            for t in 0..8 {
                let hub = &hub;
                s.spawn(move || {
                    for i in 0..2000 {
                        hub.emit(LogSource::Sniffbox, "info", format!("{t}-{i}"));
                    }
                });
            }
        });
        let mut last = 0;
        let mut n = 0;
        while let Ok(ev) = rx.try_recv() {
            assert!(
                ev.seq > last,
                "broadcast out of seq order: {} after {last}",
                ev.seq
            );
            last = ev.seq;
            n += 1;
        }
        assert_eq!(n, 16_000);
        assert_eq!(hub.since(0).len(), 16_000);
    }
}
