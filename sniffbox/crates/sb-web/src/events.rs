// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::sync::Arc;
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
    pub ts_ms: u64,
    pub source: LogSource,
    pub level: String,
    pub msg: String,
}

impl LogEvent {
    pub fn new(source: LogSource, level: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
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
        })
        .to_string()
    }
}

pub type LogTx = broadcast::Sender<Arc<LogEvent>>;

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
    }
}
