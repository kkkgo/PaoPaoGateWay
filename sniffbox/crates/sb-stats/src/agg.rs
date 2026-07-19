// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::types::{ConnRecord, RecordKind, Transport, now_epoch_ms};
use arc_swap::ArcSwap;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[derive(Clone, PartialEq, Eq, Hash)]
struct AggKey {
    client: IpAddr,
    transport: Transport,
    domain: String,
}

impl AggKey {
    fn of(rec: &ConnRecord) -> Self {
        Self {
            client: rec.src.0,
            transport: rec.transport,
            domain: rec.display_domain(),
        }
    }
}

struct AggRow {
    first_ms: u64,
    last_ms: u64,
    up: u64,
    down: u64,
    conns: u64,
    dports: BTreeSet<u16>,
    sniffs: BTreeSet<&'static str>,
    inbounds: BTreeSet<&'static str>,

    head: Option<String>,
}

impl AggRow {
    fn new(now: u64) -> Self {
        Self {
            first_ms: now,
            last_ms: now,
            up: 0,
            down: 0,
            conns: 0,
            dports: BTreeSet::new(),
            sniffs: BTreeSet::new(),
            inbounds: BTreeSet::new(),
            head: None,
        }
    }
}

pub struct AggTable {
    rows: Mutex<HashMap<AggKey, AggRow>>,
    window: Duration,
    json: ArcSwap<String>,
}

impl AggTable {
    pub fn new(window: Duration) -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            window,
            json: ArcSwap::from_pointee("[]".to_string()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<AggKey, AggRow>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn fold(&self, rec: &ConnRecord, fu: u64, fd: u64) {
        if fu == 0 && fd == 0 {
            return;
        }
        let now = now_epoch_ms();
        let key = AggKey::of(rec);
        let first = !rec.agg_counted.swap(true, Ordering::Relaxed);
        let sniff = rec.proto.as_str();
        let inbound = if rec.kind == RecordKind::Internal {
            "internal"
        } else {
            rec.inbound.as_str()
        };

        let mut rows = self.lock();
        let row = rows.entry(key).or_insert_with(|| AggRow::new(now));
        row.up += fu;
        row.down += fd;
        row.last_ms = now;
        if first {
            row.conns += 1;
        }
        row.dports.insert(rec.dst.1);
        row.sniffs.insert(sniff);
        row.inbounds.insert(inbound);
        if let Some(h) = rec.head_hex() {
            row.head = Some(h);
        }
    }

    pub fn rebuild(&self, max_rows: usize) {
        let mut rows = self.lock();
        prune_rows(&mut rows, self.window, max_rows);
        let json = serialize(&rows);
        drop(rows);
        self.json.store(Arc::new(json));
    }

    pub fn prune(&self, max_rows: usize) {
        let mut rows = self.lock();
        prune_rows(&mut rows, self.window, max_rows);
    }

    pub fn snapshot_json(&self) -> String {
        (**self.json.load()).clone()
    }

    pub fn clear(&self) {
        self.lock().clear();
        self.json.store(Arc::new("[]".to_string()));
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    #[cfg(test)]
    fn age_rows_ms(&self, ms: u64) {
        for r in self.lock().values_mut() {
            r.last_ms = r.last_ms.saturating_sub(ms);
        }
    }
}

fn prune_rows(rows: &mut HashMap<AggKey, AggRow>, window: Duration, max_rows: usize) {
    let now = now_epoch_ms();
    let window_ms = window.as_millis() as u64;
    rows.retain(|_, r| now.saturating_sub(r.last_ms) < window_ms);
    if rows.len() > max_rows {
        let mut by_recency: Vec<(AggKey, u64)> =
            rows.iter().map(|(k, r)| (k.clone(), r.last_ms)).collect();
        by_recency.sort_unstable_by_key(|x| std::cmp::Reverse(x.1));
        for (k, _) in by_recency.into_iter().skip(max_rows) {
            rows.remove(&k);
        }
    }
}

fn serialize(rows: &HashMap<AggKey, AggRow>) -> String {
    let mut items: Vec<(&AggKey, &AggRow)> = rows.iter().collect();
    items.sort_unstable_by_key(|x| std::cmp::Reverse(x.1.last_ms));
    let arr: Vec<serde_json::Value> = items.iter().map(|(k, r)| row_json(k, r)).collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

fn row_json(k: &AggKey, r: &AggRow) -> serde_json::Value {

    let mut sniff: Vec<&&str> = r.sniffs.iter().filter(|s| !s.is_empty()).collect();
    if sniff.is_empty() {
        sniff = r.sniffs.iter().collect();
    }
    serde_json::json!({
        "client": k.client.to_string(),
        "transport": k.transport.as_str(),
        "dport": r.dports.iter().collect::<Vec<_>>(),
        "domain": k.domain,
        "ts": r.first_ms,
        "last_seen": r.last_ms,
        "conns": r.conns,
        "up": r.up,
        "down": r.down,
        "sniff": sniff,
        "inbound": r.inbounds.iter().collect::<Vec<_>>(),
        "head": r.head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ConnId, InboundKind, SniffedProto};
    use std::sync::Arc;

    fn rec(client: &str, dport: u16, domain: Option<&str>) -> Arc<ConnRecord> {
        Arc::new(
            ConnRecord::new(
                ConnId(1),
                (client.parse().unwrap(), 1234),
                ("1.2.3.4".parse().unwrap(), dport),
                SniffedProto::Tls,
                domain.map(str::to_string),
            )
            .with_inbound(InboundKind::TProxy, Transport::Tcp),
        )
    }

    fn parse(t: &AggTable) -> Vec<serde_json::Value> {
        serde_json::from_str(&t.snapshot_json()).unwrap()
    }

    #[test]
    fn folds_same_triple_into_one_row() {
        let t = AggTable::new(Duration::from_secs(3600));
        let a = rec("10.0.0.1", 443, Some("ex.com"));
        let b = rec("10.0.0.1", 80, Some("ex.com"));
        a.add_up(100);
        a.add_down(200);
        b.add_up(50);
        t.fold(&a, 100, 200);
        t.fold(&b, 50, 0);
        t.rebuild(5000);
        let arr = parse(&t);
        assert_eq!(arr.len(), 1, "same (client,transport,domain) merges");
        assert_eq!(arr[0]["up"], 150);
        assert_eq!(arr[0]["down"], 200);
        assert_eq!(arr[0]["conns"], 2);
        assert_eq!(arr[0]["domain"], "ex.com");
        assert_eq!(arr[0]["transport"], "tcp");

        let dports = arr[0]["dport"].as_array().unwrap();
        assert_eq!(dports.len(), 2);
        assert_eq!(dports[0], 80);
        assert_eq!(dports[1], 443);
        assert_eq!(arr[0]["sniff"][0], "tls");
        assert_eq!(arr[0]["inbound"][0], "tproxy");
        assert!(arr[0].get("chains").is_none(), "proxy chain removed from aggregate record");
    }

    #[test]
    fn different_client_domain_or_transport_splits_rows() {
        let t = AggTable::new(Duration::from_secs(3600));
        let a = rec("10.0.0.1", 443, Some("ex.com"));
        let b = rec("10.0.0.1", 443, Some("other.com"));
        let c = rec("10.0.0.2", 443, Some("ex.com"));
        let mut d = ConnRecord::new(
            ConnId(9),
            ("10.0.0.1".parse().unwrap(), 1234),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Quic,
            Some("ex.com".into()),
        );
        d.transport = Transport::Udp;
        let d = Arc::new(d);
        t.fold(&a, 10, 0);
        t.fold(&b, 10, 0);
        t.fold(&c, 10, 0);
        t.fold(&d, 10, 0);
        t.rebuild(5000);
        assert_eq!(parse(&t).len(), 4);
    }

    #[test]
    fn pure_ip_domain_falls_back_to_dst_ip() {
        let t = AggTable::new(Duration::from_secs(3600));
        let a = rec("10.0.0.1", 443, None);
        t.fold(&a, 10, 0);
        t.rebuild(5000);
        assert_eq!(parse(&t)[0]["domain"], "1.2.3.4");
    }

    #[test]
    fn zero_delta_fold_is_noop() {
        let t = AggTable::new(Duration::from_secs(3600));
        let a = rec("10.0.0.1", 443, Some("ex.com"));
        t.fold(&a, 0, 0);
        t.rebuild(5000);
        assert!(parse(&t).is_empty(), "no delta, no row");
    }

    #[test]
    fn rolling_window_expires_idle_rows() {

        let t = AggTable::new(Duration::from_millis(100));
        let a = rec("10.0.0.1", 443, Some("ex.com"));
        t.fold(&a, 10, 0);
        t.age_rows_ms(5000);
        t.rebuild(5000);
        assert!(parse(&t).is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn prune_expires_rows_without_reserializing() {
        let t = AggTable::new(Duration::from_millis(100));
        let a = rec("10.0.0.1", 443, Some("ex.com"));
        t.fold(&a, 10, 0);
        t.rebuild(5000);
        assert_eq!(parse(&t).len(), 1);
        t.age_rows_ms(5000);
        t.prune(5000);
        assert_eq!(t.len(), 0, "prune should evict expired rows");
        assert_eq!(
            parse(&t).len(),
            1,
            "prune does not rebuild JSON (old snapshot kept, refreshed only on rebuild)"
        );
        t.rebuild(5000);
        assert!(parse(&t).is_empty());
    }

    #[test]
    fn max_rows_caps_by_recency() {
        let t = AggTable::new(Duration::from_secs(3600));
        for i in 0..5u16 {
            let dom = format!("ex{i}.com");
            let r = rec("10.0.0.1", 443, Some(dom.as_str()));
            t.fold(&r, 10, 0);
        }
        t.rebuild(3);
        assert_eq!(parse(&t).len(), 3);
    }

    #[test]
    fn head_hex_exported_and_overwritten_by_newer() {
        let t = AggTable::new(Duration::from_secs(3600));
        let a = Arc::new(ConnRecord::new(
            ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::RealIp,
            None,
        ));
        a.set_head(&[0xaa, 0xbb]);
        t.fold(&a, 10, 0);
        let b = Arc::new(ConnRecord::new(
            ConnId(2),
            ("10.0.0.1".parse().unwrap(), 2),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::RealIp,
            None,
        ));
        b.set_head(&[0xcc, 0xdd]);
        t.fold(&b, 10, 0);
        t.rebuild(5000);
        let arr = parse(&t);
        assert_eq!(arr[0]["sniff"][0], "RealIP");
        assert_eq!(arr[0]["head"], "ccdd");
    }

    #[test]
    fn empty_sniff_dropped_when_concrete_value_present() {
        let t = AggTable::new(Duration::from_secs(3600));

        let unk = Arc::new(ConnRecord::new(
            ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Unknown,
            Some("ex.com".into()),
        ));
        let tls = Arc::new(ConnRecord::new(
            ConnId(2),
            ("10.0.0.1".parse().unwrap(), 2),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            Some("ex.com".into()),
        ));
        t.fold(&unk, 10, 0);
        t.fold(&tls, 10, 0);
        t.rebuild(5000);
        let arr = parse(&t);
        let sniff = arr[0]["sniff"].as_array().unwrap();
        assert_eq!(sniff.len(), 1, "empty value replaced by concrete value");
        assert_eq!(sniff[0], "tls");
    }

    #[test]
    fn only_empty_sniff_kept_as_empty() {
        let t = AggTable::new(Duration::from_secs(3600));
        let unk = Arc::new(ConnRecord::new(
            ConnId(1),
            ("10.0.0.1".parse().unwrap(), 1),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Unknown,
            None,
        ));
        t.fold(&unk, 10, 0);
        t.rebuild(5000);
        let arr = parse(&t);
        assert_eq!(arr[0]["sniff"][0], "");
    }

    #[test]
    fn clear_empties() {
        let t = AggTable::new(Duration::from_secs(3600));
        let a = rec("10.0.0.1", 443, Some("ex.com"));
        t.fold(&a, 10, 0);
        t.clear();
        assert!(parse(&t).is_empty());
        assert_eq!(t.snapshot_json(), "[]");
    }
}
