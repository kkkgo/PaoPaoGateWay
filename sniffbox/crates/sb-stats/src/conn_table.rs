// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::types::{ConnId, ConnRecord, now_epoch_ms};
use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct ConnIdGen {
    base: u64,
    next: CachePadded<AtomicU64>,
}

const CONN_ID_SEQ_BITS: u32 = 40;
const CONN_ID_SEQ_MASK: u64 = (1 << CONN_ID_SEQ_BITS) - 1;

impl ConnIdGen {
    pub fn new() -> Self {
        Self::with_seed(boot_seed24())
    }

    pub fn with_seed(seed24: u32) -> Self {
        Self {
            base: u64::from(seed24 & 0x00FF_FFFF) << CONN_ID_SEQ_BITS,
            next: CachePadded::new(AtomicU64::new(1)),
        }
    }

    pub fn next_id(&self) -> ConnId {
        let seq = self.next.fetch_add(1, Ordering::Relaxed) & CONN_ID_SEQ_MASK;
        ConnId(self.base | seq)
    }
}

fn boot_seed24() -> u32 {
    use std::io::Read;
    let mut b = [0u8; 3];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok()
    {
        return u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0)
        & 0x00FF_FFFF
}

impl Default for ConnIdGen {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConnTable {
    inner: DashMap<ConnId, Arc<ConnRecord>>,
    started: Instant,

    started_epoch_ms: u64,
}

impl ConnTable {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            started: Instant::now(),
            started_epoch_ms: now_epoch_ms(),
        }
    }

    pub fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn started_epoch_ms(&self) -> u64 {
        self.started_epoch_ms
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn insert(&self, rec: Arc<ConnRecord>) -> ConnId {
        let id = rec.id;
        rec.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
        self.inner.insert(id, rec);
        id
    }

    pub fn get(&self, id: ConnId) -> Option<Arc<ConnRecord>> {
        self.inner.get(&id).map(|e| Arc::clone(e.value()))
    }

    pub fn touch(&self, id: ConnId) {
        if let Some(r) = self.inner.get(&id) {
            r.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
        }
    }

    pub fn remove(&self, id: ConnId) -> Option<Arc<ConnRecord>> {
        self.inner.remove(&id).map(|(_, v)| v)
    }

    pub fn close(&self, id: ConnId) {
        if let Some(r) = self.inner.get(&id) {
            r.closed_ms.store(self.now_ms().max(1), Ordering::Relaxed);
            r.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> Vec<Arc<ConnRecord>> {
        self.inner.iter().map(|e| Arc::clone(e.value())).collect()
    }

    pub fn sweep_stale(&self, stale_after: Duration) -> usize {
        self.sweep_with_close_grace(stale_after, Duration::from_secs(5))
    }

    pub fn sweep_recency(&self, max_closed: usize, active_stale_after: Duration) -> usize {
        let now = self.now_ms();
        let stale_h = active_stale_after.as_millis() as u64;
        let mut closed: Vec<(ConnId, u64)> = Vec::new();
        let mut stale_active: Vec<ConnId> = Vec::new();
        for e in self.inner.iter() {
            let r = e.value();
            let last_seen = r.last_seen_ms.load(Ordering::Relaxed);
            let closed_ms = r.closed_ms.load(Ordering::Relaxed);
            if closed_ms != 0 {
                closed.push((*e.key(), last_seen));
            } else if now.saturating_sub(last_seen) > stale_h {
                stale_active.push(*e.key());
            }
        }

        closed.sort_unstable_by_key(|c| std::cmp::Reverse(c.1));
        let mut removed = 0;
        if closed.len() > max_closed {
            for (id, _) in &closed[max_closed..] {
                self.inner.remove(id);
                removed += 1;
            }
        }
        for id in &stale_active {
            self.inner.remove(id);
            removed += 1;
        }
        removed
    }

    pub fn sweep_with_close_grace(&self, stale_after: Duration, closed_grace: Duration) -> usize {
        let now = self.now_ms();
        let stale_h = stale_after.as_millis() as u64;
        let close_h = closed_grace.as_millis() as u64;
        let dead: Vec<ConnId> = self
            .inner
            .iter()
            .filter(|e| {
                let r = e.value();
                let closed = r.closed_ms.load(Ordering::Relaxed);
                if closed != 0 {
                    now.saturating_sub(closed) >= close_h
                } else {
                    now.saturating_sub(r.last_seen_ms.load(Ordering::Relaxed)) > stale_h
                }
            })
            .map(|e| *e.key())
            .collect();
        for id in &dead {
            self.inner.remove(id);
        }
        dead.len()
    }
}

impl Default for ConnTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SniffedProto;

    fn rec(id: u64) -> Arc<ConnRecord> {
        Arc::new(ConnRecord::new(
            ConnId(id),
            ("10.0.0.1".parse().unwrap(), 1000),
            ("1.2.3.4".parse().unwrap(), 443),
            SniffedProto::Tls,
            Some("example.com".into()),
        ))
    }

    #[test]
    fn id_gen_seq_is_monotonic_within_boot() {
        let g = ConnIdGen::with_seed(0);
        assert_eq!(g.next_id(), ConnId(1));
        assert_eq!(g.next_id(), ConnId(2));
        assert_eq!(g.next_id(), ConnId(3));
    }

    #[test]
    fn distinct_boot_seeds_produce_disjoint_ids() {
        let g1 = ConnIdGen::with_seed(1);
        let g2 = ConnIdGen::with_seed(2);
        let a = g1.next_id().0;
        let b = g2.next_id().0;
        assert_ne!(a, b);
        assert_eq!(a >> 40, 1);
        assert_eq!(b >> 40, 2);
        assert_eq!(a & ((1 << 40) - 1), 1);
        assert_eq!(b & ((1 << 40) - 1), 1);
    }

    #[tokio::test]
    async fn insert_snapshot_remove() {
        let t = ConnTable::new();
        t.insert(rec(1));
        t.insert(rec(2));
        assert_eq!(t.len(), 2);
        let snap = t.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(t.remove(ConnId(1)).is_some());
        assert_eq!(t.len(), 1);
    }

    #[tokio::test]
    async fn sweep_removes_stale() {
        let t = ConnTable::new();
        t.insert(rec(1));
        tokio::time::sleep(Duration::from_millis(30)).await;

        t.insert(rec(2));
        let removed = t.sweep_stale(Duration::from_millis(20));
        assert_eq!(removed, 1);
        assert!(t.get(ConnId(1)).is_none());
        assert!(t.get(ConnId(2)).is_some());
    }

    #[tokio::test]
    async fn active_record_survives_long_grace_sweep() {
        let t = ConnTable::new();
        t.insert(rec(1));

        tokio::time::sleep(Duration::from_millis(100)).await;
        let removed = t.sweep_with_close_grace(Duration::from_secs(86_400), Duration::from_secs(5));
        assert_eq!(removed, 0, "active record incorrectly swept");
        assert!(t.get(ConnId(1)).is_some());
    }

    #[tokio::test]
    async fn sweep_recency_drops_closed_keeps_active() {
        let t = ConnTable::new();
        t.insert(rec(1));
        t.insert(rec(2));
        t.close(ConnId(1));
        let removed = t.sweep_recency(0, Duration::from_secs(86_400));
        assert_eq!(removed, 1);
        assert!(
            t.get(ConnId(1)).is_none(),
            "closed record dropped (max_closed=0)"
        );
        assert!(t.get(ConnId(2)).is_some(), "active record kept");
    }

    #[tokio::test]
    async fn touch_refreshes_last_seen() {
        let t = ConnTable::new();
        let r = rec(1);
        t.insert(Arc::clone(&r));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let t1 = r.last_seen_ms.load(Ordering::Relaxed);
        t.touch(ConnId(1));
        let t2 = r.last_seen_ms.load(Ordering::Relaxed);
        assert!(t2 > t1);
    }
}
