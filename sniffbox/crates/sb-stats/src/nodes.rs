// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::types::now_epoch_ms;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_NODES: usize = 1024;

pub struct NodeDist {
    nodes: Mutex<HashMap<String, (u64, u64)>>,
    since_ms: AtomicU64,
    json: ArcSwap<String>,
}

impl Default for NodeDist {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeDist {
    pub fn new() -> Self {
        let now = now_epoch_ms();
        Self {
            nodes: Mutex::new(HashMap::new()),
            since_ms: AtomicU64::new(now),
            json: ArcSwap::from_pointee(empty_json(now)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u64, u64)>> {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn add(&self, node: &str, dup: u64, ddown: u64) {
        if node.is_empty() || (dup == 0 && ddown == 0) {
            return;
        }
        let mut m = self.lock();
        if !m.contains_key(node) && m.len() >= MAX_NODES {
            return;
        }
        let e = m.entry(node.to_string()).or_insert((0, 0));
        e.0 += dup;
        e.1 += ddown;
    }

    pub fn rebuild(&self) {
        let m = self.lock();
        let since = self.since_ms.load(Ordering::Relaxed);
        let json = render(&m, since);
        drop(m);
        self.json.store(Arc::new(json));
    }

    pub fn snapshot_json(&self) -> String {
        (**self.json.load()).clone()
    }

    pub fn snapshot(&self) -> Vec<(String, u64, u64)> {
        self.lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.0, v.1))
            .collect()
    }

    pub fn clear(&self) {
        self.lock().clear();
        let now = now_epoch_ms();
        self.since_ms.store(now, Ordering::Relaxed);
        self.json.store(Arc::new(empty_json(now)));
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

fn render(m: &HashMap<String, (u64, u64)>, since: u64) -> String {
    let mut nodes: Vec<(String, u64, u64)> = m.iter().map(|(k, v)| (k.clone(), v.0, v.1)).collect();
    nodes.sort_unstable_by_key(|x| std::cmp::Reverse(x.1 + x.2));
    let arr: Vec<serde_json::Value> = nodes
        .iter()
        .map(|(name, up, down)| {
            serde_json::json!({ "node": name, "up": *up, "down": *down, "total": *up + *down })
        })
        .collect();
    serde_json::json!({ "since": since, "nodes": arr }).to_string()
}

fn empty_json(since: u64) -> String {
    serde_json::json!({ "since": since, "nodes": [] }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_and_sorts_by_total() {
        let nd = NodeDist::new();
        nd.add("HK01", 10, 90);
        nd.add("JP02", 5, 5);
        nd.add("HK01", 0, 100);
        nd.rebuild();
        let v: serde_json::Value = serde_json::from_str(&nd.snapshot_json()).unwrap();
        let nodes = v["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["node"], "HK01");
        assert_eq!(nodes[0]["up"], 10);
        assert_eq!(nodes[0]["down"], 190);
        assert_eq!(nodes[0]["total"], 200);
        assert_eq!(nodes[1]["node"], "JP02");
    }

    #[test]
    fn ignores_empty_node_and_zero_delta() {
        let nd = NodeDist::new();
        nd.add("", 10, 10);
        nd.add("X", 0, 0);
        assert!(nd.is_empty());
    }

    #[test]
    fn snapshot_and_clear() {
        let nd = NodeDist::new();
        nd.add("HK01", 1, 2);
        let snap = nd.snapshot();
        assert_eq!(snap, vec![("HK01".to_string(), 1, 2)]);
        nd.clear();
        assert!(nd.is_empty());
        let v: serde_json::Value = serde_json::from_str(&nd.snapshot_json()).unwrap();
        assert!(v["nodes"].as_array().unwrap().is_empty());
    }
}
