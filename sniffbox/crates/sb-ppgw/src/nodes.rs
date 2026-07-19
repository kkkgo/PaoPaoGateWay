// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::clash::{ClashClient, ClashNode};
use std::sync::Mutex;
use std::time::Duration;

const SYSTEM_NODES: [&str; 8] = [
    "REJECT",
    "DIRECT",
    "GLOBAL",
    "UNKNOWN",
    "COMPATIBLE",
    "PASS",
    "REJECT-DROP",
    "SMARTSPEEDTEST@HIDE",
];

#[derive(Debug, thiserror::Error)]
pub enum FastErr {
    #[error("all nodes failed")]
    AllFailed,
    #[error("clash api: {0}")]
    Api(String),
}

pub fn is_system_node(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    SYSTEM_NODES.contains(&up.as_str())
}

pub fn parse_excluded(ext: &str) -> Vec<String> {
    if ext.is_empty() {
        return Vec::new();
    }
    ext.split('|').map(|s| s.to_string()).collect()
}

fn contains_excluded(name: &str, excluded: &[String]) -> bool {
    excluded
        .iter()
        .any(|k| !k.is_empty() && name.contains(k.as_str()))
}

pub fn filter_nodes(nodes: Vec<ClashNode>, excluded: &[String]) -> Vec<ClashNode> {
    nodes
        .into_iter()
        .filter(|n| !contains_excluded(&n.name, excluded) && !is_system_node(&n.name))
        .collect()
}

pub fn run_fast_node_once(
    client: &ClashClient,
    test_url: &str,
    ext_node: &str,
    timeout: &str,
    cpudelay: i64,
) -> Result<String, FastErr> {
    let (nodes, _now) = client
        .get_nodes()
        .map_err(|e| FastErr::Api(e.to_string()))?;
    let excluded = parse_excluded(ext_node);
    let nodes = filter_nodes(nodes, &excluded);
    if nodes.is_empty() {
        return Err(FastErr::AllFailed);
    }

    let results: Mutex<Vec<(String, u32)>> = Mutex::new(Vec::new());
    let results_ref = &results;

    for chunk in nodes.chunks(16) {
        std::thread::scope(|s| {
            for node in chunk {
                s.spawn(move || {
                    if let Ok(d) = client.ping_node(&node.name, test_url, timeout, cpudelay) {
                        results_ref.lock().unwrap().push((node.name.clone(), d));
                    }
                });
            }
        });
    }

    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(_, d)| *d);
    match results.first() {
        Some((name, _)) => {
            client
                .select_node(name)
                .map_err(|e| FastErr::Api(e.to_string()))?;
            Ok(name.clone())
        }
        None => Err(FastErr::AllFailed),
    }
}

pub fn run_fast_node(
    client: &ClashClient,
    test_url: &str,
    ext_node: &str,
    timeout: &str,
    cpudelay: i64,
) -> Result<String, FastErr> {
    let test_url = if test_url.is_empty() {
        "http://cp.cloudflare.com/generate_204"
    } else {
        test_url
    };
    let ext_node = if ext_node.is_empty() {
        "Traffic|Expire| GB|Days|Date"
    } else {
        ext_node
    };
    let mut last = FastErr::AllFailed;
    for attempt in 0..5u64 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(3 * attempt));
        }
        match run_fast_node_once(client, test_url, ext_node, timeout, cpudelay) {
            Ok(name) => return Ok(name),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(name: &str) -> ClashNode {
        ClashNode {
            name: name.to_string(),
            typ: "Shadowsocks".to_string(),
        }
    }

    #[test]
    fn system_node_detection() {
        assert!(is_system_node("DIRECT"));
        assert!(is_system_node("direct"));
        assert!(is_system_node("GLOBAL"));
        assert!(is_system_node("REJECT-DROP"));
        assert!(!is_system_node("NodeA"));
        assert!(!is_system_node("🇯🇵 Tokyo"));
    }

    #[test]
    fn excluded_parsing_and_match() {
        assert!(parse_excluded("").is_empty());
        let ex = parse_excluded("Traffic|Expire| GB");
        assert_eq!(ex, vec!["Traffic", "Expire", " GB"]);
        assert!(contains_excluded("Sub_Traffic 100G", &ex));
        assert!(contains_excluded("Node 5 GB", &ex));
        assert!(!contains_excluded("Tokyo 01", &ex));

        assert!(
            !contains_excluded("xyz", &parse_excluded("a||b")),
            "empty keyword should not falsely kill"
        );
    }

    #[test]
    fn filter_drops_system_and_excluded() {
        let nodes = vec![n("NodeA"), n("GLOBAL"), n("Sub_Expire"), n("Tokyo")];
        let ex = parse_excluded("Expire");
        let out = filter_nodes(nodes, &ex);
        let names: Vec<_> = out.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["NodeA", "Tokyo"]);
    }
}
