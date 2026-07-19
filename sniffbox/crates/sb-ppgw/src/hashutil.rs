// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use sha2::{Digest, Sha256};
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

#[derive(Debug, thiserror::Error)]
pub enum HashErr {
    #[error("read {0}: {1}")]
    Read(String, String),
    #[error("yaml parse: {0}")]
    Parse(String),
    #[error("proxy {0} not found")]
    NotFound(String),
    #[error("emit: {0}")]
    Emit(String),
    #[error("not a yaml map")]
    NotMap,
}

pub fn node_hash(file: &str, name: &str) -> Result<String, HashErr> {
    node_hash_str(&read(file)?, name)
}
pub fn rule_hash(file: &str) -> Result<String, HashErr> {
    rule_hash_str(&read(file)?)
}
pub fn yaml_hash(file: &str) -> Result<String, HashErr> {
    yaml_hash_str(&read(file)?)
}

pub fn node_hash_str(content: &str, name: &str) -> Result<String, HashErr> {
    let doc = load(content)?;
    let proxies = doc["proxies"]
        .as_vec()
        .ok_or_else(|| HashErr::NotFound(name.to_string()))?;
    for p in proxies {
        if p["name"].as_str() == Some(name) {
            return Ok(sha256_hex(emit(p)?.as_bytes()));
        }
    }
    Err(HashErr::NotFound(name.to_string()))
}

pub fn rule_hash_str(content: &str) -> Result<String, HashErr> {
    let doc = load(content)?;

    let rules = match &doc["rules"] {
        Yaml::BadValue => Yaml::Null,
        other => other.clone(),
    };
    Ok(sha256_hex(emit(&rules)?.as_bytes()))
}

pub fn yaml_hash_str(content: &str) -> Result<String, HashErr> {
    let doc = load(content)?;
    let map = doc.as_hash().ok_or(HashErr::NotMap)?;
    let mut entries: Vec<(String, &Yaml)> = map.iter().map(|(k, v)| (key_str(k), v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut concat = String::new();
    for (k, v) in entries {
        concat.push_str(&k);
        concat.push_str(&emit(v)?);
    }
    Ok(sha256_hex(concat.as_bytes()))
}

fn read(file: &str) -> Result<String, HashErr> {
    std::fs::read_to_string(file).map_err(|e| HashErr::Read(file.to_string(), e.to_string()))
}

fn load(content: &str) -> Result<Yaml, HashErr> {
    let mut docs = YamlLoader::load_from_str(content).map_err(|e| HashErr::Parse(e.to_string()))?;
    if docs.is_empty() {
        return Err(HashErr::Parse("empty document".to_string()));
    }
    Ok(docs.remove(0))
}

fn emit(y: &Yaml) -> Result<String, HashErr> {
    let mut buf = String::new();
    YamlEmitter::new(&mut buf)
        .dump(y)
        .map_err(|e| HashErr::Emit(format!("{e:?}")))?;
    Ok(buf)
}

fn key_str(k: &Yaml) -> String {
    k.as_str()
        .map(String::from)
        .unwrap_or_else(|| format!("{k:?}"))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
proxies:
  - name: NodeA
    type: ss
    server: 1.2.3.4
  - name: NodeB
    type: vmess
    server: 5.6.7.8
rules:
  - "DOMAIN,a.com,Proxy"
  - "MATCH,DIRECT"
mode: rule
"#;

    #[test]
    fn node_hash_stable_and_distinct() {
        let a1 = node_hash_str(YAML, "NodeA").unwrap();
        let a2 = node_hash_str(YAML, "NodeA").unwrap();
        let b = node_hash_str(YAML, "NodeB").unwrap();
        assert_eq!(a1, a2, "same input must be consistent");
        assert_ne!(a1, b, "different nodes have different hashes");
        assert_eq!(a1.len(), 64, "sha256 hex");
        assert!(matches!(
            node_hash_str(YAML, "Missing"),
            Err(HashErr::NotFound(_))
        ));
    }

    #[test]
    fn rule_hash_changes_with_content() {
        let h1 = rule_hash_str(YAML).unwrap();
        let h2 = rule_hash_str(&YAML.replace("a.com", "b.com")).unwrap();
        assert_ne!(h1, h2);
        assert_eq!(rule_hash_str(YAML).unwrap(), h1);
    }

    #[test]
    fn yaml_hash_stable_and_reorder_invariant_at_top_level() {
        let h1 = yaml_hash_str(YAML).unwrap();

        let reordered = "mode: rule\nproxies:\n  - name: NodeA\n    type: ss\n    server: 1.2.3.4\n  - name: NodeB\n    type: vmess\n    server: 5.6.7.8\nrules:\n  - \"DOMAIN,a.com,Proxy\"\n  - \"MATCH,DIRECT\"\n";
        let h2 = yaml_hash_str(reordered).unwrap();
        assert_eq!(h1, h2, "top-level reordering should not change hash");

        let h3 = yaml_hash_str(&YAML.replace("rule", "global")).unwrap();
        assert_ne!(h1, h3);
    }
}
