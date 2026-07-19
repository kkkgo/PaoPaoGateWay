// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::dnsutil;
use std::collections::HashSet;
use std::net::IpAddr;
use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

#[derive(Debug, thiserror::Error)]
pub enum YamlTxErr {
    #[error("read {0}: {1}")]
    Read(String, String),
    #[error("parse {0}: {1}")]
    Parse(String, String),
    #[error("{0}: not a yaml map")]
    NotMap(String),
    #[error("No 'proxies' found in the YAML file")]
    NoProxies,
    #[error("emit: {0}")]
    Emit(String),
}

pub fn combine(files: &[String]) -> Result<String, YamlTxErr> {
    let mut result = Hash::new();
    for f in files {
        let doc = load(&read(f)?, f)?;
        let map = doc.as_hash().ok_or_else(|| YamlTxErr::NotMap(f.clone()))?;
        for (k, v) in map {
            result.insert(k.clone(), v.clone());
        }
    }
    emit(&Yaml::Hash(result))
}

pub fn dns_burn(
    input_file: &str,
    dnslist: &str,
    ipv6_enabled: bool,
) -> Result<(String, usize), YamlTxErr> {
    let doc = load(&read(input_file)?, input_file)?;
    let mut config = doc
        .as_hash()
        .ok_or_else(|| YamlTxErr::NotMap(input_file.to_string()))?
        .clone();
    let proxies = doc["proxies"].as_vec().ok_or(YamlTxErr::NoProxies)?.clone();

    let dns_servers: Vec<String> = dnslist
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut domains: Vec<String> = Vec::new();
    let mut domain_seen: HashSet<String> = HashSet::new();
    for p in &proxies {
        if let Some(server) = p["server"].as_str() {
            if server.parse::<IpAddr>().is_err() && domain_seen.insert(server.to_string()) {
                domains.push(server.to_string());
            }
        }
    }

    let ex_resolved = dnsutil::resolve_domains_concurrent(&domains, &dns_servers, ipv6_enabled);

    let sub_specs = crate::dohdot::extract_dns_servers(&doc["dns"]);
    let sub_resolved = if !sub_specs.is_empty() {
        resolve_subdns_batch(&domains, &sub_specs, ipv6_enabled)
    } else {
        std::collections::HashMap::new()
    };

    let mut used: HashSet<String> = proxies
        .iter()
        .filter_map(|p| p["name"].as_str().map(String::from))
        .collect();

    let mut ex_nodes: Vec<Yaml> = Vec::new();
    let mut subdns_nodes: Vec<Yaml> = Vec::new();

    for p in &proxies {
        let Some(server) = p["server"].as_str() else {
            continue;
        };
        if server.parse::<IpAddr>().is_ok() {
            continue;
        }
        let Some(ph) = p.as_hash() else {
            continue;
        };
        let base = p["name"].as_str().unwrap_or("").to_string();

        for ip in ex_resolved.get(server).cloned().unwrap_or_default() {
            let ipstr = ip.to_string();
            let uniq = generate_node_name(&base, &ipstr, &used);
            used.insert(uniq.clone());
            let mut np = ph.clone();
            np.insert(Yaml::String("name".to_string()), Yaml::String(uniq));
            np.insert(Yaml::String("server".to_string()), Yaml::String(ipstr));
            ex_nodes.push(Yaml::Hash(np));
        }

        for ip in sub_resolved.get(server).cloned().unwrap_or_default() {
            let ipstr = ip.to_string();
            let uniq = generate_subdns_node_name(&base, &ipstr, &used);
            used.insert(uniq.clone());
            let mut np = ph.clone();
            np.insert(Yaml::String("name".to_string()), Yaml::String(uniq));
            np.insert(Yaml::String("server".to_string()), Yaml::String(ipstr));
            subdns_nodes.push(Yaml::Hash(np));
        }
    }

    let added = ex_nodes.len() + subdns_nodes.len();
    let mut all = subdns_nodes;
    all.extend(proxies);
    all.extend(ex_nodes);
    config.insert(Yaml::String("proxies".to_string()), Yaml::Array(all));
    Ok((emit(&Yaml::Hash(config))?, added))
}

fn resolve_subdns_batch(
    domains: &[String],
    specs: &[String],
    ipv6_enabled: bool,
) -> std::collections::HashMap<String, Vec<IpAddr>> {
    use std::sync::Mutex;
    let out: Mutex<std::collections::HashMap<String, Vec<IpAddr>>> =
        Mutex::new(std::collections::HashMap::new());
    let out_ref = &out;
    for chunk in domains.chunks(16) {
        std::thread::scope(|s| {
            for domain in chunk {
                let domain = domain.clone();
                let specs: Vec<String> = specs.to_vec();
                s.spawn(move || {
                    let ips = crate::dohdot::resolve_via_servers(&domain, &specs, ipv6_enabled);
                    if !ips.is_empty() {
                        out_ref.lock().unwrap().insert(domain, ips);
                    }
                });
            }
        });
    }
    out.into_inner().unwrap()
}

pub(crate) fn generate_node_name(base: &str, ip: &str, used: &HashSet<String>) -> String {
    generate_node_name_with_prefix(base, ip, used, "")
}

fn generate_subdns_node_name(base: &str, ip: &str, used: &HashSet<String>) -> String {
    generate_node_name_with_prefix(base, ip, used, "subdns")
}

fn generate_node_name_with_prefix(
    base: &str,
    ip: &str,
    used: &HashSet<String>,
    prefix: &str,
) -> String {
    let suffix = if ip.contains(':') {
        let clean: String = ip.chars().filter(|c| *c != ':').collect();
        if clean.len() > 4 {
            clean[clean.len() - 4..].to_string()
        } else {
            clean
        }
    } else {
        ip.rsplit('.').next().unwrap_or(ip).to_string()
    };
    let candidate = if prefix.is_empty() {
        format!("{base}@{suffix}")
    } else {
        format!("{base}@{prefix}{suffix}")
    };
    if !used.contains(&candidate) {
        return candidate;
    }
    let mut counter = 0i64;
    loop {
        let cand = format!("{candidate}{}", generate_suffix(counter));
        if !used.contains(&cand) {
            return cand;
        }
        counter += 1;
    }
}

pub(crate) fn generate_suffix(mut n: i64) -> String {
    let mut s = String::new();
    loop {
        let rem = (n % 26) as u8;
        s.insert(0, (b'A' + rem) as char);
        n = n / 26 - 1;
        if n < 0 {
            break;
        }
    }
    s
}

fn read(file: &str) -> Result<String, YamlTxErr> {
    std::fs::read_to_string(file).map_err(|e| YamlTxErr::Read(file.to_string(), e.to_string()))
}

fn load(content: &str, file: &str) -> Result<Yaml, YamlTxErr> {
    let mut docs = YamlLoader::load_from_str(content)
        .map_err(|e| YamlTxErr::Parse(file.to_string(), e.to_string()))?;
    if docs.is_empty() {
        return Err(YamlTxErr::Parse(
            file.to_string(),
            "empty document".to_string(),
        ));
    }
    Ok(docs.remove(0))
}

fn emit(y: &Yaml) -> Result<String, YamlTxErr> {
    let mut buf = String::new();
    YamlEmitter::new(&mut buf)
        .dump(y)
        .map_err(|e| YamlTxErr::Emit(format!("{e:?}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_is_bijective_base26() {
        assert_eq!(generate_suffix(0), "A");
        assert_eq!(generate_suffix(25), "Z");
        assert_eq!(generate_suffix(26), "AA");
        assert_eq!(generate_suffix(27), "AB");
        assert_eq!(generate_suffix(51), "AZ");
        assert_eq!(generate_suffix(52), "BA");
    }

    #[test]
    fn node_name_octet_and_collision() {
        let mut used = HashSet::new();
        let n1 = generate_node_name("Tokyo", "1.2.3.4", &used);
        assert_eq!(n1, "Tokyo@4");
        used.insert(n1);

        let n2 = generate_node_name("Tokyo", "9.9.9.4", &used);
        assert_eq!(n2, "Tokyo@4A");
        used.insert(n2);
        let n3 = generate_node_name("Tokyo", "8.8.8.4", &used);
        assert_eq!(n3, "Tokyo@4B");
    }

    #[test]
    fn node_name_ipv6_last4_hex() {
        let used = HashSet::new();
        let n = generate_node_name("HK", "2001:db8::beef", &used);
        assert_eq!(n, "HK@beef");
    }

    #[test]
    fn combine_merges_top_level_last_wins() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.yaml");
        let b = dir.path().join("b.yaml");
        std::fs::write(&a, "proxies:\n  - {name: x}\nmode: rule\n").unwrap();
        std::fs::write(&b, "mode: global\ntproxy-port: 1081\n").unwrap();
        let out = combine(&[
            a.to_str().unwrap().to_string(),
            b.to_str().unwrap().to_string(),
        ])
        .unwrap();
        let doc = &YamlLoader::load_from_str(&out).unwrap()[0];
        assert_eq!(doc["mode"].as_str(), Some("global"), "latter overrides mode");
        assert_eq!(doc["tproxy-port"].as_i64(), Some(1081), "keep keys from b");
        assert!(doc["proxies"].as_vec().is_some(), "keep proxies from a");
    }
}
