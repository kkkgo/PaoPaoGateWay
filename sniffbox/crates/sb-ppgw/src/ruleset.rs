// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

pub const RULESET_DIR: &str = "/tmp/rule-set";

pub fn ruleset_dir() -> String {
    std::env::var("ppgw_ruleset_dir")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| RULESET_DIR.to_string())
}

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

const RULE_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "GEOSITE",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-GEOIP",
    "SRC-IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "SRC-PORT",
    "DST-PORT",
    "NETWORK",
    "RULE-SET",
    "SUB-RULE",
    "AND",
    "OR",
    "NOT",
    "MATCH",
];

pub fn default_path(url: &str, format: &str) -> String {
    format!("{}/{}.{}", ruleset_dir(), hash16(url), ext_for(format, url))
}

fn hash16(url: &str) -> String {
    let mut h = Sha256::new();
    h.update(url.as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

fn ext_for(format: &str, url: &str) -> &'static str {
    match format {
        "yaml" | "yml" => "yaml",
        "mrs" => "mrs",
        "text" => "txt",
        _ => url_ext(url).unwrap_or("txt"),
    }
}

fn url_ext(url: &str) -> Option<&'static str> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let last = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if last.ends_with(".yaml") || last.ends_with(".yml") {
        Some("yaml")
    } else if last.ends_with(".mrs") {
        Some("mrs")
    } else {
        None
    }
}

pub fn detect_format(url: &str, bytes: &[u8]) -> Option<&'static str> {
    if let Some(ext) = url_ext(url) {
        return Some(ext);
    }
    if bytes.starts_with(&ZSTD_MAGIC) {
        return Some("mrs");
    }
    let text = String::from_utf8_lossy(bytes);
    if has_yaml_feature(&text) {
        return Some("yaml");
    }
    if looks_like_text_ruleset(&text) {
        return Some("text");
    }
    None
}

fn has_yaml_feature(text: &str) -> bool {
    text.lines().any(|line| {
        let l = line.trim();
        l.starts_with("payload:") || l.starts_with("rules:")
    })
}

fn looks_like_text_ruleset(text: &str) -> bool {
    let mut rule_lines = 0usize;
    let mut hits = 0usize;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        rule_lines += 1;
        let head = l
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        if RULE_TYPES.contains(&head.as_str()) {
            hits += 1;
        }
    }
    rule_lines > 0 && hits >= 1 && hits * 100 >= rule_lines * 95
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub name: String,
    pub url: String,
    pub path: String,
    pub interval: i64,

    pub has_format: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PrefetchReport {
    pub downloaded: usize,
    pub cached: usize,
    pub failed: usize,
    pub removed: usize,
    pub backfilled: usize,
}

pub fn parse_providers(content: &str) -> Vec<Provider> {
    let Ok(mut docs) = YamlLoader::load_from_str(content) else {
        return Vec::new();
    };
    if docs.is_empty() {
        return Vec::new();
    }
    let doc = docs.remove(0);
    let Some(providers) = doc["rule-providers"].as_hash() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, p) in providers {
        let (Some(name), Some(typ)) = (name.as_str(), p["type"].as_str()) else {
            continue;
        };
        if typ != "http" {
            continue;
        }
        let (Some(url), Some(path)) = (p["url"].as_str(), p["path"].as_str()) else {
            continue;
        };
        out.push(Provider {
            name: name.to_string(),
            url: url.to_string(),
            path: path.to_string(),
            interval: p["interval"].as_i64().unwrap_or(0),
            has_format: p["format"].as_str().is_some_and(|s| !s.is_empty()),
        });
    }
    out
}

pub fn cleanup_dir(dir: &str, keep: &HashSet<String>) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for e in entries.flatten() {
        if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !keep.contains(name.as_ref()) && std::fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn is_fresh(path: &Path, interval: i64) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if interval <= 0 {
        return true;
    }
    meta.modified()
        .ok()
        .and_then(|m| m.elapsed().ok())
        .map(|age| age.as_secs() < interval as u64)
        .unwrap_or(false)
}

pub fn backfill_formats(content: &str, formats: &HashMap<String, String>) -> Option<String> {
    if formats.is_empty() {
        return None;
    }
    let mut docs = YamlLoader::load_from_str(content).ok()?;
    if docs.is_empty() {
        return None;
    }
    let Yaml::Hash(ref mut root) = docs[0] else {
        return None;
    };
    let providers = match root.get_mut(&ystr("rule-providers")) {
        Some(Yaml::Hash(h)) => h,
        _ => return None,
    };
    let mut changed = false;
    for (name, fmt) in formats {
        if let Some(Yaml::Hash(p)) = providers.get_mut(&ystr(name)) {
            p.insert(ystr("format"), ystr(fmt));
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    let mut buf = String::new();
    YamlEmitter::new(&mut buf).dump(&docs[0]).ok()?;
    Some(buf)
}

fn ystr(s: &str) -> Yaml {
    Yaml::String(s.to_string())
}

pub fn prefetch_with<F>(clash_yaml: &str, dir: &str, fetch: F) -> PrefetchReport
where
    F: Fn(&str, &str) -> Result<Vec<u8>, String>,
{
    let mut report = PrefetchReport::default();
    let content = match std::fs::read_to_string(clash_yaml) {
        Ok(c) => c,
        Err(_) => return report,
    };
    let providers = parse_providers(&content);
    let _ = std::fs::create_dir_all(dir);

    let keep: HashSet<String> = providers
        .iter()
        .filter_map(|p| {
            Path::new(&p.path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .collect();
    report.removed = cleanup_dir(dir, &keep);

    let mut backfills: HashMap<String, String> = HashMap::new();
    for p in &providers {
        let path = Path::new(&p.path);
        if is_fresh(path, p.interval) {
            report.cached += 1;
            continue;
        }
        let tmp = format!("{}.tmp", p.path);
        match fetch(&p.url, &tmp) {
            Ok(bytes) => {
                if let Some(fmt) = detect_format(&p.url, &bytes) {
                    if !p.has_format {
                        backfills.insert(p.name.clone(), fmt.to_string());
                    }
                }
                if std::fs::rename(&tmp, &p.path).is_ok() {
                    report.downloaded += 1;
                } else {
                    let _ = std::fs::remove_file(&tmp);
                    report.failed += 1;
                }
            }
            Err(_) => {
                let _ = std::fs::remove_file(&tmp);
                report.failed += 1;
            }
        }
    }

    if let Some(new_content) = backfill_formats(&content, &backfills)
        && std::fs::write(clash_yaml, new_content).is_ok()
    {
        report.backfilled = backfills.len();
    }
    report
}

pub fn prefetch(clash_yaml: &str, dir: &str) -> PrefetchReport {
    prefetch_with(clash_yaml, dir, |url, tmp| {
        crate::download::Downloader::new(url, tmp)
            .download()
            .map_err(|e| e.to_string())?;
        std::fs::read(tmp).map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_by_format_then_suffix() {
        let a = default_path("http://x/list.yaml", "");
        assert!(
            a.starts_with("/tmp/rule-set/") && a.ends_with(".yaml"),
            "{a}"
        );

        assert!(default_path("http://x/list", "mrs").ends_with(".mrs"));
        assert!(default_path("http://x/list", "text").ends_with(".txt"));

        assert!(default_path("http://x/l.mrs?v=1", "").ends_with(".mrs"));

        assert!(default_path("http://x/blob", "").ends_with(".txt"));

        assert_eq!(
            default_path("http://x/a.yaml", ""),
            default_path("http://x/a.yaml", "")
        );
        assert_ne!(
            default_path("http://x/a.yaml", ""),
            default_path("http://x/b.yaml", "")
        );
    }

    #[test]
    fn detect_by_suffix() {
        assert_eq!(detect_format("http://x/a.yaml", b"garbage"), Some("yaml"));
        assert_eq!(detect_format("http://x/a.yml?t=1", b""), Some("yaml"));
        assert_eq!(detect_format("http://x/a.mrs", b"garbage"), Some("mrs"));
    }

    #[test]
    fn detect_zstd_mrs() {
        let mut blob = ZSTD_MAGIC.to_vec();
        blob.extend_from_slice(b"\x00\x01\x02compressed");
        assert_eq!(detect_format("http://x/noext", &blob), Some("mrs"));
    }

    #[test]
    fn detect_yaml_feature() {
        assert_eq!(
            detect_format("http://x/noext", b"payload:\n  - '+.a.com'\n"),
            Some("yaml")
        );
        assert_eq!(
            detect_format("http://x/noext", b"# c\nrules:\n  - DOMAIN,a.com,DIRECT\n"),
            Some("yaml")
        );
    }

    #[test]
    fn detect_text_ruleset() {
        let txt = "# comment\n// c2\nDOMAIN-SUFFIX,google.com\nIP-CIDR,1.2.3.0/24\nDOMAIN,a.com\n";
        assert_eq!(
            detect_format("http://x/noext", txt.as_bytes()),
            Some("text")
        );
    }

    #[test]
    fn detect_text_tolerates_one_bad_line() {

        let mut s = String::new();
        for i in 0..20 {
            s.push_str(&format!("DOMAIN-SUFFIX,d{i}.com\n"));
        }
        s.push_str("this-is-not-a-rule\n");
        assert_eq!(detect_format("http://x/noext", s.as_bytes()), Some("text"));
    }

    #[test]
    fn detect_none_for_domain_list_and_junk() {

        assert_eq!(
            detect_format("http://x/noext", b"+.google.com\n+.youtube.com\n"),
            None
        );
        assert_eq!(
            detect_format("http://x/noext", b"random binary \x00\x01 text no rules"),
            None
        );
        assert_eq!(detect_format("http://x/noext", b""), None);
    }

    #[test]
    fn parse_providers_filters_http_with_path() {
        let yaml = r#"
rule-providers:
  ad:
    type: http
    url: http://u/ad.yaml
    path: /tmp/rule-set/aa.yaml
    interval: 3600
    format: yaml
  local:
    type: file
    path: /x
  nourl:
    type: http
    path: /y
  ok2:
    type: http
    url: http://u/b
    path: /tmp/rule-set/bb.txt
"#;
        let ps = parse_providers(yaml);
        assert_eq!(ps.len(), 2);
        let ad = ps.iter().find(|p| p.name == "ad").unwrap();
        assert_eq!(ad.url, "http://u/ad.yaml");
        assert_eq!(ad.interval, 3600);
        assert!(ad.has_format);
        let ok2 = ps.iter().find(|p| p.name == "ok2").unwrap();
        assert!(!ok2.has_format);
        assert_eq!(ok2.interval, 0);
    }

    #[test]
    fn backfill_only_named_providers() {
        let yaml = "rule-providers:\n  a:\n    type: http\n    url: http://u/a\n    path: /p/a\n  b:\n    type: http\n    url: http://u/b\n    path: /p/b\n    format: mrs\n";
        let mut fmts = HashMap::new();
        fmts.insert("a".to_string(), "text".to_string());
        let out = backfill_formats(yaml, &fmts).unwrap();
        let doc = &YamlLoader::load_from_str(&out).unwrap()[0];
        assert_eq!(doc["rule-providers"]["a"]["format"].as_str(), Some("text"));

        assert_eq!(doc["rule-providers"]["b"]["format"].as_str(), Some("mrs"));

        assert!(backfill_formats(yaml, &HashMap::new()).is_none());
    }

    #[test]
    fn cleanup_removes_stale_only() {
        let dir = std::env::temp_dir().join(format!("ppgw_rs_clean_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("keep.yaml"), b"x").unwrap();
        std::fs::write(dir.join("stale.txt"), b"x").unwrap();
        std::fs::write(dir.join("crash.tmp"), b"x").unwrap();
        let mut keep = HashSet::new();
        keep.insert("keep.yaml".to_string());
        let removed = cleanup_dir(dir.to_str().unwrap(), &keep);
        assert_eq!(removed, 2);
        assert!(dir.join("keep.yaml").exists());
        assert!(!dir.join("stale.txt").exists());
        assert!(!dir.join("crash.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prefetch_downloads_cleans_and_backfills() {
        let dir = std::env::temp_dir().join(format!("ppgw_rs_pf_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let ad_path = dir.join("ad.yaml");
        let txt_path = dir.join("list");

        std::fs::write(dir.join("orphan.txt"), b"old").unwrap();

        let clash =
            std::env::temp_dir().join(format!("ppgw_rs_pf_clash_{}.yaml", std::process::id()));
        let yaml = format!(
            "rule-providers:\n  ad:\n    type: http\n    url: http://u/ad.yaml\n    path: {ad}\n    interval: 3600\n  raw:\n    type: http\n    url: http://u/list\n    path: {txt}\n    interval: 3600\n",
            ad = ad_path.display(),
            txt = txt_path.display(),
        );
        std::fs::write(&clash, &yaml).unwrap();

        let rep = prefetch_with(
            clash.to_str().unwrap(),
            dir.to_str().unwrap(),
            |url, tmp| {
                let body: &[u8] = if url.ends_with("ad.yaml") {
                    b"payload:\n  - '+.a.com'\n"
                } else {
                    b"DOMAIN-SUFFIX,x.com\nIP-CIDR,1.1.1.0/24\n"
                };
                std::fs::write(tmp, body).unwrap();
                Ok(body.to_vec())
            },
        );

        assert_eq!(rep.downloaded, 2);
        assert_eq!(rep.removed, 1, "orphan cleaned");

        assert_eq!(rep.backfilled, 2);
        assert!(ad_path.exists() && txt_path.exists());

        let out = std::fs::read_to_string(&clash).unwrap();
        let doc = &YamlLoader::load_from_str(&out).unwrap()[0];
        assert_eq!(doc["rule-providers"]["ad"]["format"].as_str(), Some("yaml"));
        assert_eq!(
            doc["rule-providers"]["raw"]["format"].as_str(),
            Some("text")
        );

        let rep2 = prefetch_with(clash.to_str().unwrap(), dir.to_str().unwrap(), |_, _| {
            panic!("should not download fresh files")
        });
        assert_eq!(rep2.cached, 2);
        assert_eq!(rep2.downloaded, 0);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&clash);
    }

    #[test]
    fn prefetch_failure_is_graceful() {
        let dir = std::env::temp_dir().join(format!("ppgw_rs_fail_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let clash = dir.join("clash.yaml");
        let p = dir.join("a.yaml");
        std::fs::write(
            &clash,
            format!(
                "rule-providers:\n  a:\n    type: http\n    url: http://u/a\n    path: {}\n",
                p.display()
            ),
        )
        .unwrap();
        let rep = prefetch_with(clash.to_str().unwrap(), dir.to_str().unwrap(), |_, _| {
            Err("net down".to_string())
        });
        assert_eq!(rep.failed, 1);
        assert_eq!(rep.downloaded, 0);
        assert!(!p.exists(), "failure leaves no half-done artifacts");
        assert!(!dir.join("a.yaml.tmp").exists(), "tmp cleaned");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
