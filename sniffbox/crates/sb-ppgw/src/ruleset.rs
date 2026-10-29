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

pub fn guess_format(url: &str) -> &'static str {
    url_ext(url).unwrap_or("text")
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

    pub format: String,
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
            format: p["format"].as_str().unwrap_or("").to_string(),
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

fn note_format(
    backfills: &mut HashMap<String, String>,
    p: &Provider,
    auto: &HashSet<String>,
    bytes: &[u8],
) {
    if !p.format.is_empty() && !auto.contains(&p.name) {
        return;
    }
    if let Some(fmt) = detect_format(&p.url, bytes)
        && fmt != p.format
    {
        backfills.insert(p.name.clone(), fmt.to_string());
    }
}

pub fn prefetch_with<F>(
    clash_yaml: &str,
    dir: &str,
    auto: &HashSet<String>,
    fetch: F,
) -> PrefetchReport
where
    F: Fn(&str, &str) -> Result<Vec<u8>, String> + Sync,
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

    let mut paths = HashMap::new();
    let mut groups: Vec<Vec<&Provider>> = Vec::new();
    for p in &providers {
        let index = *paths.entry(&p.path).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[index].push(p);
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..PREFETCH_CONCURRENCY.min(groups.len()))
            .map(|_| {
                scope.spawn(|| {
                    let mut local = PrefetchReport::default();
                    let mut backfills = HashMap::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(group) = groups.get(i) else {
                            break;
                        };
                        for p in group {
                            let path = Path::new(&p.path);
                            if is_fresh(path, p.interval) {
                                local.cached += 1;
                                if let Ok(bytes) = std::fs::read(path) {
                                    note_format(&mut backfills, p, auto, &bytes);
                                }
                                continue;
                            }
                            let tmp = format!("{}.tmp", p.path);
                            match fetch(&p.url, &tmp) {
                                Ok(bytes) if std::fs::rename(&tmp, &p.path).is_ok() => {
                                    note_format(&mut backfills, p, auto, &bytes);
                                    local.downloaded += 1;
                                }
                                _ => {
                                    let _ = std::fs::remove_file(&tmp);
                                    local.failed += 1;
                                }
                            }
                        }
                    }
                    (local, backfills)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("prefetch worker panicked"))
            .collect::<Vec<_>>()
    });
    let mut backfills = HashMap::new();
    for (local, formats) in results {
        report.cached += local.cached;
        report.downloaded += local.downloaded;
        report.failed += local.failed;
        backfills.extend(formats);
    }

    if let Some(new_content) = backfill_formats(&content, &backfills)
        && std::fs::write(clash_yaml, new_content).is_ok()
    {
        report.backfilled = backfills.len();
    }
    report
}

const PREFETCH_CONCURRENCY: usize = 4;

pub const PREFETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub fn prefetch(clash_yaml: &str, dir: &str, auto: &HashSet<String>) -> PrefetchReport {
    prefetch_with(clash_yaml, dir, auto, |url, tmp| {
        crate::download::Downloader::new(url, tmp)
            .best_effort(PREFETCH_TIMEOUT)
            .download()
            .map_err(|e| e.to_string())?;
        std::fs::read(tmp).map_err(|e| e.to_string())
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PredetectReport {

    pub detected: usize,

    pub unknown: usize,
    pub backfilled: usize,
}

pub fn predetect_with<F>(clash_yaml: &str, auto: &HashSet<String>, fetch: F) -> PredetectReport
where
    F: Fn(&str, &str) -> Result<Vec<u8>, String> + Sync,
{
    let mut report = PredetectReport::default();
    let Ok(content) = std::fs::read_to_string(clash_yaml) else {
        return report;
    };
    let targets: Vec<Provider> = parse_providers(&content)
        .into_iter()
        .filter(|p| auto.contains(&p.name) && url_ext(&p.url).is_none())
        .collect();
    if targets.is_empty() {
        return report;
    }
    let fetch = &fetch;
    let found: Vec<Option<&'static str>> = std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|p| {
                s.spawn(move || {
                    if let Ok(bytes) = std::fs::read(&p.path)
                        && let Some(fmt) = detect_format(&p.url, &bytes)
                    {
                        return Some(fmt);
                    }
                    let tmp = std::env::temp_dir().join(format!(
                        "ppgw_rs_detect_{}_{}",
                        hash16(&p.url),
                        std::process::id()
                    ));
                    let tmp = tmp.to_string_lossy().into_owned();
                    let got = fetch(&p.url, &tmp);
                    let _ = std::fs::remove_file(&tmp);
                    got.ok().and_then(|b| detect_format(&p.url, &b))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().ok().flatten())
            .collect()
    });

    let mut backfills: HashMap<String, String> = HashMap::new();
    for (p, fmt) in targets.iter().zip(found) {
        match fmt {
            Some(fmt) => {
                report.detected += 1;
                if fmt != p.format {
                    backfills.insert(p.name.clone(), fmt.to_string());
                }
            }
            None => report.unknown += 1,
        }
    }
    if let Some(new_content) = backfill_formats(&content, &backfills)
        && std::fs::write(clash_yaml, new_content).is_ok()
    {
        report.backfilled = backfills.len();
    }
    report
}

pub fn predetect(clash_yaml: &str, auto: &HashSet<String>) -> PredetectReport {
    predetect_with(clash_yaml, auto, |url, tmp| {
        use crate::download::Downloader;
        let direct = Downloader::new(url, tmp)
            .best_effort(PREFETCH_TIMEOUT)
            .download();
        if direct.is_err() {
            Downloader::new(url, tmp)
                .timeout(PREFETCH_TIMEOUT)
                .via_proxy(crate::HEALTHCHECK_SOCKS5)
                .map_err(|e| e.to_string())?;
        }
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
        assert_eq!(ad.format, "yaml");
        let ok2 = ps.iter().find(|p| p.name == "ok2").unwrap();
        assert_eq!(ok2.format, "");
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
            &HashSet::new(),
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

        let rep2 = prefetch_with(
            clash.to_str().unwrap(),
            dir.to_str().unwrap(),
            &HashSet::new(),
            |_, _| panic!("should not download fresh files"),
        );
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
        let rep = prefetch_with(
            clash.to_str().unwrap(),
            dir.to_str().unwrap(),
            &HashSet::new(),
            |_, _| Err("net down".to_string()),
        );
        assert_eq!(rep.failed, 1);
        assert_eq!(rep.downloaded, 0);
        assert!(!p.exists(), "failure leaves no half-done artifacts");
        assert!(!dir.join("a.yaml.tmp").exists(), "tmp cleaned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prefetch_runs_four_downloads_concurrently_and_never_more() {
        use std::sync::{Condvar, Mutex};
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        let config = dir.path().join("clash.yaml");
        let mut yaml = "rule-providers:\n".to_string();
        for i in 0..9 {
            yaml.push_str(&format!(
                "  p{i}:\n    type: http\n    url: http://rules/{i}\n    path: {}\n",
                cache.join(format!("{i}.txt")).display()
            ));
        }
        std::fs::write(&config, yaml).unwrap();

        let gate = (Mutex::new(false), Condvar::new());
        let (entered, entries) = std::sync::mpsc::channel();
        let (report, first_wave, extra) = std::thread::scope(|scope| {
            let run = scope.spawn(|| {
                prefetch_with(
                    config.to_str().unwrap(),
                    cache.to_str().unwrap(),
                    &HashSet::new(),
                    |url, tmp| {
                        entered.send(()).unwrap();
                        let (lock, cv) = &gate;
                        let (release, timeout) = cv
                            .wait_timeout_while(
                                lock.lock().unwrap(),
                                Duration::from_secs(3),
                                |open| !*open,
                            )
                            .unwrap();
                        assert!(
                            !timeout.timed_out(),
                            "test coordinator must release fetches"
                        );
                        drop(release);
                        let body = if url.ends_with("/8") {
                            b"partial".as_slice()
                        } else {
                            b"DOMAIN,example.com\n"
                        };
                        std::fs::write(tmp, body).unwrap();
                        if url.ends_with("/8") {
                            Err("injected failure".into())
                        } else {
                            Ok(body.to_vec())
                        }
                    },
                )
            });
            let mut first_wave = 0;
            for _ in 0..4 {
                if entries.recv_timeout(Duration::from_secs(1)).is_err() {
                    break;
                }
                first_wave += 1;
            }
            let extra = entries.recv_timeout(Duration::from_millis(50)).is_ok();
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
            (run.join().unwrap(), first_wave, extra)
        });
        assert_eq!(first_wave, 4, "fetches must overlap");
        assert!(!extra, "at most four fetches may be active");
        assert_eq!(
            (report.downloaded, report.failed, report.backfilled),
            (8, 1, 8)
        );
        assert!(!cache.join("8.txt").exists());
        assert!(!cache.join("8.txt.tmp").exists());
        let formats = formats_of(&config);
        for i in 0..8 {
            assert_eq!(formats[&format!("p{i}")], "text");
        }
    }

    #[test]
    fn prefetch_shared_path_is_downloaded_once_and_backfills_both_providers() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        let config = dir.path().join("clash.yaml");
        let path = cache.join("shared.txt");
        let mut yaml = "rule-providers:\n".to_string();
        for name in ["a", "b"] {
            yaml.push_str(&format!("  {name}:\n    type: http\n    url: http://rules/same\n    path: {}\n    interval: 3600\n", path.display()));
        }
        std::fs::write(&config, yaml).unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let report = prefetch_with(
            config.to_str().unwrap(),
            cache.to_str().unwrap(),
            &HashSet::new(),
            |_, tmp| {
                calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let body = b"payload:\n  - example.com\n";
                std::fs::write(tmp, body).unwrap();
                Ok(body.to_vec())
            },
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            (report.downloaded, report.cached, report.backfilled),
            (1, 1, 2)
        );
        assert_eq!(formats_of(&config)["a"], "yaml");
        assert_eq!(formats_of(&config)["b"], "yaml");
    }

    #[test]
    fn guess_format_uses_suffix_then_text() {
        assert_eq!(guess_format("http://x/a.yaml"), "yaml");
        assert_eq!(guess_format("http://x/a.YML?v=2"), "yaml");
        assert_eq!(guess_format("http://x/a.mrs#f"), "mrs");
        assert_eq!(guess_format("http://x/a.list"), "text");
        assert_eq!(guess_format("http://x/raw"), "text");
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ppgw_rs_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn provider_yaml(entries: &[(&str, &str, &Path, &str)]) -> String {
        let mut s = String::from("rule-providers:\n");
        for (name, url, path, format) in entries {
            s.push_str(&format!(
                "  {name}:\n    type: http\n    url: {url}\n    path: {}\n",
                path.display()
            ));
            if !format.is_empty() {
                s.push_str(&format!("    format: {format}\n"));
            }
        }
        s
    }

    fn formats_of(clash: &Path) -> HashMap<String, String> {
        let out = std::fs::read_to_string(clash).unwrap();
        let doc = &YamlLoader::load_from_str(&out).unwrap()[0];
        doc["rule-providers"]
            .as_hash()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().unwrap().to_string(),
                    v["format"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn names(ns: &[&str]) -> HashSet<String> {
        ns.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn prefetch_corrects_guessed_format_but_keeps_explicit_one() {
        let dir = scratch("pf_guess");
        let clash = dir.with_extension("yaml");
        let (guessed, explicit, cached) = (dir.join("g.txt"), dir.join("e.txt"), dir.join("c.txt"));

        std::fs::write(&cached, b"payload:\n  - '+.c.com'\n").unwrap();
        std::fs::write(
            &clash,
            provider_yaml(&[
                ("guessed", "http://u/g", &guessed, "text"),
                ("explicit", "http://u/e", &explicit, "text"),
                ("cached", "http://u/c", &cached, "text"),
            ]),
        )
        .unwrap();

        let rep = prefetch_with(
            clash.to_str().unwrap(),
            dir.to_str().unwrap(),
            &names(&["guessed", "cached"]),
            |_, tmp| {
                let body = b"payload:\n  - '+.a.com'\n".to_vec();
                std::fs::write(tmp, &body).unwrap();
                Ok(body)
            },
        );
        assert_eq!(rep.downloaded, 2);
        assert_eq!(rep.cached, 1);
        assert_eq!(rep.backfilled, 2);
        let f = formats_of(&clash);
        assert_eq!(f["guessed"], "yaml");
        assert_eq!(f["cached"], "yaml");
        assert_eq!(f["explicit"], "text", "explicit format is never overridden");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&clash);
    }

    #[test]
    fn prefetch_keeps_correct_guess_without_rewriting() {
        let dir = scratch("pf_keep");
        let clash = dir.with_extension("yaml");
        let p = dir.join("a.txt");
        let yaml = provider_yaml(&[("a", "http://u/a", &p, "text")]);
        std::fs::write(&clash, &yaml).unwrap();
        let rep = prefetch_with(
            clash.to_str().unwrap(),
            dir.to_str().unwrap(),
            &names(&["a"]),
            |_, tmp| {
                let body = b"DOMAIN-SUFFIX,a.com\n".to_vec();
                std::fs::write(tmp, &body).unwrap();
                Ok(body)
            },
        );
        assert_eq!(rep.backfilled, 0);
        assert_eq!(std::fs::read_to_string(&clash).unwrap(), yaml, "untouched");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&clash);
    }

    #[test]
    fn predetect_reads_local_file_then_fetches_and_never_touches_clash_files() {
        let dir = scratch("pd");
        let clash = dir.join("clash.yaml");
        let local = dir.join("local.txt");
        let remote = dir.join("remote.txt");
        let dead = dir.join("dead.txt");
        let domains = dir.join("domains.txt");
        std::fs::write(&local, b"payload:\n  - '+.l.com'\n").unwrap();
        std::fs::write(
            &clash,
            provider_yaml(&[
                ("local", "http://u/local", &local, "text"),
                ("remote", "http://u/remote", &remote, "text"),
                ("dead", "http://u/dead", &dead, "text"),
                ("domains", "http://u/domains", &domains, "text"),
                ("suffix", "http://u/s.mrs", &dir.join("s.mrs"), "mrs"),
                ("manual", "http://u/manual", &dir.join("m.txt"), "text"),
            ]),
        )
        .unwrap();

        let fetched = std::sync::Mutex::new(Vec::new());
        let rep = predetect_with(
            clash.to_str().unwrap(),
            &names(&["local", "remote", "dead", "domains", "suffix"]),
            |url, tmp| {
                fetched.lock().unwrap().push(url.to_string());
                let body: &[u8] = match url {
                    "http://u/remote" => b"\x28\xB5\x2F\xFDzstd",
                    "http://u/domains" => b"+.a.com\n+.b.com\n",
                    _ => return Err("net down".into()),
                };
                std::fs::write(tmp, body).unwrap();
                Ok(body.to_vec())
            },
        );

        let mut fetched = fetched.into_inner().unwrap();
        fetched.sort();
        assert_eq!(
            fetched,
            ["http://u/dead", "http://u/domains", "http://u/remote"],
            "local cache hit and suffix-typed providers need no fetch; manual ones are skipped"
        );
        assert_eq!(rep.detected, 2);
        assert_eq!(rep.unknown, 2);
        assert_eq!(rep.backfilled, 2);
        let f = formats_of(&clash);
        assert_eq!(f["local"], "yaml");
        assert_eq!(f["remote"], "mrs");
        assert_eq!(f["dead"], "text", "unknown keeps the guess");
        assert_eq!(f["domains"], "text");
        assert_eq!(f["manual"], "text");
        assert!(
            !remote.exists() && !dead.exists(),
            "clash-owned paths untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
