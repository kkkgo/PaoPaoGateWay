// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::{SubProvider, SubResult, UserInfo, pp_log, pp_warn};
use yaml_rust2::{Yaml, YamlLoader};

pub fn download_subscription(sub: &SubProvider) -> SubResult {
    pp_log(&format!(
        "[{}] downloading{} {}",
        sub.name,
        if sub.is_forced { " (forced)" } else { "" },
        sub.url
    ));
    let mut last_err = String::from("unknown");
    for attempt in 1..=3 {
        let tmp = std::env::temp_dir().join(format!(
            "ppsub_{}_{}.yaml",
            sanitize(&sub.name),
            std::process::id()
        ));
        let tmp_s = tmp.to_string_lossy().into_owned();
        let dl = crate::download::Downloader::new(&sub.url, &tmp_s);
        match dl.download() {
            Ok(info) => {
                let data = match std::fs::read_to_string(&tmp) {
                    Ok(d) => d,
                    Err(e) => {
                        last_err = e.to_string();
                        let _ = std::fs::remove_file(&tmp);
                        pp_warn(&format!(
                            "[{}] attempt {attempt}/3 read tmp failed: {last_err}",
                            sub.name
                        ));
                        continue;
                    }
                };
                let _ = std::fs::remove_file(&tmp);
                let userinfo = info
                    .userinfo
                    .as_deref()
                    .and_then(parse_subscription_userinfo);
                let proxies = extract_proxies(&data, &sub.name);
                pp_log(&format!(
                    "[{}] OK: {} downloaded, {} proxy node(s) parsed",
                    sub.name,
                    human_bytes(data.len()),
                    proxies.len()
                ));
                if let Some(ui) = &userinfo {
                    let gb = 1_073_741_824f64;
                    let used = (ui.upload + ui.download) as f64 / gb;
                    let total = ui.total as f64 / gb;
                    pp_log(&format!(
                        "[{}] traffic: {used:.2}G / {total:.2}G used",
                        sub.name
                    ));
                }
                return SubResult {
                    name: sub.name.clone(),
                    success: true,
                    proxies,
                    userinfo,
                    raw_yaml: data,
                    error: String::new(),
                };
            }
            Err(e) => {
                last_err = e.to_string();
                pp_warn(&format!(
                    "[{}] attempt {attempt}/3 failed: {last_err}",
                    sub.name
                ));
            }
        }
    }
    pp_warn(&format!("[{}] all 3 attempts failed: {last_err}", sub.name));
    SubResult {
        name: sub.name.clone(),
        success: false,
        proxies: Vec::new(),
        userinfo: None,
        raw_yaml: String::new(),
        error: last_err,
    }
}

fn extract_proxies(data: &str, sub_name: &str) -> Vec<Yaml> {
    let mut out = Vec::new();
    let Ok(docs) = YamlLoader::load_from_str(data) else {
        return out;
    };
    let Some(doc) = docs.first() else {
        return out;
    };
    let Some(arr) = doc["proxies"].as_vec() else {
        return out;
    };
    for p in arr {
        let Some(h) = p.as_hash() else {
            continue;
        };
        let mut np = h.clone();
        if let Some(name) = p["name"].as_str() {
            np.insert(
                Yaml::String("name".to_string()),
                Yaml::String(format!("{sub_name}_{name}")),
            );
        }
        out.push(Yaml::Hash(np));
    }
    out
}

pub fn parse_subscription_userinfo(header: &str) -> Option<UserInfo> {
    let mut u = UserInfo::default();
    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let Ok(n) = v.trim().parse::<i64>() else {
            continue;
        };
        match k.trim() {
            "upload" => u.upload = n,
            "download" => u.download = n,
            "total" => u.total = n,
            "expire" => u.expire = n,
            _ => {}
        }
    }
    if u.total > 0 && u.expire > 0 {
        Some(u)
    } else {
        None
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

fn human_bytes(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MB", n as f64 / (1 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.2} KB", n as f64 / (1 << 10) as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userinfo_parse() {
        let u = parse_subscription_userinfo(
            "upload=100; download=200; total=1073741824; expire=1700000000",
        )
        .unwrap();
        assert_eq!(u.upload, 100);
        assert_eq!(u.total, 1073741824);
        assert_eq!(u.expire, 1700000000);

        assert!(parse_subscription_userinfo("upload=1").is_none());
        assert!(parse_subscription_userinfo("total=5").is_none());
    }

    #[test]
    fn extract_prefixes_names() {
        let data =
            "proxies:\n  - {name: HK, server: a.com, type: ss}\n  - {name: US, server: b.com}\n";
        let ps = extract_proxies(data, "MySub");
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0]["name"].as_str(), Some("MySub_HK"));
        assert_eq!(ps[1]["name"].as_str(), Some("MySub_US"));
        assert_eq!(ps[0]["type"].as_str(), Some("ss"), "remaining fields kept");
    }
}
