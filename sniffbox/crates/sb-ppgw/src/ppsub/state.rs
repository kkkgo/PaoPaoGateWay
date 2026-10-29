// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::UserInfo;
use std::collections::BTreeMap;

const BASE_DIR: &str = "/tmp";

const BASE_DIR_ENV: &str = "ppgw_retry_dir";

pub const LEGACY_MARK: &str = "/tmp/ppsub_subdns_incomplete";

pub fn dir_overridden() -> bool {
    std::env::var(BASE_DIR_ENV)
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

pub(crate) fn base_dir() -> String {
    std::env::var(BASE_DIR_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| BASE_DIR.to_string())
}

pub fn state_file() -> String {
    format!("{}/ppsub_retry.json", base_dir())
}

pub fn cache_dir() -> String {
    format!("{}/ppsub_cache", base_dir())
}

pub fn lock_file() -> String {
    format!("{}/ppsub_retry.lock", base_dir())
}

pub fn log_file() -> String {
    format!("{}/ppsub_retry.log", base_dir())
}
const VERSION: i64 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainState {

    pub ips: Vec<String>,

    pub failed_specs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SubState {
    pub name: String,
    pub url: String,
    pub forced: bool,
    pub ok: bool,

    pub cache: String,
    pub userinfo: Option<UserInfo>,

    pub specs: Vec<String>,
    pub domains: BTreeMap<String, DomainState>,
}

#[derive(Debug, Clone, Default)]
pub struct RetryState {

    pub config: String,

    pub output: String,

    pub output_hash: String,
    pub dns_burn: bool,
    pub ex_dns: String,

    pub clash_socks5: bool,

    pub burn: BTreeMap<String, Vec<String>>,
    pub subs: Vec<SubState>,
}

impl RetryState {

    pub fn pending(&self) -> bool {
        self.subs.iter().any(|s| !s.ok)
            || self
                .subs
                .iter()
                .any(|s| s.domains.values().any(|d| !d.failed_specs.is_empty()))
            || self.burn.values().any(|ips| ips.is_empty())
    }

    pub fn gaps(&self) -> (usize, usize, usize) {
        let subs = self.subs.iter().filter(|s| !s.ok).count();
        let specs = self
            .subs
            .iter()
            .flat_map(|s| s.domains.values())
            .map(|d| d.failed_specs.len())
            .sum();
        let burn = self.burn.values().filter(|ips| ips.is_empty()).count();
        (subs, specs, burn)
    }

    pub fn load(path: &str) -> Option<Self> {
        from_json(&std::fs::read_to_string(path).ok()?)
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, to_json(self))?;
        std::fs::rename(&tmp, path)
    }
}

pub fn refresh_output_hash(output: &str) {
    let path = state_file();
    if let Some(mut st) = RetryState::load(&path) {
        st.output_hash = file_hash(output);
        let _ = st.save(&path);
    }
}

pub fn file_hash(path: &str) -> String {
    use sha2::{Digest, Sha256};
    match std::fs::read(path) {
        Ok(b) => hex::encode(Sha256::digest(&b)),
        Err(_) => String::new(),
    }
}

pub fn cache_path(sub_name: &str) -> String {
    let safe: String = sub_name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    format!("{}/{safe}.yaml", cache_dir())
}

fn to_json(s: &RetryState) -> String {
    let subs: Vec<serde_json::Value> = s
        .subs
        .iter()
        .map(|sub| {
            let domains: serde_json::Map<String, serde_json::Value> = sub
                .domains
                .iter()
                .map(|(d, st)| {
                    (
                        d.clone(),
                        serde_json::json!({
                            "ips": st.ips,
                            "failed_specs": st.failed_specs,
                        }),
                    )
                })
                .collect();
            serde_json::json!({
                "name": sub.name,
                "url": sub.url,
                "forced": sub.forced,
                "ok": sub.ok,
                "cache": sub.cache,
                "userinfo": sub.userinfo.as_ref().map(|u| {
                    serde_json::json!([u.total, u.upload, u.download, u.expire])
                }),
                "specs": sub.specs,
                "domains": serde_json::Value::Object(domains),
            })
        })
        .collect();
    let burn: serde_json::Map<String, serde_json::Value> = s
        .burn
        .iter()
        .map(|(d, ips)| (d.clone(), serde_json::json!(ips)))
        .collect();
    serde_json::json!({
        "version": VERSION,
        "config": s.config,
        "output": s.output,
        "output_hash": s.output_hash,
        "dns_burn": s.dns_burn,
        "ex_dns": s.ex_dns,
        "clash_socks5": s.clash_socks5,
        "burn": serde_json::Value::Object(burn),
        "subs": subs,
    })
    .to_string()
}

fn from_json(text: &str) -> Option<RetryState> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    if v.get("version").and_then(|x| x.as_i64()) != Some(VERSION) {
        return None;
    }
    let subs = v
        .get("subs")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().map(parse_sub).collect())
        .unwrap_or_default();
    Some(RetryState {
        config: jstr(&v, "config"),
        output: jstr(&v, "output"),
        output_hash: jstr(&v, "output_hash"),
        dns_burn: jbool(&v, "dns_burn"),
        ex_dns: jstr(&v, "ex_dns"),
        clash_socks5: jbool(&v, "clash_socks5"),
        burn: v
            .get("burn")
            .and_then(|x| x.as_object())
            .map(|o| o.iter().map(|(k, v)| (k.clone(), jstrvec(v))).collect())
            .unwrap_or_default(),
        subs,
    })
}

fn parse_sub(v: &serde_json::Value) -> SubState {
    let domains = v
        .get("domains")
        .and_then(|x| x.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, d)| {
                    (
                        k.clone(),
                        DomainState {
                            ips: d.get("ips").map(jstrvec).unwrap_or_default(),
                            failed_specs: d.get("failed_specs").map(jstrvec).unwrap_or_default(),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    SubState {
        name: jstr(v, "name"),
        url: jstr(v, "url"),
        forced: jbool(v, "forced"),
        ok: jbool(v, "ok"),
        cache: jstr(v, "cache"),
        userinfo: v.get("userinfo").and_then(|u| u.as_array()).and_then(|a| {
            (a.len() == 4).then(|| UserInfo {
                total: a[0].as_i64().unwrap_or(0),
                upload: a[1].as_i64().unwrap_or(0),
                download: a[2].as_i64().unwrap_or(0),
                expire: a[3].as_i64().unwrap_or(0),
            })
        }),
        specs: v.get("specs").map(jstrvec).unwrap_or_default(),
        domains,
    }
}

fn jstr(v: &serde_json::Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn jbool(v: &serde_json::Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}
fn jstrvec(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RetryState {
        let mut burn = BTreeMap::new();
        burn.insert("a.com".to_string(), vec!["1.2.3.4".to_string()]);
        burn.insert("b.com".to_string(), vec![]);
        let mut domains = BTreeMap::new();
        domains.insert(
            "a.com".to_string(),
            DomainState {
                ips: vec!["5.6.7.8".to_string()],
                failed_specs: vec!["https://doh.example/dns-query".to_string()],
            },
        );
        RetryState {
            config: "/tmp/ppsub_cache/config.json".into(),
            output: "/tmp/paopao_custom.yaml".into(),
            output_hash: "abc".into(),
            dns_burn: true,
            ex_dns: "223.5.5.5".into(),
            clash_socks5: false,
            burn,
            subs: vec![SubState {
                name: "S".into(),
                url: "https://sub.example/x".into(),
                forced: false,
                ok: true,
                cache: "/tmp/ppsub_cache/S.yaml".into(),
                userinfo: Some(UserInfo {
                    total: 10,
                    upload: 1,
                    download: 2,
                    expire: 1_700_000_000,
                }),
                specs: vec!["https://doh.example/dns-query".into()],
                domains,
            }],
        }
    }

    #[test]
    fn json_round_trip() {
        let s = sample();
        let back = from_json(&to_json(&s)).expect("parse back");
        assert_eq!(back.config, s.config);
        assert_eq!(back.output_hash, "abc");
        assert!(back.dns_burn);
        assert_eq!(back.burn.get("b.com"), Some(&vec![]));
        let sub = &back.subs[0];
        assert!(sub.ok);
        assert_eq!(sub.userinfo.as_ref().map(|u| u.expire), Some(1_700_000_000));
        assert_eq!(
            sub.domains["a.com"].failed_specs,
            vec!["https://doh.example/dns-query"]
        );
    }

    #[test]
    fn version_mismatch_is_ignored() {
        let bad = r#"{"version":99,"subs":[]}"#;
        assert!(from_json(bad).is_none(), "future version must not be read");
        assert!(from_json("not json").is_none());
    }

    #[test]
    fn pending_detects_each_kind_of_gap() {

        let mut s = sample();
        s.burn.insert("b.com".to_string(), vec!["9.9.9.9".into()]);
        s.subs[0].domains.get_mut("a.com").unwrap().failed_specs = vec![];
        assert!(!s.pending(), "no gap should not be pending");

        let mut a = s.clone();
        a.subs[0].ok = false;
        assert!(a.pending(), "failed subscription is a gap");

        let mut b = s.clone();
        b.subs[0].domains.get_mut("a.com").unwrap().failed_specs = vec!["tls://dot.x".into()];
        assert!(b.pending(), "unanswered dedicated DNS is a gap");

        let mut c = s.clone();
        c.burn.insert("c.com".to_string(), vec![]);
        assert!(c.pending(), "empty dns_burn result is a gap");
    }

    #[test]
    fn gaps_counts_each_bucket() {
        let s = sample();
        assert_eq!(s.gaps(), (0, 1, 1));
    }

    #[test]
    fn cache_path_sanitizes() {
        assert_eq!(cache_path("My Sub/1"), "/tmp/ppsub_cache/My_Sub_1.yaml");
    }

    #[test]
    fn save_then_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        let p = p.to_str().unwrap();
        sample().save(p).unwrap();
        let back = RetryState::load(p).expect("load back");
        assert_eq!(back.subs.len(), 1);
        assert!(RetryState::load("/nonexistent/state.json").is_none());
    }
}
