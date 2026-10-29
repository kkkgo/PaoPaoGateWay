// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

mod groups;
pub(crate) mod hosts;
pub(crate) mod proxies;
pub mod retry;
mod rules;
pub(crate) mod state;
pub(crate) mod sub;
pub mod subinfo;

pub use groups::SMART_HIDE_NODE;

use std::io::Write;
use yaml_rust2::Yaml;
use yaml_rust2::YamlEmitter;
use yaml_rust2::yaml::Hash;

#[derive(Debug, thiserror::Error)]
pub enum PpsubErr {
    #[error("read {0}: {1}")]
    Read(String, String),
    #[error("parse config: {0}")]
    Config(String),
    #[error("all subscription providers failed to download")]
    AllSubsFailed,
    #[error("required subscription {0} failed to download: {1}")]
    ForcedSubFailed(String, String),
    #[error("required rule download failed (URL: {0}): {1}")]
    ForcedRuleFailed(String, String),
    #[error("emit: {0}")]
    Emit(String),
    #[error("write {0}: {1}")]
    Write(String, String),
}

pub struct SubProvider {
    pub name: String,
    pub url: String,
    pub is_forced: bool,
}

pub struct NodeGroup {
    pub name: String,
    pub keywords: Vec<String>,
    pub exclude_keywords: Vec<String>,
    pub subs: Option<Vec<String>>,
    pub include: Vec<String>,
    pub speedtest_url: String,
    pub interval: i64,

    pub smart: bool,
    pub use_pre_proxy: bool,
    pub pre_proxy_group: String,
}

pub struct RuleSet {
    pub priority: i64,
    pub typ: String,
    pub name: String,
    pub url: String,
    pub behavior: String,
    pub interval: i64,
    pub fixrule: Vec<String>,
    pub is_forced: bool,
    pub format: String,
    pub proxy: String,

    pub path: String,
}

pub struct ShadowsocksIn {
    pub password: String,
    pub cipher: String,
}

pub const SS_IN_PORT: i64 = 8080;

const SS_CIPHERS: [&str; 2] = ["2022-blake3-aes-128-gcm", "aes-128-gcm"];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub total: i64,
    pub upload: i64,
    pub download: i64,
    pub expire: i64,
}

pub struct SubResult {
    pub name: String,
    pub success: bool,
    pub proxies: Vec<Yaml>,

    pub(crate) hosts: hosts::SubHosts,
    pub userinfo: Option<UserInfo>,

    pub raw_yaml: String,
    pub error: String,
}

pub(crate) fn ystr(s: &str) -> Yaml {
    Yaml::String(s.to_string())
}

pub(crate) fn pp_log(msg: &str) {
    let _ = writeln!(
        std::io::stdout(),
        "{}{msg}",
        crate::term::green("[PaoPaoGW PPSub]")
    );
}

pub(crate) fn pp_step(msg: &str) {
    let _ = writeln!(
        std::io::stdout(),
        "{}{msg}",
        crate::term::orange("[PaoPaoGW PPSub]")
    );
}

pub(crate) fn pp_warn(msg: &str) {
    let _ = writeln!(
        std::io::stdout(),
        "{}{msg}",
        crate::term::red("[PaoPaoGW PPSub]")
    );
}

pub(crate) const LOG: crate::resolvepool::Log = crate::resolvepool::Log {
    info: pp_log,
    step: pp_step,
    warn: pp_warn,
};

pub fn process_ppsub(
    config_file: &str,
    output_file: &str,
    dns_burn: bool,
    ex_dns: &str,
) -> Result<(), PpsubErr> {
    let content = std::fs::read_to_string(config_file)
        .map_err(|e| PpsubErr::Read(config_file.to_string(), e.to_string()))?;
    let cfg: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| PpsubErr::Config(e.to_string()))?;

    let subs = parse_subs(&cfg);

    pp_log(&format!(
        "config={config_file} output={output_file} dns_burn={dns_burn}"
    ));
    if dns_burn && !ex_dns.is_empty() {
        pp_log(&format!("ex_dns={ex_dns}"));
    }
    pp_log(&format!(
        "parsed: {} subscription(s), {} node-group(s), {} rule-set(s)",
        subs.len(),
        parse_node_groups(&cfg).len(),
        parse_rules(&cfg).len()
    ));

    pp_step(&format!(
        "Step 1/4: downloading {} subscription(s)",
        subs.len()
    ));
    let mut sub_results: Vec<SubResult> = Vec::new();
    let mut has_success = false;
    for sub in &subs {
        let r = sub::download_subscription(sub);
        if r.success {
            has_success = true;
        } else if sub.is_forced {
            return Err(PpsubErr::ForcedSubFailed(sub.name.clone(), r.error.clone()));
        }
        sub_results.push(r);
    }
    if !has_success {
        return Err(PpsubErr::AllSubsFailed);
    }
    let ok_subs = sub_results.iter().filter(|r| r.success).count();
    pp_log(&format!(
        "downloaded {ok_subs}/{} subscription(s) OK",
        subs.len()
    ));

    pp_step(&format!(
        "Step 2/4: processing proxy nodes{}",
        if dns_burn { " (dns_burn ON)" } else { "" }
    ));
    let resolution = if dns_burn {
        let dns_servers = proxies::collect_dns_servers(ex_dns);
        proxies::resolve_all(&sub_results, &dns_servers, crate::dnsutil::ipv6_enabled())
    } else {
        for r in sub_results.iter().filter(|r| !r.hosts.map.is_empty()) {
            pp_log(&format!(
                "[{}] hosts: {} node domain(s) mapped by the sub's hosts, unused (dns_burn off)",
                r.name,
                r.hosts.map.len()
            ));
        }
        proxies::Resolution::default()
    };

    let buf = emit_config(&cfg, &sub_results, &resolution, dns_burn, None)?;
    let bytes = buf.len();
    std::fs::write(output_file, buf)
        .map_err(|e| PpsubErr::Write(output_file.to_string(), e.to_string()))?;
    pp_log(&format!("wrote {output_file} ({bytes} bytes)"));

    let at = subinfo::now();
    let entries: Vec<subinfo::Entry> = sub_results
        .iter()
        .map(|r| subinfo::Entry {
            name: r.name.clone(),
            info: r.userinfo.clone(),
            at: if r.success { at } else { 0 },
        })
        .collect();
    if let Err(e) = subinfo::save(&subinfo::file(), &entries) {
        pp_warn(&format!("cannot write subscription usage file: {e}"));
    }

    save_retry_state(
        config_file,
        output_file,
        dns_burn,
        ex_dns,
        &subs,
        &sub_results,
        &resolution,
    );
    Ok(())
}

pub(crate) fn emit_config(
    cfg: &serde_json::Value,
    sub_results: &[SubResult],
    resolution: &proxies::Resolution,
    dns_burn: bool,
    reuse: Option<&Yaml>,
) -> Result<String, PpsubErr> {
    let node_groups = parse_node_groups(cfg);
    let rule_sets = parse_rules(cfg);
    let ss_in = parse_shadowsocks_in(cfg);

    let all_proxies = proxies::build_proxies(sub_results, resolution, dns_burn);
    pp_log(&format!("merged {} proxy node(s)", all_proxies.len()));

    pp_step(&format!(
        "Step 3/4: generating proxy groups from {} node-group(s)",
        node_groups.len()
    ));
    let (proxy_groups, proxy_providers) =
        groups::generate_proxy_groups(&node_groups, &all_proxies, sub_results);
    pp_log(&format!(
        "generated {} proxy-group(s), {} proxy-provider(s)",
        proxy_groups.len(),
        proxy_providers.len()
    ));

    let (rule_list, rule_providers) = match reuse {
        Some(prev) => {
            pp_step("Step 4/4: reusing rules from the previous config (no rule download)");
            reuse_rules(prev)
        }
        None => {
            pp_step(&format!(
                "Step 4/4: processing {} rule-set(s)",
                rule_sets.len()
            ));
            let (list, providers) = rules::process_rules(&rule_sets, &proxy_groups)?;
            (
                Yaml::Array(list.into_iter().map(Yaml::String).collect()),
                Yaml::Hash(providers),
            )
        }
    };
    pp_log(&format!(
        "produced {} rule(s), {} rule-provider(s)",
        rule_list.as_vec().map(|v| v.len()).unwrap_or(0),
        rule_providers.as_hash().map(|h| h.len()).unwrap_or(0),
    ));

    let mut all_proxies = all_proxies;
    if group_references_smart_hide(&proxy_groups) {
        all_proxies.push(groups::smart_hide_proxy());
        pp_log(&format!(
            "smart speedtest marker node `{}` appended",
            groups::SMART_HIDE_NODE
        ));
    }

    let mut root = Hash::new();
    root.insert(ystr("proxies"), Yaml::Array(all_proxies));
    root.insert(ystr("proxy-groups"), Yaml::Array(proxy_groups));
    if !proxy_providers.is_empty() {
        root.insert(ystr("proxy-providers"), Yaml::Hash(proxy_providers));
    }
    root.insert(ystr("rules"), rule_list);
    if rule_providers
        .as_hash()
        .map(|h| !h.is_empty())
        .unwrap_or(false)
    {
        root.insert(ystr("rule-providers"), rule_providers);
    }
    if let Some(ss) = &ss_in {
        pp_log(&format!(
            "shadowsocks inbound on :{SS_IN_PORT} cipher={}",
            ss.cipher
        ));
        root.insert(ystr("listeners"), Yaml::Array(vec![build_ss_listener(ss)]));
    }
    root.insert(ystr("mode"), ystr("rule"));

    let mut buf = String::new();
    YamlEmitter::new(&mut buf)
        .dump(&Yaml::Hash(root))
        .map_err(|e| PpsubErr::Emit(format!("{e:?}")))?;
    Ok(buf)
}

fn reuse_rules(prev: &Yaml) -> (Yaml, Yaml) {
    let rules = match &prev["rules"] {
        Yaml::Array(a) => Yaml::Array(a.clone()),
        _ => Yaml::Array(Vec::new()),
    };
    let providers = match &prev["rule-providers"] {
        Yaml::Hash(h) => Yaml::Hash(h.clone()),
        _ => Yaml::Hash(Hash::new()),
    };
    (rules, providers)
}

fn save_retry_state(
    config_file: &str,
    output_file: &str,
    dns_burn: bool,
    ex_dns: &str,
    subs: &[SubProvider],
    sub_results: &[SubResult],
    res: &proxies::Resolution,
) {
    use state::{DomainState, RetryState, SubState};

    let _ = std::fs::create_dir_all(state::cache_dir());
    let config_copy = format!("{}/config.json", state::cache_dir());
    if std::fs::copy(config_file, &config_copy).is_err() {
        pp_warn("retry state: cannot cache ppsub config, background gap-fill disabled");
        return;
    }

    let mut st = RetryState {
        config: config_copy,
        output: output_file.to_string(),
        output_hash: state::file_hash(output_file),
        dns_burn,
        ex_dns: ex_dns.to_string(),
        clash_socks5: crate::dohdot::clash_socks5_ready(),
        ..Default::default()
    };

    for (sub, r) in subs.iter().zip(sub_results.iter()) {
        let mut ss = SubState {
            name: sub.name.clone(),
            url: sub.url.clone(),
            forced: sub.is_forced,
            ok: r.success,
            userinfo: r.userinfo.clone(),
            ..Default::default()
        };
        if r.success {
            let path = state::cache_path(&sub.name);
            if std::fs::write(&path, &r.raw_yaml).is_ok() {
                ss.cache = path;
            }
            ss.specs = proxies::sub_dns_servers(&r.raw_yaml);
            let empty = std::collections::HashMap::new();
            let got = res.subdns.get(&r.name).unwrap_or(&empty);
            let failed = res.failed.get(&r.name);
            for d in proxies::lookup_domains(r) {
                let ips = got
                    .get(&d)
                    .map(|v| v.iter().map(|ip| ip.to_string()).collect())
                    .unwrap_or_default();
                let failed_specs = failed.and_then(|f| f.get(&d)).cloned().unwrap_or_default();
                ss.domains.insert(d, DomainState { ips, failed_specs });
            }

            if dns_burn {
                for d in proxies::lookup_domains(r) {
                    st.burn.entry(d.clone()).or_insert_with(|| {
                        res.burn
                            .get(&d)
                            .map(|v| v.iter().map(|ip| ip.to_string()).collect())
                            .unwrap_or_default()
                    });
                }
            }
        }
        st.subs.push(ss);
    }

    if let Err(e) = st.save(&state::state_file()) {
        pp_warn(&format!("retry state: write failed: {e}"));
        return;
    }
    let (bad_subs, bad_specs, bad_burn) = st.gaps();
    if st.pending() {
        pp_warn(&format!(
            "gaps left: {bad_subs} subscription(s) undownloaded, {bad_specs} (domain, DNS) pair(s) unanswered, {bad_burn} domain(s) unresolved by dns_burn"
        ));
    }
}

fn group_references_smart_hide(proxy_groups: &[Yaml]) -> bool {
    proxy_groups.iter().any(|g| {
        g["proxies"]
            .as_vec()
            .map(|v| {
                v.iter()
                    .any(|p| p.as_str() == Some(groups::SMART_HIDE_NODE))
            })
            .unwrap_or(false)
    })
}

fn build_ss_listener(ss: &ShadowsocksIn) -> Yaml {
    let mut l = Hash::new();
    l.insert(ystr("name"), ystr("shadowsocks-in"));
    l.insert(ystr("type"), ystr("shadowsocks"));
    l.insert(ystr("port"), Yaml::Integer(SS_IN_PORT));
    l.insert(ystr("udp"), Yaml::Boolean(true));
    l.insert(ystr("listen"), ystr("0.0.0.0"));
    l.insert(ystr("password"), ystr(&ss.password));
    l.insert(ystr("cipher"), ystr(&ss.cipher));
    Yaml::Hash(l)
}

fn jstr(v: &serde_json::Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn jbool(v: &serde_json::Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}
fn jint(v: &serde_json::Value, k: &str) -> i64 {
    v.get(k).and_then(|x| x.as_i64()).unwrap_or(0)
}
fn jstrvec(v: &serde_json::Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_subs(cfg: &serde_json::Value) -> Vec<SubProvider> {
    cfg.get("subs")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .map(|s| SubProvider {
                    name: jstr(s, "name"),
                    url: jstr(s, "url"),
                    is_forced: jbool(s, "isforced"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_node_groups(cfg: &serde_json::Value) -> Vec<NodeGroup> {
    cfg.get("node-groups")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .map(|g| NodeGroup {
                    name: jstr(g, "name"),
                    keywords: jstrvec(g, "keywords"),
                    exclude_keywords: jstrvec(g, "exclude_keywords"),

                    subs: g.get("subs").map(|x| {
                        x.as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default()
                    }),
                    include: jstrvec(g, "include"),
                    speedtest_url: jstr(g, "speedtest_url"),
                    interval: jint(g, "interval"),
                    smart: jbool(g, "smart"),
                    use_pre_proxy: jbool(g, "use_pre_proxy"),
                    pre_proxy_group: jstr(g, "pre_proxy_group"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn b64_decoded_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let ok = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
    if !b[..b.len() - pad].iter().all(|&c| ok(c)) {
        return None;
    }
    Some(b.len() / 4 * 3 - pad)
}

fn parse_shadowsocks_in(cfg: &serde_json::Value) -> Option<ShadowsocksIn> {
    let ss = cfg.get("shadowsocks_in")?;
    if !jbool(ss, "enable") {
        return None;
    }
    let password = jstr(ss, "password");
    let cipher = jstr(ss, "cipher");
    if password.is_empty() {
        pp_warn("shadowsocks_in enabled but password is empty, skipping listener");
        return None;
    }
    if !SS_CIPHERS.contains(&cipher.as_str()) {
        pp_warn(&format!(
            "shadowsocks_in: unsupported cipher {cipher:?}, skipping listener"
        ));
        return None;
    }

    if cipher.starts_with("2022-") && b64_decoded_len(&password).is_none_or(|n| n < 16) {
        pp_warn(
            "shadowsocks_in: 2022-blake3 cipher needs a base64 key of >=16 bytes, skipping listener",
        );
        return None;
    }
    Some(ShadowsocksIn { password, cipher })
}

pub fn auto_format_rule_sets(config_file: &str) -> std::collections::HashSet<String> {
    std::fs::read_to_string(config_file)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .map(|cfg| {
            parse_rules(&cfg)
                .into_iter()
                .filter(|r| r.typ == "rule-set" && r.format.is_empty() && !r.name.is_empty())
                .map(|r| r.name)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_rules(cfg: &serde_json::Value) -> Vec<RuleSet> {
    cfg.get("rules")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .map(|r| RuleSet {
                    priority: jint(r, "priority"),
                    typ: jstr(r, "type"),
                    name: jstr(r, "name"),
                    url: jstr(r, "url"),
                    behavior: jstr(r, "behavior"),
                    interval: jint(r, "interval"),
                    fixrule: jstrvec(r, "fixrule"),
                    is_forced: jbool(r, "isforced"),

                    format: match jstr(r, "format").as_str() {
                        "auto" => String::new(),
                        other => other.to_string(),
                    },
                    proxy: jstr(r, "proxy"),
                    path: jstr(r, "path"),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_config_reuses_rules_without_downloading() {
        let cfg: serde_json::Value = serde_json::from_str(
            r#"{
              "subs": [{"name":"S","url":"http://x/s"}],
              "node-groups": [{"name":"HK","keywords":["HK"]}],
              "rules": [{"priority":1,"type":"rules","name":"blocked","url":"http://127.0.0.1:1/x"}]
            }"#,
        )
        .unwrap();
        let prev_text = "proxies: []\nrules:\n  - 'DOMAIN,a.com,HK'\n  - 'MATCH,DIRECT'\nrule-providers:\n  ads:\n    type: http\n    url: http://x/ads.yaml\n";
        let prev = &yaml_rust2::YamlLoader::load_from_str(prev_text).unwrap()[0];

        let mut h = yaml_rust2::yaml::Hash::new();
        h.insert(ystr("name"), ystr("S_HK01"));
        h.insert(ystr("server"), ystr("1.2.3.4"));
        h.insert(ystr("type"), ystr("ss"));
        let sub_results = vec![SubResult {
            name: "S".into(),
            success: true,
            proxies: vec![Yaml::Hash(h)],
            hosts: hosts::SubHosts::default(),
            userinfo: None,
            raw_yaml: String::new(),
            error: String::new(),
        }];

        let started = std::time::Instant::now();
        let out = emit_config(
            &cfg,
            &sub_results,
            &proxies::Resolution::default(),
            false,
            Some(prev),
        )
        .expect("emit");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "reuse path must not touch the network, took {:?}",
            started.elapsed()
        );

        let doc = &yaml_rust2::YamlLoader::load_from_str(&out).unwrap()[0];
        let rules: Vec<&str> = doc["rules"]
            .as_vec()
            .unwrap()
            .iter()
            .filter_map(|r| r.as_str())
            .collect();
        assert_eq!(
            rules,
            vec!["DOMAIN,a.com,HK", "MATCH,DIRECT"],
            "rules must come from the previous config verbatim"
        );
        assert_eq!(
            doc["rule-providers"]["ads"]["url"].as_str(),
            Some("http://x/ads.yaml"),
            "rule-providers must be carried over too"
        );

        assert_eq!(doc["proxies"][0]["name"].as_str(), Some("S_HK01"));
        assert_eq!(doc["proxy-groups"][0]["name"].as_str(), Some("HK"));
    }

    #[test]
    fn parse_node_group_subs_nil_vs_empty() {
        let cfg: serde_json::Value = serde_json::from_str(
            r#"{"node-groups":[{"name":"A"},{"name":"B","subs":[]},{"name":"C","subs":["x"]}]}"#,
        )
        .unwrap();
        let g = parse_node_groups(&cfg);
        assert_eq!(g[0].subs, None, "missing subs = nil");
        assert_eq!(g[1].subs, Some(vec![]), "subs:[] = empty, not nil");
        assert_eq!(g[2].subs, Some(vec!["x".to_string()]));
    }

    #[test]
    fn parse_group_and_rule_fields() {
        let cfg: serde_json::Value = serde_json::from_str(
            r#"{
            "node-groups":[{"name":"G","keywords":["HK","exp#JP"],"exclude_keywords":["trial"],
                "include":["DIRECT"],"speedtest_url":"http://x","interval":120,
                "use_pre_proxy":true,"pre_proxy_group":"P"},
               {"name":"S","keywords":[],"exclude_keywords":[],"smart":true}],
            "rules":[{"priority":5,"type":"rule-set","name":"ad","url":"http://u","behavior":"domain",
                      "interval":3600,"format":"yaml","proxy":"DIRECT","isforced":true},
                     {"priority":1,"fixrule":["MATCH,DIRECT"]}]
        }"#,
        )
        .unwrap();
        let g = parse_node_groups(&cfg);
        assert_eq!(g[0].keywords, vec!["HK", "exp#JP"]);
        assert_eq!(g[0].exclude_keywords, vec!["trial"]);
        assert_eq!(g[0].include, vec!["DIRECT"]);
        assert_eq!(g[0].speedtest_url, "http://x");
        assert_eq!(g[0].interval, 120);
        assert!(g[0].use_pre_proxy);
        assert_eq!(g[0].pre_proxy_group, "P");
        assert!(!g[0].smart, "default/unset smart → false");
        assert!(g[1].smart);

        let r = parse_rules(&cfg);
        assert_eq!(r[0].priority, 5);
        assert_eq!(r[0].typ, "rule-set");
        assert_eq!(r[0].name, "ad");
        assert_eq!(r[0].behavior, "domain");
        assert_eq!(r[0].interval, 3600);
        assert_eq!(r[0].format, "yaml");
        assert_eq!(r[0].proxy, "DIRECT");
        assert!(r[0].is_forced);
        assert_eq!(r[1].fixrule, vec!["MATCH,DIRECT"]);
    }

    #[test]
    fn smart_hide_reference_detection() {
        let mut pg = Hash::new();
        pg.insert(ystr("name"), ystr("Smart"));
        pg.insert(
            ystr("proxies"),
            Yaml::Array(vec![ystr("A"), ystr(groups::SMART_HIDE_NODE)]),
        );
        assert!(group_references_smart_hide(&[Yaml::Hash(pg)]));

        let mut pg2 = Hash::new();
        pg2.insert(ystr("name"), ystr("Plain"));
        pg2.insert(ystr("proxies"), Yaml::Array(vec![ystr("A")]));
        assert!(!group_references_smart_hide(&[Yaml::Hash(pg2)]));
        assert!(!group_references_smart_hide(&[]));
    }

    fn ss_cfg(json: &str) -> Option<ShadowsocksIn> {
        parse_shadowsocks_in(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn b64_len() {
        assert_eq!(b64_decoded_len("YWJjZGVmZ2hpamtsbW5vcA=="), Some(16));
        assert_eq!(b64_decoded_len("vlmpIPSyHH6f4S8W"), Some(12));
        assert_eq!(b64_decoded_len("vlmpIPSyHH6f4S8WVPdRIHIlzmB"), None);
        assert_eq!(b64_decoded_len("a===aaaa"), None);
        assert_eq!(b64_decoded_len("aa*aaaaa"), None);
        assert_eq!(b64_decoded_len(""), None);
    }

    #[test]
    fn parse_ss_in_accepts_valid() {
        let ss = ss_cfg(
            r#"{"shadowsocks_in":{"enable":true,"password":"YWJjZGVmZ2hpamtsbW5vcA==","cipher":"2022-blake3-aes-128-gcm"}}"#,
        )
        .expect("valid ss2022");
        assert_eq!(ss.cipher, "2022-blake3-aes-128-gcm");

        let ss = ss_cfg(
            r#"{"shadowsocks_in":{"enable":true,"password":"hunter2","cipher":"aes-128-gcm"}}"#,
        )
        .unwrap();
        assert_eq!(ss.password, "hunter2");
    }

    #[test]
    fn parse_ss_in_rejects_invalid() {

        assert!(ss_cfg(r#"{}"#).is_none());
        assert!(
            ss_cfg(r#"{"shadowsocks_in":{"enable":false,"password":"x","cipher":"aes-128-gcm"}}"#)
                .is_none()
        );

        assert!(
            ss_cfg(r#"{"shadowsocks_in":{"enable":true,"password":"","cipher":"aes-128-gcm"}}"#)
                .is_none()
        );

        assert!(
            ss_cfg(r#"{"shadowsocks_in":{"enable":true,"password":"x","cipher":"rc4-md5"}}"#)
                .is_none()
        );

        assert!(
            ss_cfg(r#"{"shadowsocks_in":{"enable":true,"password":"vlmpIPSyHH6f4S8W","cipher":"2022-blake3-aes-128-gcm"}}"#)
                .is_none()
        );
    }

    #[test]
    fn emit_ss_listener() {
        let ss = ShadowsocksIn {
            password: "YWJjZGVmZ2hpamtsbW5vcA==".into(),
            cipher: "2022-blake3-aes-128-gcm".into(),
        };
        let mut root = Hash::new();
        root.insert(ystr("listeners"), Yaml::Array(vec![build_ss_listener(&ss)]));
        let mut buf = String::new();
        YamlEmitter::new(&mut buf).dump(&Yaml::Hash(root)).unwrap();
        assert!(buf.contains("name: shadowsocks-in"), "{buf}");
        assert!(buf.contains("type: shadowsocks"), "{buf}");
        assert!(buf.contains("port: 8080"), "{buf}");
        assert!(buf.contains("udp: true"), "{buf}");
        assert!(buf.contains("listen: 0.0.0.0"), "{buf}");
        assert!(buf.contains("password: YWJjZGVmZ2hpamtsbW5vcA=="), "{buf}");
        assert!(buf.contains("cipher: 2022-blake3-aes-128-gcm"), "{buf}");
    }

    #[test]
    fn parse_rule_path_and_auto_format() {
        let cfg: serde_json::Value = serde_json::from_str(
            r#"{"rules":[
                {"priority":1,"type":"rule-set","name":"a","url":"http://u/a.yaml","format":"auto","path":"/tmp/rule-set/x.yaml"},
                {"priority":2,"type":"rule-set","name":"b","url":"http://u/b"}
            ]}"#,
        )
        .unwrap();
        let r = parse_rules(&cfg);

        assert_eq!(r[0].format, "");
        assert_eq!(r[0].path, "/tmp/rule-set/x.yaml");

        assert_eq!(r[1].format, "");
        assert_eq!(r[1].path, "");
    }

    #[test]
    fn auto_format_rule_sets_lists_only_auto_rule_sets() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("ppsub.json");
        std::fs::write(
            &cfg,
            r#"{"rules":[
                {"priority":1,"type":"rule-set","name":"a","url":"http://u/a","format":"auto"},
                {"priority":2,"type":"rule-set","name":"b","url":"http://u/b"},
                {"priority":3,"type":"rule-set","name":"c","url":"http://u/c","format":"text"},
                {"priority":4,"type":"url","name":"d","url":"http://u/d"}
            ]}"#,
        )
        .unwrap();
        let mut got: Vec<String> = auto_format_rule_sets(cfg.to_str().unwrap())
            .into_iter()
            .collect();
        got.sort();
        assert_eq!(got, ["a", "b"]);
        assert!(auto_format_rule_sets("/nonexistent/ppsub.json").is_empty());
    }
}
