// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::{PpsubErr, RuleSet, pp_log, pp_warn, ystr};
use std::collections::HashSet;
use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml, YamlLoader};

pub fn process_rules(
    rule_sets: &[RuleSet],
    proxy_groups: &[Yaml],
) -> Result<(Vec<String>, Hash), PpsubErr> {
    let mut sets: Vec<&RuleSet> = rule_sets.iter().collect();
    sets.sort_by_key(|r| r.priority);

    let group_names: HashSet<String> = proxy_groups
        .iter()
        .filter_map(|g| g["name"].as_str().map(String::from))
        .collect();

    let mut all_rules: Vec<String> = Vec::new();
    let mut defined: Vec<(String, Yaml)> = Vec::new();

    for rs in sets {
        if rs.typ == "rule-set" {
            if rs.name.is_empty() || rs.url.is_empty() {
                continue;
            }
            pp_log(&format!("rule-set provider [{}] {}", rs.name, rs.url));
            defined.push((rs.name.clone(), build_provider(rs)));
            continue;
        }
        let rules: Vec<String> = if rs.typ == "url" || (rs.typ.is_empty() && !rs.url.is_empty()) {
            pp_log(&format!(
                "downloading rules{} {}",
                if rs.is_forced { " (forced)" } else { "" },
                rs.url
            ));
            match download_rules(&rs.url) {
                Ok(r) => {
                    pp_log(&format!(
                        "downloaded {} rule line(s) from {}",
                        r.len(),
                        rs.url
                    ));
                    r
                }
                Err(e) => {
                    pp_warn(&format!("rule download failed ({}): {e}", rs.url));
                    if rs.is_forced {
                        return Err(PpsubErr::ForcedRuleFailed(rs.url.clone(), e));
                    }
                    continue;
                }
            }
        } else {
            rs.fixrule.clone()
        };
        for rule in rules {
            let rule = rule.trim();
            if rule.is_empty() || rule.starts_with('#') {
                continue;
            }
            if !validate_rule(rule, &group_names) {
                continue;
            }
            all_rules.push(rule.to_string());
        }
    }

    let mut used: HashSet<String> = HashSet::new();
    for rule in &all_rules {
        if rule.to_uppercase().starts_with("RULE-SET") {
            let parts: Vec<&str> = rule.split(',').collect();
            if parts.len() >= 2 {
                used.insert(parts[1].trim().to_string());
            }
        }
    }
    let mut final_providers = Hash::new();
    for (name, provider) in defined {
        if used.contains(&name) {
            final_providers.insert(ystr(&name), provider);
        }
    }
    Ok((all_rules, final_providers))
}

fn build_provider(rs: &RuleSet) -> Yaml {
    let mut p = Hash::new();
    p.insert(ystr("type"), ystr("http"));
    p.insert(ystr("url"), ystr(&rs.url));
    let mut interval = if rs.interval > 0 { rs.interval } else { 86400 };
    if interval < 60 {
        interval = 60;
    }
    p.insert(ystr("interval"), Yaml::Integer(interval));
    p.insert(
        ystr("behavior"),
        ystr(if rs.behavior.is_empty() {
            "classical"
        } else {
            &rs.behavior
        }),
    );
    let mut header = Hash::new();
    header.insert(
        ystr("User-Agent"),
        Yaml::Array(vec![ystr(super::groups::ua_ruleset())]),
    );
    p.insert(ystr("header"), Yaml::Hash(header));
    if !rs.format.is_empty() {
        p.insert(ystr("format"), ystr(&rs.format));
    }
    if !rs.proxy.is_empty() {
        p.insert(ystr("proxy"), ystr(&rs.proxy));
    }

    let path = if rs.path.is_empty() {
        crate::ruleset::default_path(&rs.url, &rs.format)
    } else {
        rs.path.clone()
    };
    p.insert(ystr("path"), ystr(&path));
    Yaml::Hash(p)
}

fn validate_rule(rule: &str, group_names: &HashSet<String>) -> bool {
    let parts: Vec<&str> = rule.split(',').collect();
    if parts.len() < 2 {
        return true;
    }
    const OPTS: [&str; 5] = ["no-resolve", "src", "dst", "no-redir", "not"];
    let mut idx = parts.len() as i64 - 1;
    while idx >= 0 {
        let cand = parts[idx as usize].trim().to_lowercase();
        if !OPTS.contains(&cand.as_str()) {
            break;
        }
        idx -= 1;
    }
    if idx < 1 {
        return true;
    }
    let target = parts[idx as usize].trim();
    const BUILTIN: [&str; 4] = ["DIRECT", "REJECT", "PROXY", "proxies"];
    if BUILTIN.contains(&target) {
        return true;
    }
    group_names.contains(target)
}

fn download_rules(url: &str) -> Result<Vec<String>, String> {
    let mut last = String::from("download failed");
    for _ in 0..3 {
        let tmp = std::env::temp_dir().join(format!("ppsub_rules_{}.yaml", std::process::id()));
        let tmp_s = tmp.to_string_lossy().into_owned();
        match crate::download::Downloader::new(url, &tmp_s).download() {
            Ok(_) => {
                let data = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
                let _ = std::fs::remove_file(&tmp);
                let docs = YamlLoader::load_from_str(&data).map_err(|e| e.to_string())?;
                if let Some(doc) = docs.first() {
                    if let Some(rules) = doc["rules"].as_vec() {
                        return Ok(rules
                            .iter()
                            .filter_map(|r| r.as_str().map(String::from))
                            .collect());
                    }
                }
                return Err("rules not found in downloaded data".to_string());
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups_with(names: &[&str]) -> Vec<Yaml> {
        names
            .iter()
            .map(|n| {
                let mut h = Hash::new();
                h.insert(ystr("name"), ystr(n));
                Yaml::Hash(h)
            })
            .collect()
    }

    #[test]
    fn validate_rule_target_and_options() {
        let gn: HashSet<String> = ["MyGroup".to_string()].into_iter().collect();
        assert!(validate_rule("DOMAIN,a.com,DIRECT", &gn));
        assert!(validate_rule("DOMAIN,a.com,MyGroup", &gn));
        assert!(
            validate_rule("IP-CIDR,1.1.1.1/32,MyGroup,no-resolve", &gn),
            "skip trailing no-resolve"
        );
        assert!(
            !validate_rule("DOMAIN,a.com,GhostGroup", &gn),
            "non-existent group → reject"
        );
        assert!(validate_rule("MATCH", &gn), "<2 segments → allow");
    }

    #[test]
    fn fixrule_and_prune_providers() {
        let groups = groups_with(&["Proxy"]);
        let sets = vec![

            RuleSet {
                priority: 1,
                typ: "rule-set".into(),
                name: "ad".into(),
                url: "http://x/ad".into(),
                behavior: String::new(),
                interval: 0,
                fixrule: vec![],
                is_forced: false,
                format: String::new(),
                proxy: String::new(),
                path: String::new(),
            },
            RuleSet {
                priority: 2,
                typ: "rule-set".into(),
                name: "unused".into(),
                url: "http://x/u".into(),
                behavior: String::new(),
                interval: 0,
                fixrule: vec![],
                is_forced: false,
                format: String::new(),
                proxy: String::new(),
                path: String::new(),
            },

            RuleSet {
                priority: 3,
                typ: String::new(),
                name: String::new(),
                url: String::new(),
                behavior: String::new(),
                interval: 0,
                fixrule: vec![
                    "RULE-SET,ad,REJECT".into(),
                    "DOMAIN,a.com,Proxy".into(),
                    "DOMAIN,b.com,Ghost".into(),
                    "MATCH,DIRECT".into(),
                ],
                is_forced: false,
                format: String::new(),
                proxy: String::new(),
                path: String::new(),
            },
        ];
        let (rules, providers) = process_rules(&sets, &groups).unwrap();
        assert!(rules.contains(&"RULE-SET,ad,REJECT".to_string()));
        assert!(rules.contains(&"DOMAIN,a.com,Proxy".to_string()));
        assert!(!rules.iter().any(|r| r.contains("Ghost")), "invalid group rules removed");
        assert!(rules.contains(&"MATCH,DIRECT".to_string()));

        assert!(providers.contains_key(&ystr("ad")));
        assert!(!providers.contains_key(&ystr("unused")));
    }

    #[test]
    fn provider_interval_and_behavior_defaults() {
        let groups = groups_with(&["Proxy"]);
        let sets = vec![
            RuleSet {
                priority: 1,
                typ: "rule-set".into(),
                name: "a".into(),
                url: "http://a".into(),
                behavior: String::new(),
                interval: 10,
                fixrule: vec![],
                is_forced: false,
                format: String::new(),
                proxy: String::new(),
                path: String::new(),
            },
            RuleSet {
                priority: 2,
                typ: String::new(),
                name: String::new(),
                url: String::new(),
                behavior: String::new(),
                interval: 0,
                fixrule: vec!["RULE-SET,a,REJECT".into()],
                is_forced: false,
                format: String::new(),
                proxy: String::new(),
                path: String::new(),
            },
        ];
        let (_rules, providers) = process_rules(&sets, &groups).unwrap();
        let a = providers.get(&ystr("a")).unwrap();
        assert_eq!(a["interval"].as_i64(), Some(60), "interval<60 → 60");
        assert_eq!(a["behavior"].as_str(), Some("classical"), "default classical");
        assert_eq!(a["type"].as_str(), Some("http"));
    }
}
