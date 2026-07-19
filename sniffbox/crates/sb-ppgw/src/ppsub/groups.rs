// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::{NodeGroup, SubResult, ystr};
use regex_lite::Regex;
use std::collections::HashMap;
use yaml_rust2::Yaml;
use yaml_rust2::yaml::Hash;

const UA_RULESET: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0 gzip, deflate, br";

pub const SMART_HIDE_NODE: &str = "smartspeedtest@hide";

pub(super) fn smart_hide_proxy() -> Yaml {
    let mut h = Hash::new();
    h.insert(ystr("name"), ystr(SMART_HIDE_NODE));
    h.insert(ystr("type"), ystr("reject"));
    Yaml::Hash(h)
}

fn parse_keywords(keywords: &[String]) -> (Vec<String>, Vec<Regex>) {
    let mut simple = Vec::new();
    let mut regexes = Vec::new();
    for k in keywords {
        if let Some(pat) = k.strip_prefix("exp#") {
            if let Ok(re) = Regex::new(pat) {
                regexes.push(re);
            }
        } else {
            simple.push(k.clone());
        }
    }
    (simple, regexes)
}

fn matches_any(text: &str, simple: &[String], regexes: &[Regex]) -> bool {
    simple.iter().any(|k| text.contains(k.as_str())) || regexes.iter().any(|re| re.is_match(text))
}

fn match_sub_source(name: &str, subs: &Option<Vec<String>>) -> bool {
    match subs {
        None => true,
        Some(s) if s.is_empty() => false,
        Some(s) => s
            .iter()
            .any(|sub| sub == "all" || name.starts_with(&format!("{sub}_"))),
    }
}

fn filtered(group: &NodeGroup, all: &[Yaml], objects: bool) -> (Vec<String>, Vec<Yaml>) {
    let (inc_s, inc_r) = parse_keywords(&group.keywords);
    let (exc_s, exc_r) = parse_keywords(&group.exclude_keywords);
    let mut names = Vec::new();
    let mut objs = Vec::new();
    for p in all {
        let Some(name) = p["name"].as_str() else {
            continue;
        };
        if crate::nodes::is_system_node(name) {
            continue;
        }
        if !match_sub_source(name, &group.subs) {
            continue;
        }
        if matches_any(name, &exc_s, &exc_r) {
            continue;
        }
        if !group.keywords.is_empty() && !matches_any(name, &inc_s, &inc_r) {
            continue;
        }
        names.push(name.to_string());
        if objects {
            objs.push(p.clone());
        }
    }
    (names, objs)
}

fn check_sub_dependencies(subs: &Option<Vec<String>>, sub_results: &[SubResult]) -> bool {
    let Some(subs) = subs else {
        return true;
    };
    if subs.is_empty() || (subs.len() == 1 && subs[0] == "all") {
        return true;
    }
    for name in subs {
        if name == "all" {
            continue;
        }
        if !sub_results.iter().any(|r| r.name == *name && r.success) {
            return false;
        }
    }
    true
}

pub fn generate_proxy_groups(
    node_groups: &[NodeGroup],
    all: &[Yaml],
    sub_results: &[SubResult],
) -> (Vec<Yaml>, Hash) {
    let mut providers = Hash::new();
    let mut group_direct: HashMap<String, Vec<String>> = HashMap::new();
    let mut group_map: HashMap<String, &NodeGroup> = HashMap::new();
    let mut potential: Vec<String> = Vec::new();
    let mut group_full: HashMap<String, Vec<Yaml>> = HashMap::new();

    for g in node_groups {
        group_map.insert(g.name.clone(), g);
        if !check_sub_dependencies(&g.subs, sub_results) {
            continue;
        }
        let (names, _) = filtered(g, all, false);
        group_direct.insert(g.name.clone(), names);
        potential.push(g.name.clone());
        if g.use_pre_proxy {
            let (_, objs) = filtered(g, all, true);
            group_full.insert(g.name.clone(), objs);
        }
    }

    let mut is_valid: HashMap<String, bool> = HashMap::new();
    for name in &potential {
        if group_direct
            .get(name)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            is_valid.insert(name.clone(), true);
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for name in &potential {
            if *is_valid.get(name).unwrap_or(&false) {
                continue;
            }
            let g = group_map[name];
            for inc in &g.include {
                if inc == "DIRECT" || inc == "REJECT" {
                    is_valid.insert(name.clone(), true);
                    changed = true;
                    break;
                }
                if group_map.contains_key(inc) && *is_valid.get(inc).unwrap_or(&false) {
                    is_valid.insert(name.clone(), true);
                    changed = true;
                    break;
                }
            }
        }
    }

    let mut groups_out: Vec<Yaml> = Vec::new();
    for g in node_groups {
        if !group_direct.contains_key(&g.name) || !*is_valid.get(&g.name).unwrap_or(&false) {
            continue;
        }
        let mut pg = Hash::new();
        pg.insert(ystr("name"), ystr(&g.name));

        if g.use_pre_proxy && !g.pre_proxy_group.is_empty() {
            let provider_name = format!("{}=({}🔗{})", g.name, g.pre_proxy_group, g.name);
            let mut provider = Hash::new();
            provider.insert(ystr("type"), ystr("inline"));
            let mut over = Hash::new();
            over.insert(ystr("dialer-proxy"), ystr(&g.pre_proxy_group));
            provider.insert(ystr("override"), Yaml::Hash(over));
            let mut payload = group_full.get(&g.name).cloned().unwrap_or_default();
            if g.smart {

                payload.push(smart_hide_proxy());
            }
            provider.insert(ystr("payload"), Yaml::Array(payload));
            providers.insert(ystr(&provider_name), Yaml::Hash(provider));
            pg.insert(ystr("use"), Yaml::Array(vec![ystr(&provider_name)]));
        } else {
            let mut final_proxies: Vec<Yaml> =
                group_direct[&g.name].iter().map(|n| ystr(n)).collect();
            for inc in &g.include {
                if inc == "DIRECT" || inc == "REJECT" || *is_valid.get(inc).unwrap_or(&false) {
                    final_proxies.push(ystr(inc));
                }
            }
            if g.smart {
                final_proxies.push(ystr(SMART_HIDE_NODE));
            }
            pg.insert(ystr("proxies"), Yaml::Array(final_proxies));
        }

        if g.smart {

            pg.insert(ystr("type"), ystr("select"));
        } else if !g.speedtest_url.trim().is_empty() {
            pg.insert(ystr("type"), ystr("url-test"));
            pg.insert(ystr("url"), ystr(&g.speedtest_url));
            let mut interval = g.interval;
            if interval == 0 {
                interval = 600;
            }
            if interval < 30 {
                interval = 30;
            }
            pg.insert(ystr("interval"), Yaml::Integer(interval));
            pg.insert(ystr("tolerance"), Yaml::Integer(0));
        } else {
            pg.insert(ystr("type"), ystr("select"));
        }
        groups_out.push(Yaml::Hash(pg));
    }
    (groups_out, providers)
}

pub(super) fn ua_ruleset() -> &'static str {
    UA_RULESET
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> Yaml {
        let mut h = Hash::new();
        h.insert(ystr("name"), ystr(name));
        Yaml::Hash(h)
    }
    fn group(name: &str, kw: &[&str], exc: &[&str], subs: Option<Vec<String>>) -> NodeGroup {
        NodeGroup {
            name: name.to_string(),
            keywords: kw.iter().map(|s| s.to_string()).collect(),
            exclude_keywords: exc.iter().map(|s| s.to_string()).collect(),
            subs,
            include: vec![],
            speedtest_url: String::new(),
            interval: 0,
            smart: false,
            use_pre_proxy: false,
            pre_proxy_group: String::new(),
        }
    }

    #[test]
    fn keyword_and_regex_filter() {
        let all = vec![
            node("S_HK 01"),
            node("S_JP Tokyo"),
            node("S_HK trial"),
            node("DIRECT"),
        ];

        let g = group("HK", &["HK"], &["trial"], Some(vec!["S".to_string()]));
        let (names, _) = filtered(&g, &all, false);
        assert_eq!(names, vec!["S_HK 01"]);

        let g2 = group("JP", &["exp#Tokyo|Osaka"], &[], Some(vec!["S".to_string()]));
        let (n2, _) = filtered(&g2, &all, false);
        assert_eq!(n2, vec!["S_JP Tokyo"]);
    }

    #[test]
    fn sub_source_match() {
        assert!(match_sub_source("A_x", &None));
        assert!(!match_sub_source("A_x", &Some(vec![])));
        assert!(match_sub_source("A_x", &Some(vec!["all".to_string()])));
        assert!(match_sub_source("A_x", &Some(vec!["A".to_string()])));
        assert!(!match_sub_source("B_x", &Some(vec!["A".to_string()])));
    }

    #[test]
    fn include_graph_transitive_validity() {
        let all = vec![node("S_HK")];
        let sr = vec![];

        let groups = vec![
            group_inc("G1", &["HK"], vec![]),
            group_inc("G2", &["NOPE"], vec!["G1".to_string()]),
            group_inc("G3", &["NOPE"], vec!["REJECT".to_string()]),
            group_inc("G4", &["NOPE"], vec![]),
        ];
        let (out, _) = generate_proxy_groups(&groups, &all, &sr);
        let out_names: Vec<&str> = out.iter().filter_map(|g| g["name"].as_str()).collect();
        assert!(out_names.contains(&"G1"));
        assert!(out_names.contains(&"G2"), "include valid group → valid");
        assert!(out_names.contains(&"G3"), "include REJECT → valid");
        assert!(!out_names.contains(&"G4"), "no nodes and no valid include → remove");
    }

    fn group_inc(name: &str, kw: &[&str], include: Vec<String>) -> NodeGroup {
        let mut g = group(name, kw, &[], None);
        g.include = include;
        g
    }

    #[test]
    fn url_test_group_interval_clamp() {
        let all = vec![node("S_HK")];
        let mk = |interval: i64| {
            let mut g = group("Auto", &["HK"], &[], None);
            g.speedtest_url = "http://x".to_string();
            g.interval = interval;
            g
        };

        let (out, _) = generate_proxy_groups(&[mk(0)], &all, &[]);
        assert_eq!(out[0]["type"].as_str(), Some("url-test"));
        assert_eq!(out[0]["interval"].as_i64(), Some(600));

        let (out2, _) = generate_proxy_groups(&[mk(10)], &all, &[]);
        assert_eq!(out2[0]["interval"].as_i64(), Some(30));

        let (out3, _) = generate_proxy_groups(&[mk(120)], &all, &[]);
        assert_eq!(out3[0]["interval"].as_i64(), Some(120));
    }

    #[test]
    fn smart_group_is_select_with_trailing_hide_marker() {
        let all = vec![node("S_HK"), node("S_JP")];
        let mut g = group("Smart", &[], &[], None);
        g.smart = true;
        g.speedtest_url = "http://x".to_string();
        g.include = vec!["DIRECT".to_string()];
        let (out, _) = generate_proxy_groups(&[g], &all, &[]);
        assert_eq!(out[0]["type"].as_str(), Some("select"));
        assert!(out[0]["url"].is_badvalue(), "smart group should not have url-test field");
        let proxies: Vec<&str> = out[0]["proxies"]
            .as_vec()
            .unwrap()
            .iter()
            .filter_map(|p| p.as_str())
            .collect();

        assert_eq!(proxies.last(), Some(&SMART_HIDE_NODE));
        assert_eq!(proxies[0], "S_HK");
        assert!(proxies.contains(&"DIRECT"));
    }

    #[test]
    fn smart_pre_proxy_marker_in_payload_tail() {
        let all = vec![node("S_HK")];
        let mut g = group("Grp", &["HK"], &[], None);
        g.smart = true;
        g.use_pre_proxy = true;
        g.pre_proxy_group = "Pre".to_string();
        let (out, providers) = generate_proxy_groups(&[g], &all, &[]);
        assert_eq!(out[0]["type"].as_str(), Some("select"));

        assert!(out[0]["proxies"].is_badvalue());
        let payload = providers[&ystr("Grp=(Pre🔗Grp)")]["payload"].as_vec().unwrap();
        let last = payload.last().unwrap();
        assert_eq!(last["name"].as_str(), Some(SMART_HIDE_NODE));
        assert_eq!(last["type"].as_str(), Some("reject"));
        assert_eq!(payload[0]["name"].as_str(), Some("S_HK"));
    }

    #[test]
    fn pre_proxy_inline_provider() {
        let all = vec![node("S_HK")];
        let mut g = group("Grp", &["HK"], &[], None);
        g.use_pre_proxy = true;
        g.pre_proxy_group = "Pre".to_string();
        let (out, providers) = generate_proxy_groups(&[g], &all, &[]);

        assert!(out[0]["use"].as_vec().is_some(), "{:?}", out[0]);
        let pname = "Grp=(Pre🔗Grp)";
        assert_eq!(providers[&ystr(pname)]["type"].as_str(), Some("inline"));
        assert_eq!(
            providers[&ystr(pname)]["override"]["dialer-proxy"].as_str(),
            Some("Pre")
        );
    }
}
