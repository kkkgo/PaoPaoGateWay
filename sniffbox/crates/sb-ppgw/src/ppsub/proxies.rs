// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::hosts::Mapping;
use super::state::LEGACY_MARK;
use super::{LOG, SubResult, pp_log, pp_step, pp_warn, ystr};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use yaml_rust2::Yaml;

pub(crate) type Resolved = HashMap<String, Vec<IpAddr>>;

#[derive(Default)]
pub(crate) struct Resolution {

    pub burn: Resolved,

    pub subdns: HashMap<String, Resolved>,

    pub failed: HashMap<String, HashMap<String, Vec<String>>>,

    pub hosts: HashMap<String, Resolved>,
}

struct SubdnsJob {
    name: String,
    specs: Vec<String>,
    domains: Vec<String>,
}

pub(crate) fn build_proxies(
    sub_results: &[SubResult],
    res: &Resolution,
    dns_burn: bool,
) -> Vec<Yaml> {
    let mut all: Vec<Yaml> = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    let subs: Vec<&SubResult> = sub_results.iter().filter(|r| r.success).collect();

    let empty = Resolved::new();
    let views: Vec<(Resolved, Resolved)> = subs
        .iter()
        .map(|r| {
            if !dns_burn {
                return (Resolved::new(), Resolved::new());
            }
            let burn = fold_alias(r, &res.burn, "dns_burn");
            let own = res.subdns.get(&r.name).unwrap_or(&empty);
            let got = fold_alias(r, own, "sub's own DNS");
            let uniq = subtract_known(got, &burn, &format!("[{}] subdns", r.name));
            (burn, uniq)
        })
        .collect();

    for (r, (burn, _)) in subs.iter().zip(&views) {
        for p in &r.proxies {
            if let Some(name) = p["name"].as_str() {
                used.insert(name.to_string());
            }
            all.push(p.clone());
            if dns_burn {
                burn_proxy(p, burn, &mut used, &mut all);
            }
        }
    }

    if dns_burn {
        for (r, (_, uniq)) in subs.iter().zip(&views) {
            emit_subdns_nodes(r, uniq, &mut used, &mut all);
        }
    }

    let mut fixed: Vec<Yaml> = Vec::new();
    if dns_burn {
        for (r, (burn, uniq)) in subs.iter().zip(&views) {
            if let Some(ips) = res.hosts.get(&r.name) {
                let left = static_unique(&r.name, ips, burn, uniq);
                emit_hosts_nodes(r, &left, &mut used, &mut fixed);
            }
        }
    }

    let (subdns, others): (Vec<Yaml>, Vec<Yaml>) = all.into_iter().partition(|p| {
        p["name"]
            .as_str()
            .map(|n| n.contains("@subdns"))
            .unwrap_or(false)
    });
    let mut result = subdns;
    result.extend(fixed);
    result.extend(others);
    result
}

fn fold_alias(r: &SubResult, map: &Resolved, source: &str) -> Resolved {
    let mut out = Resolved::new();
    for d in sub_domains(r) {
        let mut ips = map.get(&d).cloned().unwrap_or_default();
        if let Some(t) = r.hosts.alias_of(&d) {
            let own = ips.len();
            for ip in map.get(t).into_iter().flatten() {
                if !ips.contains(ip) {
                    ips.push(*ip);
                }
            }
            if ips.len() > own {
                pp_log(&format!(
                    "[{}] hosts: {d} -> alias {t} adds {} IP ({source})",
                    r.name,
                    ips.len() - own
                ));
            }
        }
        if !ips.is_empty() {
            out.insert(d, ips);
        }
    }
    out
}

fn static_unique(sub: &str, fixed: &Resolved, burn: &Resolved, subdns: &Resolved) -> Resolved {
    let mut out = Resolved::new();
    for (d, ips) in fixed {
        let known = |ip: &IpAddr| {
            burn.get(d).is_some_and(|v| v.contains(ip))
                || subdns.get(d).is_some_and(|v| v.contains(ip))
        };
        let left: Vec<IpAddr> = ips.iter().filter(|ip| !known(ip)).copied().collect();
        if left.is_empty() {
            pp_log(&format!(
                "[{sub}] hosts: {d} -> all {} static IP already resolved by DNS, no @hosts node",
                ips.len()
            ));
            continue;
        }
        out.insert(d.clone(), left);
    }
    out
}

pub(crate) fn static_hosts(sub_results: &[SubResult], ipv6: bool) -> HashMap<String, Resolved> {
    let mut out = HashMap::new();
    for r in sub_results.iter().filter(|r| r.success) {
        let mut m = Resolved::new();
        for (d, mapping) in &r.hosts.map {
            if let Mapping::Ips(list) = mapping {
                let ips = usable_static(list, ipv6);
                if !ips.is_empty() {
                    m.insert(d.clone(), ips);
                }
            }
        }
        if !m.is_empty() {
            out.insert(r.name.clone(), m);
        }
    }
    out
}

fn usable_static(list: &[IpAddr], ipv6: bool) -> Vec<IpAddr> {
    list.iter()
        .copied()
        .filter(|ip| (ipv6 || ip.is_ipv4()) && crate::fallback::is_usable_node_ip(*ip))
        .collect()
}

fn log_hosts(r: &SubResult, ipv6: bool) {
    let tag = format!("[{}] hosts", r.name);
    for (d, m) in &r.hosts.map {
        match m {
            Mapping::Alias(t) => {
                pp_log(&format!(
                    "{tag}: {d} -> alias {t} (resolved like a node domain)"
                ));
            }
            Mapping::Ips(list) => {
                let shown: Vec<String> = list.iter().map(IpAddr::to_string).collect();
                let dropped = list.len() - usable_static(list, ipv6).len();
                if dropped == list.len() {
                    pp_warn(&format!(
                        "{tag}: {d} -> static {} unusable (fakeip/reserved/IPv6 off), ignored",
                        shown.join(", ")
                    ));
                } else if dropped > 0 {
                    pp_log(&format!(
                        "{tag}: {d} -> static {} ({dropped} unusable dropped)",
                        shown.join(", ")
                    ));
                } else {
                    pp_log(&format!("{tag}: {d} -> static {}", shown.join(", ")));
                }
            }
        }
    }
    for (d, why) in &r.hosts.ignored {
        pp_warn(&format!("{tag}: {d} ignored ({why})"));
    }
    if r.hosts.skipped > 0 {
        pp_warn(&format!(
            "{tag}: {} entr(ies) with an invalid key skipped",
            r.hosts.skipped
        ));
    }
}

pub(crate) fn resolve_all(
    sub_results: &[SubResult],
    dns_servers: &[String],
    ipv6: bool,
) -> Resolution {
    for r in sub_results.iter().filter(|r| r.success) {
        log_hosts(r, ipv6);
    }

    let mut domains: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for r in sub_results.iter().filter(|r| r.success) {
        for d in sub_domains(r) {
            if seen.insert(d.clone()) {
                domains.push(d);
            }
        }
    }
    let servers = domains.len();
    for r in sub_results.iter().filter(|r| r.success) {
        for t in r.hosts.alias_targets() {
            if seen.insert(t.clone()) {
                domains.push(t);
            }
        }
    }
    let aliases = domains.len() - servers;
    if dns_servers.is_empty() {
        pp_warn(
            "dns_burn: no DNS server configured (dns_ip/ex_dns empty), skipping domain resolution",
        );
    } else {
        pp_step(&format!(
            "dns_burn: resolving {servers} unique domain server(s){} via [{}]",
            if aliases > 0 {
                format!(" + {aliases} hosts alias target(s)")
            } else {
                String::new()
            },
            dns_servers.join(", ")
        ));
    }

    let jobs: Vec<SubdnsJob> = sub_results
        .iter()
        .filter(|r| r.success)
        .filter_map(|r| {
            let specs = sub_dns_servers(&r.raw_yaml);
            let domains = lookup_domains(r);
            (!specs.is_empty() && !domains.is_empty()).then(|| SubdnsJob {
                name: r.name.clone(),
                specs,
                domains,
            })
        })
        .collect();
    for j in &jobs {
        pp_step(&format!(
            "[{}] subdns: resolving {} domain(s) via sub's own DNS [{}]",
            j.name,
            j.domains.len(),
            j.specs.join(", ")
        ));
    }

    type Failed = HashMap<String, HashMap<String, Vec<String>>>;
    let subdns: std::sync::Mutex<HashMap<String, Resolved>> = std::sync::Mutex::new(HashMap::new());

    let failed: std::sync::Mutex<Failed> = std::sync::Mutex::new(HashMap::new());
    let mut resolved = HashMap::new();
    std::thread::scope(|s| {
        let sub_ref = &subdns;
        let failed_ref = &failed;
        for j in &jobs {
            s.spawn(move || {
                let tag = format!("[{}] subdns", j.name);
                let per_domain: std::sync::Mutex<HashMap<String, Vec<String>>> =
                    std::sync::Mutex::new(HashMap::new());
                let got = crate::resolvepool::resolve_batch(
                    LOG,
                    &tag,
                    &j.domains,
                    crate::resolvepool::Budget::subdns(),
                    |domain, dl| {
                        let (outcome, specs) = crate::dohdot::resolve_via_servers_detailed(
                            domain, &j.specs, ipv6, dl, true,
                        );
                        let bad: Vec<String> = specs
                            .into_iter()
                            .filter(|s| !s.ok)
                            .map(|s| s.spec)
                            .collect();
                        if !bad.is_empty() {
                            per_domain.lock().unwrap().insert(domain.to_string(), bad);
                        }
                        outcome
                    },
                );
                let missing = j.domains.iter().filter(|d| !got.contains_key(*d)).count();
                if missing > 0 {
                    pp_warn(&format!(
                        "[{}] subdns: {missing}/{} domain(s) unresolved",
                        j.name,
                        j.domains.len()
                    ));
                }
                let per_domain = per_domain.into_inner().unwrap();
                if !per_domain.is_empty() {
                    let holes: usize = per_domain.values().map(|v| v.len()).sum();
                    pp_warn(&format!(
                        "[{}] subdns: {holes} (domain, DNS) pair(s) unanswered by the sub's own DNS",
                        j.name
                    ));
                    failed_ref.lock().unwrap().insert(j.name.clone(), per_domain);
                }
                sub_ref.lock().unwrap().insert(j.name.clone(), got);
            });
        }

        resolved =
            crate::dnsutil::resolve_domains_logged(LOG, "dns_burn", &domains, dns_servers, ipv6);
    });

    let _ = std::fs::remove_file(LEGACY_MARK);

    Resolution {
        burn: resolved,
        subdns: subdns.into_inner().unwrap(),
        failed: failed.into_inner().unwrap(),
        hosts: static_hosts(sub_results, ipv6),
    }
}

pub(crate) fn sub_domains(r: &SubResult) -> Vec<String> {
    server_domains(&r.proxies)
}

pub(crate) fn lookup_domains(r: &SubResult) -> Vec<String> {
    let mut out = sub_domains(r);
    for t in r.hosts.alias_targets() {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

pub(crate) fn server_domains(proxies: &[Yaml]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for p in proxies {
        if let Some(server) = p["server"].as_str()
            && server.parse::<IpAddr>().is_err()
            && seen.insert(server.to_string())
        {
            out.push(server.to_string());
        }
    }
    out
}

fn burn_proxy(
    p: &Yaml,
    resolved: &HashMap<String, Vec<IpAddr>>,
    used: &mut HashSet<String>,
    all: &mut Vec<Yaml>,
) {
    let Some(server) = p["server"].as_str() else {
        return;
    };
    if server.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    let Some(ph) = p.as_hash() else {
        return;
    };
    let base = p["name"].as_str().unwrap_or("").to_string();
    let ips = resolved.get(server).cloned().unwrap_or_default();
    for ip in ips {
        let ipstr = ip.to_string();
        let uniq = crate::yamltx::generate_node_name(&base, &ipstr, used);
        used.insert(uniq.clone());
        let mut np = ph.clone();
        np.insert(ystr("name"), ystr(&uniq));
        np.insert(ystr("server"), ystr(&ipstr));
        all.push(Yaml::Hash(np));
    }
}

pub(crate) fn emit_subdns_nodes(
    r: &SubResult,
    unique: &HashMap<String, Vec<IpAddr>>,
    used: &mut HashSet<String>,
    all: &mut Vec<Yaml>,
) {
    emit_copies(r, unique, used, all, generate_subdns_node_name);
}

fn emit_hosts_nodes(
    r: &SubResult,
    fixed: &HashMap<String, Vec<IpAddr>>,
    used: &mut HashSet<String>,
    all: &mut Vec<Yaml>,
) {
    emit_copies(r, fixed, used, all, |base, ip, used| {
        crate::yamltx::generate_node_name_with_prefix(base, ip, used, "hosts")
    });
}

fn emit_copies(
    r: &SubResult,
    by_server: &HashMap<String, Vec<IpAddr>>,
    used: &mut HashSet<String>,
    all: &mut Vec<Yaml>,
    name_of: impl Fn(&str, &str, &HashSet<String>) -> String,
) {

    for p in &r.proxies {
        let Some(server) = p["server"].as_str() else {
            continue;
        };
        let Some(ips) = by_server.get(server) else {
            continue;
        };
        let Some(ph) = p.as_hash() else {
            continue;
        };
        let base = p["name"].as_str().unwrap_or("").to_string();
        for ip in ips {
            let ipstr = ip.to_string();
            let uniq = name_of(&base, &ipstr, used);
            used.insert(uniq.clone());
            let mut np = ph.clone();
            np.insert(ystr("name"), ystr(&uniq));
            np.insert(ystr("server"), ystr(&ipstr));
            all.push(Yaml::Hash(np));
        }
    }
}

pub(crate) fn subtract_known(
    resolved: HashMap<String, Vec<IpAddr>>,
    known: &HashMap<String, Vec<IpAddr>>,
    tag: &str,
) -> HashMap<String, Vec<IpAddr>> {
    let mut out = HashMap::new();
    for (domain, ips) in resolved {
        let total = ips.len();
        let empty: Vec<IpAddr> = Vec::new();
        let already = known.get(&domain).unwrap_or(&empty);
        let uniq: Vec<IpAddr> = ips.into_iter().filter(|ip| !already.contains(ip)).collect();
        if uniq.is_empty() {
            if total > 0 {
                pp_log(&format!(
                    "{tag}: {domain} -> all {total} IP already covered by dns_burn, no @subdns node"
                ));
            }
            continue;
        }
        if uniq.len() < total {
            pp_log(&format!(
                "{tag}: {domain} -> {} of {total} IP unique to sub's own DNS",
                uniq.len()
            ));
        }
        out.insert(domain, uniq);
    }
    out
}

pub(crate) fn sub_dns_servers(raw_yaml: &str) -> Vec<String> {
    let Ok(docs) = yaml_rust2::YamlLoader::load_from_str(raw_yaml) else {
        return Vec::new();
    };
    let Some(doc) = docs.first() else {
        return Vec::new();
    };
    crate::dohdot::extract_dns_servers(&doc["dns"])
}

fn generate_subdns_node_name(base: &str, ip: &str, used: &HashSet<String>) -> String {
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
    let candidate = format!("{base}@subdns{suffix}");
    if !used.contains(&candidate) {
        return candidate;
    }
    let mut counter = 0i64;
    loop {
        let cand = format!("{candidate}{}", crate::yamltx::generate_suffix(counter));
        if !used.contains(&cand) {
            return cand;
        }
        counter += 1;
    }
}

pub(crate) fn collect_dns_servers(ex_dns: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let dns_ip = std::env::var("dns_ip").unwrap_or_default();
    let dns_port = std::env::var("dns_port").unwrap_or_default();
    if !dns_ip.is_empty() {
        if dns_port.is_empty() {
            servers.push(dns_ip);
        } else {
            servers.push(format!("{dns_ip}:{dns_port}"));
        }
    }
    for s in ex_dns.split(',') {
        let s = s.trim();
        if !s.is_empty() {
            servers.push(s.to_string());
        }
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_proxies(sub_results: &[SubResult], dns_burn: bool, ex_dns: &str) -> Vec<Yaml> {
        let res = if dns_burn {
            let dns_servers = collect_dns_servers(ex_dns);
            resolve_all(sub_results, &dns_servers, crate::dnsutil::ipv6_enabled())
        } else {
            Resolution::default()
        };
        build_proxies(sub_results, &res, dns_burn)
    }

    fn subdns_burn_one(
        r: &SubResult,
        ipv6: bool,
        burn: &HashMap<String, Vec<IpAddr>>,
        used: &mut HashSet<String>,
        all: &mut Vec<Yaml>,
    ) {
        let specs = sub_dns_servers(&r.raw_yaml);
        let domains = sub_domains(r);
        if specs.is_empty() || domains.is_empty() {
            return;
        }
        let got = crate::resolvepool::resolve_batch(
            LOG,
            "subdns",
            &domains,
            crate::resolvepool::Budget::subdns(),
            |domain, dl| crate::dohdot::resolve_via_servers_traced(domain, &specs, ipv6, dl),
        );
        let uniq = subtract_known(got, burn, "subdns");
        emit_subdns_nodes(r, &uniq, used, all);
    }

    #[test]
    fn userinfo_never_becomes_a_node() {
        let r = SubResult {
            name: "S".to_string(),
            success: true,
            proxies: vec![node("S_A", "1.2.3.4"), node("S_B", "5.6.7.8")],
            hosts: Default::default(),
            userinfo: Some(super::super::UserInfo {
                total: 2 * 1_073_741_824,
                upload: 0,
                download: 1_073_741_824,
                expire: 1_700_000_000,
            }),
            raw_yaml: String::new(),
            error: String::new(),
        };
        let out = process_proxies(&[r], false, "");
        let names: Vec<&str> = out.iter().filter_map(|p| p["name"].as_str()).collect();
        assert_eq!(
            names,
            vec!["S_A", "S_B"],
            "usage goes to the subinfo file, not into the node list"
        );
    }

    fn node(name: &str, server: &str) -> Yaml {
        let mut h = yaml_rust2::yaml::Hash::new();
        h.insert(ystr("name"), ystr(name));
        h.insert(ystr("server"), ystr(server));
        h.insert(ystr("type"), ystr("ss"));
        Yaml::Hash(h)
    }

    #[test]
    fn subtract_known_keeps_only_unique_ips() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut resolved = HashMap::new();
        resolved.insert(
            "a.com".to_string(),
            vec![ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")],
        );
        resolved.insert("b.com".to_string(), vec![ip("4.4.4.4")]);
        resolved.insert("c.com".to_string(), vec![ip("5.5.5.5")]);

        let mut known = HashMap::new();
        known.insert("a.com".to_string(), vec![ip("1.1.1.1"), ip("3.3.3.3")]);
        known.insert("b.com".to_string(), vec![ip("4.4.4.4")]);

        let out = subtract_known(resolved, &known, "test");
        assert_eq!(out.get("a.com"), Some(&vec![ip("2.2.2.2")]), "{out:?}");
        assert_eq!(out.get("b.com"), None, "fully covered domain is dropped");
        assert_eq!(out.get("c.com"), Some(&vec![ip("5.5.5.5")]), "{out:?}");
    }

    #[test]
    fn subdns_node_name() {
        let used = HashSet::new();
        assert_eq!(
            generate_subdns_node_name("HK", "1.2.3.4", &used),
            "HK@subdns4"
        );
        assert_eq!(
            generate_subdns_node_name("HK", "2001:db8::beef", &used),
            "HK@subdnsbeef"
        );
        let mut u = HashSet::new();
        u.insert("HK@subdns4".to_string());
        assert_eq!(
            generate_subdns_node_name("HK", "9.9.9.4", &u),
            "HK@subdns4A"
        );
    }

    #[test]
    fn sub_dns_servers_from_dns_field() {
        let raw = "dns:\n  nameserver:\n    - https://doh.pub/dns-query\n    - tls://dot.pub:853\n    - 223.5.5.5\nproxies:\n  - {name: A}\n";
        let s = sub_dns_servers(raw);
        assert_eq!(
            s,
            vec![
                "https://doh.pub/dns-query",
                "tls://dot.pub:853",
                "223.5.5.5"
            ]
        );
        assert!(
            sub_dns_servers("proxies:\n  - {name: A}\n").is_empty(),
            "no dns section → empty"
        );
    }

    #[test]
    fn subdns_burn_resolves_via_sub_dns() {
        use std::net::{Ipv4Addr, UdpSocket};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let port = sock.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let h = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = sock.recv_from(&mut buf)
                    && let Ok(q) = sb_dns::message::parse_query(&buf[..n])
                {
                    let _ = sock.send_to(&q.answer_a(Ipv4Addr::new(11, 1, 2, 3), 60), peer);
                }
            }
        });

        let raw = format!(
            "dns:\n  nameserver:\n    - 127.0.0.1:{port}\nproxies:\n  - {{name: S_HK, server: hk.example.com}}\n"
        );
        let r = SubResult {
            name: "S".to_string(),
            success: true,
            proxies: vec![node("S_HK", "hk.example.com")],
            hosts: Default::default(),
            userinfo: None,
            raw_yaml: raw,
            error: String::new(),
        };
        let mut used: HashSet<String> = HashSet::new();
        used.insert("S_HK".to_string());
        let mut all = vec![node("S_HK", "hk.example.com")];

        subdns_burn_one(&r, false, &HashMap::new(), &mut used, &mut all);
        stop.store(true, Ordering::Relaxed);
        let _ = h.join();

        let subdns: Vec<&str> = all
            .iter()
            .filter(|p| {
                p["name"]
                    .as_str()
                    .map(|n| n.contains("@subdns"))
                    .unwrap_or(false)
            })
            .filter_map(|p| p["server"].as_str())
            .collect();
        assert_eq!(
            subdns,
            vec!["11.1.2.3"],
            "should generate @subdns node server=11.1.2.3: {all:?}"
        );
    }

    #[test]
    fn subdns_burn_generates_per_node_not_per_ip() {
        use std::net::{Ipv4Addr, UdpSocket};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let port = sock.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let h = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = sock.recv_from(&mut buf)
                    && let Ok(q) = sb_dns::message::parse_query(&buf[..n])
                {
                    let _ = sock.send_to(&q.answer_a(Ipv4Addr::new(11, 1, 2, 3), 60), peer);
                }
            }
        });

        let raw = format!(
            "dns:\n  nameserver:\n    - 127.0.0.1:{port}\nproxies:\n  - {{name: HK01, server: hk.example.com}}\n  - {{name: HK02, server: hk.example.com}}\n"
        );
        let r = SubResult {
            name: "S".to_string(),
            success: true,
            proxies: vec![
                node("HK01", "hk.example.com"),
                node("HK02", "hk.example.com"),
            ],
            hosts: Default::default(),
            userinfo: None,
            raw_yaml: raw,
            error: String::new(),
        };
        let mut used: HashSet<String> = HashSet::new();
        used.insert("HK01".to_string());
        used.insert("HK02".to_string());
        let mut all = vec![
            node("HK01", "hk.example.com"),
            node("HK02", "hk.example.com"),
        ];

        subdns_burn_one(&r, false, &HashMap::new(), &mut used, &mut all);
        stop.store(true, Ordering::Relaxed);
        let _ = h.join();

        let subdns_names: Vec<&str> = all
            .iter()
            .filter(|p| {
                p["name"]
                    .as_str()
                    .map(|n| n.contains("@subdns"))
                    .unwrap_or(false)
            })
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert_eq!(
            subdns_names,
            vec!["HK01@subdns3", "HK02@subdns3"],
            "both nodes for the same domain should generate @subdns copies: {all:?}"
        );
    }

    #[test]
    fn exdns_burn_batches_unique_domains() {
        use std::net::{Ipv4Addr, UdpSocket};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let port = sock.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let query_count = Arc::new(AtomicUsize::new(0));
        let query_count2 = Arc::clone(&query_count);
        let h = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = sock.recv_from(&mut buf)
                    && let Ok(q) = sb_dns::message::parse_query(&buf[..n])
                {
                    query_count2.fetch_add(1, Ordering::Relaxed);
                    let _ = sock.send_to(&q.answer_a(Ipv4Addr::new(11, 1, 2, 3), 60), peer);
                }
            }
        });

        let r = SubResult {
            name: "S".to_string(),
            success: true,
            proxies: vec![
                node("HK01", "hk.example.com"),
                node("HK02", "hk.example.com"),
            ],
            hosts: Default::default(),
            userinfo: None,
            raw_yaml: String::new(),
            error: String::new(),
        };
        let out = process_proxies(&[r], true, &format!("127.0.0.1:{port}"));
        stop.store(true, Ordering::Relaxed);
        let _ = h.join();

        let ip_nodes: Vec<&str> = out
            .iter()
            .filter(|p| !p["name"].as_str().unwrap_or("").contains("@subdns"))
            .filter(|p| p["server"].as_str() == Some("11.1.2.3"))
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert_eq!(
            ip_nodes,
            vec!["HK01@3", "HK02@3"],
            "both nodes for the same domain should generate @IP variants: {out:?}"
        );
        assert_eq!(
            query_count.load(Ordering::Relaxed),
            1,
            "same domain should be queried only once"
        );
    }

    fn sub_from(name: &str, yaml: &str) -> SubResult {
        let (proxies, hosts) = super::super::sub::parse_payload(yaml, name);
        SubResult {
            name: name.to_string(),
            success: true,
            proxies,
            hosts,
            userinfo: None,
            raw_yaml: yaml.to_string(),
            error: String::new(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn table(entries: &[(&str, &[&str])]) -> Resolved {
        entries
            .iter()
            .map(|(d, ips)| (d.to_string(), ips.iter().map(|s| ip(s)).collect()))
            .collect()
    }

    fn name_server(out: &[Yaml]) -> Vec<(String, String)> {
        out.iter()
            .map(|p| {
                (
                    p["name"].as_str().unwrap_or("").to_string(),
                    p["server"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, s)| (n.to_string(), s.to_string()))
            .collect()
    }

    #[test]
    fn alias_rides_dns_nodes_and_only_static_becomes_hosts() {
        let a = sub_from(
            "A",
            "hosts:\n  hk.example.com: entry.example.net\n  jp.example.com: [12.0.0.7, 11.0.0.2, 127.0.0.1]\nproxies:\n  - {name: HK, server: hk.example.com, type: ss}\n  - {name: JP, server: jp.example.com, type: ss}\n",
        );
        let res = Resolution {
            burn: table(&[
                ("hk.example.com", &["11.0.0.1"]),
                ("entry.example.net", &["11.0.0.1", "11.0.0.3"]),
                ("jp.example.com", &["11.0.0.2"]),
            ]),
            subdns: [(
                "A".to_string(),
                table(&[("entry.example.net", &["11.0.1.3"])]),
            )]
            .into_iter()
            .collect(),
            hosts: static_hosts(std::slice::from_ref(&a), false),
            ..Default::default()
        };
        let out = build_proxies(&[a], &res, true);
        assert_eq!(
            name_server(&out),
            pairs(&[
                ("A_HK@subdns3", "11.0.1.3"),
                ("A_JP@hosts7", "12.0.0.7"),
                ("A_HK", "hk.example.com"),
                ("A_HK@1", "11.0.0.1"),
                ("A_HK@3", "11.0.0.3"),
                ("A_JP", "jp.example.com"),
                ("A_JP@2", "11.0.0.2"),
            ])
        );
    }

    #[test]
    fn existing_node_names_keep_their_addresses() {
        let plain = sub_from(
            "A",
            "proxies:\n  - {name: HK, server: hk.example.com, type: ss}\n",
        );
        let aliased = sub_from(
            "A",
            "hosts:\n  hk.example.com: entry.example.net\nproxies:\n  - {name: HK, server: hk.example.com, type: ss}\n",
        );
        let res = Resolution {
            burn: table(&[
                ("hk.example.com", &["11.0.0.4"]),
                ("entry.example.net", &["11.0.9.4"]),
            ]),
            ..Default::default()
        };
        let before = name_server(&build_proxies(&[plain], &res, true));
        let after = name_server(&build_proxies(&[aliased], &res, true));
        assert_eq!(
            before,
            pairs(&[("A_HK", "hk.example.com"), ("A_HK@4", "11.0.0.4")])
        );
        assert_eq!(
            after,
            pairs(&[
                ("A_HK", "hk.example.com"),
                ("A_HK@4", "11.0.0.4"),
                ("A_HK@4A", "11.0.9.4"),
            ]),
            "the alias only appends"
        );
    }

    #[test]
    fn hosts_apply_only_to_their_own_subscription() {
        let a = sub_from(
            "A",
            "hosts:\n  shared.example.com: 12.0.0.1\n  x.example.com: ta.example.net\nproxies:\n  - {name: S, server: shared.example.com, type: ss}\n  - {name: X, server: x.example.com, type: ss}\n",
        );
        let b = sub_from(
            "B",
            "hosts:\n  shared.example.com: 12.0.0.2\nproxies:\n  - {name: S, server: shared.example.com, type: ss}\n  - {name: X, server: x.example.com, type: ss}\n",
        );
        let subs = [a, b];
        let res = Resolution {
            burn: table(&[("ta.example.net", &["11.0.0.5"])]),
            hosts: static_hosts(&subs, false),
            ..Default::default()
        };
        let got = name_server(&build_proxies(&subs, &res, true));
        assert_eq!(
            got,
            pairs(&[
                ("A_S@hosts1", "12.0.0.1"),
                ("B_S@hosts2", "12.0.0.2"),
                ("A_S", "shared.example.com"),
                ("A_X", "x.example.com"),
                ("A_X@5", "11.0.0.5"),
                ("B_S", "shared.example.com"),
                ("B_X", "x.example.com"),
            ]),
            "B never sees A's alias nor A's static address"
        );
    }

    #[test]
    fn dns_burn_off_ignores_hosts() {
        let a = sub_from(
            "A",
            "hosts:\n  hk.example.com: 12.0.0.1\nproxies:\n  - {name: HK, server: hk.example.com, type: ss}\n",
        );
        let res = Resolution {
            hosts: static_hosts(std::slice::from_ref(&a), false),
            ..Default::default()
        };
        assert_eq!(
            name_server(&build_proxies(&[a], &res, false)),
            pairs(&[("A_HK", "hk.example.com")])
        );
    }

    #[test]
    fn static_hosts_keep_only_usable_addresses() {
        let a = sub_from(
            "A",
            "hosts:\n  hk.example.com: ['127.0.0.1', '2606:4700::1111', 7.1.2.3, 12.0.0.1]\n  jp.example.com: 0.0.0.0\n  us.example.com: entry.example.net\nproxies:\n  - {name: HK, server: hk.example.com}\n  - {name: JP, server: jp.example.com}\n  - {name: US, server: us.example.com}\n",
        );
        let subs = std::slice::from_ref(&a);
        let v4 = static_hosts(subs, false);
        assert_eq!(
            v4["A"],
            table(&[("hk.example.com", &["12.0.0.1"])]),
            "loopback/fakeip dropped, v6 dropped while IPv6 is off, aliases are not static"
        );
        let v6 = static_hosts(subs, true);
        assert_eq!(
            v6["A"],
            table(&[("hk.example.com", &["2606:4700::1111", "12.0.0.1"])])
        );
        assert!(static_hosts(&[sub_from("B", "proxies: []")], true).is_empty());
    }

    #[test]
    fn lookup_domains_appends_alias_targets_once() {
        let a = sub_from(
            "A",
            "hosts:\n  a.example.com: t.example.net\n  b.example.com: t.example.net\n  c.example.com: a.example.com\nproxies:\n  - {name: A, server: a.example.com}\n  - {name: B, server: b.example.com}\n  - {name: C, server: c.example.com}\n  - {name: T, server: t.example.net}\n",
        );
        assert_eq!(
            lookup_domains(&a),
            vec![
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "t.example.net",
            ],
            "a target that is itself a node domain is not repeated"
        );
        let b = sub_from(
            "B",
            "hosts:\n  a.example.com: t.example.net\n  b.example.com: t.example.net\nproxies:\n  - {name: A, server: a.example.com}\n  - {name: B, server: b.example.com}\n  - {name: I, server: 1.2.3.4}\n",
        );
        assert_eq!(
            lookup_domains(&b),
            vec!["a.example.com", "b.example.com", "t.example.net"],
            "alias targets follow the node domains, once each"
        );
    }

    struct MockDns {
        port: u16,
        hits: std::sync::Arc<std::sync::Mutex<HashMap<String, usize>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl MockDns {
        fn start(answers: &[(&str, &str)], fallback_ip: &str) -> Self {
            use std::net::{Ipv4Addr, UdpSocket};
            use std::sync::atomic::Ordering;
            let answers: HashMap<String, Ipv4Addr> = answers
                .iter()
                .map(|(d, i)| (d.to_string(), i.parse().unwrap()))
                .collect();
            let fallback_ip: Ipv4Addr = fallback_ip.parse().unwrap();
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(std::time::Duration::from_millis(50)))
                .unwrap();
            let port = sock.local_addr().unwrap().port();
            let hits = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (hits2, stop2) = (hits.clone(), stop.clone());
            let handle = std::thread::spawn(move || {
                let mut buf = [0u8; 512];
                while !stop2.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    let Ok(q) = sb_dns::message::parse_query(&buf[..n]) else {
                        continue;
                    };
                    let name = q.name.trim_end_matches('.').to_lowercase();
                    *hits2.lock().unwrap().entry(name.clone()).or_insert(0) += 1;
                    let ip = answers.get(&name).copied().unwrap_or(fallback_ip);
                    let _ = sock.send_to(&q.answer_a(ip, 60), peer);
                }
            });
            Self {
                port,
                hits,
                stop,
                handle: Some(handle),
            }
        }

        fn hits(&self, name: &str) -> usize {
            self.hits.lock().unwrap().get(name).copied().unwrap_or(0)
        }
    }

    impl Drop for MockDns {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    #[test]
    fn alias_targets_go_through_dns_burn_and_the_subs_own_dns() {
        let burn = MockDns::start(
            &[
                ("hk.example.com", "11.0.0.1"),
                ("entry.example.net", "11.0.0.3"),
            ],
            "11.0.0.9",
        );
        let own = MockDns::start(
            &[
                ("hk.example.com", "11.0.0.1"),
                ("entry.example.net", "11.0.1.3"),
            ],
            "11.0.0.9",
        );
        let a = sub_from(
            "A",
            &format!(
                "dns:\n  nameserver:\n    - 127.0.0.1:{}\nhosts:\n  hk.example.com: entry.example.net\nproxies:\n  - {{name: HK, server: hk.example.com, type: ss}}\n",
                own.port
            ),
        );
        let res = resolve_all(
            std::slice::from_ref(&a),
            &[format!("127.0.0.1:{}", burn.port)],
            false,
        );
        assert_eq!(
            res.burn.get("entry.example.net"),
            Some(&vec![ip("11.0.0.3")])
        );
        assert_eq!(
            res.subdns["A"].get("entry.example.net"),
            Some(&vec![ip("11.0.1.3")])
        );
        assert_eq!(burn.hits("entry.example.net"), 1, "dns_burn asked once");
        assert_eq!(own.hits("entry.example.net"), 1, "sub's own DNS asked once");
        assert_eq!(
            burn.hits("hk.example.com"),
            1,
            "the node domain is still resolved"
        );

        let out = name_server(&build_proxies(&[a], &res, true));
        assert_eq!(
            out,
            pairs(&[
                ("A_HK@subdns3", "11.0.1.3"),
                ("A_HK", "hk.example.com"),
                ("A_HK@1", "11.0.0.1"),
                ("A_HK@3", "11.0.0.3"),
            ])
        );
    }
}
