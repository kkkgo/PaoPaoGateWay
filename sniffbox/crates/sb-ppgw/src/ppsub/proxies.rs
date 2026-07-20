// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::{SubResult, UserInfo, pp_log, pp_step, pp_warn, ystr};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use yaml_rust2::Yaml;

pub fn process_proxies(sub_results: &[SubResult], dns_burn: bool, ex_dns: &str) -> Vec<Yaml> {
    let dns_servers = collect_dns_servers(ex_dns);
    let ipv6 = crate::dnsutil::ipv6_enabled();
    let mut all: Vec<Yaml> = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut userinfo: Option<(UserInfo, String)> = None;

    let resolved = if dns_burn {
        let mut domains: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for r in sub_results.iter().filter(|r| r.success) {
            for p in &r.proxies {
                if let Some(server) = p["server"].as_str() {
                    if server.parse::<IpAddr>().is_err() && seen.insert(server.to_string()) {
                        domains.push(server.to_string());
                    }
                }
            }
        }
        if dns_servers.is_empty() {
            pp_warn(
                "dns_burn: no DNS server configured (dns_ip/ex_dns empty), skipping domain resolution",
            );
        } else {
            pp_step(&format!(
                "dns_burn: resolving {} unique domain server(s) via [{}]",
                domains.len(),
                dns_servers.join(", ")
            ));
        }
        let resolved = crate::dnsutil::resolve_domains_concurrent(&domains, &dns_servers, ipv6);
        log_resolved("dns_burn", &domains, &resolved);
        resolved
    } else {
        HashMap::new()
    };

    for r in sub_results {
        if !r.success {
            continue;
        }
        if userinfo.is_none() {
            if let Some(ui) = &r.userinfo {
                userinfo = Some((ui.clone(), r.name.clone()));
            }
        }
        for p in &r.proxies {
            if let Some(name) = p["name"].as_str() {
                used.insert(name.to_string());
            }
            all.push(p.clone());
            if dns_burn {
                burn_proxy(p, &resolved, &mut used, &mut all);
            }
        }
    }

    if dns_burn {
        for r in sub_results.iter().filter(|r| r.success) {
            sub_subdns_burn(r, ipv6, &resolved, &mut used, &mut all);
        }
    }

    if let Some((ui, sub_name)) = &userinfo {
        if let Some(template) = all.last().and_then(|y| y.as_hash()).cloned() {
            let gb = 1_073_741_824f64;
            let remaining = (ui.total - ui.upload - ui.download) as f64 / gb;
            let total = ui.total as f64 / gb;
            let expire_date = format_expire(ui.expire);

            let mut info_node = template;
            info_node.insert(
                ystr("name"),
                ystr(&format!(
                    "{sub_name}_{sub_name}: {remaining:.2}G/{total:.2}G@@{expire_date}"
                )),
            );

            let mut prefixed = vec![Yaml::Hash(info_node)];
            prefixed.append(&mut all);
            all = prefixed;
        }
    }

    let (subdns, others): (Vec<Yaml>, Vec<Yaml>) = all.into_iter().partition(|p| {
        p["name"]
            .as_str()
            .map(|n| n.contains("@subdns"))
            .unwrap_or(false)
    });
    let mut result = subdns;
    result.extend(others);
    result
}

fn log_resolved(tag: &str, domains: &[String], resolved: &HashMap<String, Vec<IpAddr>>) {
    for d in domains {
        match resolved.get(d) {
            Some(ips) if !ips.is_empty() => {
                let list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                pp_log(&format!("{tag}: {d} -> {}", list.join(", ")));
            }
            _ => pp_warn(&format!("{tag}: {d} -> FAILED (no answer)")),
        }
    }
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

fn sub_subdns_burn(
    r: &SubResult,
    ipv6: bool,
    burn: &HashMap<String, Vec<IpAddr>>,
    used: &mut HashSet<String>,
    all: &mut Vec<Yaml>,
) {
    let specs = sub_dns_servers(&r.raw_yaml);
    if specs.is_empty() {
        return;
    }

    let mut domains: Vec<String> = Vec::new();
    let mut domain_seen: HashSet<String> = HashSet::new();
    for p in &r.proxies {
        if let Some(server) = p["server"].as_str() {
            if server.parse::<IpAddr>().is_err() && domain_seen.insert(server.to_string()) {
                domains.push(server.to_string());
            }
        }
    }
    if domains.is_empty() {
        return;
    }
    pp_step(&format!(
        "[{}] subdns: resolving {} domain(s) via sub's own DNS [{}]",
        r.name,
        domains.len(),
        specs.join(", ")
    ));
    let resolved = resolve_domains_concurrent(&domains, &specs, ipv6);
    log_resolved(&format!("[{}] subdns", r.name), &domains, &resolved);

    let unique = subtract_known(resolved, burn, &format!("[{}] subdns", r.name));

    for p in &r.proxies {
        let Some(server) = p["server"].as_str() else {
            continue;
        };
        let Some(ips) = unique.get(server) else {
            continue;
        };
        let Some(ph) = p.as_hash() else {
            continue;
        };
        let base = p["name"].as_str().unwrap_or("").to_string();
        for ip in ips {
            let ipstr = ip.to_string();
            let uniq = generate_subdns_node_name(&base, &ipstr, used);
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

fn sub_dns_servers(raw_yaml: &str) -> Vec<String> {
    let Ok(docs) = yaml_rust2::YamlLoader::load_from_str(raw_yaml) else {
        return Vec::new();
    };
    let Some(doc) = docs.first() else {
        return Vec::new();
    };
    crate::dohdot::extract_dns_servers(&doc["dns"])
}

fn resolve_domains_concurrent(
    domains: &[String],
    specs: &[String],
    ipv6: bool,
) -> HashMap<String, Vec<IpAddr>> {
    use std::sync::Mutex;
    let out: Mutex<HashMap<String, Vec<IpAddr>>> = Mutex::new(HashMap::new());
    let out_ref = &out;
    for chunk in domains.chunks(16) {
        std::thread::scope(|s| {
            for domain in chunk {
                s.spawn(move || {
                    let ips = crate::dohdot::resolve_via_servers(domain, specs, ipv6);
                    if !ips.is_empty() {
                        out_ref.lock().unwrap().insert(domain.clone(), ips);
                    }
                });
            }
        });
    }
    out.into_inner().unwrap()
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

fn collect_dns_servers(ex_dns: &str) -> Vec<String> {
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

fn format_expire(expire: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(expire) {
        Ok(dt) => format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day()),
        Err(_) => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expire_date_format() {

        assert_eq!(format_expire(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn merge_without_dnsburn_and_virtual_nodes() {
        let r = SubResult {
            name: "S".to_string(),
            success: true,
            proxies: vec![node("S_A", "1.2.3.4"), node("S_B", "5.6.7.8")],
            userinfo: Some(UserInfo {
                total: 2 * 1_073_741_824,
                upload: 0,
                download: 1_073_741_824,
                expire: 1_700_000_000,
            }),
            raw_yaml: String::new(),
            error: String::new(),
        };
        let out = process_proxies(&[r], false, "");

        assert_eq!(out.len(), 3);
        let info = out[0]["name"].as_str().unwrap();
        assert!(info.starts_with("S_S: "), "merged node has <sub>_<sub> prefix: {info}");
        assert!(info.contains("1.00G/2.00G"), "remaining/total traffic: {info}");
        assert!(info.ends_with("@@2023-11-14"), "@@ separates expiry date: {info}");
        assert_eq!(out[1]["name"].as_str(), Some("S_A"));
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
                if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                    if let Ok(q) = sb_dns::message::parse_query(&buf[..n]) {
                        let _ = sock.send_to(&q.answer_a(Ipv4Addr::new(11, 1, 2, 3), 60), peer);
                    }
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
            userinfo: None,
            raw_yaml: raw,
            error: String::new(),
        };
        let mut used: HashSet<String> = HashSet::new();
        used.insert("S_HK".to_string());
        let mut all = vec![node("S_HK", "hk.example.com")];

        sub_subdns_burn(&r, false, &HashMap::new(), &mut used, &mut all);
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
                if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                    if let Ok(q) = sb_dns::message::parse_query(&buf[..n]) {
                        let _ = sock.send_to(&q.answer_a(Ipv4Addr::new(11, 1, 2, 3), 60), peer);
                    }
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

        sub_subdns_burn(&r, false, &HashMap::new(), &mut used, &mut all);
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
                if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                    if let Ok(q) = sb_dns::message::parse_query(&buf[..n]) {
                        query_count2.fetch_add(1, Ordering::Relaxed);
                        let _ = sock.send_to(&q.answer_a(Ipv4Addr::new(11, 1, 2, 3), 60), peer);
                    }
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
}
