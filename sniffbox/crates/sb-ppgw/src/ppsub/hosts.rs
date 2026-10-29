// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use yaml_rust2::Yaml;

const MAX_HOPS: usize = 8;

const SEARCH_STEPS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mapping {

    Ips(Vec<IpAddr>),

    Alias(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SubHosts {

    pub map: BTreeMap<String, Mapping>,

    pub ignored: BTreeMap<String, &'static str>,

    pub skipped: usize,
}

impl SubHosts {

    pub(crate) fn alias_of(&self, server: &str) -> Option<&str> {
        match self.map.get(server) {
            Some(Mapping::Alias(t)) => Some(t),
            _ => None,
        }
    }

    pub(crate) fn alias_targets(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.map
            .values()
            .filter_map(|m| match m {
                Mapping::Alias(t) if seen.insert(t.as_str()) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }
}

pub(crate) fn parse(doc: &Yaml, servers: &[String]) -> SubHosts {
    let Some(entries) = doc["hosts"].as_hash() else {
        return SubHosts::default();
    };
    let mut table = Table::default();
    let mut out = SubHosts::default();
    for (k, v) in entries {
        if !k.as_str().is_some_and(|key| table.insert(key, v)) {
            out.skipped += 1;
        }
    }
    for s in servers {
        match table.resolve(s) {
            None => {}
            Some(Found::Ips(ips)) => {
                out.map.insert(s.clone(), Mapping::Ips(ips));
            }
            Some(Found::Alias(t)) => {
                out.map.insert(s.clone(), Mapping::Alias(t));
            }
            Some(Found::Ignored(why)) => {
                out.ignored.insert(s.clone(), why);
            }
        }
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
enum Found {
    Ips(Vec<IpAddr>),
    Alias(String),
    Ignored(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
enum Value {
    Ips(Vec<IpAddr>),
    Alias(String),
    Unsupported(&'static str),
}

#[derive(Default)]
struct Table<'a> {
    exact: HashMap<String, &'a Yaml>,
    wild: Node<'a>,
}

impl<'a> Table<'a> {

    fn insert(&mut self, key: &str, v: &'a Yaml) -> bool {
        let Some(lower) = normalize(key) else {
            return false;
        };
        let parts: Vec<&str> = lower.split('.').collect();
        if parts[0] == "+" {
            self.put(&parts[1..], v);
            let mut dot = parts.clone();
            dot[0] = "";
            self.put(&dot, v);
        } else {
            self.put(&parts, v);
        }
        true
    }

    fn put(&mut self, labels: &[&str], v: &'a Yaml) {
        if labels.is_empty() {
            return;
        }
        if labels[0].is_empty() || labels.contains(&"*") {
            self.wild.insert(labels, v);
        } else {
            self.exact.insert(labels.join("."), v);
        }
    }

    fn get(&self, domain: &str) -> Option<&'a Yaml> {
        let lower = normalize(domain)?;
        if lower.starts_with('.') {
            return None;
        }
        if let Some(v) = self.exact.get(&lower).copied() {
            return Some(v);
        }
        let labels: Vec<&str> = lower.split('.').collect();
        let mut steps = SEARCH_STEPS;
        let found = self.wild.search(&labels, &mut steps);

        if steps == 0 {
            return None;
        }
        found
    }

    fn resolve(&self, server: &str) -> Option<Found> {
        let mut v = self.get(server)?;
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(server.to_lowercase());
        for _ in 0..MAX_HOPS {
            match parse_value(v) {
                Value::Ips(ips) => return Some(Found::Ips(ips)),
                Value::Unsupported(why) => return Some(Found::Ignored(why)),
                Value::Alias(t) => {
                    if !seen.insert(t.clone()) {
                        return Some(Found::Ignored("alias chain loops"));
                    }
                    match self.get(&t) {
                        Some(next) => v = next,
                        None => return Some(Found::Alias(t)),
                    }
                }
            }
        }
        Some(Found::Ignored("alias chain too long"))
    }
}

#[derive(Default)]
struct Node<'a> {
    children: HashMap<String, Node<'a>>,
    data: Option<&'a Yaml>,
}

impl<'a> Node<'a> {

    fn insert(&mut self, labels: &[&str], v: &'a Yaml) {
        let mut n = self;
        for l in labels.iter().rev() {
            n = n.children.entry((*l).to_string()).or_default();
        }
        n.data = Some(v);
    }

    fn search(&self, labels: &[&str], steps: &mut usize) -> Option<&'a Yaml> {
        if *steps == 0 {
            return None;
        }
        *steps -= 1;
        let Some((last, rest)) = labels.split_last() else {
            return self.data;
        };
        if let Some(v) = self.children.get(*last).and_then(|c| c.search(rest, steps)) {
            return Some(v);
        }
        if let Some(v) = self.children.get("*").and_then(|c| c.search(rest, steps)) {
            return Some(v);
        }
        self.children.get("").and_then(|c| c.data)
    }
}

fn normalize(domain: &str) -> Option<String> {
    if domain.is_empty()
        || domain.ends_with('.')
        || domain.starts_with(char::is_whitespace)
        || domain.ends_with(char::is_whitespace)
    {
        return None;
    }
    let lower = domain.to_lowercase();
    if lower.split('.').skip(1).any(str::is_empty) {
        return None;
    }
    Some(lower)
}

fn parse_value(v: &Yaml) -> Value {
    if v.as_str() == Some("lan") {
        return Value::Unsupported("`lan` means the gateway's own addresses");
    }
    let items: Vec<&str> = match v {
        Yaml::String(s) => vec![s.as_str()],
        Yaml::Array(a) => match a.iter().map(Yaml::as_str).collect::<Option<Vec<_>>>() {
            Some(items) => items,
            None => return Value::Unsupported("address list holds a non-string item"),
        },
        _ => return Value::Unsupported("value is neither a string nor a list"),
    };
    match items.as_slice() {
        [] => Value::Unsupported("empty address list"),
        [one] => match parse_ip(one) {
            Some(ip) => Value::Ips(vec![ip]),
            None => alias(one),
        },
        many => match many.iter().map(|s| parse_ip(s)).collect::<Option<Vec<_>>>() {
            Some(ips) => {
                let mut uniq: Vec<IpAddr> = Vec::with_capacity(ips.len());
                for ip in ips {
                    if !uniq.contains(&ip) {
                        uniq.push(ip);
                    }
                }
                Value::Ips(uniq)
            }
            None => Value::Unsupported("address list holds a non-IP item"),
        },
    }
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

fn alias(s: &str) -> Value {
    let t = s.trim().trim_matches('.').to_lowercase();
    if sb_dns::valid::is_valid_fakeip_domain(&t) {
        Value::Alias(t)
    } else {
        Value::Unsupported("alias target is not a resolvable domain name")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yaml_rust2::YamlLoader;

    fn doc(text: &str) -> Yaml {
        YamlLoader::load_from_str(text).unwrap().remove(0)
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn servers(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn table_of<'a>(keys: &[&str], values: &'a [Yaml]) -> Table<'a> {
        let mut t = Table::default();
        for (k, v) in keys.iter().zip(values) {
            assert!(t.insert(k, v), "key {k} should be accepted");
        }
        t
    }

    fn numbered(n: usize) -> Vec<Yaml> {
        (1..=n).map(|i| Yaml::String(i.to_string())).collect()
    }

    fn hit(t: &Table<'_>, domain: &str) -> Option<String> {
        t.get(domain).and_then(|v| v.as_str()).map(str::to_string)
    }

    #[test]
    fn trie_basic() {
        let vals = numbered(3);
        let t = table_of(&["example.com", "google.com", "localhost"], &vals);
        assert_eq!(hit(&t, "example.com").as_deref(), Some("1"));
        assert_eq!(hit(&t, "localhost").as_deref(), Some("3"));
        assert_eq!(hit(&t, "www.google.com"), None);
        assert_eq!(hit(&t, ""), None);
        let v = Yaml::String("x".into());
        assert!(!Table::default().insert("", &v), "empty key is invalid");
    }

    #[test]
    fn trie_wildcard() {
        let keys = [
            "*.example.com",
            "sub.*.example.com",
            "*.dev",
            ".org",
            ".example.net",
            ".apple.*",
            "+.foo.com",
            "+.stun.*.*",
            "+.stun.*.*.*",
            "+.stun.*.*.*.*",
            "stun.l.google.com",
        ];
        let vals = numbered(keys.len());
        let t = table_of(&keys, &vals);
        for d in [
            "sub.example.com",
            "sub.foo.example.com",
            "test.org",
            "test.example.net",
            "test.apple.com",
            "test.foo.com",
            "foo.com",
            "global.stun.website.com",
        ] {
            assert!(hit(&t, d).is_some(), "{d} should match");
        }
        for d in ["foo.sub.example.com", "foo.example.dev", "example.com"] {
            assert!(hit(&t, d).is_none(), "{d} should not match");
        }
    }

    #[test]
    fn trie_priority() {
        let keys = [".dev", "example.dev", "*.example.dev", "test.example.dev"];
        let vals = numbered(keys.len());
        let t = table_of(&keys, &vals);
        assert_eq!(hit(&t, "test.dev").as_deref(), Some("1"));
        assert_eq!(hit(&t, "foo.bar.dev").as_deref(), Some("1"));
        assert_eq!(hit(&t, "example.dev").as_deref(), Some("2"));
        assert_eq!(hit(&t, "foo.example.dev").as_deref(), Some("3"));
        assert_eq!(hit(&t, "test.example.dev").as_deref(), Some("4"));
    }

    #[test]
    fn trie_boundaries() {
        let v = Yaml::String("1".into());
        let mut t = Table::default();
        assert!(t.insert("*.dev", &v));
        assert!(!t.insert(".", &v));
        assert!(!t.insert("..dev", &v));
        assert!(!t.insert("a.com.", &v), "trailing dot is invalid");
        assert!(!t.insert(" a.com", &v), "leading space is invalid");
        assert_eq!(hit(&t, "dev"), None);

        let vals = numbered(2);
        let t = table_of(&["+.*", "stun.*.*.*"], &vals);
        assert!(hit(&t, "example.com").is_some());
    }

    #[test]
    fn plus_alone_matches_everything_and_case_is_ignored() {
        let vals = numbered(1);
        let t = table_of(&["+"], &vals);
        assert!(hit(&t, "anything.example.com").is_some());
        assert!(hit(&t, "x").is_some());

        let vals = numbered(1);
        let t = table_of(&["Node.Example.COM"], &vals);
        assert_eq!(hit(&t, "node.example.com").as_deref(), Some("1"));
        assert_eq!(hit(&t, "NODE.example.com").as_deref(), Some("1"));
        assert_eq!(
            hit(&t, "node.example.com."),
            None,
            "query with a trailing dot"
        );
        assert_eq!(
            hit(&t, ".node.example.com"),
            None,
            "query starting with a dot"
        );
    }

    #[test]
    fn later_entry_wins_for_the_same_exact_name() {
        let vals = numbered(2);
        let t = table_of(&["example.com", "+.example.com"], &vals);
        assert_eq!(hit(&t, "example.com").as_deref(), Some("2"));
        assert_eq!(hit(&t, "a.example.com").as_deref(), Some("2"));
        let t = table_of(&["+.example.com", "example.com"], &vals);
        assert_eq!(hit(&t, "example.com").as_deref(), Some("2"));
        assert_eq!(hit(&t, "a.example.com").as_deref(), Some("1"));
    }

    #[test]
    fn value_forms() {
        let v = |text: &str| parse_value(&doc(&format!("v: {text}"))["v"]);
        assert_eq!(v("1.2.3.4"), Value::Ips(ips(&["1.2.3.4"])));
        assert_eq!(v("'2001:db8::1'"), Value::Ips(ips(&["2001:db8::1"])));
        assert_eq!(
            v("[1.2.3.4, 5.6.7.8, 1.2.3.4]"),
            Value::Ips(ips(&["1.2.3.4", "5.6.7.8"])),
            "list keeps order and drops duplicates"
        );
        assert_eq!(v("[1.2.3.4]"), Value::Ips(ips(&["1.2.3.4"])));
        assert_eq!(
            v("'::ffff:1.2.3.4'"),
            Value::Ips(ips(&["1.2.3.4"])),
            "v4-mapped is unmapped like mihomo's Unmap()"
        );
        assert_eq!(
            v("Entry.Example.NET."),
            Value::Alias("entry.example.net".into()),
            "alias is lowercased and dot-trimmed"
        );
        assert_eq!(
            v("[entry.example.net]"),
            Value::Alias("entry.example.net".into())
        );
        for bad in [
            "lan",
            "[]",
            "[1.2.3.4, entry.example.net]",
            "[entry.example.net, other.example.net]",
            "[1.2.3.4, 5]",
            "42",
            "true",
            "{a: b}",
            "~",
            "localhost",
            "x.local",
            "'a b.example.com'",
            "'1.2.3.4:443'",
        ] {
            assert!(
                matches!(v(bad), Value::Unsupported(_)),
                "{bad} should be unsupported, got {:?}",
                v(bad)
            );
        }
    }

    #[test]
    fn alias_chains_are_followed_inside_the_same_hosts() {
        let d = doc("hosts:
  a.example.com: b.example.com
  b.example.com: c.example.com
  c.example.com: [1.1.1.1, 2.2.2.2]
  x.example.com: y.example.net
  '*.wild.example.com': z.example.com
  z.example.com: 3.3.3.3
");
        let got = parse(
            &d,
            &servers(&[
                "a.example.com",
                "x.example.com",
                "n.wild.example.com",
                "unmapped.example.com",
            ]),
        );
        assert_eq!(
            got.map.get("a.example.com"),
            Some(&Mapping::Ips(ips(&["1.1.1.1", "2.2.2.2"]))),
            "two hops to a static list"
        );
        assert_eq!(
            got.map.get("x.example.com"),
            Some(&Mapping::Alias("y.example.net".into())),
            "chain ends at a name hosts does not know → dns_burn resolves it"
        );
        assert_eq!(
            got.map.get("n.wild.example.com"),
            Some(&Mapping::Ips(ips(&["3.3.3.3"]))),
            "wildcard key, then an exact hop"
        );
        assert!(!got.map.contains_key("unmapped.example.com"));
        assert!(got.ignored.is_empty(), "{:?}", got.ignored);
        assert_eq!(got.alias_targets(), vec!["y.example.net".to_string()]);
    }

    #[test]
    fn broken_chains_are_ignored_not_fatal() {
        let mut text = String::from(
            "hosts:
  self.example.com: self.example.com
  ping.example.com: pong.example.com
  pong.example.com: ping.example.com
  '*.spin.example.com': x.spin.example.com
  lan.example.com: lan
  bad.example.com: [1.2.3.4, nope]
",
        );
        for i in 0..10 {
            text.push_str(&format!("  h{i}.example.com: h{}.example.com\n", i + 1));
        }
        text.push_str("  h10.example.com: 9.9.9.9\n");
        let got = parse(
            &doc(&text),
            &servers(&[
                "self.example.com",
                "ping.example.com",
                "a.spin.example.com",
                "lan.example.com",
                "bad.example.com",
                "h0.example.com",
                "h5.example.com",
            ]),
        );
        assert_eq!(
            got.ignored.get("self.example.com"),
            Some(&"alias chain loops")
        );
        assert_eq!(
            got.ignored.get("ping.example.com"),
            Some(&"alias chain loops")
        );
        assert_eq!(
            got.ignored.get("a.spin.example.com"),
            Some(&"alias chain loops"),
            "a self-referencing wildcard must terminate (mihomo would spin here)"
        );
        assert!(got.ignored.contains_key("lan.example.com"));
        assert!(got.ignored.contains_key("bad.example.com"));
        assert_eq!(
            got.ignored.get("h0.example.com"),
            Some(&"alias chain too long")
        );
        assert_eq!(
            got.map.get("h5.example.com"),
            Some(&Mapping::Ips(ips(&["9.9.9.9"]))),
            "a short enough tail of the same chain still resolves"
        );
        assert_eq!(got.map.len(), 1, "{:?}", got.map);
    }

    #[test]
    fn only_node_domains_are_looked_up() {
        let d = doc("hosts:
  NODE-A.example.com: entry-a.example.net
  ads.example.org: 0.0.0.0
  'bad key.': 1.2.3.4
  1: 1.2.3.4
proxies: []
");
        let got = parse(&d, &servers(&["node-a.Example.com", "other.example.com"]));
        assert_eq!(
            got.map.len(),
            1,
            "unrelated entries are never evaluated: {:?}",
            got.map
        );
        assert_eq!(
            got.map.get("node-a.Example.com"),
            Some(&Mapping::Alias("entry-a.example.net".into())),
            "map is keyed by the server string exactly as the node spells it"
        );
        assert_eq!(got.skipped, 2, "invalid key + non-string key");
    }

    #[test]
    fn absent_or_malformed_hosts_is_empty() {
        let s = servers(&["a.example.com"]);
        assert_eq!(parse(&doc("proxies: []"), &s), SubHosts::default());
        assert_eq!(parse(&doc("hosts: [a, b]"), &s), SubHosts::default());
        assert_eq!(parse(&doc("hosts: ~"), &s), SubHosts::default());
        assert_eq!(parse(&doc("- 1\n- 2"), &s), SubHosts::default());
    }

    fn comb(depth: usize) -> (Vec<String>, String) {
        let mut keys = Vec::new();
        for star in 1..depth {
            let mut labels = vec!["z"];
            labels.extend(std::iter::repeat_n("a", depth));
            labels[star] = "*";
            keys.push(labels.join("."));
        }
        let mut hit_key = vec!["a"; depth - 1];
        hit_key.push("*");
        keys.push(hit_key.join("."));
        (keys, vec!["a"; depth].join("."))
    }

    #[test]
    fn wildcard_search_gives_up_at_the_step_budget() {

        for (depth, broad, want_hit) in [(20, false, true), (100, false, false), (100, true, false)]
        {
            let (mut keys, query) = comb(depth);
            if broad {
                keys.push(".a".to_string());
            }
            let vals: Vec<Yaml> = keys.iter().map(|_| Yaml::String("x".into())).collect();
            let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            let t = table_of(&key_refs, &vals);
            let started = std::time::Instant::now();
            assert_eq!(
                hit(&t, &query).is_some(),
                want_hit,
                "depth {depth}: expected hit={want_hit}"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "depth {depth}: search took {:?}",
                started.elapsed()
            );
        }
    }
}
