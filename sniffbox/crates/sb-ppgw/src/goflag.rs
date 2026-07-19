// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpgwFlags {
    pub input: Vec<String>,
    pub output: String,
    pub dnsinput: String,
    pub yamlhash_file: String,
    pub raw_url: String,
    pub down_url: String,
    pub server: String,
    pub interval: String,
    pub sleeptime: String,
    pub test_proxy: bool,
    pub dnslist: String,
    pub port: i64,
    pub api_url: String,
    pub secret: String,
    pub spec_node: String,
    pub test_node_url: String,
    pub ext_node: String,
    pub waitdelay: String,
    pub fast_node: bool,
    pub node_hash: String,
    pub rule_hash_mode: bool,
    pub yaml_hash_input: String,
    pub cpudelay: i64,
    pub reload: bool,
    pub closeall: bool,
    pub now_node: bool,
    pub ppsub: String,
    pub dns_burn: bool,
    pub ex_dns: String,
    pub healthcheck: String,

    pub clash_ready: bool,
    pub timeout: i64,
    pub genhost: String,
    pub clash_up: bool,
}

impl Default for PpgwFlags {
    fn default() -> Self {
        Self {
            input: Vec::new(),
            output: "output.yaml".to_string(),
            dnsinput: String::new(),
            yamlhash_file: String::new(),
            raw_url: String::new(),
            down_url: String::new(),
            server: String::new(),
            interval: String::new(),
            sleeptime: String::new(),
            test_proxy: false,
            dnslist: String::new(),
            port: 53,
            api_url: "unix:///tmp/clash.sock".to_string(),
            secret: String::new(),
            spec_node: String::new(),
            test_node_url: String::new(),
            ext_node: String::new(),
            waitdelay: "1000".to_string(),
            fast_node: false,
            node_hash: String::new(),
            rule_hash_mode: false,
            yaml_hash_input: String::new(),
            cpudelay: 3000,
            reload: false,
            closeall: false,
            now_node: false,
            ppsub: String::new(),
            dns_burn: false,
            ex_dns: String::new(),
            healthcheck: String::new(),
            clash_ready: false,
            timeout: 0,
            genhost: String::new(),
            clash_up: false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GoFlagErr {
    #[error("flag provided but not defined: -{0}")]
    Unknown(String),
    #[error("flag needs an argument: -{0}")]
    NeedArg(String),
    #[error("invalid value {1:?} for flag -{0}")]
    InvalidValue(String, String),
}

pub fn parse(argv: &[String]) -> Result<PpgwFlags, GoFlagErr> {
    let mut f = PpgwFlags::default();
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];

        if !tok.starts_with('-') || tok == "-" || tok == "--" {
            break;
        }
        let body = if let Some(b) = tok.strip_prefix("--") {
            b
        } else {
            &tok[1..]
        };
        let (key, inline) = match body.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (body, None),
        };

        macro_rules! value {
            () => {{
                match &inline {
                    Some(v) => v.clone(),
                    None => {
                        i += 1;
                        match argv.get(i) {
                            Some(v) => v.clone(),
                            None => return Err(GoFlagErr::NeedArg(key.to_string())),
                        }
                    }
                }
            }};
        }

        match key {

            "fastnode" => f.fast_node = bool_val(key, &inline)?,
            "rulehash" => f.rule_hash_mode = bool_val(key, &inline)?,
            "reload" => f.reload = bool_val(key, &inline)?,
            "closeall" => f.closeall = bool_val(key, &inline)?,
            "now_node" => f.now_node = bool_val(key, &inline)?,
            "dns_burn" => f.dns_burn = bool_val(key, &inline)?,
            "clash-ready" => f.clash_ready = bool_val(key, &inline)?,
            "clash-up" => f.clash_up = bool_val(key, &inline)?,
            "testProxy" => f.test_proxy = bool_val(key, &inline)?,

            "port" => f.port = int_val(key, &value!())?,
            "cpudelay" => f.cpudelay = int_val(key, &value!())?,
            "timeout" => f.timeout = int_val(key, &value!())?,

            "input" => f.input.push(value!()),

            "output" => f.output = value!(),
            "dnsinput" => f.dnsinput = value!(),
            "yamlhashFile" => f.yamlhash_file = value!(),
            "rawURL" => f.raw_url = value!(),
            "downURL" => f.down_url = value!(),
            "server" => f.server = value!(),
            "interval" => f.interval = value!(),
            "sleeptime" => f.sleeptime = value!(),
            "dnslist" => f.dnslist = value!(),
            "apiurl" => f.api_url = value!(),
            "secret" => f.secret = value!(),
            "spec_node" => f.spec_node = value!(),
            "test_node_url" => f.test_node_url = value!(),
            "ext_node" => f.ext_node = value!(),
            "waitdelay" => f.waitdelay = value!(),
            "nodehash" => f.node_hash = value!(),
            "yaml" => f.yaml_hash_input = value!(),
            "ppsub" => f.ppsub = value!(),
            "ex_dns" => f.ex_dns = value!(),
            "healthcheck" => f.healthcheck = value!(),
            "genhost" => f.genhost = value!(),
            other => return Err(GoFlagErr::Unknown(other.to_string())),
        }
        i += 1;
    }
    Ok(f)
}

fn bool_val(key: &str, inline: &Option<String>) -> Result<bool, GoFlagErr> {
    match inline {
        None => Ok(true),
        Some(v) => parse_bool(v).ok_or_else(|| GoFlagErr::InvalidValue(key.to_string(), v.clone())),
    }
}

fn int_val(key: &str, v: &str) -> Result<i64, GoFlagErr> {
    v.parse::<i64>()
        .map_err(|_| GoFlagErr::InvalidValue(key.to_string(), v.to_string()))
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(argv: &[&str]) -> Result<PpgwFlags, GoFlagErr> {
        let v: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        parse(&v)
    }

    #[test]
    fn empty_is_defaults() {
        let f = p(&[]).unwrap();
        assert_eq!(f, PpgwFlags::default());
        assert_eq!(f.output, "output.yaml");
        assert_eq!(f.port, 53);
        assert_eq!(f.api_url, "unix:///tmp/clash.sock");
        assert_eq!(f.waitdelay, "1000");
        assert_eq!(f.cpudelay, 3000);
    }

    #[test]
    fn bool_flags() {
        assert!(p(&["-reload"]).unwrap().reload);
        assert!(p(&["-now_node"]).unwrap().now_node);
        assert!(p(&["-fastnode"]).unwrap().fast_node);
        assert!(p(&["-rulehash"]).unwrap().rule_hash_mode);
        assert!(p(&["-testProxy"]).unwrap().test_proxy);

        let f = p(&["-testProxy", "-test_node_url", "u"]).unwrap();
        assert!(f.test_proxy);
        assert_eq!(f.test_node_url, "u");

        assert!(!p(&["-fastnode=false"]).unwrap().fast_node);
        assert!(p(&["-fastnode=true"]).unwrap().fast_node);

        let f = p(&["-reload", "leftover"]).unwrap();
        assert!(f.reload);
    }

    #[test]
    fn string_and_repeat_and_int() {
        let f = p(&[
            "-rawURL",
            "http://paopao.dns",
            "-server",
            "223.5.5.5",
            "-port",
            "5353",
        ])
        .unwrap();
        assert_eq!(f.raw_url, "http://paopao.dns");
        assert_eq!(f.server, "223.5.5.5");
        assert_eq!(f.port, 5353);

        let f = p(&[
            "-input", "a.yaml", "-input", "b.yaml", "-output", "out.yaml",
        ])
        .unwrap();
        assert_eq!(f.input, vec!["a.yaml".to_string(), "b.yaml".to_string()]);
        assert_eq!(f.output, "out.yaml");
    }

    #[test]
    fn inline_eq_and_double_dash() {
        let f = p(&["-apiurl=unix:///x.sock", "--reload", "-port=9090"]).unwrap();
        assert_eq!(f.api_url, "unix:///x.sock");
        assert!(f.reload);
        assert_eq!(f.port, 9090);
    }

    #[test]
    fn ext_node_pipe_value() {
        let f = p(&[
            "-fastnode",
            "-test_node_url=http://cp/generate_204",
            "-ext_node",
            "Traffic|Expire| GB",
        ])
        .unwrap();
        assert!(f.fast_node);
        assert_eq!(f.test_node_url, "http://cp/generate_204");
        assert_eq!(f.ext_node, "Traffic|Expire| GB");
    }

    #[test]
    fn errors() {
        assert_eq!(
            p(&["-bogus"]).unwrap_err(),
            GoFlagErr::Unknown("bogus".into())
        );
        assert_eq!(
            p(&["-rawURL"]).unwrap_err(),
            GoFlagErr::NeedArg("rawURL".into())
        );
        assert_eq!(
            p(&["-port", "abc"]).unwrap_err(),
            GoFlagErr::InvalidValue("port".into(), "abc".into())
        );
        assert_eq!(
            p(&["-reload=maybe"]).unwrap_err(),
            GoFlagErr::InvalidValue("reload".into(), "maybe".into())
        );
    }

    #[test]
    fn sniffbox_extension_flags() {
        let f = p(&["-clash-ready", "-timeout", "5"]).unwrap();
        assert!(f.clash_ready);
        assert_eq!(f.timeout, 5);
        let f = p(&[
            "-genhost",
            "/tmp/clash.yaml",
            "-server",
            "223.5.5.5",
            "-port",
            "53",
        ])
        .unwrap();
        assert_eq!(f.genhost, "/tmp/clash.yaml");
        assert_eq!(f.server, "223.5.5.5");
    }

    #[test]
    fn stops_at_positional() {

        let f = p(&["-reload", "positional", "-now_node"]).unwrap();
        assert!(f.reload);
        assert!(!f.now_node);
    }
}
