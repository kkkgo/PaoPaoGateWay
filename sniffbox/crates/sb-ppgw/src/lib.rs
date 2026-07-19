// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub mod clash;
pub mod clashup;
pub mod dnsutil;
pub mod dohdot;
pub mod download;
pub mod geo;
pub mod goflag;
pub mod hashutil;
pub mod health;
pub mod httpcli;
pub mod nodes;
pub mod ppsub;
pub mod privsep;
pub mod probe;
pub mod ruleset;
pub mod subtime;
pub mod term;
pub mod yamltx;

use goflag::PpgwFlags;
use std::io::Write;
use std::process::ExitCode;

pub fn invoked_as_ppgw(argv0: &str) -> bool {
    std::path::Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        == Some("ppgw")
}

pub fn cli_main(args: Vec<String>) -> ExitCode {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let mut io = Io {
        out: &mut out,
        err: &mut err,
    };
    let flags = match parse_or_usage(&args, &mut io) {
        Ok(f) => f,
        Err(code) => return ExitCode::from(code as u8),
    };
    let sub = select(&flags);
    if sub.drops_privileges() {

        let _ = privsep::drop_privileges();
    }
    let code = execute(sub, &flags, &mut io);
    ExitCode::from(code as u8)
}

pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subcommand {
    Healthcheck,
    Reload,
    TestProxy,
    Closeall,
    NowNode,
    SpecNode,
    Fastnode,
    Hash,
    TestNodeOnce,
    Ppsub,
    RawUrl,
    Download,
    Subtime,
    YamlHash,
    Dnslist,
    Input,

    ClashReady,

    Genhost,

    ClashUp,
    Usage,
}

impl Subcommand {

    pub fn name(self) -> &'static str {
        match self {
            Subcommand::Healthcheck => "healthcheck",
            Subcommand::Reload => "reload",
            Subcommand::TestProxy => "testProxy",
            Subcommand::Closeall => "closeall",
            Subcommand::NowNode => "now_node",
            Subcommand::SpecNode => "spec_node",
            Subcommand::Fastnode => "fastnode",
            Subcommand::Hash => "nodehash/rulehash",
            Subcommand::TestNodeOnce => "test_node_url",
            Subcommand::Ppsub => "ppsub",
            Subcommand::RawUrl => "rawURL",
            Subcommand::Download => "downURL",
            Subcommand::Subtime => "interval",
            Subcommand::YamlHash => "yamlhashFile",
            Subcommand::Dnslist => "dnslist",
            Subcommand::Input => "input",
            Subcommand::ClashReady => "clash-ready",
            Subcommand::Genhost => "genhost",
            Subcommand::ClashUp => "clash-up",
            Subcommand::Usage => "usage",
        }
    }

    pub fn drops_privileges(self) -> bool {
        matches!(
            self,
            Subcommand::Reload
                | Subcommand::TestProxy
                | Subcommand::Closeall
                | Subcommand::NowNode
                | Subcommand::SpecNode
                | Subcommand::Fastnode
                | Subcommand::TestNodeOnce
                | Subcommand::RawUrl
                | Subcommand::ClashReady
                | Subcommand::Genhost
        )
    }
}

pub fn select(f: &PpgwFlags) -> Subcommand {

    if f.clash_ready {
        return Subcommand::ClashReady;
    }
    if f.clash_up {
        return Subcommand::ClashUp;
    }
    if !f.genhost.is_empty() {
        return Subcommand::Genhost;
    }
    if !f.healthcheck.is_empty() {
        return Subcommand::Healthcheck;
    }
    if f.reload {
        return Subcommand::Reload;
    }
    if f.test_proxy {
        return Subcommand::TestProxy;
    }
    if f.closeall {
        return Subcommand::Closeall;
    }
    if f.now_node {
        return Subcommand::NowNode;
    }
    if !f.api_url.is_empty() && !f.spec_node.is_empty() {
        return Subcommand::SpecNode;
    }
    if f.fast_node {
        return Subcommand::Fastnode;
    }
    if !f.node_hash.is_empty() || f.rule_hash_mode {
        return Subcommand::Hash;
    }
    if !f.test_node_url.is_empty() {
        return Subcommand::TestNodeOnce;
    }
    if !f.ppsub.is_empty() {
        return Subcommand::Ppsub;
    }
    if !f.raw_url.is_empty() {
        return Subcommand::RawUrl;
    }
    if !f.down_url.is_empty() {
        return Subcommand::Download;
    }
    if !f.interval.is_empty() && !f.sleeptime.is_empty() {
        return Subcommand::Subtime;
    }
    if !f.yamlhash_file.is_empty() {
        return Subcommand::YamlHash;
    }
    if !f.dnslist.is_empty() {
        return Subcommand::Dnslist;
    }
    if !f.input.is_empty() {
        return Subcommand::Input;
    }
    Subcommand::Usage
}

pub fn run(args: &[String], io: &mut Io) -> i32 {
    let flags = match parse_or_usage(args, io) {
        Ok(f) => f,
        Err(code) => return code,
    };
    let sub = select(&flags);
    execute(sub, &flags, io)
}

fn parse_or_usage(args: &[String], io: &mut Io) -> Result<PpgwFlags, i32> {
    let rest: &[String] = if args.len() > 1 { &args[1..] } else { &[] };
    match goflag::parse(rest) {
        Ok(f) => Ok(f),
        Err(e) => {
            let _ = writeln!(io.err, "{e}");
            let _ = write!(io.err, "{}", usage());
            Err(2)
        }
    }
}

fn execute(sub: Subcommand, f: &PpgwFlags, io: &mut Io) -> i32 {
    match sub {
        Subcommand::Reload => cmd_reload(f, io),
        Subcommand::Closeall => cmd_closeall(f, io),
        Subcommand::NowNode => cmd_now_node(f, io),
        Subcommand::SpecNode => cmd_spec_node(f, io),
        Subcommand::Fastnode => cmd_fastnode(f, io, true),
        Subcommand::TestNodeOnce => cmd_fastnode(f, io, false),
        Subcommand::RawUrl => cmd_rawurl(f, io),
        Subcommand::Subtime => cmd_subtime(f, io),
        Subcommand::Hash => cmd_hash(f, io),
        Subcommand::YamlHash => cmd_yamlhash(f, io),
        Subcommand::TestProxy => cmd_testproxy(f, io),
        Subcommand::Download => cmd_download(f, io),
        Subcommand::Healthcheck => cmd_healthcheck(f, io),
        Subcommand::Input => cmd_input(f, io),
        Subcommand::Dnslist => cmd_dnslist(f, io),
        Subcommand::Ppsub => cmd_ppsub(f, io),
        Subcommand::ClashReady => cmd_clash_ready(f),
        Subcommand::Genhost => cmd_genhost(f, io),
        Subcommand::ClashUp => clashup::cmd_clash_up(io),
        Subcommand::Usage => {
            let _ = write!(io.err, "{}", usage());
            0
        }
    }
}

fn clash_client(f: &PpgwFlags) -> clash::ClashClient {
    clash::ClashClient::from_api_url(&f.api_url, &f.secret)
}

fn clash_precondition_ok(f: &PpgwFlags, client: &clash::ClashClient) -> bool {
    if f.api_url.is_empty() {
        return false;
    }
    !(client.requires_secret() && f.secret.is_empty())
}

fn cmd_reload(f: &PpgwFlags, io: &mut Io) -> i32 {
    let client = clash_client(f);
    match client.reload_yaml() {
        Ok(()) => {
            let _ = writeln!(
                io.out,
                "{}Yaml reload OK.",
                term::green("[PaoPaoGW Reload]")
            );
            0
        }
        Err(e) => {
            let _ = writeln!(io.out, "{}ERR: {e}", term::red("[PaoPaoGW Reload]"));
            1
        }
    }
}

fn cmd_closeall(f: &PpgwFlags, io: &mut Io) -> i32 {
    let client = clash_client(f);
    if !clash_precondition_ok(f, &client) {
        return 1;
    }
    match client.delete_connections() {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(
                io.out,
                "{}Unable to close connections: {e}",
                term::red("[PaoPaoGW Close]")
            );
            1
        }
    }
}

fn cmd_now_node(f: &PpgwFlags, io: &mut Io) -> i32 {
    let client = clash_client(f);
    if !clash_precondition_ok(f, &client) {
        return 1;
    }

    if client.get_mode().unwrap_or_default() != "global" {
        return 1;
    }
    let now = match client.get_nodes() {
        Ok((_, now)) => now,
        Err(_) => {
            let _ = writeln!(io.out, "Unable to get the now node.");
            String::new()
        }
    };
    if now.is_empty() {
        return 1;
    }
    let _ = write!(io.out, "{now}");
    0
}

fn cmd_spec_node(f: &PpgwFlags, io: &mut Io) -> i32 {
    let client = clash_client(f);
    match client.select_node(&f.spec_node) {
        Ok(()) => {
            let _ = writeln!(
                io.out,
                "{}The ppgwsocks node selected.",
                term::green("[PaoPaoGW SOCKS]")
            );
            0
        }
        Err(e) => {
            let _ = writeln!(
                io.out,
                "{}Unable to select ppgwsocks: {e}",
                term::red("[PaoPaoGW SOCKS]")
            );
            1
        }
    }
}

fn cmd_fastnode(f: &PpgwFlags, io: &mut Io, retry: bool) -> i32 {
    let client = clash_client(f);
    if !clash_precondition_ok(f, &client) {
        let _ = writeln!(
            io.out,
            "{}invalid API configuration",
            term::red("[PaoPaoGW Fast]")
        );
        return 1;
    }
    let res = if retry {
        nodes::run_fast_node(
            &client,
            &f.test_node_url,
            &f.ext_node,
            &f.waitdelay,
            f.cpudelay,
        )
    } else {
        nodes::run_fast_node_once(
            &client,
            &f.test_node_url,
            &f.ext_node,
            &f.waitdelay,
            f.cpudelay,
        )
    };
    match res {
        Ok(name) => {
            let _ = writeln!(
                io.out,
                "{}The fastest node selected: {name}",
                term::green("[PaoPaoGW Fast]")
            );
            0
        }
        Err(e) => {
            let _ = writeln!(io.out, "{}{e}", term::red("[PaoPaoGW Fast]"));
            1
        }
    }
}

fn cmd_rawurl(f: &PpgwFlags, io: &mut Io) -> i32 {
    let host = dnsutil::url_hostname(&f.raw_url);
    if host.is_empty() {
        let _ = writeln!(io.err, "Failed to parse URL: {}", f.raw_url);
        return 1;
    }
    match dnsutil::nslookup(&host, &f.server, f.port, dnsutil::ipv6_enabled()) {
        Some(ip) => {
            let _ = writeln!(io.out, "{ip}  {host}");
            0
        }
        None => 1,
    }
}

fn cmd_subtime(f: &PpgwFlags, io: &mut Io) -> i32 {
    let n = subtime::parse_subtime(&f.interval, &f.sleeptime);
    let _ = write!(io.out, "{n}");
    0
}

fn cmd_hash(f: &PpgwFlags, io: &mut Io) -> i32 {
    if f.yaml_hash_input.is_empty() {
        let _ = writeln!(io.err, "-yaml is required for -nodehash/-rulehash");
        return 1;
    }
    if !f.node_hash.is_empty() {
        match hashutil::node_hash(&f.yaml_hash_input, &f.node_hash) {
            Ok(h) => {
                let _ = writeln!(io.out, "{h}");
            }
            Err(e) => {
                let _ = writeln!(io.err, "[PaoPaoGW Hash]{e}");
                return 1;
            }
        }
    }
    if f.rule_hash_mode {
        match hashutil::rule_hash(&f.yaml_hash_input) {
            Ok(h) => {
                let _ = writeln!(io.out, "{h}");
            }
            Err(e) => {
                let _ = writeln!(io.err, "[PaoPaoGW Hash]{e}");
                return 1;
            }
        }
    }
    0
}

fn cmd_yamlhash(f: &PpgwFlags, io: &mut Io) -> i32 {
    match hashutil::yaml_hash(&f.yamlhash_file) {
        Ok(h) => {
            let _ = write!(io.out, "{h}");
            0
        }
        Err(e) => {
            let _ = writeln!(io.err, "Cannot read {e}");
            1
        }
    }
}

pub(crate) const HEALTHCHECK_SOCKS5: &str = "socks5h://127.0.0.1:1079";

fn cmd_testproxy(f: &PpgwFlags, io: &mut Io) -> i32 {
    if f.test_node_url.is_empty() {
        let _ = writeln!(io.err, "Please provide URL parameter");
        return 1;
    }
    testproxy_probe(&f.test_node_url, HEALTHCHECK_SOCKS5, io)
}

pub fn testproxy_probe(url: &str, proxy: &str, io: &mut Io) -> i32 {
    match httpcli::check_url_connectivity(url, proxy, "0") {
        Ok((_, code)) => {
            let _ = writeln!(io.out, "Node Check success. HTTP CODE: {code}");
            0
        }
        Err(e) => {
            let _ = writeln!(io.err, "Request error: {e}");
            1
        }
    }
}

fn cmd_download(f: &PpgwFlags, io: &mut Io) -> i32 {
    let dl = download::Downloader::new(&f.down_url, &f.output);
    match dl.download() {
        Ok(_) => {
            let _ = writeln!(io.out, "{}Download: OK!", term::green("[PaoPaoGW Get]"));
            0
        }
        Err(e) => {
            let _ = writeln!(
                io.out,
                "{}Download failed: {e}",
                term::red("[PaoPaoGW Get]")
            );
            1
        }
    }
}

fn cmd_healthcheck(f: &PpgwFlags, io: &mut Io) -> i32 {
    let content = match std::fs::read_to_string(&f.healthcheck) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(
                io.out,
                "{}Failed to read config file: {e}",
                term::red("[PaoPaoGW Health]")
            );
            return 255;
        }
    };
    let client = clash_client(f);
    health::run(&content, &client, io)
}

fn cmd_input(f: &PpgwFlags, io: &mut Io) -> i32 {
    match yamltx::combine(&f.input) {
        Ok(yaml) => {
            if let Err(e) = std::fs::write(&f.output, yaml) {
                let _ = writeln!(io.out, "Failed to write result to file : {} {e}", f.output);
                return 1;
            }
            let _ = writeln!(io.out, "Merged YAML written to {}", f.output);
            0
        }
        Err(e) => {
            let _ = writeln!(io.out, "{e}");
            1
        }
    }
}

fn cmd_dnslist(f: &PpgwFlags, io: &mut Io) -> i32 {
    if f.dnsinput.is_empty() {
        let _ = writeln!(
            io.out,
            "Please provide an input YAML file using the -dnsinput flag"
        );
        return 1;
    }
    match yamltx::dns_burn(&f.dnsinput, &f.dnslist, dnsutil::ipv6_enabled()) {
        Ok((yaml, added)) => {
            if let Err(e) = std::fs::write(&f.output, yaml) {
                let _ = writeln!(io.out, "Error writing output file: {e}");
                return 1;
            }
            let _ = writeln!(
                io.out,
                "{}New configuration written to {} (Added {added} nodes)",
                term::green("[PaoPaoGW DNS]"),
                f.output
            );
            0
        }
        Err(e) => {
            let _ = writeln!(io.out, "{}{e}", term::red("[PaoPaoGW DNS]"));
            1
        }
    }
}

fn cmd_ppsub(f: &PpgwFlags, io: &mut Io) -> i32 {
    let dns_burn = f.dns_burn
        || std::env::var("dns_burn")
            .map(|v| v == "yes")
            .unwrap_or(false);
    let ex_dns = match std::env::var("ex_dns") {
        Ok(v) if !v.is_empty() => v,
        _ => f.ex_dns.clone(),
    };
    match ppsub::process_ppsub(&f.ppsub, &f.output, dns_burn, &ex_dns) {
        Ok(()) => {
            let _ = writeln!(
                io.out,
                "{}PPSub processed successfully, output file: {}",
                term::green("[PaoPaoGW PPSub]"),
                f.output
            );

            let rep = ruleset::prefetch(&f.output, &ruleset::ruleset_dir());
            let _ = writeln!(
                io.out,
                "{}rule-set prefetch: downloaded={} cached={} failed={} removed={} format_backfilled={}",
                term::green("[PaoPaoGW RuleSet]"),
                rep.downloaded,
                rep.cached,
                rep.failed,
                rep.removed,
                rep.backfilled,
            );
            0
        }
        Err(e) => {
            let _ = writeln!(
                io.out,
                "{}PPSub processing failed: {e}",
                term::red("[PaoPaoGW PPSub]")
            );
            1
        }
    }
}

fn cmd_clash_ready(f: &PpgwFlags) -> i32 {
    let mut client = clash_client(f);
    client.set_timeout(std::time::Duration::from_secs(2));
    let timeout = if f.timeout > 0 { f.timeout as u64 } else { 10 };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        if client.get_mode().is_ok() {
            return 0;
        }
        if std::time::Instant::now() >= deadline {
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn cmd_genhost(f: &PpgwFlags, io: &mut Io) -> i32 {
    let content = match std::fs::read_to_string(&f.genhost) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(io.err, "Failed to read {}: {e}", f.genhost);
            return 1;
        }
    };
    let hosts = dnsutil::extract_hosts(&content);
    let ipv6 = dnsutil::ipv6_enabled();
    for (host, ip) in dnsutil::resolve_hosts_batch(&hosts, &f.server, f.port, ipv6) {
        let _ = writeln!(io.out, "{ip}  {host}");
    }
    0
}

pub fn usage() -> String {
    let mut s = String::new();
    s.push_str("ppgw (sniffbox multi-call) — PaoPaoGateWay CLI replacement\n");
    s.push_str("Usage: ppgw -<subcommand> [flags]\n");
    s.push_str("  -reload                            Trigger clash reload /tmp/clash.yaml\n");
    s.push_str("  -closeall                          Close all clash connections\n");
    s.push_str("  -now_node                          Print current GLOBAL node\n");
    s.push_str("  -spec_node <name>                  Select node\n");
    s.push_str("  -fastnode -test_node_url <u> -ext_node <e>  Speed-test and pick fastest node\n");
    s.push_str("  -test_node_url <u>                 Single-round speed-test node picker\n");
    s.push_str("  -nodehash <name> -yaml <f>         Node config hash\n");
    s.push_str("  -rulehash -yaml <f>                Rule section hash\n");
    s.push_str("  -yamlhashFile <f>                  YAML content hash\n");
    s.push_str("  -healthcheck <f>                   PPSub health check + group failover\n");
    s.push_str("  -testProxy -test_node_url <u>      Probe via health-check inbound (:1079)\n");
    s.push_str("  -rawURL <u> -server <dns> -port <p>  nslookup\n");
    s.push_str("  -downURL <u> -output <f>           Download\n");
    s.push_str("  -interval <Nd|Nh|Nm> -sleeptime <n>  Poll interval/count\n");
    s.push_str("  -dnslist <s> -dnsinput <f> -output <f>   dns_burn\n");
    s.push_str("  -input <f> [-input <f>...] -output <f>   Merge YAML\n");
    s.push_str(
        "  -ppsub <f> -output <f>             Subscription engine (rule-set prefetch + format detection)\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goflag::parse;

    fn pf(argv: &[&str]) -> PpgwFlags {
        let v: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        parse(&v).expect("parse")
    }

    #[test]
    fn invoked_basename() {
        assert!(invoked_as_ppgw("ppgw"));
        assert!(invoked_as_ppgw("/usr/bin/ppgw"));
        assert!(invoked_as_ppgw("./ppgw"));
        assert!(!invoked_as_ppgw("sniffbox"));
        assert!(!invoked_as_ppgw("/usr/bin/sniffbox"));
        assert!(!invoked_as_ppgw(""));
    }

    #[test]
    fn select_priority_matches_ppgw_main() {
        assert_eq!(select(&PpgwFlags::default()), Subcommand::Usage);
        assert_eq!(select(&pf(&["-reload"])), Subcommand::Reload);
        assert_eq!(select(&pf(&["-now_node"])), Subcommand::NowNode);
        assert_eq!(select(&pf(&["-closeall"])), Subcommand::Closeall);

        assert_eq!(
            select(&pf(&["-healthcheck", "x.json", "-reload"])),
            Subcommand::Healthcheck
        );

        assert_eq!(select(&pf(&["-reload", "-now_node"])), Subcommand::Reload);

        assert_eq!(select(&pf(&["-spec_node", "DIRECT"])), Subcommand::SpecNode);
        assert_eq!(
            select(&pf(&["-nodehash", "n", "-yaml", "f"])),
            Subcommand::Hash
        );
        assert_eq!(select(&pf(&["-rulehash", "-yaml", "f"])), Subcommand::Hash);

        assert_eq!(
            select(&pf(&["-fastnode", "-test_node_url", "u"])),
            Subcommand::Fastnode
        );

        assert_eq!(
            select(&pf(&["-testProxy", "-test_node_url", "u"])),
            Subcommand::TestProxy
        );
        assert_eq!(
            select(&pf(&["-test_node_url", "u"])),
            Subcommand::TestNodeOnce
        );
        assert_eq!(
            select(&pf(&["-ppsub", "f", "-output", "o"])),
            Subcommand::Ppsub
        );
        assert_eq!(
            select(&pf(&["-rawURL", "http://paopao.dns"])),
            Subcommand::RawUrl
        );
        assert_eq!(
            select(&pf(&["-downURL", "https://x/y", "-output", "o"])),
            Subcommand::Download
        );
        assert_eq!(
            select(&pf(&["-interval", "1d", "-sleeptime", "30"])),
            Subcommand::Subtime
        );

        assert_eq!(select(&pf(&["-interval", "1d"])), Subcommand::Usage);
        assert_eq!(select(&pf(&["-yamlhashFile", "f"])), Subcommand::YamlHash);
        assert_eq!(
            select(&pf(&[
                "-dnslist",
                "1.1.1.1",
                "-dnsinput",
                "i",
                "-output",
                "o"
            ])),
            Subcommand::Dnslist
        );
        assert_eq!(
            select(&pf(&["-input", "a", "-output", "o"])),
            Subcommand::Input
        );

        assert_eq!(
            select(&pf(&["-clash-ready", "-timeout", "5"])),
            Subcommand::ClashReady
        );
        assert_eq!(select(&pf(&["-genhost", "f.yaml"])), Subcommand::Genhost);
        assert_eq!(
            select(&pf(&["-clash-ready", "-reload"])),
            Subcommand::ClashReady,
            "extension takes precedence over reload"
        );
    }
}
