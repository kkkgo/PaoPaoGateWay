// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const KEY: &str = "network.@globals[0].packet_steering";
const ALL_CPUS: &str = "2";
const CMD_TIMEOUT: Duration = Duration::from_secs(10);
const UCI_PATHS: &[&str] = &["sbin/uci", "usr/sbin/uci", "bin/uci", "usr/bin/uci"];

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    NotOpenWrt,
    SingleCpu,
    NoSingleQueueNic,

    AlreadySet(String),

    Applied(Vec<(String, String)>),
    Failed(&'static str),
}

pub trait Runner {

    fn run(&mut self, prog: &str, args: &[&str]) -> Option<(bool, String)>;
}

struct System;

impl Runner for System {
    fn run(&mut self, prog: &str, args: &[&str]) -> Option<(bool, String)> {
        run_with_timeout(prog, args, CMD_TIMEOUT)
    }
}

fn run_with_timeout(prog: &str, args: &[&str], limit: Duration) -> Option<(bool, String)> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        let _ = tx.send(s);
    });
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    status.map(|st| (st.success(), out))
}

fn find_uci(root: &Path) -> Option<PathBuf> {
    UCI_PATHS.iter().map(|p| root.join(p)).find(|p| p.is_file())
}

pub fn single_queue_nics(class_net: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(class_net) else {
        return Vec::new();
    };
    let mut out: Vec<String> = rd
        .flatten()
        .filter(|e| e.path().join("device").exists())
        .filter(|e| {
            let Ok(q) = std::fs::read_dir(e.path().join("queues")) else {
                return false;
            };
            q.flatten()
                .filter(|q| q.file_name().to_string_lossy().starts_with("rx-"))
                .count()
                == 1
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "lo")
        .collect();
    out.sort();
    out
}

fn ok(r: Option<(bool, String)>) -> bool {
    matches!(r, Some((true, _)))
}

pub fn tune(root: &Path, cpus: usize, r: &mut impl Runner) -> Outcome {
    let Some(uci) = find_uci(root) else {
        return Outcome::NotOpenWrt;
    };
    let init = root.join("etc/init.d/packet_steering");
    if !init.is_file() || !root.join("etc/config/network").is_file() {
        return Outcome::NotOpenWrt;
    }
    if cpus < 2 {
        return Outcome::SingleCpu;
    }
    let class_net = root.join("sys/class/net");
    let nics = single_queue_nics(&class_net);
    if nics.is_empty() {
        return Outcome::NoSingleQueueNic;
    }
    let uci = uci.to_string_lossy().into_owned();

    match r.run(&uci, &["-q", "get", KEY]) {
        Some((true, v)) if !v.trim().is_empty() => {
            return Outcome::AlreadySet(v.trim().to_string());
        }
        Some(_) => {}
        None => return Outcome::Failed("uci get"),
    }
    let has_section = ok(r.run(&uci, &["-q", "get", "network.@globals[0]"]));
    let set = format!("{KEY}={ALL_CPUS}");
    let staged = (has_section || ok(r.run(&uci, &["set", "network.globals=globals"])))
        && ok(r.run(&uci, &["set", &set]));
    if !staged || !ok(r.run(&uci, &["commit", "network"])) {

        let _ = r.run(&uci, &["revert", "network"]);
        return Outcome::Failed("uci set/commit");
    }
    if !ok(r.run(&init.to_string_lossy(), &["reload"])) {
        return Outcome::Failed("packet_steering reload");
    }
    let rps = nics
        .into_iter()
        .map(|n| {
            let v = std::fs::read_to_string(class_net.join(&n).join("queues/rx-0/rps_cpus"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            (n, v)
        })
        .collect();
    Outcome::Applied(rps)
}

pub fn spawn_tune() {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    let spawned = std::thread::Builder::new()
        .name("packet-steering".into())
        .spawn(move || match tune(Path::new("/"), cpus, &mut System) {
            Outcome::Applied(rps) => tracing::info!(
                cpus,
                ?rps,
                "packet steering: {KEY} unset -> {ALL_CPUS} (spread single-queue RX over all CPUs)"
            ),
            Outcome::AlreadySet(v) => {
                tracing::debug!(value = %v, "packet steering already configured; leaving as-is")
            }
            Outcome::Failed(step) => {
                tracing::warn!(step, "packet steering tune failed; keeping OpenWrt default")
            }
            other => tracing::debug!(?other, "packet steering tune skipped"),
        });
    if let Err(e) = spawned {
        tracing::warn!(?e, "spawn packet-steering thread failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        get_value: Option<String>,
        has_section: bool,
        fail: Option<&'static str>,
    }

    impl Runner for Fake {
        fn run(&mut self, prog: &str, args: &[&str]) -> Option<(bool, String)> {
            let name = Path::new(prog)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let line = format!("{name} {}", args.join(" "));
            self.calls.push(line.clone());
            if self.fail.is_some_and(|f| line.contains(f)) {
                return Some((false, String::new()));
            }
            match args {
                ["-q", "get", k] if *k == KEY => Some(match &self.get_value {
                    Some(v) => (true, format!("{v}\n")),
                    None => (false, String::new()),
                }),
                ["-q", "get", "network.@globals[0]"] => {
                    Some((self.has_section, "globals\n".into()))
                }
                _ => Some((true, String::new())),
            }
        }
    }

    fn openwrt_root(nics: &[(&str, usize)]) -> tempfile_dir::Dir {
        let d = tempfile_dir::Dir::new();
        for p in ["sbin", "etc/init.d", "etc/config"] {
            fs::create_dir_all(d.0.join(p)).unwrap();
        }
        fs::write(d.0.join("sbin/uci"), "").unwrap();
        fs::write(d.0.join("etc/init.d/packet_steering"), "").unwrap();
        fs::write(d.0.join("etc/config/network"), "").unwrap();
        for (name, queues) in nics {
            let base = d.0.join("sys/class/net").join(name);
            fs::create_dir_all(base.join("device")).unwrap();
            for q in 0..*queues {
                fs::create_dir_all(base.join(format!("queues/rx-{q}"))).unwrap();
                fs::write(base.join(format!("queues/rx-{q}/rps_cpus")), "1\n").unwrap();
            }
        }
        fs::create_dir_all(d.0.join("sys/class/net/lo/queues/rx-0")).unwrap();
        d
    }

    mod tempfile_dir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                use std::sync::atomic::{AtomicU32, Ordering};
                static N: AtomicU32 = AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!(
                    "sniffbox-steering-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn unset_on_single_queue_box_sets_all_cpus_creating_the_section() {
        let root = openwrt_root(&[("eth0", 1)]);
        let mut r = Fake::default();
        let out = tune(&root.0, 4, &mut r);
        assert_eq!(out, Outcome::Applied(vec![("eth0".into(), "1".into())]));
        assert_eq!(
            r.calls,
            vec![
                "uci -q get network.@globals[0].packet_steering",
                "uci -q get network.@globals[0]",
                "uci set network.globals=globals",
                "uci set network.@globals[0].packet_steering=2",
                "uci commit network",
                "packet_steering reload",
            ]
        );
    }

    #[test]
    fn existing_globals_section_is_reused() {
        let root = openwrt_root(&[("eth0", 1)]);
        let mut r = Fake {
            has_section: true,
            ..Default::default()
        };
        assert!(matches!(tune(&root.0, 4, &mut r), Outcome::Applied(_)));
        assert!(
            !r.calls
                .iter()
                .any(|c| c.contains("network.globals=globals")),
            "must not create a second globals section: {:?}",
            r.calls
        );
    }

    #[test]
    fn explicit_admin_value_is_never_overridden() {
        for v in ["0", "1", "2"] {
            let root = openwrt_root(&[("eth0", 1)]);
            let mut r = Fake {
                get_value: Some(v.into()),
                ..Default::default()
            };
            assert_eq!(tune(&root.0, 4, &mut r), Outcome::AlreadySet(v.into()));
            assert_eq!(
                r.calls.len(),
                1,
                "only the read may run for {v}: {:?}",
                r.calls
            );
        }
    }

    #[test]
    fn skipped_off_openwrt_single_cpu_or_multiqueue_only() {
        let bare = tempfile_dir::Dir::new();
        let mut r = Fake::default();
        assert_eq!(tune(&bare.0, 4, &mut r), Outcome::NotOpenWrt);

        let root = openwrt_root(&[("eth0", 1)]);
        assert_eq!(tune(&root.0, 1, &mut r), Outcome::SingleCpu);

        let mq = openwrt_root(&[("eth0", 4), ("eth1", 2)]);
        assert_eq!(tune(&mq.0, 4, &mut r), Outcome::NoSingleQueueNic);
        assert!(
            r.calls.is_empty(),
            "no command may run when skipped: {:?}",
            r.calls
        );
    }

    #[test]
    fn failed_commit_reverts_staged_change() {
        let root = openwrt_root(&[("eth0", 1)]);
        let mut r = Fake {
            fail: Some("commit"),
            ..Default::default()
        };
        assert_eq!(tune(&root.0, 4, &mut r), Outcome::Failed("uci set/commit"));
        assert_eq!(
            r.calls.last().map(String::as_str),
            Some("uci revert network")
        );
        assert!(!r.calls.iter().any(|c| c.contains("reload")));
    }

    #[test]
    fn single_queue_detection_ignores_lo_and_virtual() {
        let root = openwrt_root(&[("eth0", 1), ("eth1", 4)]);
        fs::create_dir_all(root.0.join("sys/class/net/br-lan/queues/rx-0")).unwrap();
        assert_eq!(
            single_queue_nics(&root.0.join("sys/class/net")),
            vec!["eth0".to_string()]
        );
    }

    #[test]
    fn command_runner_reports_status_output_and_timeout() {
        assert_eq!(
            run_with_timeout("sh", &["-c", "echo hi"], Duration::from_secs(5)),
            Some((true, "hi\n".into()))
        );
        assert_eq!(
            run_with_timeout("sh", &["-c", "exit 1"], Duration::from_secs(5)),
            Some((false, String::new()))
        );
        let t = Instant::now();
        assert_eq!(
            run_with_timeout("sleep", &["5"], Duration::from_millis(200)),
            None
        );
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "timeout must kill the child"
        );
        assert_eq!(
            run_with_timeout("/nonexistent/prog", &[], Duration::from_secs(1)),
            None
        );
        let t = Instant::now();
        assert_eq!(
            run_with_timeout("sh", &["-c", "sleep 3 & echo bg"], Duration::from_secs(5)),
            Some((true, String::new())),
            "a backgrounded grandchild holding stdout must not hang the call"
        );
        assert!(t.elapsed() < Duration::from_secs(4));
    }
}
