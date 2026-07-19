// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};

pub fn meminfo() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = parse_kb(rest);
        }
    }
    (total, avail)
}

fn parse_kb(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}

pub fn kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn uptime_secs() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
        .map(|s| s as u64)
        .unwrap_or(0)
}

pub fn cpu_model_cores() -> (String, usize) {
    let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut model = String::new();
    let mut cores = 0usize;
    for line in text.lines() {
        if line.starts_with("processor") {
            cores += 1;
        } else if model.is_empty() {

            if let Some(v) = line.strip_prefix("model name") {
                model = v.trim_start_matches([':', ' ', '\t']).trim().to_string();
            }
        }
    }
    if cores == 0 {
        cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
    }
    (model, cores)
}

pub fn cpu_jiffies() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let rest = line.strip_prefix("cpu")?.trim_start();
    let vals: Vec<u64> = rest
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    if vals.len() < 5 {
        return None;
    }

    let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
    let total: u64 = vals.iter().sum();
    Some((total, idle))
}

pub fn cpu_jiffies_per_core() -> Vec<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {

        let Some(rest) = line.strip_prefix("cpu") else {
            break;
        };
        if rest.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(nums) = rest.split_once(char::is_whitespace).map(|(_, r)| r) else {
            continue;
        };
        let vals: Vec<u64> = nums
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        if vals.len() < 5 {
            continue;
        }
        let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
        let total: u64 = vals.iter().sum();
        out.push((total, idle));
    }
    out
}

pub fn cpu_usage_pct(prev: (u64, u64), now: (u64, u64)) -> f64 {
    let dt = now.0.saturating_sub(prev.0);
    let di = now.1.saturating_sub(prev.1);
    if dt == 0 {
        return 0.0;
    }
    let busy = dt.saturating_sub(di) as f64;
    (busy / dt as f64) * 100.0
}

#[derive(Debug, Default, Clone)]
pub struct Iface {
    pub name: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mac: Option<String>,
    pub gateway: Option<String>,
}

pub fn interfaces() -> Vec<Iface> {
    let mut map: BTreeMap<String, Iface> = BTreeMap::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Vec::new();
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_name.is_null() {
                continue;
            }
            if ifa.ifa_flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0 {
                continue;
            }
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let entry = map.entry(name.clone()).or_insert_with(|| Iface {
                name,
                ..Default::default()
            });
            if ifa.ifa_addr.is_null() {
                continue;
            }
            let fam = (*ifa.ifa_addr).sa_family as i32;
            match fam {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    let prefix = if ifa.ifa_netmask.is_null() {
                        32
                    } else {
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                        u32::from_be(m.sin_addr.s_addr).count_ones() as u8
                    };
                    entry.ipv4.push(format!("{ip}/{prefix}"));
                }
                libc::AF_INET6 => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let prefix = if ifa.ifa_netmask.is_null() {
                        128
                    } else {
                        let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                        m.sin6_addr
                            .s6_addr
                            .iter()
                            .map(|b| b.count_ones())
                            .sum::<u32>() as u8
                    };
                    entry.ipv6.push(format!("{ip}/{prefix}"));
                }
                libc::AF_PACKET => {
                    let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                    let n = sll.sll_halen as usize;
                    if n == 6 {
                        let a = &sll.sll_addr;
                        entry.mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            a[0], a[1], a[2], a[3], a[4], a[5]
                        ));
                    }
                }
                _ => {}
            }
        }
        libc::freeifaddrs(ifap);
    }
    for (ifname, gw) in default_gateways() {
        if let Some(e) = map.get_mut(&ifname) {
            e.gateway = Some(gw.to_string());
        }
    }
    map.into_values().collect()
}

fn default_gateways() -> BTreeMap<String, Ipv4Addr> {
    let mut out = BTreeMap::new();
    let text = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (Some(iface), Some(dest), Some(gw)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if dest != "00000000" {
            continue;
        }

        if let Ok(raw) = u32::from_str_radix(gw, 16) {
            let ip = Ipv4Addr::from(raw.swap_bytes());
            out.entry(iface.to_string()).or_insert(ip);
        }
    }
    out
}

pub fn resolv_nameservers() -> Vec<String> {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn self_rss() -> u64 {
    rss_of_status(&std::fs::read_to_string("/proc/self/status").unwrap_or_default())
}

pub fn find_pid_by_name(names: &[&str]) -> Option<u32> {
    let dir = std::fs::read_dir("/proc").ok()?;
    for ent in dir.flatten() {
        let fname = ent.file_name();
        let Some(pid) = fname.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if names.contains(&comm.trim()) {
            return Some(pid);
        }
    }
    None
}

pub fn process_rss(pid: u32) -> u64 {
    rss_of_status(&std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default())
}

pub fn self_uptime() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let starttime_ticks: u64 = tokens.get(19)?.parse().ok()?;
    let starttime_secs = starttime_ticks / 100;
    Some(uptime_secs().saturating_sub(starttime_secs))
}

pub fn process_uptime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let starttime_ticks: u64 = tokens.get(19)?.parse().ok()?;
    let starttime_secs = starttime_ticks / 100;
    Some(uptime_secs().saturating_sub(starttime_secs))
}

pub fn self_cpu_jiffies() -> Option<u64> {
    cpu_jiffies_of_stat(&std::fs::read_to_string("/proc/self/stat").ok()?)
}

pub fn process_cpu_jiffies(pid: u32) -> Option<u64> {
    cpu_jiffies_of_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn cpu_jiffies_of_stat(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = tokens.get(11)?.parse().ok()?;
    let stime: u64 = tokens.get(12)?.parse().ok()?;
    Some(utime + stime)
}

pub fn process_cpu_pct(proc_delta: u64, total_delta: u64) -> f64 {
    if total_delta == 0 {
        return 0.0;
    }
    ((proc_delta as f64 / total_delta as f64) * 100.0).clamp(0.0, 100.0)
}

fn rss_of_status(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .map(parse_kb)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default)]
pub struct ClashVersion {
    pub version: String,
    pub meta: bool,
}

pub fn clash_version(sock: &std::path::Path) -> Option<ClashVersion> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut s = UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(300))).ok();
    s.set_write_timeout(Some(Duration::from_millis(300))).ok();
    s.write_all(b"GET /version HTTP/1.0\r\nHost: clash\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = Vec::with_capacity(512);

    let mut chunk = [0u8; 512];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1)?;
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let version = v.get("version")?.as_str()?.to_string();
    let meta = v.get("meta").and_then(|x| x.as_bool()).unwrap_or(false);
    Some(ClashVersion { version, meta })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_nonzero_on_linux() {
        let (t, a) = meminfo();
        assert!(t > 0, "MemTotal should be readable");
        assert!(a > 0 && a <= t);
    }

    #[test]
    fn uptime_positive() {
        assert!(uptime_secs() > 0);
    }

    #[test]
    fn kernel_version_nonempty() {
        let k = kernel_version();
        assert!(!k.is_empty() && !k.contains('\n'), "kernel={k:?}");
    }

    #[test]
    fn cpu_model_cores_sane() {
        let (_m, c) = cpu_model_cores();
        assert!(c >= 1);
    }

    #[test]
    fn cpu_per_core_matches_core_count() {

        let per_core = cpu_jiffies_per_core();
        let (_m, cores) = cpu_model_cores();
        assert_eq!(per_core.len(), cores);
        for (total, idle) in per_core {
            assert!(total >= idle);
        }
    }

    #[test]
    fn cpu_usage_bounds() {
        let u = cpu_usage_pct((100, 40), (200, 90));
        assert!((0.0..=100.0).contains(&u));
        assert_eq!(cpu_usage_pct((100, 40), (100, 40)), 0.0);
    }

    #[test]
    fn self_rss_positive() {
        assert!(self_rss() > 0);
    }

    #[test]
    fn cpu_jiffies_of_stat_parses_utime_stime() {

        let stat = "1234 (sniffbox) S 1 1234 1234 0 -1 4194560 100 0 0 0 71 29 0 0 20 0 3 0 999";
        assert_eq!(cpu_jiffies_of_stat(stat), Some(100));
    }

    #[test]
    fn cpu_jiffies_of_stat_survives_parens_and_spaces_in_comm() {

        let stat = "77 (weird ) name) S 1 1 1 0 -1 0 0 0 0 0 5 7 0 0 20 0 1 0 42";
        assert_eq!(cpu_jiffies_of_stat(stat), Some(12));
    }

    #[test]
    fn cpu_jiffies_of_stat_rejects_garbage() {
        assert_eq!(cpu_jiffies_of_stat(""), None);
        assert_eq!(cpu_jiffies_of_stat("1 (x) S 1 2"), None);
    }

    #[test]
    fn self_cpu_jiffies_readable_and_monotonic() {
        let a = self_cpu_jiffies().expect("/proc/self/stat readable");
        let mut spin = 0u64;
        for i in 0..3_000_000u64 {
            spin = spin.wrapping_add(i);
        }
        std::hint::black_box(spin);
        assert!(self_cpu_jiffies().unwrap() >= a);
    }

    #[test]
    fn process_cpu_pct_bounds() {
        assert_eq!(process_cpu_pct(0, 0), 0.0);
        assert_eq!(process_cpu_pct(50, 200), 25.0);
        assert_eq!(process_cpu_pct(999, 100), 100.0);
    }

    #[test]
    fn find_pid_by_name_finds_this_test_binary() {
        let comm = std::fs::read_to_string("/proc/self/comm").unwrap();
        let comm = comm.trim();
        let pid = find_pid_by_name(&[comm]).expect("own comm should be found");
        assert!(process_rss(pid) > 0);
        assert!(find_pid_by_name(&["definitely-not-a-real-process-xyz"]).is_none());
    }

    #[test]
    fn interfaces_no_loopback() {
        let ifs = interfaces();
        assert!(
            !ifs.iter().any(|i| i.name == "lo"),
            "loopback interface should be filtered"
        );
    }

    #[test]
    fn gateway_route_parse() {

        let raw = u32::from_str_radix("0100A8C0", 16).unwrap();
        assert_eq!(
            Ipv4Addr::from(raw.swap_bytes()),
            Ipv4Addr::new(192, 168, 0, 1)
        );
    }
}
