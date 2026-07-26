// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

fn proc_is_clash(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "clash")
        .unwrap_or(false)
}

pub fn clash_pid() -> Option<u32> {
    let rd = std::fs::read_dir("/proc").ok()?;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if proc_is_clash(pid) {
            return Some(pid);
        }
    }
    None
}

fn uptime_secs() -> Option<u64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|v| v as u64)
}

pub fn process_uptime_secs(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    let tokens: Vec<&str> = rest.split_whitespace().collect();

    let starttime_ticks: u64 = tokens.get(19)?.parse().ok()?;
    Some(uptime_secs()?.saturating_sub(starttime_ticks / 100))
}

pub fn clash_uptime_secs() -> Option<u64> {
    process_uptime_secs(clash_pid()?)
}

pub const CLASH_READY_MARKER: &str = "/tmp/ppgw_clash_ready.ts";

pub fn touch_ready_marker() {
    if let Some(up) = uptime_secs() {
        let _ = std::fs::write(CLASH_READY_MARKER, up.to_string());
    }
}

pub fn ready_marker_age_secs() -> Option<u64> {
    let stored: u64 = std::fs::read_to_string(CLASH_READY_MARKER)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(uptime_secs()?.saturating_sub(stored))
}

pub fn readiness_age_secs() -> Option<u64> {
    match (ready_marker_age_secs(), clash_uptime_secs()) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_process_uptime_is_readable_and_sane() {

        let pid = std::process::id();
        let up = process_uptime_secs(pid).expect("own process must have a stat entry");

        assert!(up < 86_400, "self uptime absurdly large: {up}");
    }

    #[test]
    fn missing_pid_yields_none() {

        assert_eq!(process_uptime_secs(u32::MAX), None);
    }

    #[test]
    fn no_clash_process_is_none_not_panic() {

        let _ = clash_pid();
        let _ = clash_uptime_secs();
    }

    #[test]
    fn ready_marker_roundtrip_is_fresh() {

        touch_ready_marker();
        let age = ready_marker_age_secs().expect("marker just written must be readable");
        assert!(age < 60, "freshly touched marker age too large: {age}");

        assert!(readiness_age_secs().is_some_and(|a| a < 60));
    }
}
