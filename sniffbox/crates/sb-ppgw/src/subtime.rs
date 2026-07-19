// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub fn parse_subtime(subtime: &str, sleeptime: &str) -> i64 {
    let mut duration: i64 = 86400;
    if !subtime.is_empty() {
        let parsed = if let Some(n) = subtime.strip_suffix('d') {
            n.parse::<i64>().ok().map(|v| v * 86400)
        } else if let Some(n) = subtime.strip_suffix('h') {
            n.parse::<i64>().ok().map(|v| v * 3600)
        } else if let Some(n) = subtime.strip_suffix('m') {
            n.parse::<i64>().ok().map(|v| v * 60)
        } else {
            None
        };
        if let Some(d) = parsed {
            duration = d;
        }
    }
    let mut sleep = sleeptime.parse::<i64>().unwrap_or(30);
    if sleep <= 0 {
        sleep = 30;
    }
    duration / sleep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ppgw_semantics() {
        assert_eq!(parse_subtime("1d", "30"), 2880);
        assert_eq!(parse_subtime("2h", "30"), 240);
        assert_eq!(parse_subtime("30m", "30"), 60);
        assert_eq!(parse_subtime("", "30"), 2880);
        assert_eq!(parse_subtime("bad", "30"), 2880);
        assert_eq!(parse_subtime("1.5d", "30"), 2880);
        assert_eq!(parse_subtime("1d", "bad"), 2880);
        assert_eq!(parse_subtime("1d", "0"), 2880);
        assert_eq!(parse_subtime("1d", "60"), 1440);
    }
}
