// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

fn enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

fn wrap(s: &str, code: &str) -> String {
    if enabled() {
        format!("{code}{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn green(s: &str) -> String {
    wrap(s, "\x1b[32m")
}

pub fn orange(s: &str) -> String {
    wrap(s, "\x1b[38;5;208m")
}

pub fn red(s: &str) -> String {
    wrap(s, "\x1b[31m")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_strips() {

        assert_eq!(
            wrap("x", "\x1b[32m"),
            if enabled() {
                "\x1b[32mx\x1b[0m".to_string()
            } else {
                "x".to_string()
            }
        );
    }
}
