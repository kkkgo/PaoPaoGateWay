// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

const RESERVED_TLDS: &[&str] = &[
    "test",
    "example",
    "invalid",
    "localhost",
    "arpa",
    "local",
    "onion",
    "alt",
];

pub fn is_valid_fakeip_domain(name: &str) -> bool {

    let name = name.strip_suffix('.').unwrap_or(name);

    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let mut n_labels = 0usize;
    let mut tld = "";
    for label in name.split('.') {
        if !is_valid_label(label) {
            return false;
        }
        n_labels += 1;
        tld = label;
    }
    if n_labels < 2 {
        return false;
    }
    if tld.len() < 2 {
        return false;
    }
    if RESERVED_TLDS.iter().any(|r| r.eq_ignore_ascii_case(tld)) {
        return false;
    }
    true
}

fn is_valid_label(label: &str) -> bool {
    let b = label.as_bytes();
    let len = b.len();
    if len == 0 || len > 63 {
        return false;
    }
    if !b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-') {
        return false;
    }
    if b[0] == b'-' || b[len - 1] == b'-' {
        return false;
    }

    if len >= 4
        && b[2] == b'-'
        && b[3] == b'-'
        && !(b[0].eq_ignore_ascii_case(&b'x') && b[1].eq_ignore_ascii_case(&b'n'))
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_domains() {
        for d in [
            "google.com",
            "www.gstatic.com",
            "a.b.c.example.org",
            "sub.example.com",
            "x.io",
            "1.2.3.host.net",
            "xn--p1ai.com",
            "foo.xn--80akhbyknj4f",
            "host123.co.uk",
        ] {
            assert!(is_valid_fakeip_domain(d), "{d} should be valid");
        }
    }

    #[test]
    fn rejects_reserved_tlds() {
        for d in [
            "foo.test",
            "a.b.example",
            "x.invalid",
            "host.localhost",
            "myhost.local",
            "myhost.local.",
            "abc.onion",
            "x.alt",
            "1.2.3.4.in-addr.arpa",
            "service.arpa",
        ] {
            assert!(
                !is_valid_fakeip_domain(d),
                "{d} (reserved TLD) must be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed() {
        for d in [
            "",
            "localhost",
            "foo",
            ".com",
            "a..b.com",
            "under_score.com",
            "has space.com",
            "-lead.com",
            "trail-.com",
            "ab--cd.com",
            "a.b",
            "192.168.0.1",
        ] {
            assert!(
                !is_valid_fakeip_domain(d),
                "{d} (malformed) must be rejected"
            );
        }
    }

    #[test]
    fn label_and_total_length_bounds() {
        let lab63 = "a".repeat(63);
        assert!(
            is_valid_fakeip_domain(&format!("{lab63}.com")),
            "63-char label OK"
        );
        let lab64 = "a".repeat(64);
        assert!(
            !is_valid_fakeip_domain(&format!("{lab64}.com")),
            "64-char label too long"
        );

        let long = format!("{}.com", vec!["abcdefgh"; 40].join("."));
        assert!(long.len() > 253);
        assert!(!is_valid_fakeip_domain(&long), "total > 253 rejected");
    }

    #[test]
    fn case_insensitive() {
        assert!(is_valid_fakeip_domain("GOOGLE.COM"));
        assert!(!is_valid_fakeip_domain("Host.LOCAL"));
        assert!(is_valid_fakeip_domain("XN--P1AI.COM"));
    }
}
