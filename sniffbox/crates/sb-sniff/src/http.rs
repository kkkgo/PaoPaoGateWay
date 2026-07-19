// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::ParseErr;

pub fn parse_host(buf: &[u8]) -> Result<Option<&str>, ParseErr> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {

            for h in req.headers.iter() {
                if h.name.eq_ignore_ascii_case("host") {
                    let s = std::str::from_utf8(h.value)
                        .map_err(|_| ParseErr::Malformed("host not utf8"))?
                        .trim();

                    let hostname = if let Some(rest) = s.strip_prefix('[') {
                        match rest.find(']') {
                            Some(end) => &rest[..end],
                            None => return Err(ParseErr::Malformed("unmatched '[' in host")),
                        }
                    } else {
                        s.split(':').next().unwrap_or(s)
                    };
                    if hostname.is_empty() {
                        return Ok(None);
                    }

                    let start = hostname.as_ptr() as usize - buf.as_ptr() as usize;
                    let end = start + hostname.len();
                    return Ok(Some(
                        std::str::from_utf8(&buf[start..end])
                            .map_err(|_| ParseErr::Malformed("host not utf8"))?,
                    ));
                }
            }
            Ok(None)
        }
        Err(_) => Err(ParseErr::Malformed("not http")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_get() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(parse_host(req).unwrap(), Some("example.com"));
    }

    #[test]
    fn host_with_port_strips_port() {
        let req = b"GET /path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(parse_host(req).unwrap(), Some("example.com"));
    }

    #[test]
    fn case_insensitive_header() {
        let req = b"POST / HTTP/1.1\r\nhOsT:  example.com\r\n\r\n";
        assert_eq!(parse_host(req).unwrap(), Some("example.com"));
    }

    #[test]
    fn partial_still_extracts() {

        let req = b"GET /a HTTP/1.1\r\nHost: a.b.c\r\nContent-Length: 10\r\n\r\nincomplete";
        assert_eq!(parse_host(req).unwrap(), Some("a.b.c"));
    }

    #[test]
    fn not_http_errs() {
        let junk = b"\x00\x01\x02\x03\x04\x05\x06";
        assert!(parse_host(junk).is_err());
    }

    #[test]
    fn ipv6_literal_host() {
        let req = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n";
        assert_eq!(parse_host(req).unwrap(), Some("2001:db8::1"));
    }

    #[test]
    fn ipv6_literal_host_no_port() {
        let req = b"GET / HTTP/1.1\r\nHost: [fe80::1]\r\n\r\n";
        assert_eq!(parse_host(req).unwrap(), Some("fe80::1"));
    }

    #[test]
    fn ipv6_literal_unmatched_bracket_errors() {
        let req = b"GET / HTTP/1.1\r\nHost: [2001:db8::1\r\n\r\n";
        assert!(parse_host(req).is_err());
    }

    #[test]
    fn missing_host_returns_none() {
        let req = b"GET / HTTP/1.0\r\n\r\n";
        assert_eq!(parse_host(req).unwrap(), None);
    }
}
