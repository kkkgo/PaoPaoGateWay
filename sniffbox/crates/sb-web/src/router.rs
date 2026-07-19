// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {

    RedirectRoot,

    Static,

    DataFiles,

    Blocked,

    ConfigPatch,

    ConfigGet,

    Native,

    GeoUpdate,

    ProxyClash,
}

impl Route {

    pub fn needs_auth(&self) -> bool {
        !matches!(self, Route::RedirectRoot | Route::Static)
    }
}

#[derive(Clone, Copy)]
enum Seg {
    Lit(&'static str),
    Param,
}
use Seg::{Lit, Param};

const CLASH_ALLOW: &[(&str, &[Seg])] = &[

    ("GET", &[Lit("connections")]),
    ("DELETE", &[Lit("connections")]),
    ("DELETE", &[Lit("connections"), Param]),
    ("GET", &[Lit("proxies")]),
    ("GET", &[Lit("proxies"), Param]),
    ("PUT", &[Lit("proxies"), Param]),
    ("DELETE", &[Lit("proxies"), Param]),
    ("GET", &[Lit("proxies"), Param, Lit("delay")]),
    ("GET", &[Lit("group"), Param, Lit("delay")]),
    ("GET", &[Lit("providers"), Lit("proxies")]),
    ("PUT", &[Lit("providers"), Lit("proxies"), Param]),
    (
        "GET",
        &[Lit("providers"), Lit("proxies"), Param, Lit("healthcheck")],
    ),

    (
        "GET",
        &[
            Lit("providers"),
            Lit("proxies"),
            Param,
            Param,
            Lit("healthcheck"),
        ],
    ),
    ("GET", &[Lit("providers"), Lit("rules")]),
    ("PUT", &[Lit("providers"), Lit("rules"), Param]),
    ("GET", &[Lit("rules")]),
    ("PATCH", &[Lit("rules"), Lit("disable")]),

];

pub fn classify(method: &str, path: &str) -> Route {
    if method.eq_ignore_ascii_case("GET") && (path == "/" || path.is_empty()) {
        return Route::RedirectRoot;
    }
    if path == "/ui" || path.starts_with("/ui/") {

        return Route::Static;
    }
    if path == "/data" || path.starts_with("/data/") {
        return Route::DataFiles;
    }

    if path == "/sniffbox" || path.starts_with("/sniffbox/") {
        return Route::Native;
    }

    if method.eq_ignore_ascii_case("POST") && path == "/upgrade/geo" {
        return Route::GeoUpdate;
    }

    if method.eq_ignore_ascii_case("PATCH") && (path == "/configs" || path == "/configs/") {
        return Route::ConfigPatch;
    }

    if method.eq_ignore_ascii_case("GET") && (path == "/configs" || path == "/configs/") {
        return Route::ConfigGet;
    }

    if clash_allowed(method, path) {
        return Route::ProxyClash;
    }
    Route::Blocked
}

fn clash_allowed(method: &str, path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    CLASH_ALLOW.iter().any(|(m, pat)| {
        method.eq_ignore_ascii_case(m)
            && pat.len() == segs.len()
            && pat.iter().zip(&segs).all(|(p, s)| match p {
                Lit(lit) => s == lit,
                Param => !s.is_empty(),
            })
    })
}

pub fn configs_patch_mode_only(body: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<serde_json::Value>(body),
        Ok(serde_json::Value::Object(map)) if map.len() == 1 && map.contains_key("mode")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies() {
        assert_eq!(classify("GET", "/"), Route::RedirectRoot);
        assert_eq!(classify("GET", "/ui/index.html"), Route::Static);
        assert_eq!(classify("GET", "/ui"), Route::Static);
        assert_eq!(classify("GET", "/sniffbox/traffic/export"), Route::Native);
        assert_eq!(classify("GET", "/data"), Route::DataFiles);
        assert_eq!(classify("GET", "/data/version"), Route::DataFiles);
        assert_eq!(classify("PATCH", "/configs"), Route::ConfigPatch);
        assert_eq!(classify("GET", "/configs"), Route::ConfigGet);
        assert_eq!(classify("GET", "/configs/"), Route::ConfigGet);
    }

    #[test]
    fn whitelist_allows_frontend_clash_apis() {

        for (m, p) in [
            ("GET", "/connections"),
            ("DELETE", "/connections"),
            ("DELETE", "/connections/abc123"),
            ("GET", "/proxies"),
            ("GET", "/proxies/my-node"),
            ("PUT", "/proxies/GLOBAL"),
            ("DELETE", "/proxies/AUTO"),
            ("GET", "/proxies/my-node/delay"),
            ("GET", "/group/AUTO/delay"),
            ("GET", "/providers/proxies"),
            ("PUT", "/providers/proxies/Sub1"),
            ("GET", "/providers/proxies/Sub1/healthcheck"),
            ("GET", "/providers/proxies/Sub1/node-a/healthcheck"),
            ("GET", "/providers/rules"),
            ("PUT", "/providers/rules/geosite"),
            ("GET", "/rules"),
            ("PATCH", "/rules/disable"),
        ] {
            assert_eq!(
                classify(m, p),
                Route::ProxyClash,
                "{m} {p} should be whitelisted"
            );
        }
    }

    #[test]
    fn geo_update_is_intercepted() {

        assert_eq!(classify("POST", "/upgrade/geo"), Route::GeoUpdate);
        assert!(Route::GeoUpdate.needs_auth(), "geo update requires auth");

        assert_eq!(classify("GET", "/upgrade/geo"), Route::Blocked);
    }

    #[test]
    fn whitelist_blocks_everything_else() {

        for (m, p) in [
            ("POST", "/restart"),
            ("POST", "/upgrade"),
            ("POST", "/upgrade/ui"),
            ("POST", "/upgrade/core"),
            ("PUT", "/configs"),
            ("GET", "/version"),
            ("GET", "/memory"),
            ("GET", "/dns/query"),
            ("POST", "/cache/fakeip/flush"),
            ("POST", "/proxies/GLOBAL"),
            ("GET", "/restart"),
            ("PUT", "/proxies/GLOBAL/delay"),
            ("GET", "/configs/extra"),
            ("PUT", "/providers/proxies/Sub1/node-a/healthcheck"),
            ("GET", "/providers/proxies/Sub1/node-a"),
        ] {
            assert_eq!(classify(m, p), Route::Blocked, "{m} {p} should be blocked");
        }
    }

    #[test]
    fn auth_needed_except_static() {
        assert!(!Route::RedirectRoot.needs_auth());
        assert!(!Route::Static.needs_auth());
        assert!(Route::DataFiles.needs_auth());
        assert!(Route::ProxyClash.needs_auth());
        assert!(Route::Native.needs_auth());
        assert!(Route::Blocked.needs_auth());
        assert!(Route::ConfigPatch.needs_auth());
    }

    #[test]
    fn configs_patch_mode_only_gate() {

        assert!(configs_patch_mode_only(br#"{"mode":"global"}"#));
        assert!(configs_patch_mode_only(br#"{ "mode" : "rule" }"#));

        assert!(!configs_patch_mode_only(
            br#"{"mode":"global","allow-lan":true}"#
        ));
        assert!(!configs_patch_mode_only(br#"{"tproxy-port":1081}"#));
        assert!(!configs_patch_mode_only(br#"{"mixed-port":7890}"#));

        assert!(!configs_patch_mode_only(b"{}"));
        assert!(!configs_patch_mode_only(b""));
        assert!(!configs_patch_mode_only(b"\"mode\""));
        assert!(!configs_patch_mode_only(b"not json"));
    }
}
