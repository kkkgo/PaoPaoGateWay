// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::path::{Component, Path, PathBuf};

pub fn resolve(webroot: &Path, url_path: &str) -> Option<PathBuf> {
    resolve_prefixed(webroot, url_path, "/ui")
}

pub fn resolve_prefixed(webroot: &Path, url_path: &str, prefix: &str) -> Option<PathBuf> {
    let rel = url_path.strip_prefix(prefix).unwrap_or(url_path);
    let rel = rel.strip_prefix('/').unwrap_or(rel);
    let rel = if rel.is_empty() { "index.html" } else { rel };

    let mut safe = PathBuf::new();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => safe.push(c),

            _ => return None,
        }
    }
    let full = webroot.join(&safe);

    Some(if full.is_dir() {
        full.join("index.html")
    } else {
        full
    })
}

pub fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("map") => "application/json; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

pub fn cache_control(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some(
            "js" | "mjs" | "css" | "svg" | "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico"
            | "woff2" | "woff" | "ttf" | "wasm",
        ) => "public, max-age=31536000, immutable",
        _ => "no-cache",
    }
}

pub const SECURITY_HEADERS: [(&str, &str); 4] = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "frame-ancestors 'none'"),
    ("Referrer-Policy", "no-referrer"),
];

pub fn etag(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    let mtime_ns = (meta.mtime() as i128) * 1_000_000_000 + i128::from(meta.mtime_nsec());
    format!("W/\"{:x}-{:x}-{:x}\"", meta.len(), mtime_ns, meta.ino())
}

pub fn etag_matches(if_none_match: Option<&[u8]>, etag: &str) -> bool {
    let Some(h) = if_none_match.and_then(|v| std::str::from_utf8(v).ok()) else {
        return false;
    };
    let opaque = |t: &str| t.trim().trim_start_matches("W/").to_string();
    let want = opaque(etag);
    h.split(',').any(|t| t.trim() == "*" || opaque(t) == want)
}

pub fn accepts_gzip(accept_encoding: Option<&[u8]>) -> bool {
    let Some(h) = accept_encoding.and_then(|v| std::str::from_utf8(v).ok()) else {
        return false;
    };
    h.split(',').any(|part| {
        let mut it = part.split(';');
        let coding = it.next().unwrap_or("").trim();
        if !(coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip")) {
            return false;
        }
        !it.any(|p| {
            let p = p.trim();
            p.strip_prefix("q=")
                .or_else(|| p.strip_prefix("Q="))
                .and_then(|q| q.trim().parse::<f32>().ok())
                .is_some_and(|q| q <= 0.0)
        })
    })
}

pub const GZIP_MIN: u64 = 1024;

pub const GZIP_MAX_FILE: u64 = 4 * 1024 * 1024;

const GZIP_CACHE_BUDGET: usize = 8 * 1024 * 1024;

pub fn compressible(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("html" | "htm" | "js" | "mjs" | "css" | "json" | "svg" | "map" | "txt" | "wasm")
    )
}

pub fn gzip(raw: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(
        Vec::with_capacity(raw.len() / 3 + 64),
        flate2::Compression::default(),
    );
    let _ = enc.write_all(raw);
    enc.finish().unwrap_or_default()
}

type GzipEntry = (String, std::sync::Arc<[u8]>);

#[derive(Default)]
pub struct GzipCache {
    inner: std::sync::Mutex<std::collections::HashMap<PathBuf, GzipEntry>>,
}

impl GzipCache {
    pub fn get(&self, path: &Path, etag: &str) -> Option<std::sync::Arc<[u8]>> {
        let m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.get(path)
            .filter(|(tag, _)| tag == etag)
            .map(|(_, gz)| std::sync::Arc::clone(gz))
    }

    pub fn put(&self, path: PathBuf, etag: String, gz: std::sync::Arc<[u8]>) {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let held: usize = m.values().map(|(_, g)| g.len()).sum();
        if held + gz.len() > GZIP_CACHE_BUDGET {
            m.clear();
        }
        m.insert(path, (etag, gz));
    }

    pub fn bytes(&self) -> usize {
        let m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.values().map(|(_, g)| g.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_encoding_parsing() {
        assert!(accepts_gzip(Some(b"gzip, deflate, br, zstd")));
        assert!(accepts_gzip(Some(b"br;q=1.0, GZIP;q=0.5")));
        assert!(accepts_gzip(Some(b"x-gzip")));
        assert!(!accepts_gzip(Some(b"gzip;q=0")));
        assert!(!accepts_gzip(Some(b"gzip; q=0.0, br")));
        assert!(!accepts_gzip(Some(b"br, deflate")));
        assert!(!accepts_gzip(Some(b"identity")));
        assert!(!accepts_gzip(None));
    }

    #[test]
    fn if_none_match_weak_comparison() {
        let tag = r#"W/"10-20-30""#;
        assert!(etag_matches(Some(br#"W/"10-20-30""#), tag));
        assert!(etag_matches(Some(br#""10-20-30""#), tag));
        assert!(etag_matches(Some(br#""x", W/"10-20-30""#), tag));
        assert!(etag_matches(Some(b"*"), tag));
        assert!(!etag_matches(Some(br#"W/"10-20-31""#), tag));
        assert!(!etag_matches(None, tag));
    }

    #[test]
    fn etag_tracks_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("index.html");
        std::fs::write(&p, "a").unwrap();
        let t1 = etag(&std::fs::metadata(&p).unwrap());
        assert!(t1.starts_with("W/\""), "{t1}");
        assert_eq!(t1, etag(&std::fs::metadata(&p).unwrap()), "stable");
        std::fs::write(&p, "bb").unwrap();
        assert_ne!(t1, etag(&std::fs::metadata(&p).unwrap()), "length change");
    }

    #[test]
    fn gzip_round_trips_and_only_text_is_compressible() {
        use std::io::Read;
        let raw = "<html>".repeat(1000);
        let gz = gzip(raw.as_bytes());
        assert!(gz.len() * 10 < raw.len());
        let mut back = String::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_string(&mut back)
            .unwrap();
        assert_eq!(back, raw);
        assert!(compressible(Path::new("bundle.X.js")));
        assert!(compressible(Path::new("index.HTML")));
        assert!(!compressible(Path::new("font.woff2")));
        assert!(!compressible(Path::new("a.png")));
    }

    #[test]
    fn gzip_cache_is_keyed_by_etag_and_bounded() {
        let c = GzipCache::default();
        let p = PathBuf::from("/w/ui/index.html");
        c.put(
            p.clone(),
            "W/\"1\"".into(),
            std::sync::Arc::from(&b"gz1"[..]),
        );
        assert!(c.get(&p, "W/\"1\"").is_some());
        assert!(c.get(&p, "W/\"2\"").is_none(), "stale after file change");
        let big: std::sync::Arc<[u8]> = vec![0u8; GZIP_CACHE_BUDGET - 1].into();
        c.put(PathBuf::from("/w/ui/big.js"), "W/\"b\"".into(), big);
        assert!(c.bytes() <= GZIP_CACHE_BUDGET);
        assert!(c.get(&p, "W/\"1\"").is_none(), "evicted to stay in budget");
    }

    #[test]
    fn root_maps_to_index() {

        let wr = Path::new("/srv/www/ui");
        assert_eq!(
            resolve(wr, "/ui/").unwrap(),
            PathBuf::from("/srv/www/ui/index.html")
        );
        assert_eq!(
            resolve(wr, "/ui").unwrap(),
            PathBuf::from("/srv/www/ui/index.html")
        );
    }

    #[test]
    fn normal_files() {
        let wr = Path::new("/srv/www/ui");
        assert_eq!(
            resolve(wr, "/ui/assets/app.js").unwrap(),
            PathBuf::from("/srv/www/ui/assets/app.js")
        );
    }

    #[test]
    fn rejects_traversal() {
        let wr = Path::new("/srv/www/ui");
        assert!(resolve(wr, "/ui/../../etc/passwd").is_none());
        assert!(resolve(wr, "/ui/../secret").is_none());

        assert!(resolve(wr, "/ui//etc/passwd").is_none());

        assert_eq!(
            resolve(wr, "/ui/a//b.js").unwrap(),
            PathBuf::from("/srv/www/ui/a/b.js")
        );
    }

    #[test]
    fn data_prefix() {

        let root = Path::new("/srv/ui/data");
        assert_eq!(
            resolve_prefixed(root, "/data/version", "/data").unwrap(),
            PathBuf::from("/srv/ui/data/version")
        );
        assert!(resolve_prefixed(root, "/data/../../etc/passwd", "/data").is_none());
    }

    #[test]
    fn content_types() {
        assert_eq!(
            content_type(Path::new("a.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("a.JS")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("a.unknown")),
            "application/octet-stream"
        );
    }

    #[test]
    fn cache_control_immutable_for_assets() {
        let long = "public, max-age=31536000, immutable";
        assert_eq!(cache_control(Path::new("bundle.D4w4yfhp.js")), long);
        assert_eq!(cache_control(Path::new("a.CSS")), long);
        assert_eq!(cache_control(Path::new("logo.svg")), long);
        assert_eq!(cache_control(Path::new("font.woff2")), long);

        assert_eq!(cache_control(Path::new("index.html")), "no-cache");
        assert_eq!(cache_control(Path::new("data.json")), "no-cache");
    }
}
