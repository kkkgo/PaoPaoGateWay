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

#[cfg(test)]
mod tests {
    use super::*;

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
