// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::httpcli::{UA_DOWNLOAD, agent};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);
const SOCKS5: &str = "socks5h://127.0.0.1:1080";
const VERSION_FEED: &str = "https://github.com/MetaCubeX/meta-rules-dat/commits/release.atom";
const UPDATE_LOG: &str = "update.log";

const CDN_HOSTS: [&str; 3] = [
    "fastly.jsdelivr.net",
    "cdn.jsdelivr.net",
    "testingcf.jsdelivr.net",
];

type Accept = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

pub struct GeoFile {
    pub local: &'static str,
    pub gh: &'static str,
    pub cdn: &'static str,
}

pub const GEO_FILES: [GeoFile; 3] = [
    GeoFile {
        local: "GeoIP.dat",
        gh: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
        cdn: "geoip.dat",
    },
    GeoFile {
        local: "GeoSite.dat",
        gh: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        cdn: "geosite.dat",
    },
    GeoFile {
        local: "ASN.mmdb",
        gh: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
        cdn: "GeoLite2-ASN.mmdb",
    },
];

fn cdn_url(host: &str, cdn_name: &str) -> String {
    format!("https://{host}/gh/MetaCubeX/meta-rules-dat@release/{cdn_name}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoStatus {

    UpToDate,

    SkippedHashMatch,

    Downloaded,

    FetchFailed,

    DownloadFailed,
}

impl GeoStatus {
    fn as_str(self) -> &'static str {
        match self {
            GeoStatus::UpToDate => "uptodate",
            GeoStatus::SkippedHashMatch => "skipped",
            GeoStatus::Downloaded => "downloaded",
            GeoStatus::FetchFailed => "fetch_failed",
            GeoStatus::DownloadFailed => "download_failed",
        }
    }
}

pub struct GeoFileStatus {
    pub name: String,
    pub version: String,
    pub status: GeoStatus,
}

pub struct GeoReport {
    pub files: Vec<GeoFileStatus>,

    pub changed: bool,

    pub version: Option<String>,
}

impl GeoReport {
    pub fn to_json(&self) -> String {
        let files: Vec<serde_json::Value> = self
            .files
            .iter()
            .map(|f| {
                serde_json::json!({
                    "name": f.name,
                    "version": f.version,
                    "status": f.status.as_str(),
                })
            })
            .collect();
        serde_json::json!({
            "changed": self.changed,
            "version": self.version,
            "files": files,
        })
        .to_string()
    }
}

pub fn status(dir: &Path) -> GeoReport {
    init_update_log_if_missing(dir);
    let log = read_update_log(dir);
    let files = GEO_FILES
        .iter()
        .map(|f| GeoFileStatus {
            name: f.local.to_string(),
            version: log.get(f.local).cloned().unwrap_or_default(),
            status: GeoStatus::UpToDate,
        })
        .collect();
    GeoReport {
        files,
        changed: false,
        version: None,
    }
}

struct FileOutcome {
    name: String,
    status: GeoStatus,

    display_version: String,

    commit_version: Option<String>,

    changed: bool,
}

fn update_one(f: &GeoFile, dir: &Path, rv: &Option<String>, sv: String) -> FileOutcome {

    if let Some(rv) = rv {
        if !sv.is_empty() && sv == *rv {
            return FileOutcome {
                name: f.local.into(),
                status: GeoStatus::UpToDate,
                display_version: sv,
                commit_version: None,
                changed: false,
            };
        }
    }

    let Some(rh) = remote_sha256(f) else {
        return FileOutcome {
            name: f.local.into(),
            status: GeoStatus::FetchFailed,
            display_version: sv,
            commit_version: None,
            changed: false,
        };
    };

    if local_sha256(&dir.join(f.local)).as_deref() == Some(rh.as_str()) {
        let version = rv.clone().unwrap_or_else(|| sv.clone());
        return FileOutcome {
            name: f.local.into(),
            status: GeoStatus::SkippedHashMatch,
            display_version: version,
            commit_version: rv.clone(),
            changed: false,
        };
    }

    match download_verified(f, dir, &rh) {
        Ok(()) => FileOutcome {
            name: f.local.into(),
            status: GeoStatus::Downloaded,
            display_version: rv.clone().unwrap_or_default(),
            commit_version: rv.clone(),
            changed: true,
        },
        Err(_) => FileOutcome {
            name: f.local.into(),
            status: GeoStatus::DownloadFailed,
            display_version: sv,
            commit_version: None,
            changed: false,
        },
    }
}

pub fn update(dir: &Path) -> GeoReport {
    init_update_log_if_missing(dir);
    let mut log = read_update_log(dir);
    let rv = remote_version();

    let results: Vec<FileOutcome> = std::thread::scope(|s| {
        let handles: Vec<(&GeoFile, _)> = GEO_FILES
            .iter()
            .map(|f| {
                let sv = log.get(f.local).cloned().unwrap_or_default();
                let rv = rv.clone();
                (f, s.spawn(move || update_one(f, dir, &rv, sv)))
            })
            .collect();
        handles
            .into_iter()
            .map(|(f, h)| {
                h.join().unwrap_or_else(|_| FileOutcome {
                    name: f.local.into(),
                    status: GeoStatus::DownloadFailed,
                    display_version: String::new(),
                    commit_version: None,
                    changed: false,
                })
            })
            .collect()
    });

    let mut files = Vec::with_capacity(results.len());
    let mut changed = false;
    for oc in results {
        if let Some(v) = oc.commit_version {
            log.insert(oc.name.clone(), v);
        }
        changed |= oc.changed;
        files.push(GeoFileStatus {
            name: oc.name,
            version: oc.display_version,
            status: oc.status,
        });
    }

    let _ = write_update_log(dir, &log);
    GeoReport {
        files,
        changed,
        version: rv,
    }
}

pub fn remote_version() -> Option<String> {
    let sources = vec![
        (VERSION_FEED.to_string(), SOCKS5.to_string()),
        (VERSION_FEED.to_string(), String::new()),
    ];
    let body = race_accept(sources, Arc::new(|b: &[u8]| parse_updated(b).is_some()))?;
    parse_updated(&body)
}

pub fn remote_sha256(file: &GeoFile) -> Option<String> {
    let mut sources = Vec::new();
    let gh_sum = format!("{}.sha256sum", file.gh);
    for proxy in [SOCKS5, ""] {
        sources.push((gh_sum.clone(), proxy.to_string()));
    }
    for host in CDN_HOSTS {
        let cdn_sum = format!("{}.sha256sum", cdn_url(host, file.cdn));
        for proxy in [SOCKS5, ""] {
            sources.push((cdn_sum.clone(), proxy.to_string()));
        }
    }
    let body = race_accept(sources, Arc::new(|b: &[u8]| parse_sha(b).is_some()))?;
    parse_sha(&body)
}

pub fn download_verified(file: &GeoFile, dir: &Path, expected: &str) -> Result<(), String> {
    let exp = expected.to_lowercase();
    let accept: Accept = Arc::new(move |b: &[u8]| sha256_hex(b) == exp);

    let mut socks = vec![(file.gh.to_string(), SOCKS5.to_string())];
    for host in CDN_HOSTS {
        socks.push((cdn_url(host, file.cdn), SOCKS5.to_string()));
    }
    let mut direct = vec![(file.gh.to_string(), String::new())];
    for host in CDN_HOSTS {
        direct.push((cdn_url(host, file.cdn), String::new()));
    }

    let body = race_accept(socks, Arc::clone(&accept))
        .or_else(|| race_accept(direct, Arc::clone(&accept)));
    let Some(body) = body else {
        return Err("all sources failed or sha256 mismatch".to_string());
    };
    write_atomic(dir, file.local, &body).map_err(|e| e.to_string())
}

fn race_accept(sources: Vec<(String, String)>, accept: Accept) -> Option<Vec<u8>> {
    if sources.is_empty() {
        return None;
    }
    let n = sources.len();
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
    let done = Arc::new(AtomicBool::new(false));
    for (url, proxy) in sources {
        let tx = tx.clone();
        let done = Arc::clone(&done);
        let accept = Arc::clone(&accept);
        std::thread::spawn(move || {
            if done.load(Ordering::Relaxed) {
                return;
            }
            let res = fetch(&url, &proxy).ok().filter(|b| accept(b));
            let _ = tx.send(res);
        });
    }
    drop(tx);

    let mut fails = 0usize;
    while let Ok(res) = rx.recv() {
        match res {
            Some(body) => {
                done.store(true, Ordering::Relaxed);
                return Some(body);
            }
            None => {
                fails += 1;
                if fails == n {
                    break;
                }
            }
        }
    }
    None
}

fn fetch(url: &str, proxy: &str) -> Result<Vec<u8>, String> {
    let ag = agent(proxy, UA_DOWNLOAD, TIMEOUT).map_err(|e| e.to_string())?;
    let mut resp = ag.get(url).call().map_err(|e| e.to_string())?;
    let code = resp.status().as_u16();
    if code >= 400 {
        return Err(format!("status {code}"));
    }
    resp.body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| e.to_string())
}

fn parse_updated(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    let start = s.find("<updated>")? + "<updated>".len();
    let rest = &s[start..];
    let end = rest.find("</updated>")?;
    let ts = rest[..end].trim();

    if ts.len() >= 20 && ts.ends_with('Z') && ts.as_bytes()[4] == b'-' {
        Some(ts.to_string())
    } else {
        None
    }
}

fn parse_sha(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    let tok = s.split_whitespace().next()?.trim().to_lowercase();
    if tok.len() == 64 && tok.bytes().all(|c| c.is_ascii_hexdigit()) {
        Some(tok)
    } else {
        None
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn local_sha256(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|b| sha256_hex(&b))
}

fn write_atomic(dir: &Path, name: &str, body: &[u8]) -> std::io::Result<()> {
    let final_path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, body)?;
    match std::fs::rename(&tmp, &final_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn read_update_log(dir: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(content) = std::fs::read_to_string(dir.join(UPDATE_LOG)) {
        for line in content.lines() {
            if let Some((name, ver)) = line.split_once(',') {
                let (name, ver) = (name.trim(), ver.trim());
                if !name.is_empty() && !ver.is_empty() {
                    map.insert(name.to_string(), ver.to_string());
                }
            }
        }
    }
    map
}

fn write_update_log(dir: &Path, map: &BTreeMap<String, String>) -> std::io::Result<()> {
    let mut out = String::new();
    for f in &GEO_FILES {
        if let Some(v) = map.get(f.local) {
            out.push_str(f.local);
            out.push(',');
            out.push_str(v);
            out.push('\n');
        }
    }
    write_atomic(dir, UPDATE_LOG, out.as_bytes())
}

fn init_update_log_if_missing(dir: &Path) {
    if dir.join(UPDATE_LOG).exists() {
        return;
    }
    let mut map = BTreeMap::new();
    for f in &GEO_FILES {
        if let Some(v) = mtime_iso(&dir.join(f.local)) {
            map.insert(f.local.to_string(), v);
        }
    }
    if !map.is_empty() {
        let _ = write_update_log(dir, &map);
    }
}

fn mtime_iso(path: &Path) -> Option<String> {
    let mt = std::fs::metadata(path).ok()?.modified().ok()?;
    let secs = mt.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    let odt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    odt.format(&fmt).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write as _};
    use std::net::TcpListener;

    #[test]
    fn sha256_known_vector() {

        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parse_updated_extracts_first_timestamp() {
        let feed = b"<feed><updated>2026-07-11T23:26:04Z</updated><entry><updated>2020-01-01T00:00:00Z</updated></entry></feed>";
        assert_eq!(parse_updated(feed).as_deref(), Some("2026-07-11T23:26:04Z"));
        assert_eq!(parse_updated(b"no timestamp here"), None);
        assert_eq!(parse_updated(b"<updated>garbage</updated>"), None);
    }

    #[test]
    fn parse_sha_first_token_only() {
        assert_eq!(
            parse_sha(
                b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  geoip.dat\n"
            )
            .as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(parse_sha(b"deadbeef  x"), None);
        assert_eq!(parse_sha(b""), None);
    }

    #[test]
    fn update_log_roundtrip_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = BTreeMap::new();
        map.insert("GeoIP.dat".to_string(), "2026-07-11T23:26:04Z".to_string());
        map.insert("ASN.mmdb".to_string(), "2026-07-11T23:26:04Z".to_string());
        write_update_log(dir.path(), &map).unwrap();
        let back = read_update_log(dir.path());
        assert_eq!(back.get("GeoIP.dat").unwrap(), "2026-07-11T23:26:04Z");
        assert_eq!(back.get("ASN.mmdb").unwrap(), "2026-07-11T23:26:04Z");

        let raw = std::fs::read_to_string(dir.path().join(UPDATE_LOG)).unwrap();
        assert!(raw.find("GeoIP.dat").unwrap() < raw.find("ASN.mmdb").unwrap());
    }

    #[test]
    fn init_creates_log_from_mtime() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("GeoIP.dat"), b"x").unwrap();
        init_update_log_if_missing(dir.path());
        let log = read_update_log(dir.path());
        let v = log.get("GeoIP.dat").expect("should initialize from mtime");
        assert!(v.ends_with('Z') && v.len() >= 20, "ISO8601: {v}");

        std::fs::write(dir.path().join(UPDATE_LOG), b"GeoIP.dat,SENTINEL\n").unwrap();
        init_update_log_if_missing(dir.path());
        assert_eq!(
            read_update_log(dir.path()).get("GeoIP.dat").unwrap(),
            "SENTINEL"
        );
    }

    fn mock_http(body: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(body);
            }
        });
        (format!("http://127.0.0.1:{port}/"), h)
    }

    #[test]
    fn race_accept_returns_matching_body() {
        let (url, h) = mock_http(b"hello-geo");
        let want = sha256_hex(b"hello-geo");
        let accept: Accept = Arc::new(move |b| sha256_hex(b) == want);
        let got = race_accept(vec![(url, String::new())], accept);
        let _ = h.join();
        assert_eq!(got.as_deref(), Some(&b"hello-geo"[..]));
    }

    #[test]
    fn race_accept_rejects_mismatch() {
        let (url, h) = mock_http(b"hello-geo");
        let accept: Accept = Arc::new(|_b| false);
        let got = race_accept(vec![(url, String::new())], accept);
        let _ = h.join();
        assert_eq!(got, None);
    }
}
