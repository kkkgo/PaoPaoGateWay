// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub fn state_path() -> PathBuf {
    std::env::var_os("SNIFFBOX_SMART_FIXED")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/sniffbox.smartfixed.json"))
}

#[derive(Debug)]
pub struct SmartFixed {
    map: Mutex<HashMap<String, String>>,
    path: PathBuf,
}

impl SmartFixed {

    pub fn load(path: PathBuf) -> Arc<Self> {
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<HashMap<String, String>>(&s).ok())
            .unwrap_or_default();
        Arc::new(Self {
            map: Mutex::new(map),
            path,
        })
    }

    pub fn in_memory() -> Arc<Self> {
        Arc::new(Self {
            map: Mutex::new(HashMap::new()),
            path: PathBuf::new(),
        })
    }

    pub fn get(&self, group: &str) -> Option<String> {
        self.lock().get(group).cloned()
    }

    pub fn all(&self) -> HashMap<String, String> {
        self.lock().clone()
    }

    pub fn set(&self, group: &str, node: &str) {
        self.lock().insert(group.to_string(), node.to_string());
        self.persist();
    }

    pub fn clear(&self, group: &str) -> bool {
        let had = self.lock().remove(group).is_some();
        if had {
            self.persist();
        }
        had
    }

    pub fn retain_groups(&self, keep: &[String]) {
        let keep: std::collections::HashSet<&str> = keep.iter().map(String::as_str).collect();
        let mut m = self.lock();
        let before = m.len();
        m.retain(|g, _| keep.contains(g.as_str()));
        let changed = m.len() != before;
        drop(m);
        if changed {
            self.persist();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {

        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist(&self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let snapshot = self.lock().clone();
        if let Ok(s) = serde_json::to_string(&snapshot)
            && let Err(e) = write_atomic(&self.path, s.as_bytes())
        {
            tracing::debug!("smart fixed persist failed ({}): {e}", self.path.display());
        }
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sb-smartfixed-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn set_get_clear_roundtrip() {
        let f = SmartFixed::in_memory();
        assert_eq!(f.get("G"), None);
        f.set("G", "N1");
        assert_eq!(f.get("G").as_deref(), Some("N1"));
        f.set("G", "N2");
        assert_eq!(f.get("G").as_deref(), Some("N2"), "set must overwrite");
        assert!(f.clear("G"), "clear on a locked group reports true");
        assert_eq!(f.get("G"), None);
        assert!(!f.clear("G"), "clear on an unlocked group reports false");
    }

    #[test]
    fn retain_groups_drops_vanished_groups() {
        let f = SmartFixed::in_memory();
        f.set("A", "N1");
        f.set("B", "N2");
        f.retain_groups(&["A".to_string()]);
        assert_eq!(f.get("A").as_deref(), Some("N1"));
        assert_eq!(f.get("B"), None);
    }

    #[test]
    fn persists_across_reload() {
        let p = tmpdir().join("persist.json");
        let _ = std::fs::remove_file(&p);
        let f = SmartFixed::load(p.clone());
        f.set("G", "N1");
        drop(f);
        let again = SmartFixed::load(p.clone());
        assert_eq!(again.get("G").as_deref(), Some("N1"));
        again.clear("G");
        let third = SmartFixed::load(p.clone());
        assert_eq!(third.get("G"), None, "clear must be persisted too");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn garbage_state_file_loads_as_empty() {
        let p = tmpdir().join("garbage.json");
        std::fs::write(&p, b"{not json").unwrap();
        let f = SmartFixed::load(p.clone());
        assert!(f.all().is_empty(), "corrupt state must degrade to no locks");

        f.set("G", "N1");
        assert_eq!(SmartFixed::load(p.clone()).get("G").as_deref(), Some("N1"));
        let _ = std::fs::remove_file(&p);
    }
}
