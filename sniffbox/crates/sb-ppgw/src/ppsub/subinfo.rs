// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use super::UserInfo;

const VERSION: i64 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub info: Option<UserInfo>,
    pub at: i64,
}

pub fn file() -> String {
    format!("{}/ppsub_subinfo.json", super::state::base_dir())
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn save(path: &str, subs: &[Entry]) -> std::io::Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, to_json(subs))?;
    std::fs::rename(&tmp, path)
}

pub fn load(path: &str) -> Vec<Entry> {
    std::fs::read_to_string(path)
        .ok()
        .map(|t| from_json(&t))
        .unwrap_or_default()
}

fn to_json(subs: &[Entry]) -> String {
    let subs: Vec<serde_json::Value> = subs
        .iter()
        .map(|e| {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), e.name.clone().into());
            m.insert("at".into(), e.at.into());
            if let Some(u) = &e.info {
                m.insert("upload".into(), u.upload.into());
                m.insert("download".into(), u.download.into());
                m.insert("total".into(), u.total.into());
                m.insert("expire".into(), u.expire.into());
            }
            serde_json::Value::Object(m)
        })
        .collect();
    serde_json::json!({ "version": VERSION, "subs": subs }).to_string()
}

fn from_json(text: &str) -> Vec<Entry> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    if v.get("version").and_then(|x| x.as_i64()) != Some(VERSION) {
        return Vec::new();
    }
    let Some(arr) = v.get("subs").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| {
            let name = s.get("name")?.as_str()?.to_string();
            let num = |k: &str| s.get(k).and_then(|x| x.as_i64());
            let info = match (num("total"), num("expire")) {
                (None, None) => None,
                (total, expire) => Some(UserInfo {
                    total: total.unwrap_or(0),
                    upload: num("upload").unwrap_or(0),
                    download: num("download").unwrap_or(0),
                    expire: expire.unwrap_or(0),
                }),
            };
            Some(Entry {
                name,
                info,
                at: num("at").unwrap_or(0),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Entry> {
        vec![
            Entry {
                name: "A".into(),
                info: Some(UserInfo {
                    total: 100,
                    upload: 1,
                    download: 2,
                    expire: 1_700_000_000,
                }),
                at: 1_690_000_000,
            },
            Entry {
                name: "A_B".into(),
                info: None,
                at: 0,
            },
        ]
    }

    #[test]
    fn round_trip_keeps_order_and_info_less_subs() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("subinfo.json");
        let p = p.to_str().unwrap();
        save(p, &sample()).unwrap();
        assert_eq!(load(p), sample());
    }

    #[test]
    fn written_file_has_only_names_and_numbers() {
        let v: serde_json::Value = serde_json::from_str(&to_json(&sample())).unwrap();
        let keys: Vec<&str> = v["subs"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys.len(),
            6,
            "name, at and the four userinfo numbers only: {keys:?}"
        );
        assert!(
            v["subs"][1].get("total").is_none(),
            "no userinfo -> no numbers"
        );
    }

    #[test]
    fn unreadable_or_foreign_files_are_empty() {
        assert!(load("/nonexistent/subinfo.json").is_empty());
        assert!(from_json("not json").is_empty());
        assert!(from_json(r#"{"version":99,"subs":[{"name":"A"}]}"#).is_empty());
        assert!(from_json(r#"{"version":1,"subs":[{"total":5}]}"#).is_empty());
    }
}
