// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub struct Gate {
    set: Arc<Mutex<HashSet<String>>>,
    key: String,
}

impl Gate {

    pub fn try_acquire(set: &Arc<Mutex<HashSet<String>>>, key: &str) -> Option<Self> {
        let mut g = set.lock().unwrap_or_else(|e| e.into_inner());
        if !g.insert(key.to_string()) {
            return None;
        }
        drop(g);
        Some(Gate {
            set: Arc::clone(set),
            key: key.to_string(),
        })
    }
}

impl Drop for Gate {
    fn drop(&mut self) {

        self.set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_set() -> Arc<Mutex<HashSet<String>>> {
        Arc::new(Mutex::new(HashSet::new()))
    }

    #[test]
    fn second_acquire_of_same_key_is_refused_until_release() {
        let set = new_set();
        let first = Gate::try_acquire(&set, "AUTO").expect("first acquire should win");
        assert!(
            Gate::try_acquire(&set, "AUTO").is_none(),
            "same key must be refused while in flight"
        );
        drop(first);
        assert!(
            Gate::try_acquire(&set, "AUTO").is_some(),
            "key must be reusable after release"
        );
    }

    #[test]
    fn distinct_keys_do_not_contend() {
        let set = new_set();
        let _a = Gate::try_acquire(&set, "A").expect("A should acquire");
        let _b = Gate::try_acquire(&set, "B").expect("B should acquire independently");
        assert_eq!(set.lock().unwrap().len(), 2);
    }

    #[test]
    fn poisoned_lock_still_releases_on_drop() {
        let set = new_set();
        let g = Gate::try_acquire(&set, "AUTO").expect("acquire");
        let poison = Arc::clone(&set);
        let _ = std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();
        drop(g);
        assert!(
            !set.lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains("AUTO"),
            "key must be released even through a poisoned mutex"
        );
    }
}
