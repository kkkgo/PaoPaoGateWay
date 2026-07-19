// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct TrafficCache {
    total_down: AtomicU64,
    total_up: AtomicU64,
}

impl TrafficCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_totals(&self, down: u64, up: u64) {
        self.total_down.fetch_add(down, Ordering::Relaxed);
        self.total_up.fetch_add(up, Ordering::Relaxed);
    }

    pub fn totals(&self) -> (u64, u64) {
        (
            self.total_down.load(Ordering::Relaxed),
            self.total_up.load(Ordering::Relaxed),
        )
    }

    pub fn clear(&self) {
        self.total_down.store(0, Ordering::Relaxed);
        self.total_up.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_accumulate_and_clear() {
        let c = TrafficCache::new();
        c.add_totals(900, 100);
        c.add_totals(100, 50);
        assert_eq!(c.totals(), (1000, 150));
        c.clear();
        assert_eq!(c.totals(), (0, 0));
    }
}
