// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::time::{Duration, Instant};

pub struct IdleGate {
    since: Option<Instant>,
    window: Duration,
}

impl IdleGate {
    pub fn new(window: Duration) -> Self {
        Self {
            since: None,
            window,
        }
    }

    pub fn tick_at(&mut self, subscriber_count: usize, now: Instant) -> bool {
        if subscriber_count == 0 {
            let since = *self.since.get_or_insert(now);
            now.duration_since(since) >= self.window
        } else {
            self.since = None;
            false
        }
    }

    pub fn tick(&mut self, subscriber_count: usize) -> bool {
        self.tick_at(subscriber_count, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_active_while_subscribed() {
        let mut g = IdleGate::new(Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(!g.tick_at(1, t0));
        assert!(!g.tick_at(1, t0 + Duration::from_secs(100)));
    }

    #[test]
    fn skips_once_idle_past_window() {
        let mut g = IdleGate::new(Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(!g.tick_at(0, t0));
        assert!(!g.tick_at(0, t0 + Duration::from_secs(29)));
        assert!(g.tick_at(0, t0 + Duration::from_secs(30)));
        assert!(g.tick_at(0, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn new_subscriber_resets_the_clock() {
        let mut g = IdleGate::new(Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(!g.tick_at(0, t0));
        assert!(g.tick_at(0, t0 + Duration::from_secs(30)));
        assert!(!g.tick_at(1, t0 + Duration::from_secs(31)));

        assert!(!g.tick_at(0, t0 + Duration::from_secs(40)));
        assert!(g.tick_at(0, t0 + Duration::from_secs(70)));
    }
}
