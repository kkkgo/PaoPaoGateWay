// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::idle_gate::IdleGate;
use crate::screen::{self, ScreenHistory};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const IDLE_WINDOW: Duration = Duration::from_secs(30);

pub fn spawn(dev: PathBuf, history: Arc<ScreenHistory>, shutdown: watch::Receiver<bool>) {
    tokio::spawn(run(dev, history, shutdown));
}

async fn run(dev: PathBuf, history: Arc<ScreenHistory>, mut shutdown: watch::Receiver<bool>) {
    let mut prev_lines: Vec<String> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut idle = IdleGate::new(IDLE_WINDOW);
    loop {
        tokio::select! {
            _ = shutdown.changed() => { if *shutdown.borrow() { return; } }
            _ = tick.tick() => {}
        }
        if *shutdown.borrow() {
            return;
        }

        if idle.tick(history.subscriber_count()) {

            continue;
        }

        let dev2 = dev.clone();
        let text = tokio::task::spawn_blocking(move || screen::read_screen(&dev2).ok())
            .await
            .unwrap_or(None);
        let Some(text) = text else {
            continue;
        };
        let cur_lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
        let new_lines = diff_new_lines(&prev_lines, &cur_lines);
        history.push_lines(&new_lines);
        prev_lines = cur_lines;
    }
}

fn diff_new_lines(prev: &[String], cur: &[String]) -> Vec<String> {
    for shift in 0..=prev.len() {
        let overlap = &prev[shift..];
        if overlap.len() <= cur.len() && cur[..overlap.len()] == *overlap {
            return cur[overlap.len()..].to_vec();
        }
    }
    cur.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn no_change_yields_no_new_lines() {
        let a = v(&["1", "2", "3"]);
        assert_eq!(diff_new_lines(&a, &a), Vec::<String>::new());
    }

    #[test]
    fn pure_append_at_bottom() {
        let prev = v(&["1", "2", "3"]);
        let cur = v(&["1", "2", "3", "4"]);
        assert_eq!(diff_new_lines(&prev, &cur), v(&["4"]));
    }

    #[test]
    fn scroll_by_one_line() {

        let prev = v(&["1", "2", "3"]);
        let cur = v(&["2", "3", "4"]);
        assert_eq!(diff_new_lines(&prev, &cur), v(&["4"]));
    }

    #[test]
    fn burst_scroll_multiple_lines() {

        let prev = v(&["1", "2", "3"]);
        let cur = v(&["3", "4", "5"]);
        assert_eq!(diff_new_lines(&prev, &cur), v(&["4", "5"]));
    }

    #[test]
    fn empty_prev_treats_all_as_new() {
        let cur = v(&["a", "b"]);
        assert_eq!(diff_new_lines(&[], &cur), cur);
    }

    #[test]
    fn unrelated_screen_treats_all_current_as_new() {

        let prev = v(&["x", "y", "z"]);
        let cur = v(&["a", "b"]);
        assert_eq!(diff_new_lines(&prev, &cur), v(&["a", "b"]));
    }
}
