// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

const FALLBACK_ROWS: usize = 25;
const FALLBACK_COLS: usize = 80;

const VGA_TO_ANSI: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];

fn vcsa_path(vcs: &Path) -> PathBuf {
    match vcs.file_name().and_then(|n| n.to_str()) {
        Some(name) if name.starts_with("vcs") && !name.starts_with("vcsa") => {
            let suffix = &name[3..];
            vcs.with_file_name(format!("vcsa{suffix}"))
        }
        _ => vcs.with_file_name("vcsa1"),
    }
}

pub fn read_screen(vcs_dev: &Path) -> io::Result<String> {
    if let Ok(raw) = std::fs::read(vcsa_path(vcs_dev)) {

        if raw.len() > 4 && raw[0] > 0 && raw[1] > 0 {
            let (rows, cols) = (raw[0] as usize, raw[1] as usize);
            return Ok(render_colored(&raw[4..], rows, cols));
        }
    }

    let content = std::fs::read(vcs_dev)?;
    Ok(render_plain(&content, FALLBACK_ROWS, FALLBACK_COLS))
}

fn attr_to_sgr(attr: u8) -> String {
    let fg = VGA_TO_ANSI[(attr & 0x07) as usize];
    let bg = VGA_TO_ANSI[((attr >> 4) & 0x07) as usize];
    let bright = attr & 0x08 != 0;
    let fg_code = if bright { 90 + fg } else { 30 + fg };
    if bg == 0 {
        format!("\x1b[0;{fg_code}m")
    } else {
        let bg_code = 40 + bg;
        format!("\x1b[0;{fg_code};{bg_code}m")
    }
}

fn render_colored(cells: &[u8], rows: usize, cols: usize) -> String {
    let mut out = String::with_capacity(rows * (cols + 16));
    for r in 0..rows {
        let row_start = r * cols * 2;
        if row_start >= cells.len() {
            break;
        }

        let mut row: Vec<(u8, u8)> = Vec::with_capacity(cols);
        for c in 0..cols {
            let i = row_start + c * 2;
            if i + 1 >= cells.len() {
                break;
            }
            row.push((cells[i], cells[i + 1]));
        }
        let last = row
            .iter()
            .rposition(|&(ch, _)| ch != 0 && ch != b' ')
            .map(|p| p + 1)
            .unwrap_or(0);

        let mut cur_attr: Option<u8> = None;
        let mut wrote = false;
        for &(ch, attr) in &row[..last] {
            if cur_attr != Some(attr) {
                out.push_str(&attr_to_sgr(attr));
                cur_attr = Some(attr);
            }
            let ch = if ch == 0 || ch.is_ascii_control() {
                b' '
            } else {
                ch
            };
            out.push(ch as char);
            wrote = true;
        }
        if wrote {
            out.push_str("\x1b[0m");
        }
        out.push('\n');
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

fn render_plain(content: &[u8], rows: usize, cols: usize) -> String {
    let mut out = String::with_capacity(rows * (cols + 1));
    for r in 0..rows {
        let start = r * cols;
        if start >= content.len() {
            break;
        }
        let end = (start + cols).min(content.len());
        let line: String = content[start..end]
            .iter()
            .map(|&b| {
                if b == 0 || b.is_ascii_control() {
                    ' '
                } else {
                    b as char
                }
            })
            .collect();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

pub struct ScreenHistory {
    lines: Mutex<VecDeque<Arc<str>>>,
    cap: usize,
    tx: broadcast::Sender<Arc<str>>,
}

impl ScreenHistory {
    pub fn new(cap: usize) -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(256);
        Arc::new(Self {
            lines: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            cap,
            tx,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<str>> {
        self.tx.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    pub fn push_lines(&self, new_lines: &[String]) {
        if new_lines.is_empty() {
            return;
        }
        {
            let mut g = self.lines.lock().unwrap();
            for l in new_lines {
                g.push_back(Arc::from(l.as_str()));
            }
            while g.len() > self.cap {
                g.pop_front();
            }
        }
        let joined = new_lines.join("\n");
        let _ = self.tx.send(Arc::from(joined.as_str()));
    }

    pub fn snapshot_text(&self) -> String {
        let g = self.lines.lock().unwrap();
        g.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcsa_derivation() {
        assert_eq!(
            vcsa_path(Path::new("/dev/vcs1")),
            PathBuf::from("/dev/vcsa1")
        );
        assert_eq!(
            vcsa_path(Path::new("/dev/vcs2")),
            PathBuf::from("/dev/vcsa2")
        );
    }

    #[test]
    fn attr_swaps_blue_and_red() {

        assert_eq!(attr_to_sgr(0x04), "\x1b[0;31m");

        assert_eq!(attr_to_sgr(0x01), "\x1b[0;34m");

        assert_eq!(attr_to_sgr(0x4A), "\x1b[0;92;41m");
    }

    #[test]
    fn render_plain_strips_and_wraps() {
        let content = b"hi\0\0\0world";
        let s = render_plain(content, 2, 5);
        assert_eq!(s, "hi\nworld\n");
    }

    #[test]
    fn render_colored_emits_sgr_and_rstrips() {

        let mut cells = Vec::new();
        cells.extend_from_slice(&[b'h', 0x07, b'i', 0x07, b' ', 0x07, b' ', 0x07]);
        let s = render_colored(&cells, 1, 4);

        assert_eq!(s, "\x1b[0;37mhi\x1b[0m\n");
    }

    #[test]
    fn render_colored_changes_sgr_on_attr_change() {

        let cells = [b'a', 0x04, b'b', 0x01];
        let s = render_colored(&cells, 1, 2);
        assert_eq!(s, "\x1b[0;31ma\x1b[0;34mb\x1b[0m\n");
    }

    #[test]
    fn read_screen_prefers_vcsa_colored() {
        let dir = tempfile::tempdir().unwrap();
        let vcs = dir.path().join("vcs1");
        let vcsa = dir.path().join("vcsa1");

        let mut buf = vec![1u8, 2, 0, 0];
        buf.extend_from_slice(&[b'O', 0x02, b'K', 0x02]);
        std::fs::write(&vcsa, buf).unwrap();
        std::fs::write(&vcs, b"OK").unwrap();
        let s = read_screen(&vcs).unwrap();
        assert_eq!(s, "\x1b[0;32mOK\x1b[0m\n");
    }

    #[test]
    fn read_screen_falls_back_to_plain() {
        let dir = tempfile::tempdir().unwrap();
        let vcs = dir.path().join("vcs1");

        std::fs::write(&vcs, b"hello").unwrap();
        let s = read_screen(&vcs).unwrap();
        assert_eq!(s, "hello\n");
    }

    #[test]
    fn missing_device_errors() {
        assert!(read_screen(Path::new("/nonexistent/vcs1")).is_err());
    }

    #[test]
    fn history_accumulates_and_evicts_bounded() {
        let h = ScreenHistory::new(3);
        h.push_lines(&["a".into(), "b".into()]);
        h.push_lines(&["c".into(), "d".into()]);

        assert_eq!(h.snapshot_text(), "b\nc\nd");
    }

    #[test]
    fn history_broadcasts_joined_new_lines() {
        let h = ScreenHistory::new(100);
        let mut rx = h.subscribe();
        h.push_lines(&["x".into(), "y".into()]);
        let got = rx.try_recv().unwrap();
        assert_eq!(&*got, "x\ny");
    }

    #[test]
    fn empty_push_does_not_broadcast() {
        let h = ScreenHistory::new(100);
        let mut rx = h.subscribe();
        h.push_lines(&[]);
        assert!(rx.try_recv().is_err());
    }
}
