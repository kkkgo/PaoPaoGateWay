// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use sb_web::{LogEvent, LogSource, LogTx};
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer, fmt, prelude::*};

static ANSI: AtomicBool = AtomicBool::new(false);

static LOG_TX: OnceLock<LogTx> = OnceLock::new();

static LOG_SINK: OnceLock<LogSink> = OnceLock::new();

const LOG_QUEUE_CAP: usize = 4096;

#[derive(Default)]
struct Dropped {
    pending: AtomicU64,
    total: AtomicU64,
}

#[derive(Clone)]
pub struct LogSink {
    tx: SyncSender<Msg>,
    dropped: Arc<Dropped>,
}

enum Msg {
    Line(Vec<u8>),

    Flush(SyncSender<()>),
}

impl LogSink {

    fn new<W: std::io::Write + Send + 'static>(cap: usize, mut out: W) -> Self {
        let (tx, rx) = sync_channel::<Msg>(cap);
        let dropped: Arc<Dropped> = Arc::new(Dropped::default());
        let lost = Arc::clone(&dropped);
        let spawned = std::thread::Builder::new()
            .name("sniffbox-log".into())
            .spawn(move || {
                while let Ok(msg) = rx.recv() {
                    match msg {
                        Msg::Line(line) => {

                            let n = lost.pending.swap(0, Ordering::Relaxed);
                            if n > 0 {
                                let _ = writeln!(
                                    out,
                                    " PaoPaoGW BOX  WARN dropped {n} log lines (log consumer too slow)"
                                );
                            }
                            let _ = out.write_all(&line);
                            let _ = out.flush();
                        }
                        Msg::Flush(ack) => {
                            let _ = out.flush();
                            let _ = ack.try_send(());
                        }
                    }
                }
            })
            .is_ok();
        if !spawned {
            tracing::warn!("log writer thread spawn failed; log lines will be dropped");
        }
        Self { tx, dropped }
    }

    fn submit(&self, line: Vec<u8>) {
        match self.tx.try_send(Msg::Line(line)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.pending.fetch_add(1, Ordering::Relaxed);
                self.dropped.total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    fn dropped_total(&self) -> u64 {
        self.dropped.total.load(Ordering::Relaxed)
    }

    fn flush(&self, timeout: Duration) {
        let (ack_tx, ack_rx) = sync_channel::<()>(1);
        if self.tx.try_send(Msg::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(timeout);
        }
    }
}

pub struct LogLine {
    sink: LogSink,
    buf: Vec<u8>,
}

impl std::io::Write for LogLine {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LogLine {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            self.sink.submit(std::mem::take(&mut self.buf));
        }
    }
}

impl<'a> MakeWriter<'a> for LogSink {
    type Writer = LogLine;
    fn make_writer(&'a self) -> Self::Writer {
        LogLine {
            sink: self.clone(),
            buf: Vec::with_capacity(192),
        }
    }
}

pub fn flush(timeout: Duration) {
    if let Some(sink) = LOG_SINK.get() {
        sink.flush(timeout);
    }
}

pub fn log_sender() -> Option<LogTx> {
    LOG_TX.get().cloned()
}

pub const RESET: &str = "\x1b[0m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";
pub const GRAY: &str = "\x1b[90m";
pub const BRIGHT_BLUE: &str = "\x1b[94m";
pub const BRIGHT_CYAN: &str = "\x1b[96m";
pub const BOLD_RED: &str = "\x1b[1;31m";

pub const BOX_STYLE: &str = "\x1b[1;44;97m";

pub fn ansi_enabled() -> bool {
    ANSI.load(Ordering::Relaxed)
}

pub fn paint(color: &str, s: &str) -> String {
    if ansi_enabled() {
        format!("{color}{s}{RESET}")
    } else {
        s.to_string()
    }
}

fn sanitize(s: &str) -> Cow<'_, str> {
    if s.chars().any(char::is_control) {
        Cow::Owned(
            s.chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(s)
    }
}

pub fn fmt_flow(
    client: std::net::IpAddr,
    orig: std::net::SocketAddr,
    scheme: Option<&str>,
    domain: Option<&str>,
    udp: bool,
) -> String {
    let ansi = ansi_enabled();
    let (gray, yellow, reset) = if ansi {
        (GRAY, YELLOW, RESET)
    } else {
        ("", "", "")
    };
    let port = orig.port();
    let domain = domain.map(sanitize);
    let domain = domain.as_deref();

    let color = if !ansi {
        ""
    } else {
        match scheme {
            Some("tls") => GREEN,
            Some("http") => BRIGHT_CYAN,
            _ => CYAN,
        }
    };
    let target = match (scheme, domain) {
        (Some(s), Some(d)) => format!("{color}{s}://{d}:{port}{reset}"),
        (None, Some(d)) => format!("{color}{d}:{port}{reset}"),
        _ => format!("{color}{}:{port}{reset}", orig.ip()),
    };
    let arrow = if udp { "UDP ->" } else { "->" };
    format!("{yellow}{client}{reset} {gray}{arrow}{reset} {target}")
}

struct PpgwFormat {
    timestamp: bool,
    ansi: bool,
    offset: time::UtcOffset,
}

struct FieldVisitor<'a, 'b> {
    writer: &'a mut Writer<'b>,
    ansi: bool,
    result: std::fmt::Result,
}

impl tracing::field::Visit for FieldVisitor<'_, '_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if self.result.is_err() {
            return;
        }
        if field.name() == "message" {
            self.result = write!(self.writer, "{value:?}");
        } else {
            let v = format!("{value:?}");
            let (dim, reset) = if self.ansi { (DIM, RESET) } else { ("", "") };
            self.result = write!(
                self.writer,
                " {dim}{}={reset}{}",
                field.name(),
                sanitize(&v)
            );
        }
    }
}

impl<S, N> FormatEvent<S, N> for PpgwFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let (box_style, gray, reset) = if self.ansi {
            (BOX_STYLE, GRAY, RESET)
        } else {
            ("", "", "")
        };

        let own_tag = message_starts_with(event, "[PaoPaoGW ");
        if !own_tag {
            write!(writer, "{box_style} PaoPaoGW BOX {reset}")?;
        }
        if self.timestamp {
            let t = time::OffsetDateTime::now_utc().to_offset(self.offset);
            write!(
                writer,
                "{gray}{:02}:{:02}:{:02}{reset}",
                t.hour(),
                t.minute(),
                t.second()
            )?;
        }
        write!(writer, " ")?;
        let level = *event.metadata().level();
        if level != Level::INFO {
            let color = if !self.ansi {
                ""
            } else {
                match level {
                    Level::ERROR => BOLD_RED,
                    Level::WARN => YELLOW,
                    Level::DEBUG => BLUE,
                    _ => MAGENTA,
                }
            };
            write!(writer, "{color}{level}{reset} ")?;
        }
        let mut visitor = FieldVisitor {
            writer: &mut writer,
            ansi: self.ansi,
            result: Ok(()),
        };
        event.record(&mut visitor);
        visitor.result?;
        writeln!(writer)
    }
}

fn message_starts_with(event: &Event<'_>, prefix: &str) -> bool {
    struct Probe<'a> {
        prefix: &'a str,
        hit: bool,
    }
    impl tracing::field::Visit for Probe<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.hit = format!("{value:?}").starts_with(self.prefix);
            }
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.hit = value.starts_with(self.prefix);
            }
        }
    }
    let mut p = Probe { prefix, hit: false };
    event.record(&mut p);
    p.hit
}

struct BroadcastLayer {
    tx: LogTx,
}

impl<S: Subscriber> Layer<S> for BroadcastLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if self.tx.receiver_count() == 0 {
            return;
        }
        let mut msg = String::new();
        let mut v = MsgVisitor { out: &mut msg };
        event.record(&mut v);
        let level = event.metadata().level().as_str().to_ascii_lowercase();
        let _ = self
            .tx
            .send(Arc::new(LogEvent::new(LogSource::Sniffbox, level, msg)));
    }
}

struct MsgVisitor<'a> {
    out: &'a mut String,
}

impl tracing::field::Visit for MsgVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if field.name() == "message" {
            let _ = write!(self.out, "{value:?}");
        } else {
            let s = format!("{value:?}");
            let _ = write!(self.out, " {}={}", field.name(), sanitize(&s));
        }
    }
}

pub fn init(level: &str, timestamp: bool) {

    let base = std::env::var("RUST_LOG").unwrap_or_else(|_| level.to_string());
    let filter = EnvFilter::try_new(format!("{base},sniffbox::smart_speed=debug"))
        .unwrap_or_else(|_| EnvFilter::new("info,sniffbox::smart_speed=debug"));

    let ansi = std::env::var_os("NO_COLOR").is_none();
    ANSI.store(ansi, Ordering::Relaxed);

    let offset = time::UtcOffset::from_hms(8, 0, 0).expect("UTC+8 is valid");

    let sink = LOG_SINK
        .get_or_init(|| LogSink::new(LOG_QUEUE_CAP, std::io::stdout()))
        .clone();

    let fmt_layer = fmt::layer()
        .with_writer(sink)
        .with_ansi(ansi)
        .event_format(PpgwFormat {
            timestamp,
            ansi,
            offset,
        })
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            !(meta.target().starts_with("sniffbox::smart_speed") && *meta.level() == Level::DEBUG)
        }));

    let (tx, _rx0) = tokio::sync::broadcast::channel::<Arc<LogEvent>>(1024);
    let _ = LOG_TX.set(tx.clone());
    let bcast_layer = BroadcastLayer { tx };

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(bcast_layer)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use std::time::Instant;

    struct GatedSink {
        gate: std::sync::mpsc::Receiver<()>,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for GatedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.gate.recv();
            self.out.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct OpenSink(Arc<Mutex<Vec<u8>>>);

    impl Write for OpenSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn log_sink_never_blocks_the_caller_and_reports_drops() {
        let (tokens, gate) = std::sync::mpsc::channel::<()>();
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = LogSink::new(
            4,
            GatedSink {
                gate,
                out: Arc::clone(&out),
            },
        );

        let (done_tx, done) = std::sync::mpsc::channel::<Duration>();
        let writer = sink.clone();
        std::thread::spawn(move || {
            let t0 = Instant::now();
            for i in 0..500 {
                writer.submit(format!("line {i}\n").into_bytes());
            }
            let _ = done_tx.send(t0.elapsed());
        });
        let elapsed = done
            .recv_timeout(Duration::from_secs(2))
            .expect("submitting must not wait for the console");
        assert!(
            elapsed < Duration::from_secs(1),
            "submitting must not wait for the console: {elapsed:?}"
        );
        assert!(
            sink.dropped_total() >= 400,
            "a stalled consumer must shed load, dropped={}",
            sink.dropped_total()
        );

        for _ in 0..32 {
            let _ = tokens.send(());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = String::from_utf8_lossy(&out.lock().unwrap()).to_string();
            if text.contains("dropped") && text.contains("log lines") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "writer thread must report the dropped lines, got: {text:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn log_sink_delivers_every_line_when_the_consumer_keeps_up() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = LogSink::new(256, OpenSink(Arc::clone(&out)));
        for i in 0..50 {
            sink.submit(format!("l{i}\n").into_bytes());
        }
        sink.flush(Duration::from_secs(5));
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert_eq!(
            sink.dropped_total(),
            0,
            "no drops when the consumer keeps up"
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 50, "got: {text:?}");
        assert_eq!(lines[0], "l0");
        assert_eq!(lines[49], "l49");
    }

    fn flow(scheme: Option<&str>, domain: Option<&str>) -> String {
        fmt_flow(
            "10.10.10.202".parse().unwrap(),
            "44.33.22.11:443".parse().unwrap(),
            scheme,
            domain,
            false,
        )
    }

    #[test]
    fn flow_plain_ip_when_no_domain() {
        assert_eq!(flow(None, None), "10.10.10.202 -> 44.33.22.11:443");
        assert_eq!(flow(Some("bt"), None), "10.10.10.202 -> 44.33.22.11:443");
    }

    #[test]
    fn flow_scheme_domain_port() {
        assert_eq!(
            flow(Some("tls"), Some("a.com")),
            "10.10.10.202 -> tls://a.com:443"
        );
        assert_eq!(flow(None, Some("a.com")), "10.10.10.202 -> a.com:443");
    }

    #[test]
    fn flow_udp_marker_before_arrow() {
        let s = fmt_flow(
            "10.10.10.202".parse().unwrap(),
            "44.33.22.11:443".parse().unwrap(),
            Some("quic"),
            Some("a.com"),
            true,
        );
        assert_eq!(s, "10.10.10.202 UDP -> quic://a.com:443");
    }

    #[test]
    fn flow_sanitizes_control_chars_in_domain() {
        assert_eq!(
            flow(Some("tls"), Some("a\x1b[31m.com")),
            "10.10.10.202 -> tls://a\u{FFFD}[31m.com:443"
        );
    }

    #[test]
    fn broadcast_preserves_message_ansi_color_codes() {
        use std::sync::Arc;
        use tokio::sync::broadcast;

        let (tx, mut rx) = broadcast::channel::<Arc<sb_web::LogEvent>>(8);
        let bcast_layer = BroadcastLayer { tx };
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(bcast_layer));

        tracing::info!("{}", "\x1b[32ma.com\x1b[0m");

        let ev = rx.try_recv().expect("event should be broadcast");
        assert_eq!(ev.msg, "\x1b[32ma.com\x1b[0m");
    }
}
