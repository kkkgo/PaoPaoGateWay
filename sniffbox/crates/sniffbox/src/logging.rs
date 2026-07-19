// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use sb_web::{LogEvent, LogSource, LogTx};
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer, fmt, prelude::*};

static ANSI: AtomicBool = AtomicBool::new(false);

static LOG_TX: OnceLock<LogTx> = OnceLock::new();

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

    let fmt_layer = fmt::layer()
        .with_ansi(ansi)
        .event_format(PpgwFormat {
            timestamp,
            ansi,
            offset,
        })
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            !(meta.target().starts_with("sniffbox::smart_speed")
                && *meta.level() == Level::DEBUG)
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

    fn flow(scheme: Option<&str>, domain: Option<&str>) -> String {
        fmt_flow(
            "10.10.10.202".parse().unwrap(),
            "43.132.107.47:443".parse().unwrap(),
            scheme,
            domain,
            false,
        )
    }

    #[test]
    fn flow_plain_ip_when_no_domain() {
        assert_eq!(flow(None, None), "10.10.10.202 -> 43.132.107.47:443");
        assert_eq!(flow(Some("bt"), None), "10.10.10.202 -> 43.132.107.47:443");
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
            "43.132.107.47:443".parse().unwrap(),
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
