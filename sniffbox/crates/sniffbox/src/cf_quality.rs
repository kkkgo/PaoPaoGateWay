// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::cf_ctl::Egress;
use crate::cf_edge::EdgeRtts;
use crate::cf_probe::Sample;
use crate::config::Protocol;

pub const ROUNDS: usize = 4;

const MARGIN: f64 = 1.25;

const MIN_LATENCY_GAIN: Duration = Duration::from_millis(30);

pub const SCORE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

const MIN_PROBE_GAP: Duration = Duration::from_secs(20 * 60);

const MAX_PROBE_GAP: Duration = Duration::from_secs(6 * 60 * 60);

const REFUSED_GAP: Duration = Duration::from_secs(2 * 60 * 60);

const HISTORY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub const DWELL: Duration = Duration::from_secs(60 * 60);

pub const RESCORE_INTERVAL: Duration = Duration::from_secs(60 * 60);

const PATH_CHANGE: f64 = 2.0;

fn state_dir() -> String {
    std::env::var("SNIFFBOX_CF_STATE_DIR").unwrap_or_else(|_| "/tmp".to_string())
}

fn verdict_path(egress: Egress) -> String {
    format!("{}/sniffbox.cf.proto.{}", state_dir(), egress.as_str())
}

fn gate_path(egress: Egress) -> String {
    format!("{}/sniffbox.cf.probe.{}", state_dir(), egress.as_str())
}

fn history_path(egress: Egress) -> String {
    format!("{}/sniffbox.cf.history.{}", state_dir(), egress.as_str())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictSource {

    Scored,

    Fallback,
}

impl VerdictSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scored => "scored",
            Self::Fallback => "fallback",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "scored" => Some(Self::Scored),
            "fallback" => Some(Self::Fallback),
            _ => None,
        }
    }
}

pub fn remember_verdict(egress: Egress, proto: Protocol, src: VerdictSource) {
    remember_verdict_in(&verdict_path(egress), proto, src);
}

fn remember_verdict_in(path: &str, proto: Protocol, src: VerdictSource) {
    let _ = std::fs::write(
        path,
        format!("{} {} {}", proto.as_str(), now_secs(), src.as_str()),
    );
}

pub fn read_verdict(egress: Egress) -> Option<(Protocol, Duration, VerdictSource)> {
    read_verdict_in(&verdict_path(egress))
}

fn read_verdict_in(path: &str) -> Option<(Protocol, Duration, VerdictSource)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut parts = text.split_whitespace();
    let proto = Protocol::parse(parts.next()?)?;
    let age = parts
        .next()
        .and_then(|ts| ts.parse::<u64>().ok())
        .and_then(|ts| now_secs().checked_sub(ts))
        .map(Duration::from_secs)
        .unwrap_or(Duration::MAX);
    let src = parts
        .next()
        .and_then(VerdictSource::parse)
        .unwrap_or(VerdictSource::Scored);
    Some((proto, age, src))
}

pub fn fresh_verdict(egress: Egress) -> Option<(Protocol, VerdictSource)> {
    read_verdict(egress).and_then(|(p, age, src)| (age < SCORE_TTL).then_some((p, src)))
}

pub fn forget(egress: Egress) {
    for p in [
        verdict_path(egress),
        gate_path(egress),
        history_path(egress),
    ] {
        let _ = std::fs::remove_file(p);
    }
}

#[derive(Debug, Clone)]
pub struct LastRound {

    pub at: u64,

    pub arms: Vec<ArmView>,

    pub verdict: Option<Protocol>,
}

#[derive(Debug, Clone)]
pub struct ArmView {
    pub protocol: Protocol,

    pub rate_bps: Option<f64>,

    pub ttfb_ms: Option<u128>,

    pub completed: Option<f64>,

    pub edge_rtt_ms: Option<u64>,

    pub note: Option<String>,
}

impl ArmView {
    fn new(protocol: Protocol, score: &Option<Score>, sample: &Sample) -> Self {
        match score {
            Some(s) => Self {
                protocol,
                rate_bps: Some(s.rate),
                ttfb_ms: Some(s.ttfb.as_millis()),
                completed: Some(s.completed),
                edge_rtt_ms: sample.min_rtt_ms,
                note: None,
            },
            None => Self {
                protocol,
                rate_bps: None,
                ttfb_ms: None,
                completed: None,
                edge_rtt_ms: sample.min_rtt_ms,
                note: Some(describe(score, sample)),
            },
        }
    }
}

impl LastRound {

    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.at)
    }
}

static LAST_ROUND: [std::sync::Mutex<Option<LastRound>>; 2] =
    [std::sync::Mutex::new(None), std::sync::Mutex::new(None)];

fn store_last_round(egress: Egress, r: LastRound) {
    let mut g = LAST_ROUND[egress.idx()]
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *g = Some(r);
}

pub fn last_round(egress: Egress) -> Option<LastRound> {
    LAST_ROUND[egress.idx()]
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn read_gate(egress: Egress) -> (u64, u32) {
    let text = std::fs::read_to_string(gate_path(egress)).unwrap_or_default();
    let mut parts = text.split_whitespace();
    let at = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let fails = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    (at, fails)
}

pub fn backoff(fails: u32, refused: bool) -> Duration {
    let base = if refused { REFUSED_GAP } else { MIN_PROBE_GAP };
    base.saturating_mul(1u32 << fails.min(5)).min(MAX_PROBE_GAP)
}

pub fn probe_wait(egress: Egress) -> Duration {
    let (at, fails) = read_gate(egress);
    let since = Duration::from_secs(now_secs().saturating_sub(at));
    backoff(fails, false).saturating_sub(since)
}

fn record_attempt(egress: Egress, fails: u32) {
    let _ = std::fs::write(gate_path(egress), format!("{} {fails}", now_secs()));
}

type HistRow = (Protocol, f64, u128, f64, u128, u64);

fn record_history(egress: Egress, scores: &[&Score], edge_ms: u128) {
    record_history_in(&history_path(egress), scores, edge_ms);
}

fn record_history_in(path: &str, scores: &[&Score], edge_ms: u128) {
    let mut lines: Vec<String> = load_history_in(path)
        .into_iter()
        .filter(|row| !scores.iter().any(|s| s.protocol == row.0))
        .map(|r| format!("{} {} {} {} {} {}", r.0.as_str(), r.1, r.2, r.3, r.4, r.5))
        .collect();
    for s in scores {
        lines.push(format!(
            "{} {} {} {} {} {}",
            s.protocol.as_str(),
            s.rate,
            s.ttfb.as_millis(),
            s.completed,
            edge_ms,
            now_secs()
        ));
    }
    let _ = std::fs::write(path, lines.join("\n"));
}

fn load_history_in(path: &str) -> Vec<HistRow> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();

            if f.len() != 6 {
                return None;
            }
            Some((
                Protocol::parse(f[0])?,
                f[1].parse().ok()?,
                f[2].parse().ok()?,
                f[3].parse().ok()?,
                f[4].parse().ok()?,
                f[5].parse().ok()?,
            ))
        })
        .collect()
}

pub fn remembered(egress: Egress, protocol: Protocol, edge_ms: Option<u128>) -> Option<Score> {
    remembered_in(&history_path(egress), protocol, edge_ms)
}

fn remembered_in(path: &str, protocol: Protocol, edge_ms: Option<u128>) -> Option<Score> {
    let now = now_secs();
    load_history_in(path)
        .into_iter()
        .find_map(|(p, rate, ttfb, completed, was_edge, at)| {
            if p != protocol || Duration::from_secs(now.saturating_sub(at)) > HISTORY_TTL {
                return None;
            }
            if let Some(now_edge) = edge_ms {
                let (a, b) = (now_edge.max(1) as f64, was_edge.max(1) as f64);
                if a / b > PATH_CHANGE || b / a > PATH_CHANGE {
                    return None;
                }
            }
            Some(Score {
                protocol: p,
                completed,
                rate,
                ttfb: Duration::from_millis(ttfb as u64),
            })
        })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    pub protocol: Protocol,

    pub completed: f64,

    pub rate: f64,

    pub ttfb: Duration,
}

pub fn score(s: &Sample) -> Option<Score> {
    let protocol = s.protocol?;
    if !s.ready || s.ttfb.is_empty() || s.rate.is_empty() {
        return None;
    }
    let attempts = (s.ttfb.len() + s.rate.len() + s.failures as usize) as f64;
    Some(Score {
        protocol,
        completed: (s.ttfb.len() + s.rate.len()) as f64 / attempts,
        rate: median_f64(&s.rate),
        ttfb: median_dur(&s.ttfb),
    })
}

pub fn clearly_better(challenger: &Score, incumbent: &Score) -> bool {

    if challenger.completed > incumbent.completed + f64::EPSILON {
        return true;
    }
    if challenger.completed < incumbent.completed - f64::EPSILON {
        return false;
    }

    if challenger.rate >= incumbent.rate * MARGIN {
        return true;
    }
    if incumbent.rate >= challenger.rate * MARGIN {
        return false;
    }

    challenger.ttfb.mul_f64(MARGIN) <= incumbent.ttfb
        && incumbent.ttfb.saturating_sub(challenger.ttfb) >= MIN_LATENCY_GAIN
}

pub fn rank(a: (&Option<Score>, &Sample), b: (&Option<Score>, &Sample)) -> Option<Ordering> {
    match (a.0, b.0) {
        (Some(x), Some(y)) => Some(if clearly_better(x, y) {
            Ordering::Greater
        } else if clearly_better(y, x) {
            Ordering::Less
        } else {
            Ordering::Equal
        }),
        (Some(_), None) => (!b.1.ready).then_some(Ordering::Greater),
        (None, Some(_)) => (!a.1.ready).then_some(Ordering::Less),
        (None, None) => None,
    }
}

pub fn degraded_pick(
    edge: &EdgeRtts,
    hist_quic: &Option<Score>,
    hist_http2: &Option<Score>,
) -> Option<Protocol> {
    let (eq, eh) = (edge.quic?, edge.http2?);
    let by_edge = if eh >= eq.mul_f64(MARGIN) && eh.saturating_sub(eq) >= MIN_LATENCY_GAIN {
        Protocol::Quic
    } else if eq >= eh.mul_f64(MARGIN) && eq.saturating_sub(eh) >= MIN_LATENCY_GAIN {
        Protocol::Http2
    } else {
        return None;
    };
    let (hq, hh) = (hist_quic.as_ref()?, hist_http2.as_ref()?);
    let by_history = if clearly_better(hq, hh) {
        Protocol::Quic
    } else if clearly_better(hh, hq) {
        Protocol::Http2
    } else {
        return None;
    };
    (by_edge == by_history).then_some(by_edge)
}

pub async fn pick(egress: Egress) -> Option<Protocol> {

    let wait = probe_wait(egress);
    if !wait.is_zero() {
        tracing::info!(
            egress = egress.as_str(),
            next_in_min = wait.as_secs() / 60,
            "cloudflared: skipping the transport probe (gate)"
        );
        return None;
    }
    let (_, fails) = read_gate(egress);
    record_attempt(egress, fails.saturating_add(1));

    let (quic_sample, http2_sample) = crate::cf_probe::measure_pair(egress, ROUNDS).await;
    let (quic, http2) = (score(&quic_sample), score(&http2_sample));
    let (say_quic, say_http2) = (
        describe(&quic, &quic_sample),
        describe(&http2, &http2_sample),
    );
    tracing::info!(
        egress = egress.as_str(),
        "cloudflared: probe quic: {say_quic}"
    );
    tracing::info!(
        egress = egress.as_str(),
        "cloudflared: probe http2: {say_http2}"
    );

    let mut round = LastRound {
        at: now_secs(),
        arms: vec![
            ArmView::new(Protocol::Quic, &quic, &quic_sample),
            ArmView::new(Protocol::Http2, &http2, &http2_sample),
        ],
        verdict: None,
    };
    store_last_round(egress, round.clone());

    let measured: Vec<&Score> = [quic.as_ref(), http2.as_ref()]
        .into_iter()
        .flatten()
        .collect();
    let edge_now = if measured.is_empty() {
        None
    } else {
        Some(crate::cf_edge::edge_rtts(egress).await)
    };
    if let Some(edge) = &edge_now {
        record_history(egress, &measured, edge.reference_ms());
    }
    if measured.len() == 2 {
        record_attempt(egress, 0);
    } else if quic_sample.rate_limited || http2_sample.rate_limited {

        record_attempt(egress, fails.saturating_add(2));
        tracing::warn!(
            egress = egress.as_str(),
            "cloudflared: trycloudflare refused the probe (rate limited)"
        );
    }

    if let Some(verdict) = rank((&quic, &quic_sample), (&http2, &http2_sample)) {
        round.verdict = match verdict {
            Ordering::Greater => Some(Protocol::Quic),
            Ordering::Less => Some(Protocol::Http2),

            Ordering::Equal => quic.is_some().then_some(Protocol::Quic),
        };
        store_last_round(egress, round.clone());
        return round.verdict;
    }

    let edge = match edge_now {
        Some(e) => e,
        None => crate::cf_edge::edge_rtts(egress).await,
    };
    let path = Some(edge.reference_ms());
    let (hq, hh) = (
        quic.or_else(|| remembered(egress, Protocol::Quic, path)),
        http2.or_else(|| remembered(egress, Protocol::Http2, path)),
    );
    let verdict = degraded_pick(&edge, &hq, &hh);
    tracing::info!(
        egress = egress.as_str(),
        quic = edge
            .quic
            .map_or("n/a".into(), |d| format!("{} ms", d.as_millis())),
        http2 = edge
            .http2
            .map_or("n/a".into(), |d| format!("{} ms", d.as_millis())),
        verdict = verdict.map_or("no verdict", |p| p.as_str()),
        "cloudflared: falling back to edge probes + history"
    );
    round.verdict = verdict;
    store_last_round(egress, round);
    verdict
}

fn describe(s: &Option<Score>, sample: &Sample) -> String {
    use crate::cf_probe::Stage;
    let why = || match &sample.detail {
        Some(d) => format!(" — {d}"),
        None => String::new(),
    };
    match s {
        Some(s) => format!(
            "{:.1} Mbit/s, ttfb {} ms, {:.0}% completed{}",
            s.rate * 8.0 / 1_000_000.0,
            s.ttfb.as_millis(),
            s.completed * 100.0,
            match sample.min_rtt_ms {
                Some(rtt) => format!(", edge rtt {rtt} ms"),
                None => String::new(),
            }
        ),
        None => match sample.stage {
            Stage::NotRegistered => "did not register".to_string(),
            Stage::Registered => {
                "registered, but the new hostname never resolved on this egress".to_string()
            }
            Stage::Resolved => format!("registered and resolved, but never answered 200{}", why()),
            Stage::Warm => format!(
                "reachable, but no usable sample ({} failed){}",
                sample.failures,
                why()
            ),
        },
    }
}

pub fn spawn_rescoring(
    sup: Arc<crate::cf_ctl::CloudflaredSupervisor>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let every = RESCORE_INTERVAL;
    tokio::spawn(async move {

        let mut placed: [std::time::Instant; 2] =
            [std::time::Instant::now(), std::time::Instant::now()];
        loop {
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = shutdown.changed() => return,
            }
            if *shutdown.borrow() {
                return;
            }
            for egress in Egress::ALL {
                if !sup.scoring_wanted(egress) {
                    continue;
                }
                let Some(incumbent) = sup.current_protocol(egress) else {
                    continue;
                };
                match pick(egress).await {
                    Some(winner) if winner == incumbent => {
                        remember_verdict(egress, winner, VerdictSource::Scored);
                        tracing::debug!(
                            egress = egress.as_str(),
                            protocol = winner.as_str(),
                            "cloudflared: incumbent still wins"
                        );
                    }
                    Some(winner) if placed[egress.idx()].elapsed() >= DWELL => {
                        tracing::info!(
                            egress = egress.as_str(),
                            from = incumbent.as_str(),
                            to = winner.as_str(),
                            "cloudflared: switching transport"
                        );
                        remember_verdict(egress, winner, VerdictSource::Scored);
                        sup.switch_protocol(egress, winner).await;
                        placed[egress.idx()] = std::time::Instant::now();
                    }
                    Some(winner) => tracing::info!(
                        egress = egress.as_str(),
                        winner = winner.as_str(),
                        incumbent = incumbent.as_str(),
                        up_min = placed[egress.idx()].elapsed().as_secs() / 60,
                        dwell_min = DWELL.as_secs() / 60,
                        "cloudflared: challenger scored better but the dwell has not elapsed; not switching"
                    ),
                    None => tracing::debug!(
                        egress = egress.as_str(),
                        "cloudflared: scoring produced no verdict; changing nothing"
                    ),
                }
            }
        }
    });
}

fn median_dur(v: &[Duration]) -> Duration {
    let mut v = v.to_vec();
    v.sort_unstable();
    v[v.len() / 2]
}

fn median_f64(v: &[f64]) -> f64 {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    v[v.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(protocol: Protocol, completed: f64, rate: f64, ttfb_ms: u64) -> Score {
        Score {
            protocol,
            completed,
            rate,
            ttfb: Duration::from_millis(ttfb_ms),
        }
    }

    #[test]
    fn stability_outranks_everything() {
        let fast_but_broken = s(Protocol::Quic, 0.75, 10_000_000.0, 50);
        let slow_but_solid = s(Protocol::Http2, 1.0, 1_000_000.0, 500);
        assert!(clearly_better(&slow_but_solid, &fast_but_broken));
        assert!(!clearly_better(&fast_but_broken, &slow_but_solid));
    }

    #[test]
    fn throughput_outranks_latency() {
        let fat = s(Protocol::Http2, 1.0, 3_150_000.0, 926);
        let quick = s(Protocol::Quic, 1.0, 1_900_000.0, 412);
        assert!(clearly_better(&fat, &quick));
        assert!(!clearly_better(&quick, &fat));
    }

    #[test]
    fn latency_speaks_only_when_throughput_ties() {
        let a = s(Protocol::Quic, 1.0, 1_000_000.0, 100);
        let b = s(Protocol::Http2, 1.0, 1_100_000.0, 400);
        assert!(
            clearly_better(&a, &b),
            "1.1x is inside the margin, so latency decides"
        );
        assert!(!clearly_better(&b, &a));
    }

    #[test]
    fn a_small_gap_is_a_tie() {
        let a = s(Protocol::Quic, 1.0, 1_575_000.0, 457);
        let b = s(Protocol::Http2, 1.0, 1_912_500.0, 496);
        assert!(!clearly_better(&a, &b));
        assert!(!clearly_better(&b, &a));
    }

    #[test]
    fn a_tiny_absolute_latency_gain_is_not_a_win() {
        let a = s(Protocol::Quic, 1.0, 1_000_000.0, 30);
        let b = s(Protocol::Http2, 1.0, 1_000_000.0, 50);
        assert!(
            !clearly_better(&a, &b),
            "20 ms is below the absolute floor even though the ratio clears the margin"
        );
        let far = s(Protocol::Quic, 1.0, 1_000_000.0, 300);
        let farther = s(Protocol::Http2, 1.0, 1_000_000.0, 500);
        assert!(clearly_better(&far, &farther));
    }

    #[test]
    fn an_unusable_arm_scores_none_not_zero() {
        let never_registered = Sample {
            protocol: Some(Protocol::Quic),
            ready: false,
            ..Default::default()
        };
        assert_eq!(score(&never_registered), None);
        let registered_but_silent = Sample {
            protocol: Some(Protocol::Quic),
            ready: true,
            failures: 8,
            ..Default::default()
        };
        assert_eq!(score(&registered_but_silent), None);
    }

    #[test]
    fn rank_separates_disqualification_from_no_information() {
        let good = Some(s(Protocol::Http2, 1.0, 1_000_000.0, 100));
        let dead = Sample {
            protocol: Some(Protocol::Quic),
            ready: false,
            ..Default::default()
        };
        let mute = Sample {
            protocol: Some(Protocol::Quic),
            ready: true,
            failures: 8,
            ..Default::default()
        };
        let ok = Sample {
            protocol: Some(Protocol::Http2),
            ready: true,
            ttfb: vec![Duration::from_millis(100)],
            rate: vec![1_000_000.0],
            ..Default::default()
        };
        assert_eq!(
            rank((&good, &ok), (&None, &dead)),
            Some(Ordering::Greater),
            "a transport that never registered loses by default"
        );
        assert_eq!(
            rank((&good, &ok), (&None, &mute)),
            None,
            "a transport that registered but could not be measured is no information"
        );
        assert_eq!(rank((&None, &dead), (&None, &mute)), None);
    }

    #[test]
    fn score_summarises_medians_and_completion() {
        let sample = Sample {
            protocol: Some(Protocol::Quic),
            ready: true,
            ttfb: vec![
                Duration::from_millis(100),
                Duration::from_millis(300),
                Duration::from_millis(200),
            ],
            rate: vec![1_000_000.0, 3_000_000.0, 2_000_000.0],
            failures: 2,
            ..Default::default()
        };
        let got = score(&sample).unwrap();
        assert_eq!(got.ttfb, Duration::from_millis(200));
        assert_eq!(got.rate, 2_000_000.0);
        assert!((got.completed - 6.0 / 8.0).abs() < 1e-9);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(0, false), MIN_PROBE_GAP);
        assert_eq!(backoff(1, false), MIN_PROBE_GAP * 2);
        assert_eq!(backoff(2, false), MIN_PROBE_GAP * 4);
        assert_eq!(backoff(9, false), MAX_PROBE_GAP, "capped");
        assert_eq!(backoff(0, true), REFUSED_GAP);
        assert!(backoff(1, true) >= REFUSED_GAP * 2);
        assert_eq!(backoff(5, true), MAX_PROBE_GAP);
    }

    #[test]
    fn degraded_pick_requires_both_signals_to_agree() {
        let edge_favours_quic = EdgeRtts {
            quic: Some(Duration::from_millis(100)),
            http2: Some(Duration::from_millis(400)),
        };
        let hq = Some(s(Protocol::Quic, 1.0, 3_000_000.0, 100));
        let hh = Some(s(Protocol::Http2, 1.0, 1_000_000.0, 400));
        assert_eq!(
            degraded_pick(&edge_favours_quic, &hq, &hh),
            Some(Protocol::Quic)
        );

        let hh_fast = Some(s(Protocol::Http2, 1.0, 9_000_000.0, 400));
        assert_eq!(degraded_pick(&edge_favours_quic, &hq, &hh_fast), None);

        let edge_tied = EdgeRtts {
            quic: Some(Duration::from_millis(158)),
            http2: Some(Duration::from_millis(156)),
        };
        assert_eq!(degraded_pick(&edge_tied, &hq, &hh), None);

        assert_eq!(degraded_pick(&edge_favours_quic, &None, &hh), None);
        assert_eq!(
            degraded_pick(
                &EdgeRtts {
                    quic: None,
                    http2: Some(Duration::from_millis(400))
                },
                &hq,
                &hh
            ),
            None
        );
    }

    #[test]
    fn verdict_round_trips_with_its_source() {
        let path = tmp_history("verdict");
        assert_eq!(read_verdict_in(&path), None, "no file = no memory");

        remember_verdict_in(&path, Protocol::Http2, VerdictSource::Fallback);
        let (p, age, src) = read_verdict_in(&path).unwrap();
        assert_eq!(p, Protocol::Http2);
        assert_eq!(src, VerdictSource::Fallback);
        assert!(age < Duration::from_secs(5));

        std::fs::write(&path, format!("quic {}", now_secs())).unwrap();
        let (p, _, src) = read_verdict_in(&path).unwrap();
        assert_eq!((p, src), (Protocol::Quic, VerdictSource::Scored));

        std::fs::write(
            &path,
            format!("quic {} scored", now_secs() - SCORE_TTL.as_secs() - 60),
        )
        .unwrap();
        let (_, age, _) = read_verdict_in(&path).unwrap();
        assert!(age > SCORE_TTL, "the row parses but is stale");

        std::fs::write(&path, "garbage\n").unwrap();
        assert_eq!(read_verdict_in(&path), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn arms_carry_numbers_when_measured_and_a_note_when_not() {
        use crate::cf_probe::Stage;
        let measured = Sample {
            protocol: Some(Protocol::Quic),
            ready: true,
            stage: Stage::Warm,
            ttfb: vec![Duration::from_millis(91)],
            rate: vec![10_912_500.0],
            min_rtt_ms: Some(16),
            ..Default::default()
        };
        let a = ArmView::new(Protocol::Quic, &score(&measured), &measured);
        assert_eq!(a.rate_bps, Some(10_912_500.0));
        assert_eq!(a.ttfb_ms, Some(91));
        assert_eq!(a.completed, Some(1.0));
        assert_eq!(a.edge_rtt_ms, Some(16));
        assert!(a.note.is_none(), "a measured arm needs no prose");

        let stuck = Sample {
            protocol: Some(Protocol::Http2),
            ready: true,
            stage: Stage::Resolved,
            detail: Some("edge answered \"HTTP/1.1 530\"".into()),
            ..Default::default()
        };
        let b = ArmView::new(Protocol::Http2, &score(&stuck), &stuck);
        assert_eq!(
            (b.rate_bps, b.ttfb_ms, b.completed),
            (None, None, None),
            "no numbers to show"
        );
        let note = b.note.expect("an unmeasured arm must explain itself");
        assert!(note.contains("never answered 200") && note.contains("530"));
    }

    #[test]
    fn state_files_are_per_replica() {
        let d = verdict_path(Egress::Direct);
        let p = verdict_path(Egress::Proxied);
        assert_ne!(d, p);
        assert!(d.ends_with(".direct") && p.ends_with(".proxy"));
        assert_ne!(gate_path(Egress::Direct), gate_path(Egress::Proxied));
        assert_ne!(history_path(Egress::Direct), history_path(Egress::Proxied));
    }

    fn tmp_history(tag: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("sniffbox-cfq-{}-{tag}.history", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn history_round_trips_and_replaces_per_protocol() {
        let path = tmp_history("roundtrip");
        let q = s(Protocol::Quic, 1.0, 3_000_000.0, 120);
        record_history_in(&path, &[&q], 160);
        let back = remembered_in(&path, Protocol::Quic, Some(160)).unwrap();
        assert_eq!(back.rate, 3_000_000.0);
        assert_eq!(back.ttfb, Duration::from_millis(120));
        assert_eq!(remembered_in(&path, Protocol::Http2, Some(160)), None);

        let h = s(Protocol::Http2, 1.0, 1_000_000.0, 300);
        record_history_in(&path, &[&h], 160);
        assert!(
            remembered_in(&path, Protocol::Quic, Some(160)).is_some(),
            "recording one arm must not wipe the other"
        );
        let newer = s(Protocol::Quic, 1.0, 9_000_000.0, 90);
        record_history_in(&path, &[&newer], 160);
        assert_eq!(load_history_in(&path).len(), 2, "one row per transport");
        assert_eq!(
            remembered_in(&path, Protocol::Quic, Some(160))
                .unwrap()
                .rate,
            9_000_000.0
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_is_discarded_when_the_path_changed() {
        let path = tmp_history("path");
        let q = s(Protocol::Quic, 1.0, 3_000_000.0, 120);
        record_history_in(&path, &[&q], 160);
        assert!(remembered_in(&path, Protocol::Quic, Some(200)).is_some());
        assert_eq!(
            remembered_in(&path, Protocol::Quic, Some(14)).map(|s| s.rate),
            None,
            "edge rtt 160ms -> 14ms is a different link entirely"
        );
        assert_eq!(remembered_in(&path, Protocol::Quic, Some(400)), None);

        assert!(remembered_in(&path, Protocol::Quic, None).is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn legacy_history_rows_are_dropped_not_guessed() {
        let path = tmp_history("legacy");
        std::fs::write(&path, format!("quic 3000000 120 1 {}\n", now_secs())).unwrap();
        assert!(load_history_in(&path).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_expires() {
        let path = tmp_history("ttl");
        let old = now_secs() - HISTORY_TTL.as_secs() - 60;
        std::fs::write(&path, format!("quic 3000000 120 1 160 {old}\n")).unwrap();
        assert_eq!(load_history_in(&path).len(), 1, "the row parses");
        assert_eq!(
            remembered_in(&path, Protocol::Quic, Some(160)),
            None,
            "but it is too old to be used"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn describe_tells_every_stage_apart() {
        use crate::cf_probe::Stage;
        let at = |stage, failures, detail: Option<&str>| Sample {
            protocol: Some(Protocol::Quic),
            ready: stage != Stage::NotRegistered,
            stage,
            failures,
            detail: detail.map(str::to_string),
            ..Default::default()
        };
        let said: Vec<String> = vec![
            describe(&None, &at(Stage::NotRegistered, 0, None)),
            describe(&None, &at(Stage::Registered, 0, None)),
            describe(
                &None,
                &at(Stage::Resolved, 0, Some("edge answered \"HTTP/1.1 530\"")),
            ),
            describe(&None, &at(Stage::Warm, 8, Some("timed out"))),
        ];
        assert!(said[0].contains("did not register"));
        assert!(said[1].contains("never resolved"));
        assert!(said[2].contains("never answered 200") && said[2].contains("530"));
        assert!(said[3].contains("no usable sample") && said[3].contains("timed out"));

        for i in 0..said.len() {
            for j in (i + 1)..said.len() {
                assert_ne!(said[i], said[j], "stages {i} and {j} read the same");
            }
        }

        for line in &said {
            assert!(!line.starts_with("quic"), "no protocol prefix: {line}");
        }
    }
}
