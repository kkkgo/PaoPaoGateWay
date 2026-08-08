// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::inbound_proxy::HEALTHCHECK_PORT;

const MAX_INFLIGHT: usize = 8;

pub struct WebProbe {
    inflight: Arc<AtomicUsize>,
    proxy: String,

    socks_addr: std::net::SocketAddr,

    udp_enabled: bool,
}

impl WebProbe {
    pub fn new(udp_enabled: bool) -> Self {
        Self {
            inflight: Arc::new(AtomicUsize::new(0)),
            proxy: format!("socks5h://127.0.0.1:{HEALTHCHECK_PORT}"),
            socks_addr: std::net::SocketAddr::from(([127, 0, 0, 1], HEALTHCHECK_PORT)),
            udp_enabled,
        }
    }
}

fn probe_udp(socks_addr: std::net::SocketAddr, udp_enabled: bool) -> String {
    use sb_ppgw::udp_probe::UdpOutcome;
    use std::time::Instant;

    if !udp_enabled {
        return r#"{"ok":true,"status":200,"body":"udp=0","ms":0}"#.to_string();
    }
    let started = Instant::now();

    let (body, ms) = match sb_ppgw::udp_probe::run(socks_addr) {
        Ok(UdpOutcome::Egress { ip, via, ms }) => (format!("udp=1\nip={ip}\nvia={via}"), ms),

        Ok(UdpOutcome::Partial { via, err, ms }) => (
            format!("udp=3\nerr=udp reachable ({via}), egress probe blocked: {err}"),
            ms,
        ),
        Err(err) => (
            format!("udp=2\nerr={err}"),
            started.elapsed().as_millis() as u64,
        ),
    };
    serde_json::json!({ "ok": true, "status": 200, "body": body, "ms": ms }).to_string()
}

struct Permit(Arc<AtomicUsize>);

impl Permit {

    fn acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_INFLIGHT).then_some(n + 1)
            })
            .ok()
            .map(|_| Permit(Arc::clone(counter)))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl sb_web::ProbeSource for WebProbe {
    fn probe<'a>(&'a self, req_json: &'a str) -> sb_web::ProbeFut<'a> {
        Box::pin(async move {
            let _permit = Permit::acquire(&self.inflight).ok_or(sb_web::Busy)?;

            if is_udp_req(req_json) {

                let (addr, enabled) = (self.socks_addr, self.udp_enabled);
                return Ok(
                    tokio::task::spawn_blocking(move || probe_udp(addr, enabled))
                        .await
                        .unwrap_or_else(|_| {
                            r#"{"ok":true,"status":200,"body":"udp=2\nerr=probe task failed","ms":0}"#
                                .to_string()
                        }),
                );
            }
            Ok(sb_ppgw::probe::run_json(req_json, &self.proxy).await)
        })
    }

    fn probe_relaxed<'a>(&'a self, req_json: &'a str) -> sb_web::ProbeFut<'a> {
        Box::pin(async move {
            let _permit = Permit::acquire(&self.inflight).ok_or(sb_web::Busy)?;
            Ok(sb_ppgw::probe::run_json_relaxed(req_json, &self.proxy).await)
        })
    }
}

fn is_udp_req(req_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(req_json)
        .ok()
        .and_then(|v| v.get("udp").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_web::ProbeSource;

    #[test]
    fn inflight_cap_returns_busy_and_permits_are_returned() {
        let p = WebProbe::new(false);
        let permits: Vec<_> = (0..MAX_INFLIGHT)
            .map(|_| Permit::acquire(&p.inflight).expect("under cap"))
            .collect();
        assert_eq!(p.inflight.load(Ordering::Acquire), MAX_INFLIGHT);
        assert!(
            Permit::acquire(&p.inflight).is_none(),
            "when quota full, should not get permit"
        );

        drop(permits);
        assert_eq!(
            p.inflight.load(Ordering::Acquire),
            0,
            "permit drop should return quota"
        );
        assert!(Permit::acquire(&p.inflight).is_some());
    }

    #[tokio::test]
    async fn denied_request_never_touches_the_proxy() {

        let p = WebProbe::new(false);
        let out = p
            .probe(r#"{"url":"http://127.0.0.1/admin"}"#)
            .await
            .expect("has quota");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["denied"], true);
        assert_eq!(
            p.inflight.load(Ordering::Acquire),
            0,
            "permit should have been returned"
        );
    }

    #[test]
    fn proxy_targets_the_healthcheck_inbound() {
        assert_eq!(
            WebProbe::new(false).proxy,
            format!("socks5h://127.0.0.1:{HEALTHCHECK_PORT}")
        );
    }

    #[test]
    fn udp_request_is_routed_to_the_udp_probe() {
        assert!(is_udp_req(r#"{"udp":true}"#));
        assert!(!is_udp_req(r#"{"udp":false}"#));
        assert!(!is_udp_req(r#"{"url":"https://example.com/"}"#));
        assert!(
            !is_udp_req("not json"),
            "bad json falls through to http probe"
        );
    }

    #[tokio::test]
    async fn udp_probe_short_circuits_when_udp_disabled() {
        let p = WebProbe::new(false);
        let out = p.probe(r#"{"udp":true}"#).await.expect("has quota");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["body"], "udp=0");
        assert_eq!(
            p.inflight.load(Ordering::Acquire),
            0,
            "permit should have been returned"
        );
    }

    #[tokio::test]
    async fn udp_probe_failure_is_encoded_in_body_not_ok_false() {
        let p = WebProbe::new(true);
        let out = p.probe(r#"{"udp":true}"#).await.expect("has quota");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true, "failure must not surface as ok:false");
        let body = v["body"].as_str().unwrap();
        assert!(
            body.starts_with("udp=2\nerr="),
            "expected udp=2 failure encoding, got: {body}"
        );
        assert_eq!(
            p.inflight.load(Ordering::Acquire),
            0,
            "permit should have been returned"
        );
    }
}
