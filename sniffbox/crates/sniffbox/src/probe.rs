// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::inbound_proxy::HEALTHCHECK_PORT;

const MAX_INFLIGHT: usize = 8;

pub struct WebProbe {
    inflight: Arc<AtomicUsize>,
    proxy: String,
}

impl WebProbe {
    pub fn new() -> Self {
        Self {
            inflight: Arc::new(AtomicUsize::new(0)),
            proxy: format!("socks5h://127.0.0.1:{HEALTHCHECK_PORT}"),
        }
    }
}

impl Default for WebProbe {
    fn default() -> Self {
        Self::new()
    }
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
    fn probe(&self, req_json: &str) -> Result<String, sb_web::Busy> {
        let _permit = Permit::acquire(&self.inflight).ok_or(sb_web::Busy)?;
        Ok(sb_ppgw::probe::run_json(req_json, &self.proxy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_web::ProbeSource;

    #[test]
    fn inflight_cap_returns_busy_and_permits_are_returned() {
        let p = WebProbe::new();
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

    #[test]
    fn denied_request_never_touches_the_proxy() {

        let p = WebProbe::new();
        let out = p
            .probe(r#"{"url":"http://127.0.0.1/admin"}"#)
            .expect("has quota");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["denied"], true);
        assert_eq!(p.inflight.load(Ordering::Acquire), 0, "permit should have been returned");
    }

    #[test]
    fn proxy_targets_the_healthcheck_inbound() {
        assert_eq!(
            WebProbe::new().proxy,
            format!("socks5h://127.0.0.1:{HEALTHCHECK_PORT}")
        );
    }
}
