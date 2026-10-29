// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub(crate) const DEFAULT_RESERVED: usize = 32;

pub(crate) fn default_sessions() -> usize {
    sessions_for_memory(crate::sysinfo::meminfo().0)
}

fn sessions_for_memory(bytes: u64) -> usize {

    if bytes == 0 {
        return 256;
    }
    (bytes / (2 * 1024 * 1024)).clamp(64, 1024) as usize
}

pub(crate) struct UdpBudget {
    pub sessions: Arc<Budget>,
    pub flows: Arc<Budget>,
}

impl UdpBudget {
    pub fn new(sessions: usize, reserved: usize) -> Self {
        Self {
            sessions: Budget::new(sessions, reserved, 1024),
            flows: Budget::new(
                sessions.saturating_mul(16),
                reserved.saturating_mul(16),
                16384,
            ),
        }
    }
}

pub(crate) struct Budget {
    limits: [usize; 2],
    per_client: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    used: [usize; 2],
    clients: HashMap<(IpAddr, bool), usize>,
}

impl Budget {
    fn new(users: usize, internal: usize, per_client: usize) -> Arc<Self> {
        Arc::new(Self {
            limits: [users, internal],
            per_client,
            state: Mutex::new(State::default()),
        })
    }

    pub fn acquire(self: &Arc<Self>, ip: IpAddr, internal: bool) -> Option<Arc<Permit>> {
        self.acquire_with_headroom(ip, internal, 0, 0)
    }

    pub fn acquire_with_headroom(
        self: &Arc<Self>,
        ip: IpAddr,
        internal: bool,
        headroom: usize,
        client_headroom: usize,
    ) -> Option<Arc<Permit>> {
        let mut state = self.state.lock();
        let class = usize::from(internal);
        if state.used[class] >= self.limits[class].saturating_sub(headroom)
            || state.clients.get(&(ip, internal)).copied().unwrap_or(0)
                >= self.per_client.saturating_sub(client_headroom)
        {
            return None;
        }
        state.used[class] += 1;
        *state.clients.entry((ip, internal)).or_default() += 1;
        Some(Arc::new(Permit {
            budget: Arc::clone(self),
            ip,
            internal,
        }))
    }

    pub fn limits(&self) -> [usize; 2] {
        self.limits
    }

    #[cfg(test)]
    pub fn used(&self) -> [usize; 2] {
        self.state.lock().used
    }
}

pub(crate) struct Permit {
    budget: Arc<Budget>,
    ip: IpAddr,
    internal: bool,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock();
        state.used[usize::from(self.internal)] -= 1;
        let count = state.clients.get_mut(&(self.ip, self.internal)).unwrap();
        *count -= 1;
        if *count == 0 {
            state.clients.remove(&(self.ip, self.internal));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_budget_scales_conservatively_with_device_memory() {
        assert_eq!(sessions_for_memory(512 * 1024 * 1024), 256);
        assert_eq!(sessions_for_memory(1024 * 1024 * 1024), 512);
        assert_eq!(sessions_for_memory(64 * 1024 * 1024 * 1024), 1024);
        assert_eq!(sessions_for_memory(0), 256);
    }
    #[test]
    fn fullcone_headroom_preserves_global_and_shared_client_slots() {
        let b = Budget::new(8, 2, 4);
        let ip = "10.0.0.1".parse().unwrap();
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(b.acquire_with_headroom(ip, false, 2, 1).unwrap());
        }
        assert!(b.acquire_with_headroom(ip, false, 2, 1).is_none());
        held.push(b.acquire(ip, false).unwrap());
        for n in 2..=3 {
            held.push(
                b.acquire_with_headroom(IpAddr::from([10, 0, 0, n]), false, 2, 1)
                    .unwrap(),
            );
        }
        assert!(
            b.acquire_with_headroom("10.0.0.4".parse().unwrap(), false, 2, 1)
                .is_none()
        );
        assert!(b.acquire("10.0.0.4".parse().unwrap(), false).is_some());
        drop(held);
        assert_eq!(b.used(), [0, 0]);
    }

    #[test]
    fn shared_budget_bounds_concurrency_reserves_internal_and_releases_last_owner() {
        let b = Budget::new(3, 1, 2);
        let ip = "127.0.0.1".parse().unwrap();
        let a = b.acquire(ip, false).unwrap();
        let held = Arc::clone(&a);
        let a2 = b.acquire(ip, false).unwrap();
        assert!(b.acquire(ip, false).is_none());
        drop(a);
        assert!(
            b.acquire(ip, false).is_none(),
            "reader/opening task still owns the slot"
        );
        drop(held);
        let barrier = Arc::new(std::sync::Barrier::new(20));
        std::thread::scope(|s| {
            for i in 0..20 {
                let b = Arc::clone(&b);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let permit = b.acquire(IpAddr::from([10, 0, 0, i]), false);
                    barrier.wait();
                    assert_eq!(b.used()[0], 3);
                    barrier.wait();
                    drop(permit);
                });
            }
        });
        let internal = b.acquire(ip, true).unwrap();
        assert!(b.acquire("::1".parse().unwrap(), true).is_none());
        assert_eq!(b.used(), [1, 1]);
        drop((internal, a2));
        assert_eq!(b.used(), [0, 0]);
        assert!(b.state.lock().clients.is_empty());
    }
}
