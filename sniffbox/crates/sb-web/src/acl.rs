// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use arc_swap::ArcSwap;
use ipnet::Ipv4Net;
use std::net::IpAddr;
use std::sync::Arc;

pub type AdminHandle = Arc<ArcSwap<AdminAcl>>;

pub fn admin_handle(acl: AdminAcl) -> AdminHandle {
    Arc::new(ArcSwap::from_pointee(acl))
}

#[derive(Debug, Clone, Default)]
pub struct AdminAcl {
    nets: Vec<Ipv4Net>,
}

impl AdminAcl {
    pub fn new(nets: Vec<Ipv4Net>) -> Self {
        Self { nets }
    }

    pub fn nets(&self) -> &[Ipv4Net] {
        &self.nets
    }

    pub fn allows(&self, ip: IpAddr) -> bool {

        if self.nets.is_empty() {
            return true;
        }
        let v4 = match ip {
            IpAddr::V4(a) => a,
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(a) => a,

                None => return a.is_loopback(),
            },
        };
        v4.is_loopback() || self.nets.iter().any(|n| n.contains(&v4))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allows_all() {
        let acl = AdminAcl::default();
        assert!(acl.allows("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn empty_allows_all_including_plain_ipv6() {
        let acl = AdminAcl::default();
        assert!(acl.allows("2001:db8::1".parse().unwrap()));
        assert!(acl.allows("::1".parse().unwrap()));
        assert!(acl.allows("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn non_empty_acl_still_only_admits_loopback_for_plain_ipv6() {
        let acl = AdminAcl::new(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(acl.allows("::1".parse().unwrap()));
        assert!(!acl.allows("2001:db8::1".parse().unwrap()));
        assert!(acl.allows("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!acl.allows("::ffff:192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn loopback_always_allowed() {
        let acl = AdminAcl::new(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(acl.allows("127.0.0.1".parse().unwrap()));
        assert!(acl.allows("10.1.2.3".parse().unwrap()));
        assert!(!acl.allows("192.168.1.1".parse().unwrap()));
    }
}
