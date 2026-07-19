// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub mod hash;
pub mod message;
pub mod pool;
pub mod valid;

pub use pool::{APPROX_BYTES_PER_ENTRY, FakeIpConfig, FakeIpError, FakeIpPool, usable_addrs};
pub use valid::is_valid_fakeip_domain;
