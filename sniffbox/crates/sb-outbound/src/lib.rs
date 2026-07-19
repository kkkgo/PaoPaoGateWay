// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub mod direct;
pub mod error;
pub mod pool;
pub mod server;
pub mod socks5;
pub mod socks5_udp;

pub use error::OutboundErr;
pub use pool::{PoolCfg, SocksPool};
