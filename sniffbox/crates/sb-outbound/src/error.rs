// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OutboundErr {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("socks5 protocol error: {0}")]
    Proto(&'static str),
    #[error("socks5 rejected with rep=0x{0:02x}")]
    Rejected(u8),
    #[error("host name too long ({0} > 255)")]
    HostTooLong(usize),
    #[error("pool closed")]
    PoolClosed,
}
