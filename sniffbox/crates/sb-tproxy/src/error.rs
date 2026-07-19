// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TproxyErr {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("setsockopt {opt} failed: errno={errno}")]
    SetSockOpt { opt: &'static str, errno: i32 },
    #[error("no IP_RECVORIGDSTADDR cmsg returned")]
    NoOrigDst,
    #[error("unsupported address family in cmsg")]
    UnsupportedFamily,
}
