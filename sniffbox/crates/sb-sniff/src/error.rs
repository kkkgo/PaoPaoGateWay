// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseErr {
    #[error("buffer too short: need {need} bytes, have {have}")]
    Short { need: usize, have: usize },
    #[error("not a handshake record")]
    NotHandshake,
    #[error("not a ClientHello")]
    NotClientHello,
    #[error("truncated extension")]
    TruncatedExt,
    #[error("malformed: {0}")]
    Malformed(&'static str),
}

#[derive(Debug, Error)]
pub enum SniffErr {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sniff timeout")]
    Timeout,
    #[error("buffer limit exceeded")]
    BufferOverflow,
}
