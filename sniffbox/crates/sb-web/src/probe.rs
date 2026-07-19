// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

#[derive(Debug, Clone, Copy)]
pub struct Busy;

pub trait ProbeSource: Send + Sync {
    fn probe(&self, req_json: &str) -> Result<String, Busy>;
}
