// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, Copy)]
pub struct Busy;

pub type ProbeFut<'a> = Pin<Box<dyn Future<Output = Result<String, Busy>> + Send + 'a>>;

pub trait ProbeSource: Send + Sync {
    fn probe<'a>(&'a self, req_json: &'a str) -> ProbeFut<'a>;

    fn probe_relaxed<'a>(&'a self, req_json: &'a str) -> ProbeFut<'a> {
        self.probe(req_json)
    }
}
