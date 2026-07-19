// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoScope {
    All,
    Static,
    Dynamic,
}

pub trait InfoSource: Send + Sync {

    fn info_json(&self, scope: InfoScope) -> String;
}
