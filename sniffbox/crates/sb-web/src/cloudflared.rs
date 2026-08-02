// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub trait CloudflaredSource: Send + Sync {

    fn status_json(&self) -> String;

    fn restart(&self, egress: Option<&str>) -> Result<usize, String>;
}
