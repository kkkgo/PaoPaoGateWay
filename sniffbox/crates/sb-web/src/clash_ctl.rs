// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub trait ClashControl: Send + Sync {

    fn ensure_up(&self) -> std::io::Result<bool>;
}
