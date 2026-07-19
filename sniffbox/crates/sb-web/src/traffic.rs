// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub trait TrafficSource: Send + Sync {

    fn snapshot_json(&self) -> String;

    fn totals(&self) -> (u64, u64);

    fn clear(&self);
}
