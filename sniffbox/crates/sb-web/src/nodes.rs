// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub trait NodesSource: Send + Sync {

    fn nodes_json(&self) -> String;

    fn clear(&self);
}
