// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub trait GeoControl: Send + Sync {

    fn status_json(&self) -> String;

    fn update(&self) -> String;
}
