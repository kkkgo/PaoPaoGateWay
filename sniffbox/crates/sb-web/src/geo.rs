// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::future::Future;
use std::pin::Pin;

pub type GeoFut<'a> = Pin<Box<dyn Future<Output = String> + Send + 'a>>;

pub trait GeoControl: Send + Sync {

    fn status_json(&self) -> String;

    fn update(&self) -> GeoFut<'_>;
}
