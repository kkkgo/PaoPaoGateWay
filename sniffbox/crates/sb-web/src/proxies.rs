// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

pub trait ProxiesSource: Send + Sync {

    fn proxies_json(&self) -> String;

    fn proxies_json_fresh(&self) -> String;

    fn mode_json(&self) -> String;

    fn warm(&self);

    fn proxy_detail(&self, _name: &str) -> (u16, String) {
        (404, r#"{"message":"Resource not found"}"#.to_string())
    }
}
