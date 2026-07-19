// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SNIFFBOX_VERSION");
    println!("cargo:rerun-if-changed=.git/HEAD");

    let version = if let Ok(v) = std::env::var("SNIFFBOX_VERSION") {
        v
    } else {

        match Command::new("git")
            .args(["log", "-1", "--format=%cd-%h", "--date=format:%Y%m%d"])
            .output()
        {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => env!("CARGO_PKG_VERSION").to_string(),
        }
    };

    println!("cargo:rustc-env=SNIFFBOX_VERSION={}", version);
}
