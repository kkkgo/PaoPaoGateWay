// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Handle, Runtime};

static CLI_RT: OnceLock<Runtime> = OnceLock::new();

pub fn handle() -> Handle {
    if let Ok(h) = Handle::try_current() {
        return h;
    }
    CLI_RT
        .get_or_init(|| {

            Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("ppgw-rt")
                .build()
                .expect("build ppgw tokio runtime")
        })
        .handle()
        .clone()
}

pub fn block_on<F: Future>(fut: F) -> F::Output {
    handle().block_on(fut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_on_without_ambient_runtime_uses_cli_rt() {
        let v = block_on(async { 1 + 1 });
        assert_eq!(v, 2);

        assert!(CLI_RT.get().is_some());
        assert_eq!(block_on(async { 3 }), 3);
    }

    #[test]
    fn block_on_inside_spawn_blocking_reuses_ambient_runtime() {
        let rt = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let got = rt.block_on(async {
            tokio::task::spawn_blocking(|| block_on(async { 42 }))
                .await
                .unwrap()
        });
        assert_eq!(got, 42);
    }
}
