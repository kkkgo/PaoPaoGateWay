// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let Some(arg0) = args.first() {
        if sb_ppgw::invoked_as_ppgw(arg0) {
            return sb_ppgw::cli_main(args);
        }
    }
    if args.get(1).map(|s| s == "ppgw").unwrap_or(false) {

        return sb_ppgw::cli_main(args[1..].to_vec());
    }
    sniffbox::cli_main()
}
