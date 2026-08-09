#!/bin/bash
# Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#
# End to end check of the finished image: rustc, the cross linker and the C++
# toolchain, for both targets. Run at image build time so a broken toolchain
# fails the publish rather than an ISO build hours later.
set -euo pipefail

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

cat >main.rs <<'EOF'
fn main() {
    println!("{}", std::env::consts::ARCH);
}
EOF

check() {
    rust_target=$1
    cross=$2
    em=$3

    echo ">>> $rust_target"
    rustc --target "$rust_target" \
        -C "linker=$cross-gcc" \
        -C target-feature=+crt-static \
        -O -o "out-$rust_target" main.rs

    od -An -tx1 -j18 -N2 "out-$rust_target" | grep -q "$em" || {
        echo "Error: out-$rust_target has the wrong ELF machine type." >&2
        exit 1
    }
    if "$cross-readelf" -d "out-$rust_target" 2>/dev/null | grep -q NEEDED; then
        echo "Error: out-$rust_target is not statically linked." >&2
        exit 1
    fi

    # bindgen resolves headers through this sysroot; if clang cannot find the
    # musl headers there, btls-sys fails deep inside a cargo build instead.
    sysroot=$("$cross-gcc" -print-sysroot)
    [ -f "$sysroot/usr/include/stdio.h" ] || {
        echo "Error: no stdio.h under $sysroot." >&2
        exit 1
    }
    echo "    ok ($("$cross-gcc" -dumpversion), sysroot $sysroot)"
}

check x86_64-unknown-linux-musl  x86_64-linux-musl  "3e 00"
check aarch64-unknown-linux-musl aarch64-linux-musl "b7 00"

echo ">>> smoke test passed"
