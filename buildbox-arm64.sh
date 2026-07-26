#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    gcc-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    curl \
    ca-certificates
rm -rf /var/lib/apt/lists/*

TARGET=aarch64-unknown-linux-musl
cd /box
rustup target add "$TARGET"

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=yes"
export CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc
export AR_aarch64_unknown_linux_musl=aarch64-linux-gnu-ar

version=$(curl -s https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/autobuild | grep -Eo "releases/download/autobuild/Clash.Verge_[^_]+" | cut -d"_" -f2 | head -n 1 || true)
if ! echo "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+.+'; then
    version="2.5.2+autobuild.0627.b7a454f"
fi
echo "clash-verge version: $version"

UA_DOWNLOAD="${UA_DOWNLOAD:-clash-verge/$version}"
export UA_DOWNLOAD
echo "UA_DOWNLOAD=$UA_DOWNLOAD"

UA_DOWNLOAD="$UA_DOWNLOAD" PROFILE=release-small TARGET="$TARGET" bash ./build.sh
binpath="/box/target/$TARGET/release-small/sniffbox"
if [ ! -f "$binpath" ]; then
    echo "Error: sniffbox binary not found at $binpath"
    exit 1
fi
aarch64-linux-gnu-strip "$binpath"
# 0xb7 == EM_AARCH64, make sure we did not just build a host binary.
if ! od -An -tx1 -j18 -N2 "$binpath" | grep -q "b7 00"; then
    echo "Error: $binpath is not an aarch64 ELF."
    exit 1
fi
cp "$binpath" /app/sniffbox
chmod +x /app/sniffbox
ls -lah /app/sniffbox
sha256sum /app/sniffbox
rm -rf /box/target
