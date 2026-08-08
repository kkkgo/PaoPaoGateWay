#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    cmake \
    perl \
    git \
    g++ \
    curl \
    ca-certificates
rm -rf /var/lib/apt/lists/*

MUSL_TC=aarch64-linux-musl-cross
if [ ! -x "/opt/$MUSL_TC/bin/aarch64-linux-musl-g++" ]; then
    curl -fsSL "https://musl.cc/$MUSL_TC.tgz" | tar xz -C /opt
fi
export PATH="/opt/$MUSL_TC/bin:$PATH"

TARGET=aarch64-unknown-linux-musl
cd /box
rustup target add "$TARGET"

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
export CXX_aarch64_unknown_linux_musl=aarch64-linux-musl-g++
export AR_aarch64_unknown_linux_musl=aarch64-linux-musl-ar
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_musl="--sysroot=/opt/$MUSL_TC/aarch64-linux-musl"

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
aarch64-linux-musl-strip "$binpath"
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
