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

MUSL_TC=x86_64-linux-musl-cross
if [ ! -x "/opt/$MUSL_TC/bin/x86_64-linux-musl-g++" ]; then
    curl -fsSL "https://musl.cc/$MUSL_TC.tgz" | tar xz -C /opt
fi
export PATH="/opt/$MUSL_TC/bin:$PATH"

TARGET=x86_64-unknown-linux-musl
cd /box
rustup target add "$TARGET"

export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_musl="--sysroot=/opt/$MUSL_TC/x86_64-linux-musl"

# Fetch latest clash-verge autobuild version; fall back to known stable version.
version=$(curl -s https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/autobuild | grep -Eo "releases/download/autobuild/Clash.Verge_[^_]+" | cut -d"_" -f2 | head -n 1 || true)
if ! echo "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+.+'; then
    version="2.5.2+autobuild.0627.b7a454f"
fi
echo "clash-verge version: $version"

UA_DOWNLOAD="${UA_DOWNLOAD:-clash-verge/$version}"
export UA_DOWNLOAD
echo "UA_DOWNLOAD=$UA_DOWNLOAD"

# Build the local sniffbox source (mounted at /box by makeiso.sh).
UA_DOWNLOAD="$UA_DOWNLOAD" PROFILE=release-small TARGET="$TARGET" bash ./build.sh
binpath="/box/target/$TARGET/release-small/sniffbox"
if [ ! -f "$binpath" ]; then
    echo "Error: sniffbox binary not found at $binpath"
    exit 1
fi
# 0x3e == EM_X86_64, make sure we did not just build something else.
if ! od -An -tx1 -j18 -N2 "$binpath" | grep -q "3e 00"; then
    echo "Error: $binpath is not an x86_64 ELF."
    exit 1
fi
cp "$binpath" /app/sniffbox
chmod +x /app/sniffbox
ls -lah /app/sniffbox
sha256sum /app/sniffbox
rm -rf /box/target
