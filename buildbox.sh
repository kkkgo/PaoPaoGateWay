#!/bin/bash
set -e

CROSS=x86_64-linux-musl
TARGET=x86_64-unknown-linux-musl

if ! command -v "$CROSS-g++" >/dev/null 2>&1; then
    echo "Error: $CROSS-g++ not found in PATH."
    echo "This script expects the sliamb/rust-musl-builder image."
    echo "Build it locally with:"
    echo "    docker build -t sliamb/rust-musl-builder ./rust-musl-builder"
    exit 1
fi
echo "toolchain: $("$CROSS-gcc" -dumpmachine) gcc $("$CROSS-gcc" -dumpversion)"

cd /box
# Already present in the image; only reached if someone runs this elsewhere.
rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"

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
