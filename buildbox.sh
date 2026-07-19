#!/bin/sh
set -e
apk add --no-cache \
    musl-dev \
    gcc \
    g++ \
    linux-headers \
    make \
    perl \
    git \
    curl \
    bash

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
cd /box
UA_DOWNLOAD="$UA_DOWNLOAD" PROFILE=release-small TARGET=x86_64-unknown-linux-musl bash ./build.sh
binpath="/box/target/x86_64-unknown-linux-musl/release-small/sniffbox"
if [ ! -f "$binpath" ]; then
    echo "Error: sniffbox binary not found at $binpath"
    exit 1
fi
cp "$binpath" /app/sniffbox
chmod +x /app/sniffbox
ls -lah /app/sniffbox
sha256sum /app/sniffbox
rm -rf /box/target
