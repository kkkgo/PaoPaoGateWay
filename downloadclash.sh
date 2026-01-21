#!/bin/sh
ver=$(curl -s https://github.com/MetaCubeX/mihomo/releases|grep mihomo-android-|grep MetaCubeX/mihomo/releases|grep -Eo "download/[^/]+"|cut -d"/" -f2|head -1)
downlink_compatible="https://github.com/MetaCubeX/mihomo/releases/download/""$ver""/mihomo-linux-amd64-compatible-""$ver"".gz"
downlink_v3="https://github.com/MetaCubeX/mihomo/releases/download/""$ver""/mihomo-linux-amd64-v3-""$ver"".gz"
