#!/bin/bash
# Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#
# Prints the toolchain image reference for the current recipe. Both build.sh and
# the workflow resolve it through here so the tag is derived in exactly one
# place.
set -euo pipefail
cd "$(dirname "$0")"

. ./versions.env

REPO=${TOOLCHAIN_REPO:-sliamb/rust-musl-builder}
RECIPE_FILES="versions.env checksums.txt fetch-sources.sh build-toolchain.sh Dockerfile.toolchain"
# shellcheck disable=SC2086
RECIPE_HASH=$(cat $RECIPE_FILES | sha256sum | cut -c1-8)

echo "${REPO}:toolchain-gcc${GCC_VER}-musl${MUSL_VER}-${RECIPE_HASH}"
