#!/bin/bash
# Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#
# Builds the builder image locally, reusing a published toolchain image when the
# recipe has not changed. Mirrors what the workflow does.
#
#   ./rust-musl-builder/build.sh
#   REPO=my/rust-musl-builder ./rust-musl-builder/build.sh
set -euo pipefail
cd "$(dirname "$0")"

REPO=${REPO:-sliamb/rust-musl-builder}
TC_IMAGE=$(TOOLCHAIN_REPO="$REPO" ./toolchain-image.sh)

if docker image inspect "$TC_IMAGE" >/dev/null 2>&1; then
    echo ">>> toolchain already built locally: $TC_IMAGE"
elif docker pull -q "$TC_IMAGE" >/dev/null 2>&1; then
    echo ">>> pulled published toolchain: $TC_IMAGE"
else
    echo ">>> no toolchain image for this recipe, building: $TC_IMAGE"
    echo ">>> this compiles GCC for two targets and takes a while"
    docker build -f Dockerfile.toolchain -t "$TC_IMAGE" .
fi

echo ">>> building ${REPO}:latest"
docker build --build-arg TOOLCHAIN_IMAGE="$TC_IMAGE" -t "${REPO}:latest" .

echo ">>> done"
docker run --rm "${REPO}:latest" musl-builder-smoke-test
