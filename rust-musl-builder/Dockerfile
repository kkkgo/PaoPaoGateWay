# Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#
# Build image for sniffbox: official Rust image plus the musl cross toolchains
# from Dockerfile.toolchain.

ARG TOOLCHAIN_IMAGE
FROM ${TOOLCHAIN_IMAGE} AS toolchain

FROM rust:bookworm
ENV DEBIAN_FRONTEND=noninteractive

# What sniffbox itself needs at build time: clang/libclang for bindgen, cmake
# and perl for BoringSSL, git for the version stamp. 
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        cmake \
        perl \
        git \
        g++ \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=toolchain /opt/x86_64-linux-musl  /opt/x86_64-linux-musl
COPY --from=toolchain /opt/aarch64-linux-musl /opt/aarch64-linux-musl

ENV PATH="/opt/x86_64-linux-musl/bin:/opt/aarch64-linux-musl/bin:$PATH"

# Baked in so the buildbox scripts do not have to repeat them, and so anything
# else run in this image cross compiles correctly by default.
ENV CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc \
    CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++ \
    AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc \
    BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_musl="--sysroot=/opt/x86_64-linux-musl/x86_64-linux-musl" \
    CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc \
    CXX_aarch64_unknown_linux_musl=aarch64-linux-musl-g++ \
    AR_aarch64_unknown_linux_musl=aarch64-linux-musl-ar \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc \
    BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_musl="--sysroot=/opt/aarch64-linux-musl/aarch64-linux-musl"


RUN rustup toolchain install stable \
        --profile minimal \
        --component rustfmt --component clippy \
        --target x86_64-unknown-linux-musl \
        --target aarch64-unknown-linux-musl \
    && rustup default stable \
    && rustup toolchain list | awk '{print $1}' | grep -v '^stable' \
        | xargs -r rustup toolchain uninstall

# Prove the whole chain works -- rustc, the cross linker and the C++ side --
# rather than finding out during an ISO build that the image is broken.
COPY smoke-test.sh /usr/local/bin/musl-builder-smoke-test
RUN chmod +x /usr/local/bin/musl-builder-smoke-test && musl-builder-smoke-test

COPY versions.env /etc/rust-musl-builder-versions

LABEL org.opencontainers.image.title="rust-musl-builder" \
      org.opencontainers.image.description="Rust plus self-built musl cross toolchains (x86_64, aarch64) for PaoPaoGateWay" \
      org.opencontainers.image.source="https://github.com/kkkgo/PaoPaoGateWay"
