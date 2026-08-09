#!/bin/bash
# Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#
# Downloads and verifies every source tarball the toolchain is built from.
# Each URL points at the project's own official server; checksums.txt is the
# only thing that decides whether a download is accepted.
set -euo pipefail
SELFDIR=$(cd "$(dirname "$0")" && pwd)
cd "$SELFDIR"

. ./versions.env

SRCDIR=${SRCDIR:-/src}
mkdir -p "$SRCDIR"

GNU=https://ftp.gnu.org/gnu
MUSL=https://musl.libc.org/releases
KERNEL=https://cdn.kernel.org/pub/linux/kernel

# The v6.x part of the kernel path follows the major version.
KERNEL_DIR="v${LINUX_VER%%.*}.x"

fetch() {
    url=$1
    file=${url##*/}
    if [ -f "$SRCDIR/$file" ]; then
        echo ">>> have $file"
        return
    fi
    echo ">>> fetch $url"
    # --retry-all-errors matters as much as --retry here: plain --retry ignores
    # connection-level failures, and musl.libc.org in particular will drop a TLS
    # handshake under load. A truncated file would fail the checksum anyway, so
    # retrying costs nothing but is the difference between a flaky and a stable
    # image build.
    curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors \
        --connect-timeout 30 -o "$SRCDIR/$file.part" "$url"
    mv "$SRCDIR/$file.part" "$SRCDIR/$file"
}

fetch "$GNU/binutils/binutils-$BINUTILS_VER.tar.xz"
fetch "$GNU/gcc/gcc-$GCC_VER/gcc-$GCC_VER.tar.xz"
fetch "$GNU/gmp/gmp-$GMP_VER.tar.xz"
fetch "$GNU/mpfr/mpfr-$MPFR_VER.tar.xz"
fetch "$GNU/mpc/mpc-$MPC_VER.tar.xz"
fetch "$MUSL/musl-$MUSL_VER.tar.gz"
fetch "$KERNEL/$KERNEL_DIR/linux-$LINUX_VER.tar.xz"

echo ">>> verifying sha256"
cd "$SRCDIR"
sha256sum -c "$SELFDIR/checksums.txt"

echo ">>> extracting"
for f in *.tar.*; do
    d=${f%.tar.*}
    [ -d "$d" ] && continue
    echo "    $f"
    tar xf "$f"
done

# GCC builds gmp/mpfr/mpc in-tree when they are present under its source
# directory, which avoids installing three host libraries we never use again.
cd "$SRCDIR/gcc-$GCC_VER"
for lib in "gmp-$GMP_VER:gmp" "mpfr-$MPFR_VER:mpfr" "mpc-$MPC_VER:mpc"; do
    src=${lib%%:*}
    dst=${lib##*:}
    [ -e "$dst" ] || ln -s "../$src" "$dst"
done

echo ">>> sources ready in $SRCDIR"
