#!/bin/bash
# Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#
# Builds one musl cross toolchain from the sources fetch-sources.sh laid down.
# Usage: build-toolchain.sh <target>   e.g. aarch64-linux-musl

set -euo pipefail
cd "$(dirname "$0")"

. ./versions.env

TARGET=${1:?usage: build-toolchain.sh <target>}
SRCDIR=${SRCDIR:-/src}
PREFIX=${PREFIX:-/opt/$TARGET}
SYSROOT=$PREFIX/$TARGET
JOBS=${JOBS:-$(nproc)}

case "$TARGET" in
    x86_64-linux-musl)  KARCH=x86 ;;
    aarch64-linux-musl) KARCH=arm64 ;;
    *) echo "Error: unsupported target $TARGET" >&2; exit 1 ;;
esac

BUILD=/build/$TARGET
rm -rf "$BUILD"
mkdir -p "$BUILD" "$SYSROOT/include" "$SYSROOT/lib"

# The sysroot doubles as GCC's tooldir ($prefix/$target), so while building the
# target libraries GCC passes "-isystem $SYSROOT/include -isystem
# $SYSROOT/sys-include" -- not $SYSROOT/usr/include. Headers therefore go
# straight into $SYSROOT/include, and "usr" is a self-link so that consumers
# using the ordinary sysroot convention, clang via BINDGEN_EXTRA_CLANG_ARGS
# among them, still resolve $SYSROOT/usr/include. lib32/lib64 are the same trick
# for multilib-shaped library searches.
for link in usr lib32 lib64; do
    if [ ! -L "$SYSROOT/$link" ]; then
        rm -rf "$SYSROOT/$link"
        ln -s "$([ "$link" = usr ] && echo . || echo lib)" "$SYSROOT/$link"
    fi
done

# -g0 keeps debug info out of the host binaries; the toolchain ends up in every
# layer of the final image and unstripped GCC is roughly a gigabyte on its own.
export CFLAGS="-g0 -O2"
export CXXFLAGS="-g0 -O2"
export LDFLAGS="-s"

echo "=============================================================="
echo ">>> [1/7] binutils $BINUTILS_VER for $TARGET"
echo "=============================================================="
mkdir -p "$BUILD/binutils"
cd "$BUILD/binutils"
"$SRCDIR/binutils-$BINUTILS_VER/configure" \
    --target="$TARGET" \
    --prefix="$PREFIX" \
    --with-sysroot="$SYSROOT" \
    --disable-multilib \
    --disable-nls \
    --disable-werror \
    --enable-deterministic-archives
make -j"$JOBS" MAKEINFO=true
make install MAKEINFO=true
# Step out before deleting: make refuses to run from a directory that no longer
# exists. Each build tree goes as soon as it is installed, because the two
# targets build concurrently and that peak is what has to fit on a CI runner.
cd "$BUILD"
rm -rf "$BUILD/binutils"

export PATH="$PREFIX/bin:$PATH"

echo "=============================================================="
echo ">>> [2/7] linux $LINUX_VER uapi headers ($KARCH)"
echo "=============================================================="
make -C "$SRCDIR/linux-$LINUX_VER" \
    ARCH="$KARCH" \
    INSTALL_HDR_PATH="$SYSROOT" \
    O="$BUILD/linux" \
    headers_install
# headers_install leaves .install/..install.cmd markers behind.
find "$SYSROOT/include" '(' -name '.install' -o -name '..install.cmd' ')' -delete
cd "$BUILD"
rm -rf "$BUILD/linux"

echo "=============================================================="
echo ">>> [3/7] gcc $GCC_VER: compiler proper"
echo "=============================================================="
mkdir -p "$BUILD/gcc"
cd "$BUILD/gcc"
# Configured once, in its final shape. libsanitizer does not build against musl
# and has to stay off; musl implements the stack protector itself, so libssp is
# redundant; the rest is weight we never link against and would only cost build
# time and image size.
"$SRCDIR/gcc-$GCC_VER/configure" \
    --target="$TARGET" \
    --prefix="$PREFIX" \
    --with-sysroot="$SYSROOT" \
    --enable-languages=c,c++ \
    --enable-shared \
    --enable-threads=posix \
    --enable-tls \
    --enable-initfini-array \
    --enable-libstdcxx-time=rt \
    --disable-multilib \
    --disable-nls \
    --disable-werror \
    --disable-libsanitizer \
    --disable-libssp \
    --disable-libgomp \
    --disable-libquadmath \
    --disable-libitm \
    --disable-libvtv \
    --disable-bootstrap
make -j"$JOBS" MAKEINFO=true all-gcc

echo "=============================================================="
echo ">>> [4/7] musl $MUSL_VER headers"
echo "=============================================================="
mkdir -p "$BUILD/musl"
cd "$BUILD/musl"
# xgcc is the compiler that step 3 just built, still inside the build tree and
# not installed yet. musl only needs it to answer configure's compile tests --
# there is no libc for it to link against at this point, which is the whole
# reason this step comes before libgcc. LIBCC names the libgcc that step 5 will
# produce; it is not read until step 6 links libc.so.
XGCC="$BUILD/gcc/gcc/xgcc -B $BUILD/gcc/gcc"
# An empty prefix puts headers in $SYSROOT/include and libraries in
# $SYSROOT/lib, which is where GCC actually looks (see the sysroot note above).
CROSS_COMPILE="$TARGET-" \
    "$SRCDIR/musl-$MUSL_VER/configure" \
    --host="$TARGET" \
    --prefix= \
    --syslibdir=/lib \
    --disable-gcc-wrapper \
    CC="$XGCC" \
    LIBCC="$BUILD/gcc/$TARGET/libgcc/libgcc.a"
make DESTDIR="$SYSROOT" install-headers

echo "=============================================================="
echo ">>> [5/7] libgcc (static)"
echo "=============================================================="
cd "$BUILD/gcc"
# enable_shared=no because libgcc_s.so would need crti.o and -lc, and musl does
# not exist until step 6. Step 7 builds it once musl is in.
#
# It has to go through MAKE= as well as on the command line: GCC's target
# libraries are built by a recursive make that does not inherit the override,
# and without this the build gets as far as linking libgcc_s.so and dies on a
# missing libc.
make -j"$JOBS" MAKEINFO=true \
    MAKE="make enable_shared=no" \
    enable_shared=no \
    all-target-libgcc

echo "=============================================================="
echo ">>> [6/7] musl $MUSL_VER"
echo "=============================================================="
cd "$BUILD/musl"
make -j"$JOBS"
# syslibdir=/lib keeps the ld-musl-*.so.1 symlink at the path the ELF
# interpreter field names.
make DESTDIR="$SYSROOT" install
cd "$BUILD"
rm -rf "$BUILD/musl"

echo "=============================================================="
echo ">>> [7/7] gcc $GCC_VER: libgcc_s, libstdc++"
echo "=============================================================="
cd "$BUILD/gcc"
make -j"$JOBS" MAKEINFO=true
make MAKEINFO=true install

echo ">>> trimming"
rm -rf "$PREFIX/share/man" "$PREFIX/share/info" "$PREFIX/share/locale" "$PREFIX/share/doc"
find "$PREFIX" -name '*.la' -delete
# The target libraries carry debug info regardless of the host CFLAGS above.
find "$PREFIX/$TARGET" "$PREFIX/lib/gcc" -name '*.a' -exec "$TARGET-strip" --strip-debug {} + 2>/dev/null || true
cd /
rm -rf "$BUILD"

echo "=============================================================="
echo ">>> smoke test: $TARGET"
echo "=============================================================="
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/t.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("c ok\n"); return 0; }
EOF
# A C++ test that actually pulls libstdc++ in; btls-sys builds BoringSSL as C++
# and a toolchain that links C but not C++ would pass a hello-world.
cat >"$TMP/t.cc" <<'EOF'
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
int main() {
    std::vector<std::string> v{"c", "+", "+"};
    std::string s;
    for (auto &p : v) s += p;
    try { throw std::runtime_error(s); } catch (const std::exception &e) { printf("%s ok\n", e.what()); }
    return 0;
}
EOF

"$TARGET-gcc" -static -O2 -o "$TMP/t.c.bin" "$TMP/t.c"
"$TARGET-g++" -static -O2 -o "$TMP/t.cc.bin" "$TMP/t.cc"

case "$TARGET" in
    x86_64-linux-musl)  EM="3e 00" ;;   # EM_X86_64
    aarch64-linux-musl) EM="b7 00" ;;   # EM_AARCH64
esac
for b in "$TMP/t.c.bin" "$TMP/t.cc.bin"; do
    od -An -tx1 -j18 -N2 "$b" | grep -q "$EM" || {
        echo "Error: $b is not a $TARGET ELF." >&2
        exit 1
    }
    # Nothing should have crept in as a dynamic dependency under -static.
    if "$TARGET-readelf" -d "$b" 2>/dev/null | grep -q NEEDED; then
        echo "Error: $b is not statically linked." >&2
        exit 1
    fi
done

echo ">>> $TARGET toolchain OK ($("$TARGET-gcc" -dumpversion), $(du -sh "$PREFIX" | cut -f1))"
