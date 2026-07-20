#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${TARGET:-x86_64-unknown-linux-musl}"
PROFILE="${PROFILE:-release}"

echo ">>> cargo test --workspace --locked (gate: build aborts on failure)"
cargo test --workspace --locked

cargo build -p sniffbox --locked --profile "$PROFILE" --target "$TARGET"

BIN="${CARGO_TARGET_DIR:-target}/$TARGET/$PROFILE/sniffbox"
strip "$BIN" 2>/dev/null || true
echo ">>> produced $BIN ($(( $(stat -c %s "$BIN") / 1024 )) KB)"
