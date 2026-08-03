#!/usr/bin/env bash
# Build the minimal ESP32 hello module as a stripped, relocation-free flat image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/env.sh"

if [ ! -x "${RUST_ESP_TOOLCHAIN_BIN:-}/cargo" ]; then
    echo "ESP Rust toolchain is missing; run scripts/esp32-deps.sh" >&2
    exit 1
fi

TARGET="${1:-xtensa-esp32-espidf}"
case "$TARGET" in
    xtensa-esp32-espidf) tool_prefix=xtensa-esp32-elf ;;
    xtensa-esp32s3-espidf) tool_prefix=xtensa-esp32s3-elf ;;
    *) echo "unsupported module target: $TARGET" >&2; exit 2 ;;
esac

PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"
TOOL_BIN="$(dirname "$(command -v "${tool_prefix}-objcopy")")"
OUT_DIR="$ROOT/target/modules/$TARGET"
ELF="$ROOT/target/$TARGET/release/mod_hello"
RAW="$OUT_DIR/mod_hello.raw.bin"
IMAGE="$OUT_DIR/mod_hello.dmod"

mkdir -p "$OUT_DIR"
cargo rustc --manifest-path "$ROOT/fw/mod_hello/Cargo.toml" --bin mod_hello --features flat-image \
    --target "$TARGET" --release \
    -Zbuild-std=core,compiler_builtins -Zbuild-std-features=compiler-builtins-mem \
    --config "target.$TARGET.linker=\"${tool_prefix}-gcc\"" -- \
    -C relocation-model=static \
    -C link-arg=-T"$ROOT/fw/mod_hello/link.x" -C link-arg=-nostdlib

if "${TOOL_BIN}/${tool_prefix}-readelf" -r "$ELF" | grep -q "There are no relocations"; then :; else
    echo "module ELF has relocations; refusing to package it" >&2
    exit 1
fi
if "${TOOL_BIN}/${tool_prefix}-nm" -g "$ELF" 2>&1 | grep -qv "no symbols"; then
    echo "module ELF has exported symbols; refusing to package it" >&2
    exit 1
fi
if ! "${TOOL_BIN}/${tool_prefix}-size" "$ELF" | awk 'NR == 2 { exit ($2 == 0 && $3 == 0) ? 0 : 1 }'; then
    echo "module ELF has data or bss; refusing to package it" >&2
    exit 1
fi
"${TOOL_BIN}/${tool_prefix}-objcopy" -O binary "$ELF" "$RAW"
"$DMESH_PYTHON" "$ROOT/fw/mod_hello/pack.py" --name hello "$RAW" "$IMAGE"
printf 'module image: %s\n' "$IMAGE"
