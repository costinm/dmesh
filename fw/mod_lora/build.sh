#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/env.sh"
TARGET="${1:-xtensa-esp32-espidf}"
case "$TARGET" in
  xtensa-esp32-espidf) tool_prefix=xtensa-esp32-elf ;;
  xtensa-esp32s3-espidf) tool_prefix=xtensa-esp32s3-elf ;;
  *) echo "unsupported module target: $TARGET" >&2; exit 2 ;;
esac
PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"
TOOL_BIN="$(dirname "$(command -v "${tool_prefix}-objcopy")")"
OUT_DIR="$ROOT/target/modules/$TARGET"
ELF="$ROOT/target/$TARGET/release/mod_lora"
RAW="$OUT_DIR/mod_lora.raw.bin"
IMAGE="$OUT_DIR/mod_lora.dmod"
mkdir -p "$OUT_DIR"
cargo rustc --manifest-path "$ROOT/fw/mod_lora/Cargo.toml" --bin mod_lora --features flat-image \
  --target "$TARGET" --release -Zbuild-std=core,compiler_builtins \
  -Zbuild-std-features=compiler-builtins-mem \
  --config "target.$TARGET.linker=\"${tool_prefix}-gcc\"" -- \
  -C relocation-model=static -C link-arg=-T"$ROOT/fw/mod_lora/link.x" -C link-arg=-nostdlib
if ! "${TOOL_BIN}/${tool_prefix}-readelf" -r "$ELF" | grep -q "There are no relocations"; then
  echo "module ELF has relocations" >&2; exit 1
fi
"${TOOL_BIN}/${tool_prefix}-objcopy" -O binary "$ELF" "$RAW"
"$DMESH_PYTHON" "$ROOT/fw/mod_hello/pack.py" --name lora "$RAW" "$IMAGE"
printf 'module image: %s\n' "$IMAGE"
