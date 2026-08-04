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
  riscv32imac-unknown-none-elf|riscv32imac-esp-espidf) tool_prefix=riscv32-esp-elf ;;
  *) echo "unsupported module target: $TARGET" >&2; exit 2 ;;
esac
if [ -n "${DMESH_MODULE_VMA:-}" ]; then
    module_vma_value=$((DMESH_MODULE_VMA))
    fixed_window=$((module_vma_value - 64))
    if (( fixed_window < 0 || fixed_window % 0x10000 != 0 )); then
        echo "DMESH_MODULE_VMA must be a 64-byte code address after a 64 KiB window" >&2
        exit 2
    fi
    if [[ "$TARGET" == xtensa-esp32s3-espidf ]]; then
        module_data_vma=$((0x3c000000 + module_vma_value - 0x42000000))
    elif [[ "$TARGET" == xtensa-esp32-espidf ]]; then
        module_data_vma=$((0x3f400000 + module_vma_value - 0x400d0000))
    fi
fi

PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"
TOOL_BIN="$(dirname "$(command -v "${tool_prefix}-objcopy")")"
OUT_DIR="$ROOT/target/modules/$TARGET"
ELF="$ROOT/target/$TARGET/release/mod_hello"
RAW="$OUT_DIR/mod_hello.raw.bin"
IMAGE="$OUT_DIR/mod_hello.dmod"
LINK_SCRIPT="$ROOT/fw/mod_hello/link.x"
if [ -n "${DMESH_MODULE_VMA:-}" ]; then LINK_SCRIPT="$ROOT/fw/mod_hello/link-fixed.x"; fi

mkdir -p "$OUT_DIR"
if [[ "$TARGET" == riscv32* ]]; then
  relocation_model=pic
  extra_llvm_args=()
else
  relocation_model=static
  extra_llvm_args=(
    -C llvm-args=--jump-table-density=1000000
    -C llvm-args=--min-jump-table-entries=1000000
  )
fi
link_data_args=()
if [ -n "${DMESH_MODULE_VMA:-}" ]; then
    link_data_args=(-C "link-arg=-Wl,--defsym=MODULE_DATA_VMA=$module_data_vma")
fi
build_elf() {
  cargo rustc --manifest-path "$ROOT/fw/mod_hello/Cargo.toml" --bin mod_hello --features flat-image \
      --target "$TARGET" --release \
      -Zbuild-std=core,compiler_builtins -Zbuild-std-features=compiler-builtins-mem \
      --config "target.$TARGET.linker=\"${tool_prefix}-gcc\"" -- \
      -C relocation-model="$relocation_model" \
      "${extra_llvm_args[@]}" \
      ${DMESH_MODULE_VMA:+-C} ${DMESH_MODULE_VMA:+link-arg=-Wl,--defsym=MODULE_VMA=$DMESH_MODULE_VMA} \
      "${link_data_args[@]}" \
      -C link-arg=-T"$LINK_SCRIPT" -C link-arg=-nostdlib
}
build_elf
if [ -n "${DMESH_MODULE_VMA:-}" ]; then
    text_size_hex="$(${TOOL_BIN}/${tool_prefix}-readelf -S -W "$ELF" | awk '$3 == ".text" { print $7; exit }')"
    text_size=$((0x$text_size_hex))
    module_data_vma=$((module_data_vma + text_size))
    link_data_args=(-C "link-arg=-Wl,--defsym=MODULE_DATA_VMA=$module_data_vma")
    touch "$ROOT/fw/mod_hello/src/lib.rs"
    build_elf
fi

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
ENTRY_OFFSET_HEX="$(${TOOL_BIN}/${tool_prefix}-readelf -h "$ELF" | awk '/Entry point address:/ {print $NF}')"
ENTRY_OFFSET=$((ENTRY_OFFSET_HEX))
# With a fixed linker VMA, the raw binary starts at that VMA. DMOD offsets are
# relative to the raw code, not absolute instruction addresses.
MODULE_VMA_BASE=$(( ${DMESH_MODULE_VMA:-0} ))
ENTRY_OFFSET=$((ENTRY_OFFSET - MODULE_VMA_BASE))
# readelf reports the entry relative to the raw code; DMOD offsets are from
# the image start and therefore include the 64-byte header.
DMOD_ENTRY_OFFSET=$((ENTRY_OFFSET + 64))
DMOD_FLAGS=0
if [ -n "${DMESH_MODULE_VMA:-}" ]; then DMOD_FLAGS=1; fi
"$DMESH_PYTHON" "$ROOT/fw/mod_hello/pack.py" --name hello \
  --entry-offset "$DMOD_ENTRY_OFFSET" --flags "$DMOD_FLAGS" "$RAW" "$IMAGE"
printf 'module image: %s\n' "$IMAGE"
