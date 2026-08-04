#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/env.sh"
build_started_ms="$(date +%s%3N)"
TARGET="${1:-xtensa-esp32-espidf}"
case "$TARGET" in
  xtensa-esp32-espidf) tool_prefix=xtensa-esp32-elf ;;
  xtensa-esp32s3-espidf) tool_prefix=xtensa-esp32s3-elf ;;
  riscv32imac-unknown-none-elf|riscv32imac-esp-espidf) tool_prefix=riscv32-esp-elf ;;
  *) echo "unsupported module target: $TARGET" >&2; exit 2 ;;
esac
# Xtensa flat images are statically linked and must use the reserved fixed
# execution window.  Keep the override for slot experiments, but do not allow
# the ordinary build command to silently produce an image that Main would
# treat as dynamically mapped PIC code.
if [[ "$TARGET" == xtensa-esp32s3-espidf && -z "${DMESH_MODULE_VMA:-}" ]]; then
  DMESH_MODULE_VMA=0x43000040
elif [[ "$TARGET" == xtensa-esp32-espidf && -z "${DMESH_MODULE_VMA:-}" ]]; then
  DMESH_MODULE_VMA=0x400d0040
fi
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
ELF="$ROOT/target/$TARGET/release/mod_lora"
RAW="$OUT_DIR/mod_lora.raw.bin"
IMAGE="$OUT_DIR/mod_lora.dmod"
LINK_SCRIPT="$ROOT/fw/mod_lora/link.x"
if [ -n "${DMESH_MODULE_VMA:-}" ]; then LINK_SCRIPT="$ROOT/fw/mod_lora/link-fixed.x"; fi
mkdir -p "$OUT_DIR"
if [[ "$TARGET" == riscv32* ]]; then
  relocation_model=pic
  extra_llvm_args=()
else
  # Xtensa Rust currently rejects PIC relocations. Keep this explicit while the
  # loader/placement experiment is resolved; a static image must not be treated
  # as position-independent merely because it is flash-mapped.
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
  cargo rustc --manifest-path "$ROOT/fw/mod_lora/Cargo.toml" --bin mod_lora --features flat-image \
    --target "$TARGET" --release -Zbuild-std=core,compiler_builtins \
    -Zbuild-std-features=compiler-builtins-mem \
    --config "target.$TARGET.linker=\"${tool_prefix}-gcc\"" -- \
    -C relocation-model="$relocation_model" -C opt-level=s \
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
  # Cargo fingerprints linker arguments poorly for this two-pass layout;
  # bump the source mtime so the second invocation really relinks with the
  # computed data-bus origin (content is unchanged).
  touch "$ROOT/fw/mod_lora/src/lib.rs"
  build_elf
fi
if ! "${TOOL_BIN}/${tool_prefix}-readelf" -r "$ELF" | grep -q "There are no relocations"; then
  echo "module ELF has relocations" >&2; exit 1
fi
if "${TOOL_BIN}/${tool_prefix}-nm" -g "$ELF" 2>&1 | grep -qv "no symbols"; then
  echo "module ELF has exported symbols" >&2; exit 1
fi
if ! "${TOOL_BIN}/${tool_prefix}-size" "$ELF" | awk 'NR == 2 { exit ($2 == 0 && $3 == 0) ? 0 : 1 }'; then
  echo "module ELF has data or bss" >&2; exit 1
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
"$DMESH_PYTHON" "$ROOT/fw/mod_hello/pack.py" --name lora --stack-words 16384 \
  --entry-offset "$DMOD_ENTRY_OFFSET" --flags "$DMOD_FLAGS" "$RAW" "$IMAGE"
printf 'module image: %s\n' "$IMAGE"
build_elapsed_ms=$(( $(date +%s%3N) - build_started_ms ))
image_size="$(stat -c '%s' "$IMAGE")"
image_sha256="$(sha256sum "$IMAGE" | awk '{print $1}')"
mkdir -p "$DMESH_TIMING_DIR"
printf '{"kind":"module-build","target":"%s","image":"%s","size":%s,"sha256":"%s","elapsed_ms":%s}\n' \
  "$TARGET" "$IMAGE" "$image_size" "$image_sha256" "$build_elapsed_ms" >> "$DMESH_TIMING_DIR/module-timing.jsonl"
printf 'MODULE_IMAGE_SIZE=%s MODULE_IMAGE_SHA256=%s\n' "$image_size" "$image_sha256"
printf 'MODULE_BUILD_MS=%s\n' "$build_elapsed_ms"
