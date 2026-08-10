#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/env.sh"
TARGET="${1:-xtensa-esp32-espidf}"
SERVICE_TAG="${DMESH_MODULE_TAG:-45}"
SLOT_COUNT="${DMESH_MODULE_SLOTS:-1}"
if (( SERVICE_TAG < 43 || SERVICE_TAG > 100 )); then
  echo "DMESH_MODULE_TAG must be in 43..100" >&2; exit 2
fi
SLOT=$((SERVICE_TAG - 43))
case "$TARGET" in
  xtensa-esp32-espidf) prefix=xtensa-esp32-elf; code_base=0x40300000; data_base=0x3f700000; vma_stride=0x20000 ;;
  xtensa-esp32s3-espidf) prefix=xtensa-esp32s3-elf; code_base=0x43000000; data_base=0x3d000000; vma_stride=0x40000 ;;
  riscv32imac-unknown-none-elf|riscv32imac-esp-espidf) prefix=riscv32-esp-elf; vma=0 ;;
  *) echo "unsupported target: $TARGET" >&2; exit 2 ;;
esac
if [[ "$TARGET" == xtensa-* ]]; then
  vma=$((code_base + SLOT * vma_stride + 64))
  data_vma=$((data_base + SLOT * vma_stride))
else
  vma=0
  data_vma=0
fi
PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"
OUT="$ROOT/target/modules/$TARGET"
ELF="$ROOT/target/$TARGET/release/mod_hw"
RAW="$OUT/mod_hw.raw.bin"
IMAGE="$OUT/mod_hw.dmod"
mkdir -p "$OUT"
tool_dir="$(dirname "$(command -v "$prefix-objcopy")")"
link_script="$ROOT/fw/mod_hw/link.x"
relocation_model=pic
link_args=()
if [[ "$TARGET" == xtensa-* ]]; then
  link_script="$ROOT/fw/mod_hw/link-fixed.x"
  relocation_model=static
  link_args=(-C "link-arg=-Wl,--defsym=MODULE_VMA=$vma"
             -C "link-arg=-Wl,--defsym=MODULE_DATA_VMA=$data_vma"
             -C llvm-args=--jump-table-density=1000000
             -C llvm-args=--min-jump-table-entries=1000000)
fi
# RISC-V supports Rust's position-independent code model.  The flat linker
# image is linked at VMA zero and the loader maps it at its runtime address;
# requiring an empty relocation table proves this particular no_std module has
# no unresolved dynamic fixups at the ABI boundary.
cargo rustc --manifest-path "$ROOT/fw/mod_hw/Cargo.toml" --bin mod_hw --features flat-image \
  --target "$TARGET" --release -Zbuild-std=core,compiler_builtins \
  -Zbuild-std-features=compiler-builtins-mem \
  --config "target.$TARGET.linker=\"$prefix-gcc\"" -- \
  -C relocation-model="$relocation_model" -C opt-level=s -C lto=fat -C codegen-units=1 \
  "${link_args[@]}" -C link-arg=-T"$link_script" -C link-arg=-nostdlib
if ! "$tool_dir/$prefix-readelf" -r "$ELF" | grep -q "There are no relocations"; then
  echo "hw module has relocations" >&2; exit 1
fi
if "$tool_dir/$prefix-readelf" -S -W "$ELF" | awk '$2 == ".data" || $2 == ".bss" { found=1 } END { exit found ? 0 : 1 }'; then
  echo "hw module has writable data or bss; flat PIC image is not safe" >&2
  exit 1
fi
if "$tool_dir/$prefix-nm" -g "$ELF" 2>&1 | grep -qv "no symbols"; then
  echo "hw module has exported symbols" >&2; exit 1
fi
"$tool_dir/$prefix-objcopy" -O binary "$ELF" "$RAW"
entry_hex="$($tool_dir/$prefix-readelf -h "$ELF" | awk '/Entry point address:/ {print $NF}')"
entry=$((entry_hex - vma + 64))
"$DMESH_PYTHON" "$ROOT/fw/mod_hw/pack.py" --service-tag "$SERVICE_TAG" \
  --slot-count "$SLOT_COUNT" --code-vma "$((vma - 64))" --data-vma "$data_vma" \
  --entry-offset "$entry" --flags 1 "$RAW" "$IMAGE"
printf 'HW_MODULE_IMAGE=%s HW_MODULE_SIZE=%s HW_MODULE_SHA256=%s\n' \
  "$IMAGE" "$(stat -c %s "$IMAGE")" "$(sha256sum "$IMAGE" | awk '{print $1}')"
