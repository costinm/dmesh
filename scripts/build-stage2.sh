#!/usr/bin/env bash
# Build the C Stage2 boot selector and its partition table for the 4 MiB and 8 MiB layouts.
#
# Stage2 (and the partition tables) live in the esp-wifi-loader repository ($ESP_WIFI_LOADER_DIR, its
# boot/ directory); fw/boot was removed on 2026-10-10. This script runs that build and publishes the
# results under the names the rest of DMesh expects:
#   target/stage2/<cpu>/<size>/{bootloader.bin,partition-table.bin,partitions.csv}
#   target/flash/<cpu>/<size>/{stage2.bin,partition-table.bin}   (+ the CPU's default size one level up)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
usage() {
    echo "Usage: scripts/build-stage2.sh [all|esp32|esp32s3|esp32c6|e6] [4mb|8mb]"
    echo "Default: all (both flash sizes for every Stage2 CPU family)"
}
case "${1:-}" in -h|--help|help) usage; exit 0 ;; esac
. "$ROOT/env.sh"
WL="${ESP_WIFI_LOADER_DIR:-}"
[[ -x "$WL/scripts/build.sh" ]] || { echo "set ESP_WIFI_LOADER_DIR to a checkout of github.com/costinm/esp-wifi-loader (env.sh finds ../esp-wifi-loader)" >&2; exit 1; }

case "${1:-all}" in
    all) CPUS="esp32 esp32s3 esp32c6" ;;
    esp32|classic) CPUS=esp32 ;;
    esp32s3|s3) CPUS=esp32s3 ;;
    esp32c6|c6|e6) CPUS=esp32c6 ;;
    *) usage >&2; exit 2 ;;
esac
SELECTED_SIZE="${2:-}"
if [[ -n "$SELECTED_SIZE" && "$SELECTED_SIZE" != 4mb && "$SELECTED_SIZE" != 8mb ]]; then usage >&2; exit 2; fi
SIZES="${SELECTED_SIZE:-4mb 8mb}"
OUT_ROOT="${DMESH_STAGE2_TARGET_DIR:-$ROOT/target/stage2}"
FLASH_ROOT_BASE="${DMESH_STAGE2_FLASH_ROOT:-$ROOT/target/flash}"

for cpu in $CPUS; do
    "$WL/scripts/build.sh" "$cpu" "${SELECTED_SIZE:-all}"
    for size in $SIZES; do
        src="$WL/target/out/$cpu"
        out="$OUT_ROOT/$cpu/$size"
        flash="$FLASH_ROOT_BASE/$cpu"
        mkdir -p "$out" "$flash/$size"
        cp "$src/stage2-$size.bin" "$out/bootloader.bin"
        cp "$src/partition-table-$size.bin" "$out/partition-table.bin"
        cp "$WL/boot/partitions/$size.csv" "$out/partitions.csv"
        cp "$out/bootloader.bin" "$flash/$size/stage2.bin"
        cp "$out/partition-table.bin" "$flash/$size/partition-table.bin"
        if [[ "$size" == 4mb && "$cpu" != esp32s3 ]] || [[ "$size" == 8mb && "$cpu" == esp32s3 ]]; then
            cp "$out/bootloader.bin" "$flash/stage2.bin"
            cp "$out/partition-table.bin" "$flash/partition-table.bin"
        fi
        printf 'built stage2 %s %s bootloader=%s\n' "$cpu" "$size" "$(stat -c%s "$out/bootloader.bin")"
    done
done
