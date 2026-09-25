#!/usr/bin/env bash
# Build the C second-stage bootloader and its partition table only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
usage() {
    echo "Usage: scripts/build-stage2.sh [all|esp32|esp32s3|esp32c6|e6] [4mb|8mb]"
    echo "Default: all (build both flash sizes for every Stage2 CPU family)"
}
case "${1:-}" in
    -h|--help|help) usage; exit 0 ;;
esac
. "$ROOT/env.sh"
STAGE2_ESP_ROOT="${DMESH_BOOT_RECOVERY_ESP_ROOT:-$DMESH_ESP_ROOT}"
if [[ "$STAGE2_ESP_ROOT" != /* ]]; then STAGE2_ESP_ROOT="$ROOT/$STAGE2_ESP_ROOT"; fi
if [[ ! -f "$STAGE2_ESP_ROOT/env.sh" ]]; then
    echo "Stage2 ESP-IDF environment is missing: $STAGE2_ESP_ROOT" >&2
    exit 1
fi
unset IDF_DEACTIVATE_FILE_PATH IDF_PYTHON_ENV_PATH ESP_PYTHON PYTHON
. "$STAGE2_ESP_ROOT/env.sh"

TARGET_NAME="${1:-all}"
SELECTED_SIZE="${2:-}"
if [[ -n "$SELECTED_SIZE" && "$SELECTED_SIZE" != 4mb && "$SELECTED_SIZE" != 8mb ]]; then
    usage >&2
    exit 2
fi
OUT_ROOT="${DMESH_STAGE2_TARGET_DIR:-$ROOT/target/stage2}"
IDF_PY="$IDF_PATH/tools/idf.py"
IDF_PYTHON="$IDF_PYTHON_ENV_PATH/bin/python"
mkdir -p "$OUT_ROOT"

build_one() {
    local name="$1" target="$2" flash_size="$3" defaults="$4"
    local out="$OUT_ROOT/$name/$flash_size"
    local build="$out/build"
    local partitions=partitions.csv
    if [[ "$flash_size" == 8mb ]]; then partitions=partitions_8mb.csv; fi
    local partition="$ROOT/fw/boot/${DMESH_BOOT_PARTITIONS:-$partitions}"
    local config="$out/sdkconfig"
    mkdir -p "$out"
    {
        sed '/CONFIG_ESPTOOLPY_FLASHSIZE_/d' "$ROOT/fw/boot/$defaults"
        printf 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="%s"\n' "$partition"
        if [[ "$flash_size" == 8mb ]]; then
            printf 'CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y\n'
        else
            printf 'CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y\n'
        fi
    } > "$config"
    IDF_TARGET="$target" "$IDF_PYTHON" "$IDF_PY" --project-dir "$ROOT/fw/boot" -B "$build" -D SDKCONFIG="$config" build
    cp "$build/bootloader/bootloader.bin" "$out/bootloader.bin"
    cp "$build/partition_table/partition-table.bin" "$out/partition-table.bin"
    cp "$partition" "$out/partitions.csv"
    # Publish the CPU-qualified boot image into the shared object catalog.
    # `object.flash target=2` writes only this bounded Stage2 region; the
    # partition table remains an explicit provisioning artifact.
    local flash_root="$ROOT/target/flash/$name"
    mkdir -p "$flash_root/$flash_size"
    cp "$out/bootloader.bin" "$flash_root/$flash_size/stage2.bin"
    cp "$out/partition-table.bin" "$flash_root/$flash_size/partition-table.bin"
    # The object server's existing CPU-qualified Stage2 slot uses the
    # established default size for that CPU. Direct provisioning chooses the
    # explicit size directory after probing physical flash capacity.
    if [[ "$flash_size" == 4mb && "$name" != esp32s3 ]] ||
       [[ "$flash_size" == 8mb && "$name" == esp32s3 ]]; then
        cp "$out/bootloader.bin" "$flash_root/stage2.bin"
        cp "$out/partition-table.bin" "$flash_root/partition-table.bin"
    fi
    printf 'built stage2 %s %s bootloader=%s\n' "$name" "$flash_size" "$(stat -c%s "$out/bootloader.bin")"
}

build_family() {
    local name="$1" target="$2" defaults="$3"
    if [[ -n "$SELECTED_SIZE" ]]; then
        build_one "$name" "$target" "$SELECTED_SIZE" "$defaults"
    else
        build_one "$name" "$target" 4mb "$defaults"
        build_one "$name" "$target" 8mb "$defaults"
    fi
}

case "$TARGET_NAME" in
    esp32|classic) build_family esp32 esp32 sdkconfig.defaults ;;
    esp32s3|s3) build_family esp32s3 esp32s3 sdkconfig.esp32s3.defaults ;;
    esp32c6|c6|e6) build_family esp32c6 esp32c6 sdkconfig.esp32c6.defaults ;;
    all)
        build_family esp32 esp32 sdkconfig.defaults
        build_family esp32s3 esp32s3 sdkconfig.esp32s3.defaults
        build_family esp32c6 esp32c6 sdkconfig.esp32c6.defaults ;;
    *) usage >&2; exit 2 ;;
esac
