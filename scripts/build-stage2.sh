#!/usr/bin/env bash
# Build the C second-stage bootloader and its partition table only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
usage() {
    echo "Usage: scripts/build-stage2.sh [all|esp32|esp32s3|esp32c6|e6]"
    echo "Default: all (build every Stage2 CPU family)"
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
OUT_ROOT="${DMESH_STAGE2_TARGET_DIR:-$ROOT/target/stage2}"
IDF_PY="$IDF_PATH/tools/idf.py"
IDF_PYTHON="$IDF_PYTHON_ENV_PATH/bin/python"
mkdir -p "$OUT_ROOT"

build_one() {
    local name="$1" target="$2" flash_size="$3" defaults="$4" partitions="$5"
    local out="$OUT_ROOT/$name"
    local build="$out/build"
    local partition="$ROOT/fw/boot/${DMESH_BOOT_PARTITIONS:-$partitions}"
    local config="$out/sdkconfig"
    mkdir -p "$out"
    {
        cat "$ROOT/fw/boot/$defaults"
        printf 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="%s"\n' "$partition"
        if [[ "$flash_size" == 8mb ]]; then
            printf '# CONFIG_ESPTOOLPY_FLASHSIZE_4MB is not set\nCONFIG_ESPTOOLPY_FLASHSIZE_8MB=y\n'
        fi
    } > "$config"
    IDF_TARGET="$target" "$IDF_PYTHON" "$IDF_PY" --project-dir "$ROOT/fw/boot" -B "$build" -D SDKCONFIG="$config" build
    cp "$build/bootloader/bootloader.bin" "$out/bootloader.bin"
    cp "$build/partition_table/partition-table.bin" "$out/partition-table.bin"
    cp "$partition" "$out/partitions.csv"
    printf 'built stage2 %s bootloader=%s\n' "$name" "$(stat -c%s "$out/bootloader.bin")"
}

case "$TARGET_NAME" in
    esp32|classic) build_one esp32 esp32 4mb sdkconfig.defaults partitions.csv ;;
    esp32s3|s3) build_one esp32s3 esp32s3 8mb sdkconfig.esp32s3.defaults partitions.csv ;;
    esp32c6|c6|e6) build_one esp32c6 esp32c6 4mb sdkconfig.esp32c6.defaults partitions.csv ;;
    all)
        build_one esp32 esp32 4mb sdkconfig.defaults partitions.csv
        build_one esp32s3 esp32s3 8mb sdkconfig.esp32s3.defaults partitions.csv
        build_one esp32c6 esp32c6 4mb sdkconfig.esp32c6.defaults partitions.csv ;;
    *) usage >&2; exit 2 ;;
esac
