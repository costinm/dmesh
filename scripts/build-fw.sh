#!/usr/bin/env bash
# Build DMesh Rust firmware for ESP32 and ESP32-S3 with repo-local tools.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"
# shellcheck disable=SC1091
. "$DMESH_REPO/fw/esp32/env.sh"

FIRMWARE_DIR="$DMESH_REPO/fw/esp32/rust"
BUILD_MODE="${DMESH_FW_PROFILE:-release}"
REQUESTED_TARGET="${1:-all}"

if [ ! -x "$RUST_ESP_TOOLCHAIN_BIN/rustc" ] || [ ! -d "$IDF_PATH" ]; then
    echo "ESP-IDF or Rust ESP is missing. Run: scripts/esp32-deps.sh" >&2
    exit 1
fi

export PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR="${DMESH_FW_TARGET_DIR:-$DMESH_REPO/target/fw}"

build_one() {
    local name="$1" target="$2" sdkconfig="$3" partition_file="$4" chip="$5" flash_size="$6"
    local args=(build --target "$target")
    local config_dir="$CARGO_TARGET_DIR/sdkconfig"
    local partition_overlay="$config_dir/${name}-partition.defaults"
    local image_dir="$CARGO_TARGET_DIR/flash/$name"
    local image_path="$image_dir/dmesh-rs-merged.bin"

    case "$BUILD_MODE" in
        release) args+=(--release) ;;
        debug) ;;
        *) echo "DMESH_FW_PROFILE must be debug or release, got: $BUILD_MODE" >&2; exit 2 ;;
    esac

    echo "=== Building $name ($target, $BUILD_MODE) ==="
    mkdir -p "$config_dir"
    mkdir -p "$image_dir"
    printf 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="%s"\n' \
        "$FIRMWARE_DIR/$partition_file" > "$partition_overlay"
    (
        cd "$FIRMWARE_DIR"
        export ESP_IDF_SDKCONFIG_DEFAULTS="$sdkconfig;$partition_overlay"
        cargo "${args[@]}"
        cargo espflash save-image "${args[@]:1}" --chip "$chip" --flash-size "$flash_size" \
            --merge --skip-padding "$image_path"
    )
    printf '=== Merged image: %s ===\n' "$image_path"
}

case "$REQUESTED_TARGET" in
    all)
        build_one esp32 xtensa-esp32-espidf sdkconfig.defaults partitions_4mb_large_app.csv esp32 4mb
        build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3_8mb.defaults partitions_8mb_large_app_store.csv esp32s3 8mb
        ;;
    esp32) build_one esp32 xtensa-esp32-espidf sdkconfig.defaults partitions_4mb_large_app.csv esp32 4mb ;;
    esp32s3|esp32-s3) build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3_8mb.defaults partitions_8mb_large_app_store.csv esp32s3 8mb ;;
    *) echo "Usage: scripts/build-fw.sh {all|esp32|esp32s3}" >&2; exit 2 ;;
esac
