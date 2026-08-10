#!/usr/bin/env bash
# Build DMesh Rust firmware for ESP32 and ESP32-S3 with repo-local tools.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"
# shellcheck disable=SC1091

FIRMWARE_DIR="$DMESH_REPO/fw/esp32/rust"
BUILD_MODE="${DMESH_FW_PROFILE:-release}"
REQUESTED_TARGET="${1:-all}"
now_ms() { "$DMESH_PYTHON" -c 'import time; print(time.time_ns() // 1_000_000)'; }
build_started_ms="$(now_ms)"

if [ ! -x "$RUST_ESP_TOOLCHAIN_BIN/rustc" ] || [ ! -d "$IDF_PATH" ]; then
    echo "ESP-IDF or Rust ESP is missing. Run: scripts/esp32-deps.sh" >&2
    exit 1
fi

export PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR="${DMESH_FW_TARGET_DIR:-${CARGO_TARGET_DIR:-$DMESH_REPO/target/fw}}"
mkdir -p "$CARGO_TARGET_DIR"
SDK_STAMP="$CARGO_TARGET_DIR/.dmesh-esp-idf-sdk"
SDK_ID="cache-v2:${IDF_PATH}:$(git -C "$IDF_PATH" describe --tags --always 2>/dev/null || true)"

build_one() {
    local name="$1" target="$2" sdkconfig="$3" partition_file="$4" chip="$5" flash_size="$6"
    local args=(build --target "$target")
    local config_dir="$CARGO_TARGET_DIR/sdkconfig"
    local partition_overlay="$config_dir/${name}-partition.defaults"
    local image_dir="$CARGO_TARGET_DIR/flash/$name"
    local image_path="$image_dir/dmesh-rs-merged.bin"
    local image_flash_size="${DMESH_FLASH_HEADER_SIZE:-$flash_size}"
    local elf_path="$CARGO_TARGET_DIR/$target/release/dmesh-rs"
    local boot_path="$CARGO_TARGET_DIR/$target/release/bootloader.bin"
    local partition_table_path="$CARGO_TARGET_DIR/$target/release/partition-table.bin"
    local app_offset=0xe0000
    local boot_offset=0x0
    if [ "$chip" = esp32 ]; then
        boot_offset=0x1000
    fi

    case "$BUILD_MODE" in
        release) args+=(--release) ;;
        debug) ;;
        *) echo "DMESH_FW_PROFILE must be debug or release, got: $BUILD_MODE" >&2; exit 2 ;;
    esac

    echo "=== Building $name ($target, $BUILD_MODE) ==="
    if [[ ! -f "$SDK_STAMP" || "$(cat "$SDK_STAMP")" != "$SDK_ID" ]]; then
        echo "ESP-IDF changed; clearing esp-idf-sys CMake cache for $target" >&2
        # esp-idf-sys runs on the host, so its CMake cache is under the host
        # release directory rather than the embedded target directory.
        cargo clean -p esp-idf-sys 2>/dev/null || true
        rm -rf "$CARGO_TARGET_DIR/$target/$BUILD_MODE/build"/esp-idf-sys-* \
               "$CARGO_TARGET_DIR/$target/$BUILD_MODE/deps"/libesp_idf_sys-* \
               "$CARGO_TARGET_DIR/$target/$BUILD_MODE/deps"/esp_idf_sys-*
        printf '%s' "$SDK_ID" > "$SDK_STAMP"
    fi
    mkdir -p "$config_dir"
    mkdir -p "$image_dir"
    local partition_path="$partition_file"
    if [[ "$partition_path" != /* ]]; then
        partition_path="$FIRMWARE_DIR/$partition_path"
    fi
    printf 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="%s"\n' \
        "$partition_path" > "$partition_overlay"
    (
        cd "$FIRMWARE_DIR"
        export ESP_IDF_SDKCONFIG_DEFAULTS="$sdkconfig;$partition_overlay"
        cargo "${args[@]}"
        # Package the application with the repo's esptool lane. This creates
        # an image; it never opens a serial port or flashes a board.
        "$DMESH_PYTHON" -m esptool --chip "$chip" elf2image \
            --flash_mode dio --flash_freq 40m --flash_size "${image_flash_size^^}" \
            --output "$image_dir/main-app-image.bin" "$elf_path"
        "$DMESH_PYTHON" -m esptool --chip "$chip" merge_bin --output "$image_path" \
            "$boot_offset" "$boot_path" 0x8000 "$partition_table_path" \
            "$app_offset" "$image_dir/main-app-image.bin"
    )
    printf '=== Merged image: %s ===\n' "$image_path"
    # Recovery/DRS2 always transfers the raw Main app, never the padded merged
    # image.  All current provisioned layouts use the named `main` partition
    # at 0xe0000.  The old classic single-factory image at 0x10000 is retained
    # only in historical flash evidence and must not be regenerated here.
    "$DMESH_PYTHON" "$DMESH_REPO/scripts/extract-esp-app.py" "$image_path" \
        "$image_dir/main-app.bin" --offset "$app_offset"
}

case "$REQUESTED_TARGET" in
    all)
        build_one esp32 xtensa-esp32-espidf sdkconfig.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32 4mb
        build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32s3 4mb
        build_one esp32c6 riscv32imac-esp-espidf sdkconfig.esp32c6.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32c6 4mb
        ;;
    esp32) build_one esp32 xtensa-esp32-espidf sdkconfig.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32 4mb ;;
    # E5 is a board name, not a separate CPU image family.  Keep its artifact
    # in target/flash/esp32 so the unified server cannot accidentally serve a
    # stale generic ESP32 image after an E5 build.
    e5) build_one esp32 xtensa-esp32-espidf sdkconfig.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32 4mb ;;
    recovery-s3) build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32s3 4mb ;;
    esp32s3|esp32-s3) build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32s3 4mb ;;
    esp32c6|c6|e6) build_one esp32c6 riscv32imac-esp-espidf sdkconfig.esp32c6.defaults "$DMESH_REPO/fw/boot/partitions.csv" esp32c6 4mb ;;
    *) echo "Usage: scripts/build-fw.sh {all|esp32|e5|recovery-s3|esp32s3|esp32c6|e6}" >&2; exit 2 ;;
esac

build_elapsed_ms=$(( $(now_ms) - build_started_ms ))
main_image="$CARGO_TARGET_DIR/flash/esp32s3/main-app.bin"
if [ "$REQUESTED_TARGET" = esp32 ] || [ "$REQUESTED_TARGET" = e5 ]; then
    main_image="$CARGO_TARGET_DIR/flash/esp32/main-app.bin"
elif [ "$REQUESTED_TARGET" = esp32c6 ] || [ "$REQUESTED_TARGET" = c6 ] || [ "$REQUESTED_TARGET" = e6 ]; then
    main_image="$CARGO_TARGET_DIR/flash/esp32c6/main-app.bin"
fi
if [ -f "$main_image" ]; then
    main_image_size="$(stat -c '%s' "$main_image")"
    main_image_sha256="$(sha256sum "$main_image" | awk '{print $1}')"
    printf 'MAIN_IMAGE=%s MAIN_IMAGE_SIZE=%s MAIN_IMAGE_SHA256=%s\n' \
      "$main_image" "$main_image_size" "$main_image_sha256"
else
    main_image_size=0
    main_image_sha256=""
fi
mkdir -p "$DMESH_TIMING_DIR"
printf '{"kind":"main-build","target":"%s","profile":"%s","image":"%s","size":%s,"sha256":"%s","elapsed_ms":%s}\n' \
  "$REQUESTED_TARGET" "$BUILD_MODE" "$main_image" "$main_image_size" "$main_image_sha256" "$build_elapsed_ms" >> "$DMESH_TIMING_DIR/main-timing.jsonl"
printf 'MAIN_BUILD_MS=%s\n' "$build_elapsed_ms"
