#!/usr/bin/env bash
# Build DMesh Rust firmware for ESP32 and ESP32-S3 with repo-local tools.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
usage() {
    echo "Usage: scripts/build-fw.sh [all|esp32|e5|recovery-s3|esp32s3|esp32c6|e6]"
    echo "Default: all (build every Main CPU family)"
}
case "${1:-}" in
    -h|--help|help) usage; exit 0 ;;
esac
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
# Cargo unifies features per target directory. A previous raw-UDP or ESP-NOW
# lab build must not silently leak its one-shot client into the next image.
# Keep the normal default composition implicit, but clean only the two local
# firmware packages when an explicit diagnostic feature set changes.
FEATURE_STAMP="$CARGO_TARGET_DIR/.dmesh-main-feature-set"
FEATURE_SET="default,${DMESH_FW_FEATURES:-}"
if [ ! -f "$FEATURE_STAMP" ] || [ "$(cat "$FEATURE_STAMP")" != "$FEATURE_SET" ]; then
    (
        cd "$FIRMWARE_DIR"
        cargo clean -p dmesh-rs -p dmesh-fw-transport 2>/dev/null || true
    )
    printf '%s' "$FEATURE_SET" > "$FEATURE_STAMP"
fi
# ``build.rs`` intentionally reruns when this value changes.  Never invent a
# wall-clock value here: that turns a no-source-change Main build into a full
# LTO relink.  Packaging callers can provide an explicit timestamp; a
# reproducible caller may instead provide SOURCE_DATE_EPOCH.  Interactive
# builds keep build.rs's stable "unknown" marker and identify an image by its
# printed SHA-256.
if [ -z "${DMESH_BUILD_TIMESTAMP:-}" ] && [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    export DMESH_BUILD_TIMESTAMP="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"
fi
mkdir -p "$CARGO_TARGET_DIR"
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
    # ESP-IDF's generated CMake/bindings are target-specific.  A shared stamp
    # made a previous ESP32/S3 build invalidate the C6 cache (and vice versa),
    # needlessly rebuilding the SDK when the selected target was unchanged.
    local sdk_stamp="$CARGO_TARGET_DIR/.dmesh-esp-idf-sdk-${name}-${BUILD_MODE}"
    # Keep the packaged app at the same offset declared by the shared
    # Stage2 partition table.  Recovery transfers the extracted raw app,
    # while provisioning tools use this offset for a direct Main write.
    local app_offset=0x110000
    local boot_offset=0x0
    if [ "$chip" = esp32 ]; then
        boot_offset=0x1000
    fi

    case "$BUILD_MODE" in
        release) args+=(--release) ;;
        debug) ;;
        *) echo "DMESH_FW_PROFILE must be debug or release, got: $BUILD_MODE" >&2; exit 2 ;;
    esac
    # Normal firmware uses raw IPv6/UDP and raw ESP-NOW by default. This
    # remains available only for narrowly scoped diagnostic features.
    if [ -n "${DMESH_FW_FEATURES:-}" ]; then
        args+=(--features "$DMESH_FW_FEATURES")
    fi

    echo "=== Building $name ($target, $BUILD_MODE) ==="
    mkdir -p "$config_dir"
    mkdir -p "$image_dir"
    local partition_path="$partition_file"
    if [[ "$partition_path" != /* ]]; then
        partition_path="$FIRMWARE_DIR/$partition_path"
    fi
    # esp-idf-sys watches every sdkconfig defaults file by mtime.  Generating
    # this overlay with a plain redirect invalidates the entire ESP-IDF/Cargo
    # graph on every build even when the configuration is byte-for-byte the
    # same.  Generate a private temporary file, then atomically replace the
    # tracked input only when its contents actually changed.
    local partition_overlay_tmp
    partition_overlay_tmp="$(mktemp "${partition_overlay}.tmp.XXXXXX")"
    printf 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="%s"\n' \
        "$partition_path" > "$partition_overlay_tmp"
    # Diagnostic-only raw-bearer profile. NAN beacon synchronization and
    # power policy remain Main-owned; this overlay lets a C6 canary measure
    # whether either ESP-IDF service prevents the shared raw transport from
    # allocating its Wi-Fi driver.
    if [[ "${DMESH_FW_RAW_DIAGNOSTIC_PROFILE:-0}" == "1" ]]; then
        {
            # In a layered sdkconfig.defaults list, `# CONFIG_... is not set`
            # is only a comment.  Use explicit `=n` assignments so this
            # diagnostic overlay wins over the Main defaults file.
            printf 'CONFIG_ESP_WIFI_NAN_ENABLE=n\n'
            printf 'CONFIG_PM_ENABLE=n\n'
            printf 'CONFIG_FREERTOS_USE_TICKLESS_IDLE=n\n'
        } >> "$partition_overlay_tmp"
    fi
    if cmp -s "$partition_overlay_tmp" "$partition_overlay"; then
        rm -f "$partition_overlay_tmp"
    else
        mv -f "$partition_overlay_tmp" "$partition_overlay"
    fi
    # ESP-IDF bakes sdkconfig into esp-idf-sys's generated bindings and CMake
    # tree. A cache keyed only by the IDF revision can silently package an old
    # Wi-Fi/heap configuration after a defaults-file change.
    local sdk_defaults_path="$FIRMWARE_DIR/$sdkconfig"
    local sdk_defaults_digest
    sdk_defaults_digest="$(sha256sum \
        "$sdk_defaults_path" "$partition_overlay" \
        | sha256sum | awk '{print $1}')"
    local sdk_id="cache-v3:${IDF_PATH}:$(git -C "$IDF_PATH" describe --tags --always 2>/dev/null || true):${sdk_defaults_digest}"
    if [[ ! -f "$sdk_stamp" || "$(cat "$sdk_stamp")" != "$sdk_id" ]]; then
        echo "ESP-IDF SDK configuration changed; clearing esp-idf-sys cache for $target" >&2
        cargo clean -p esp-idf-sys 2>/dev/null || true
        rm -rf "$CARGO_TARGET_DIR/$target/$BUILD_MODE/build"/esp-idf-sys-* \
               "$CARGO_TARGET_DIR/$target/$BUILD_MODE/deps"/libesp_idf_sys-* \
               "$CARGO_TARGET_DIR/$target/$BUILD_MODE/deps"/esp_idf_sys-*
        printf '%s' "$sdk_id" > "$sdk_stamp"
    fi
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
    # at 0x110000.  The old classic single-factory image at 0x10000 is retained
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
    *) usage >&2; exit 2 ;;
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
