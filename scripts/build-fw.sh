#!/usr/bin/env bash
# Build DMesh Rust firmware for ESP32 and ESP32-S3 with repo-local tools.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
usage() {
    echo "Usage: scripts/build-fw.sh [all|esp32|e5|recovery-s3|esp32s3|esp32c6|e6]"
    echo "Default: all (build every Main CPU family)"
    echo "BLE defaults on for C6, off for ESP32/S3. To build Main without BLE:"
    echo "  DMESH_FW_NO_DEFAULT_FEATURES=1 DMESH_FW_FEATURES=modules scripts/build-fw.sh esp32c6"
    echo "Opt-in driver queue experiment (does not change normal defaults):"
    echo "  DMESH_WIFI_DYNAMIC_TX_BUFFERS=4 scripts/build-fw.sh esp32"
    echo "  DMESH_WIFI_DYNAMIC_RX_BUFFERS=10 scripts/build-fw.sh esp32"
    echo "  DMESH_WIFI_STATIC_RX_BUFFERS=6 DMESH_WIFI_DYNAMIC_RX_BUFFERS=6 DMESH_WIFI_DYNAMIC_TX_BUFFERS=8 scripts/build-fw.sh esp32"
    echo "  Static RX must cover the selected SDK RX BA window; verify generated sdkconfig."
}
case "${1:-}" in
    -h|--help|help) usage; exit 0 ;;
esac
# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"
# shellcheck disable=SC1091

FIRMWARE_DIR="${DMESH_MAIN_FIRMWARE_DIR:-$DMESH_REPO/fw/main}"
BUILD_MODE="${DMESH_FW_PROFILE:-release}"
REQUESTED_TARGET="${1:-all}"
# Flash clock for every image (Stage2 and the loader use the same default);
# 80 MHz is tested on all boards. Main's own flash driver is always DIO:
# Stage2 selects QIO code reads per boot (NVS stg2:flash) and configures the
# quad pins only then, so a QIO driver reads garbage after a DIO boot and can
# damage NVS. See docs/dmesh-stage2-lessons.md and boot.md "QIO autodetect" in the esp-wifi-loader repository.
FLASH_MODE=dio
FLASH_MHZ="${DMESH_FLASH_MHZ:-80}"
if [[ -n "${DMESH_FLASH_MODE:-}" && "$DMESH_FLASH_MODE" != dio ]]; then
    echo 'DMESH_FLASH_MODE: Main is always DIO; set QIO with NVS stg2:flash for Stage2' >&2
    exit 2
fi
case "$FLASH_MHZ" in 40|80) ;; *) echo 'DMESH_FLASH_MHZ must be 40 or 80' >&2; exit 2 ;; esac
if [[ -n "${DMESH_WIFI_DYNAMIC_TX_BUFFERS:-}" ]] &&
   [[ ! "$DMESH_WIFI_DYNAMIC_TX_BUFFERS" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]; then
    echo 'DMESH_WIFI_DYNAMIC_TX_BUFFERS must be an integer from 1 to 128' >&2
    exit 2
fi
if [[ -n "${DMESH_WIFI_STATIC_RX_BUFFERS:-}" ]] &&
   [[ ! "$DMESH_WIFI_STATIC_RX_BUFFERS" =~ ^([6-9]|1[0-9]|2[0-5])$ ]]; then
    echo 'DMESH_WIFI_STATIC_RX_BUFFERS must be an integer from 6 to 25 (and at least the selected SDK RX BA window)' >&2
    exit 2
fi
if [[ -n "${DMESH_WIFI_DYNAMIC_RX_BUFFERS:-}" ]] &&
   [[ ! "$DMESH_WIFI_DYNAMIC_RX_BUFFERS" =~ ^([2-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]; then
    echo 'DMESH_WIFI_DYNAMIC_RX_BUFFERS must be an integer from 2 to 128' >&2
    exit 2
fi
if [[ -n "${DMESH_WIFI_DYNAMIC_RX_BUFFERS:-}" ]] &&
   (( DMESH_WIFI_DYNAMIC_RX_BUFFERS < ${DMESH_WIFI_STATIC_RX_BUFFERS:-10} )); then
    echo 'Dynamic RX must be at least static RX (default floor 10 unless explicitly overridden)' >&2
    exit 2
fi
now_ms() { "$DMESH_PYTHON" -c 'import time; print(time.time_ns() // 1_000_000)'; }
build_started_ms="$(now_ms)"

if [ ! -x "$RUST_ESP_TOOLCHAIN_BIN/rustc" ] || [ ! -d "$IDF_PATH" ]; then
    echo "ESP-IDF or Rust ESP is missing. Run: scripts/esp32-deps.sh" >&2
    exit 1
fi

export PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR="${DMESH_FW_TARGET_DIR:-${CARGO_TARGET_DIR:-$DMESH_REPO/target/fw}}"
FLASH_ROOT="${DMESH_MAIN_FLASH_ROOT:-$CARGO_TARGET_DIR/flash}"
# Cargo unifies features per target directory. A previous raw-UDP or ESP-NOW
# lab build must not silently leak its one-shot client into the next image.
# Keep the normal default composition implicit, but clean only the two local
# firmware packages when an explicit diagnostic feature set changes.
FEATURE_STAMP="$CARGO_TARGET_DIR/.dmesh-main-feature-set"
NO_DEFAULT_FEATURES="${DMESH_FW_NO_DEFAULT_FEATURES:-0}"
case "$NO_DEFAULT_FEATURES" in 0|1) ;; *) echo 'DMESH_FW_NO_DEFAULT_FEATURES must be 0 or 1' >&2; exit 2 ;; esac
FEATURE_SET="no-defaults=${NO_DEFAULT_FEATURES},${DMESH_FW_FEATURES:-}"
mkdir -p "$CARGO_TARGET_DIR"
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
    local no_defaults="$NO_DEFAULT_FEATURES" fw_features="${DMESH_FW_FEATURES:-}"
    # Normal Xtensa images omit BLE; C6 keeps the default BLE feature.
    # An explicit feature selection remains available for diagnostic builds.
    if [[ "$chip" != esp32c6 && -z "${DMESH_FW_NO_DEFAULT_FEATURES+x}" && -z "${DMESH_FW_FEATURES+x}" ]]; then
        no_defaults=1
        fw_features=modules
    fi
    local args=(build --target "$target")
    local config_dir="$CARGO_TARGET_DIR/sdkconfig"
    local partition_overlay="$config_dir/${name}-partition.defaults"
    local image_dir="$FLASH_ROOT/$name"
    local image_path="$image_dir/dmesh-rs-merged.bin"
    local image_flash_size="${DMESH_FLASH_HEADER_SIZE:-$flash_size}"
    local elf_path="$CARGO_TARGET_DIR/$target/$BUILD_MODE/dmesh-rs"
    local boot_path="$CARGO_TARGET_DIR/$target/$BUILD_MODE/bootloader.bin"
    # ESP-IDF's generated CMake/bindings are target-specific.  A shared stamp
    # made a previous ESP32/S3 build invalidate the C6 cache (and vice versa),
    # needlessly rebuilding the SDK when the selected target was unchanged.
    local sdk_stamp="$CARGO_TARGET_DIR/.dmesh-esp-idf-sdk-${name}-${BUILD_MODE}"
    # Keep the packaged app at the same offset declared by the shared
    # Stage2 partition table.  Recovery transfers the extracted raw app,
    # while provisioning tools use this offset for a direct Main write.
    local app_offset=0xf0000

    case "$BUILD_MODE" in
        release) args+=(--release) ;;
        debug) ;;
        *) echo "DMESH_FW_PROFILE must be debug or release, got: $BUILD_MODE" >&2; exit 2 ;;
    esac
    # Normal firmware uses raw IPv6/UDP and raw ESP-NOW by default. This
    # remains available only for narrowly scoped diagnostic features.
    if [[ "$no_defaults" == "1" ]]; then
        args+=(--no-default-features)
    fi
    if [ -n "$fw_features" ]; then
        args+=(--features "$fw_features")
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
    if [[ -n "${DMESH_WIFI_DYNAMIC_TX_BUFFERS:-}" ]]; then
        # Explicit canary overlay only. Driver queue capacity is independent
        # of QUIC packet-pool slots, stream credit and retransmission limits.
        printf 'CONFIG_ESP_WIFI_STATIC_TX_BUFFER=n\nCONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER=y\nCONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=%s\n' \
            "$DMESH_WIFI_DYNAMIC_TX_BUFFERS" >> "$partition_overlay_tmp"
    fi
    if [[ -n "${DMESH_WIFI_STATIC_RX_BUFFERS:-}" ]]; then
        printf 'CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=%s\n' \
            "$DMESH_WIFI_STATIC_RX_BUFFERS" >> "$partition_overlay_tmp"
    fi
    if [[ -n "${DMESH_WIFI_DYNAMIC_RX_BUFFERS:-}" ]]; then
        printf 'CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=%s\n' \
            "$DMESH_WIFI_DYNAMIC_RX_BUFFERS" >> "$partition_overlay_tmp"
    fi
    # Keep the app driver settings identical to the espflash image header.
    printf 'CONFIG_ESPTOOLPY_FLASHMODE_DIO=%s\nCONFIG_ESPTOOLPY_FLASHMODE_QIO=%s\nCONFIG_ESPTOOLPY_FLASHMODE="%s"\nCONFIG_ESPTOOLPY_FLASHFREQ_40M=%s\nCONFIG_ESPTOOLPY_FLASHFREQ_80M=%s\nCONFIG_ESPTOOLPY_FLASHFREQ="%sm"\n' \
        "$([[ "$FLASH_MODE" == dio ]] && echo y || echo n)" \
        "$([[ "$FLASH_MODE" == qio ]] && echo y || echo n)" "$FLASH_MODE" \
        "$([[ "$FLASH_MHZ" == 40 ]] && echo y || echo n)" \
        "$([[ "$FLASH_MHZ" == 80 ]] && echo y || echo n)" "$FLASH_MHZ" >> "$partition_overlay_tmp"
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
    if [[ ",${DMESH_FW_FEATURES:-}," == *",rtos-stats,"* ]]; then
        printf 'CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS=y\nCONFIG_FREERTOS_USE_TRACE_FACILITY=y\nCONFIG_FREERTOS_RUN_TIME_STATS_USING_ESP_TIMER=y\n' >> "$partition_overlay_tmp"
    fi
    if [[ "$no_defaults" == "1" && ",$fw_features," != *",ble-stack,"* ]]; then
        # Cargo feature and ESP-IDF component selection must agree: omitting
        # the Rust adapter alone leaves NimBLE's SDK RAM allocation enabled.
        printf 'CONFIG_BT_ENABLED=n\nCONFIG_BT_NIMBLE_ENABLED=n\n' >> "$partition_overlay_tmp"
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
    # Native ESP-IDF components are outside Cargo's Rust dependency graph.
    # Include their source/ABI inputs in the target cache key so a module
    # loader fix cannot silently package the prior C object file.
    sdk_defaults_digest="$(sha256sum \
        "$sdk_defaults_path" "$partition_overlay" "$FIRMWARE_DIR/Cargo.toml" \
        $(find "${ESP_MODULES_DIR:-$DMESH_REPO/../esp-xip-modules}/components" -type f \( -name '*.c' -o -name '*.h' -o -name CMakeLists.txt -o -name Kconfig \) | sort) \
        "$DMESH_REPO/fw/main/native/dmesh_uart_log/CMakeLists.txt" \
        "$DMESH_REPO/fw/main/native/dmesh_uart_log/dmesh_uart_log.c" \
        "$DMESH_REPO/fw/ble/native/dmesh_nimble/CMakeLists.txt" \
        "$DMESH_REPO/fw/ble/native/dmesh_nimble/dmesh_nimble.c" \
        "$DMESH_REPO/fw/ble/native/dmesh_nimble/include/dmesh_nimble.h" \
        "$DMESH_REPO/fw/main/partitions.csv" \
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
        # espflash packages the ELF without opening a serial port. Keep the
        # partition offsets selected by the shared Stage2 table.
        espflash --skip-update-check save-image --chip "$chip" \
            --flash-mode "$FLASH_MODE" --flash-freq "${FLASH_MHZ}mhz" --flash-size "$image_flash_size" \
            --target-app-partition main --partition-table "$partition_file" \
            --bootloader "$boot_path" --merge --skip-padding \
            "$elf_path" "$image_path"
    )
    printf '=== Merged image: %s ===\n' "$image_path"
    # Recovery/DRS2 always transfers the raw Main app, never the padded merged
    # image.  All current provisioned layouts use the named `main` partition
    # at 0xf0000.  The old classic single-factory image at 0x10000 is retained
    # only in historical flash evidence and must not be regenerated here.
    "$DMESH_PYTHON" "$DMESH_REPO/scripts/extract-esp-app.py" "$image_path" \
        "$image_dir/main-app.bin" --offset "$app_offset"
    cp "$image_dir/main-app.bin" "$image_dir/main-app-image.bin"
}

case "$REQUESTED_TARGET" in
    all)
        build_one esp32 xtensa-esp32-espidf sdkconfig.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32 4mb
        build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32s3 4mb
        build_one esp32c6 riscv32imac-esp-espidf sdkconfig.esp32c6.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32c6 4mb
        ;;
    esp32) build_one esp32 xtensa-esp32-espidf sdkconfig.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32 4mb ;;
    # E5 is a board name, not a separate CPU image family.  Keep its artifact
    # in target/flash/esp32 so the unified server cannot accidentally serve a
    # stale generic ESP32 image after an E5 build.
    e5) build_one esp32 xtensa-esp32-espidf sdkconfig.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32 4mb ;;
    recovery-s3) build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32s3 4mb ;;
    esp32s3|esp32-s3) build_one esp32s3 xtensa-esp32s3-espidf sdkconfig.esp32s3.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32s3 4mb ;;
    esp32c6|c6|e6) build_one esp32c6 riscv32imac-esp-espidf sdkconfig.esp32c6.defaults "$DMESH_REPO/fw/main/partitions.csv" esp32c6 4mb ;;
    *) usage >&2; exit 2 ;;
esac

build_elapsed_ms=$(( $(now_ms) - build_started_ms ))
main_image="$FLASH_ROOT/esp32s3/main-app.bin"
if [ "$REQUESTED_TARGET" = esp32 ] || [ "$REQUESTED_TARGET" = e5 ]; then
    main_image="$FLASH_ROOT/esp32/main-app.bin"
elif [ "$REQUESTED_TARGET" = esp32c6 ] || [ "$REQUESTED_TARGET" = c6 ] || [ "$REQUESTED_TARGET" = e6 ]; then
    main_image="$FLASH_ROOT/esp32c6/main-app.bin"
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
