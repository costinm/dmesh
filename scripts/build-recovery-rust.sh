#!/usr/bin/env bash
# Recovery is intentionally frozen while Main becomes the only active firmware
# lane. Keep this entry point as a loud guard so automation cannot silently
# produce an image for the retired Recovery path.
set -euo pipefail

if [[ "${DMESH_ALLOW_RECOVERY_BUILD:-0}" != "1" ]]; then
    echo "FATAL: Rust Recovery builds are disabled; build Main with scripts/build-fw.sh" >&2
    echo "Set DMESH_ALLOW_RECOVERY_BUILD=1 only to compile/measure the frozen lane." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
usage() {
    echo "Usage: scripts/build-recovery-rust.sh [esp32|esp32s3|esp32c6|e6]"
    echo "Default: esp32 (classic ESP32 Recovery)"
}
case "${1:-}" in
    -h|--help|help) usage; exit 0 ;;
esac
. "$ROOT/env.sh"
export PATH="$RUST_ESP_TOOLCHAIN_BIN:$CARGO_HOME/bin:$PATH"

PROJECT="$ROOT/fw/recovery-rust"
REQUESTED_TARGET="${1:-esp32}"
case "$REQUESTED_TARGET" in
    esp32|classic)
        IDF_TARGET_NAME="esp32"
        RUST_TARGET="xtensa-esp32-espidf"
        CHIP="esp32"
        BOOT_OFFSET="0x1000"
        ;;
    esp32c6|c6|e6|riscv)
        IDF_TARGET_NAME="esp32c6"
        RUST_TARGET="riscv32imac-esp-espidf"
        CHIP="esp32c6"
        BOOT_OFFSET="0x0"
        ;;
    esp32s3|s3)
        IDF_TARGET_NAME="esp32s3"
        RUST_TARGET="xtensa-esp32s3-espidf"
        CHIP="esp32s3"
        BOOT_OFFSET="0x0"
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
TARGET_DIR="${DMESH_RECOVERY_RUST_TARGET_DIR:-$ROOT/target/recovery-rust}"
CONFIG_DIR="$TARGET_DIR/config"
mkdir -p "$CONFIG_DIR"
OVERLAY="$CONFIG_DIR/sdkconfig.defaults"
{
    printf 'CONFIG_IDF_TARGET="%s"\n' "$IDF_TARGET_NAME"
    printf 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="%s"\n' \
        "$ROOT/fw/boot/partitions.csv"
} > "$OVERLAY"
if [[ "$IDF_TARGET_NAME" == "esp32c6" ]]; then
    {
        printf 'CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y\n'
        printf '# CONFIG_ESP_CONSOLE_UART_DEFAULT is not set\n'
    } >> "$OVERLAY"
fi

export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_WORKSPACE_DIR="$PROJECT"
export ESP_IDF_SDKCONFIG_DEFAULTS="$PROJECT/sdkconfig.defaults;$OVERLAY"
# Recovery's default firmware lane is raw IPv6/UDP rather than the lwIP socket
# worker. ESP-IDF still supplies Wi-Fi/FreeRTOS primitives and may link lwIP.
RECOVERY_MODULES="${DMESH_RECOVERY_MODULES:-0}"
export ESP_IDF_COMPONENTS="main;driver;esp_wifi;esp_event;esp_netif;esp_partition;nvs_flash;esp_driver_uart"
BUILD_FEATURES=()
if [[ "$RECOVERY_MODULES" == "1" ]]; then
    # The moved loader is optional in Recovery so its flash cost can be
    # measured independently from the raw UDP6 transport core.
    export ESP_IDF_COMPONENTS+=";dmesh_module_loader"
    BUILD_FEATURES+=(--features modules)
fi

# The raw UDP6 and raw ESP-NOW bearers are Recovery defaults. Keep an explicit

# Keep the same SDK-cache invalidation rule as scripts/build-fw.sh. This is
# important when the component list changes: esp-idf-sys otherwise reuses a
# bindings/CMake tree made for a different ESP-IDF surface.
SDK_STAMP="$TARGET_DIR/.dmesh-esp-idf-sdk"
# ESP-IDF bakes sdkconfig into the esp-idf-sys CMake tree. Include both
# defaults files in the cache key: otherwise an edited lwIP setting can leave
# a successful Rust rebuild carrying the previous SDK configuration.
SDK_DEFAULTS_DIGEST="$(sha256sum \
    "$PROJECT/sdkconfig.defaults" "$OVERLAY" \
    "$ROOT/fw/modules/native/dmesh_module_loader/CMakeLists.txt" \
    "$ROOT/fw/modules/native/dmesh_module_loader/dmesh_module_loader.c" \
    "$ROOT/fw/modules/native/dmesh_module_loader/dmesh_hw_host.c" \
    "$ROOT/fw/modules/native/dmesh_module_loader/dmesh_module_weak_platform.c" \
    | sha256sum | awk '{print $1}')"
SDK_ID="cache-v6:modules=${RECOVERY_MODULES}:${IDF_PATH}:$(git -C "$IDF_PATH" describe --tags --always 2>/dev/null || true):${SDK_DEFAULTS_DIGEST}"
if [[ ! -f "$SDK_STAMP" || "$(cat "$SDK_STAMP")" != "$SDK_ID" ]]; then
    cargo clean -p esp-idf-sys 2>/dev/null || true
    rm -rf "$TARGET_DIR/$RUST_TARGET/release/build"/esp-idf-sys-* \
           "$TARGET_DIR/$RUST_TARGET/release/deps"/libesp_idf_sys-* \
           "$TARGET_DIR/$RUST_TARGET/release/deps"/esp_idf_sys-*
    printf '%s' "$SDK_ID" > "$SDK_STAMP"
fi

cd "$PROJECT"
cargo build --target "$RUST_TARGET" --release "${BUILD_FEATURES[@]}"

# Recovery artifacts are architecture-specific. Keeping a single shared
# filename made it possible to build classic ESP32 and then accidentally hand
# that image to an ESP32-C6 flasher. The deployment helper selects the same
# family directory from its probed chip identity.
IMAGE_DIR="$TARGET_DIR/flash/$IDF_TARGET_NAME"
mkdir -p "$IMAGE_DIR"
ELF="$TARGET_DIR/$RUST_TARGET/release/dmesh-recovery-rs"
BOOT="$TARGET_DIR/$RUST_TARGET/release/bootloader.bin"
PARTITION_TABLE="$TARGET_DIR/$RUST_TARGET/release/partition-table.bin"
APP_IMAGE="$IMAGE_DIR/dmesh-recovery-rs-app.bin"
# esptool is used here only to turn the ELF into a flash image and package the
# build artifacts. It never opens a serial port or flashes a board.
FLASH_SIZE="4MB"
if [[ "$IDF_TARGET_NAME" == "esp32s3" ]]; then
    FLASH_SIZE="8MB"
fi
"$DMESH_PYTHON" -m esptool --chip "$CHIP" elf2image \
    --flash_mode dio --flash_freq 40m --flash_size "$FLASH_SIZE" \
    --output "$APP_IMAGE" "$ELF"
"$DMESH_PYTHON" -m esptool --chip "$CHIP" merge_bin \
    --output "$IMAGE_DIR/dmesh-recovery-rs-merged.bin" \
    "$BOOT_OFFSET" "$BOOT" 0x8000 "$PARTITION_TABLE" 0x10000 "$APP_IMAGE"

app_size="$(stat -c '%s' "$APP_IMAGE")"
printf 'Rust Recovery app bytes: %s (0x%x)\n' "$app_size" "$app_size"
printf 'Rust Recovery target: %s (%s)\n' "$RUST_TARGET" "$CHIP"
printf 'Rust Recovery ELF: %s\n' "$TARGET_DIR/$RUST_TARGET/release/dmesh-recovery-rs"
printf 'Rust Recovery image: %s\n' "$IMAGE_DIR/dmesh-recovery-rs-merged.bin"
