#!/usr/bin/env bash
# Install ESP-IDF, Rust ESP, and host tools exclusively under target/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ESP_ROOT="${ESP_ROOT:-${REPO_ROOT}/target/esp32-5.5}"
PROFILE="${1:-${DMESH_ESP32_NIX_PROFILE:-${REPO_ROOT}/target/nix/esp32-profile}}"
ESP_IDF_VERSION="${ESP_IDF_VERSION:-v5.5.4}"

export HOME="${REPO_ROOT}/target/home"
export XDG_CACHE_HOME="${REPO_ROOT}/target/cache"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"
export IDF_TOOLS_PATH="${ESP_ROOT}/espressif"
export CARGO_HOME="${ESP_ROOT}/cargo"
export RUSTUP_HOME="${ESP_ROOT}/rustup"
export ESP_HOME="${ESP_ROOT}/home"
unset IDF_PYTHON_ENV_PATH
mkdir -p "$ESP_ROOT" "$IDF_TOOLS_PATH" "$CARGO_HOME" "$RUSTUP_HOME" "$ESP_HOME" "$XDG_CACHE_HOME" "$(dirname "$PROFILE")"

echo "Installing ESP32 host tools into Nix profile: $PROFILE"
nix profile install --profile "$PROFILE" "path:${REPO_ROOT}/fw/esp32#esp32-deps"
export PATH="$PROFILE/bin:$CARGO_HOME/bin:$PATH"

if [ ! -d "$ESP_ROOT/esp-idf/.git" ]; then
    git clone --branch "$ESP_IDF_VERSION" --depth 1 --recursive \
        https://github.com/espressif/esp-idf.git "$ESP_ROOT/esp-idf"
fi

IDF_TOOLS_PATH="$IDF_TOOLS_PATH" "$ESP_ROOT/esp-idf/install.sh" esp32,esp32s3
HOME="$ESP_HOME" espup install --targets esp32,esp32s3 --export-file "$ESP_ROOT/export-esp.sh"

cat >"$ESP_ROOT/env.sh" <<EOF
export REPO_ROOT="$REPO_ROOT"
export ESP_ROOT="$ESP_ROOT"
export IDF_PATH="$ESP_ROOT/esp-idf"
export IDF_TOOLS_PATH="$IDF_TOOLS_PATH"
export CARGO_HOME="$CARGO_HOME"
export RUSTUP_HOME="$RUSTUP_HOME"
export RUST_ESP_TOOLCHAIN_BIN="$RUSTUP_HOME/toolchains/esp/bin"
export PATH="$PROFILE/bin:$RUSTUP_HOME/toolchains/esp/bin:$CARGO_HOME/bin:\$PATH"
[ -f "$ESP_ROOT/export-esp.sh" ] && . "$ESP_ROOT/export-esp.sh"
[ -f "$ESP_ROOT/esp-idf/export.sh" ] && . "$ESP_ROOT/esp-idf/export.sh"
export PATH="$PROFILE/bin:$RUSTUP_HOME/toolchains/esp/bin:$CARGO_HOME/bin:\$PATH"
EOF

echo "ESP32 dependencies are ready. Load with: . fw/esp32/env.sh"
