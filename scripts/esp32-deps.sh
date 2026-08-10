#!/usr/bin/env bash
# Install ESP-IDF, Rust ESP, and host tools exclusively under target/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ESP_ROOT="${ESP_ROOT:-${REPO_ROOT}/target/esp32-6.0}"
PROFILE="${DMESH_ESP32_NIX_PROFILE:-${REPO_ROOT}/target/nix/esp32-profile}"
readonly ESP_IDF_VERSION="v6.0.2"
ESP_IDF_GIT_JOBS="${ESP_IDF_GIT_JOBS:-8}"

usage() {
    cat >&2 <<'EOF'
usage: scripts/esp32-deps.sh [--root PATH] [--profile PATH]

Install one repo-local ESP-IDF/Rust-ESP toolchain. Examples:
  scripts/esp32-deps.sh
  scripts/esp32-deps.sh --root target/esp32-6.0
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --root) [[ $# -ge 2 ]] || { usage; exit 2; }; ESP_ROOT="$2"; shift 2 ;;
        --profile) [[ $# -ge 2 ]] || { usage; exit 2; }; PROFILE="$2"; shift 2 ;;
        -h|--help) usage >&1; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ "$ESP_ROOT" != /* ]]; then
    ESP_ROOT="$REPO_ROOT/$ESP_ROOT"
fi
ESP_IDF_PYTHON_ENV_VERSION="${ESP_IDF_VERSION#v}"
ESP_IDF_PYTHON_ENV_VERSION="${ESP_IDF_PYTHON_ENV_VERSION%.*}"

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
if command -v nix >/dev/null 2>&1; then
    nix profile install --profile "$PROFILE" "path:${REPO_ROOT}/fw/esp32#esp32-deps"
elif [[ -x "$PROFILE/bin/espup" && -x "$PROFILE/bin/python" &&
        -x "$PROFILE/bin/cmake" && -x "$PROFILE/bin/ninja" ]]; then
    # Some build containers expose the already-populated Nix profile but not
    # the nix client itself. Reusing that immutable profile is reproducible;
    # a missing profile remains an error rather than falling back to host
    # packages.
    echo "nix client unavailable; using existing complete profile $PROFILE" >&2
else
    echo "nix is unavailable and the required profile is incomplete: $PROFILE" >&2
    exit 127
fi
export PATH="$PROFILE/bin:$CARGO_HOME/bin:$PATH"

if [ ! -d "$ESP_ROOT/esp-idf/.git" ]; then
    git clone --branch "$ESP_IDF_VERSION" --depth 1 --recursive \
        --jobs "$ESP_IDF_GIT_JOBS" \
        https://github.com/espressif/esp-idf.git "$ESP_ROOT/esp-idf"
else
    # Complete interrupted/partial checkouts deterministically. This also
    # makes rerunning the downloader safe after a transient submodule failure.
    git -C "$ESP_ROOT/esp-idf" checkout --force "$ESP_IDF_VERSION"
    git -C "$ESP_ROOT/esp-idf" submodule sync --recursive
    git -C "$ESP_ROOT/esp-idf" submodule update --init --recursive \
        --force --jobs "$ESP_IDF_GIT_JOBS"
fi

IDF_TOOLS_PATH="$IDF_TOOLS_PATH" "$ESP_ROOT/esp-idf/install.sh" esp32,esp32s3,esp32c6
HOME="$ESP_HOME" espup install --targets esp32,esp32s3,esp32c6 --export-file "$ESP_ROOT/export-esp.sh"

IDF_PYTHON_ENV_PATH="$IDF_TOOLS_PATH/python_env/idf${ESP_IDF_PYTHON_ENV_VERSION}_py3.13_env"

cat >"$ESP_ROOT/env.sh" <<EOF
export REPO_ROOT="$REPO_ROOT"
export ESP_ROOT="$ESP_ROOT"
export IDF_PATH="$ESP_ROOT/esp-idf"
export IDF_TOOLS_PATH="$IDF_TOOLS_PATH"
export IDF_PYTHON_ENV_PATH="$IDF_TOOLS_PATH/python_env/idf${ESP_IDF_PYTHON_ENV_VERSION}_py3.13_env"
export DMESH_PYTHON="$IDF_PYTHON_ENV_PATH/bin/python"
export PYTHON="$IDF_PYTHON_ENV_PATH/bin/python"
export CARGO_HOME="$CARGO_HOME"
export RUSTUP_HOME="$RUSTUP_HOME"
export RUST_ESP_TOOLCHAIN_BIN="$RUSTUP_HOME/toolchains/esp/bin"
export PATH="$PROFILE/bin:$RUSTUP_HOME/toolchains/esp/bin:$CARGO_HOME/bin:\$PATH"
if [ -f "$ESP_ROOT/export-esp.sh" ]; then
    . "$ESP_ROOT/export-esp.sh"
fi
# ESP-IDF's exporter prints an interactive banner on stdout even when the
# environment is valid.  The generated repo-local env is a machine-facing
# shell fragment, so keep it silent; installation diagnostics remain in this
# dependency script itself.
if [ -f "$ESP_ROOT/esp-idf/export.sh" ]; then
    . "$ESP_ROOT/esp-idf/export.sh" >/dev/null 2>&1
fi
export PATH="$PROFILE/bin:$RUSTUP_HOME/toolchains/esp/bin:$CARGO_HOME/bin:\$PATH"
EOF

echo "ESP32 dependencies are ready. Load with: . env.sh"
