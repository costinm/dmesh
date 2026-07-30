# Source this file from the repo root or fw/esp32 after running scripts/esp32-deps.sh.
if [ -n "${BASH_SOURCE:-}" ]; then
    _fw_esp32_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _fw_esp32_env_dir="$(pwd)"
fi

export REPO_ROOT="${REPO_ROOT:-$(cd "${_fw_esp32_env_dir}/../.." && pwd)}"

if [ -f "${REPO_ROOT}/target/esp32-5.5/env.sh" ]; then
    . "${REPO_ROOT}/target/esp32-5.5/env.sh"
else
    export ESP_ROOT="${REPO_ROOT}/target/esp32-5.5"
    export IDF_PATH="${ESP_ROOT}/esp-idf"
    export IDF_TOOLS_PATH="${ESP_ROOT}/espressif"
    export CARGO_HOME="${ESP_ROOT}/cargo"
    export RUSTUP_HOME="${ESP_ROOT}/rustup"
    export RUST_ESP_TOOLCHAIN_BIN="${RUSTUP_HOME}/toolchains/esp/bin"
    unset IDF_PYTHON_ENV_PATH
fi

# esp-idf-sys discovers Python through PATH when configuring CMake.  The
# generated environment deliberately restores the Nix profile at the front,
# but that Python does not contain ESP-IDF's component-manager module.  Keep
# the IDF virtualenv first while retaining every tool path supplied by Nix.
if [ -n "${IDF_PYTHON_ENV_PATH:-}" ] && [ -x "${IDF_PYTHON_ENV_PATH}/bin/python" ]; then
    export PATH="${IDF_PYTHON_ENV_PATH}/bin:${PATH}"
fi

unset _fw_esp32_env_dir
