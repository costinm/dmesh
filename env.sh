# Source from the DMesh repository root before Cargo, Nix, Android, or firmware
# commands. All mutable build state stays under target/.

if [ -n "${BASH_SOURCE:-}" ]; then
    _dmesh_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _dmesh_env_dir="$(pwd)"
fi

export DMESH_REPO="${DMESH_REPO:-${_dmesh_env_dir}}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${DMESH_REPO}/target/cache}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-${DMESH_REPO}/target/config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-${DMESH_REPO}/target/share}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-${DMESH_REPO}/target/state}"
export CARGO_HOME="${DMESH_CARGO_HOME:-${DMESH_REPO}/target/cargo}"
export RUSTUP_HOME="${DMESH_RUSTUP_HOME:-${DMESH_REPO}/target/rustup}"
# SDK 6 is the repository default.  Do not inherit an old SDK environment
# from the parent shell: that was the source of commands needing `env -u`
# during the migration.  An alternate SDK is an explicit exception.
export DMESH_ESP_ROOT="${DMESH_ESP_ROOT_OVERRIDE:-${DMESH_REPO}/target/esp32-6.0}"
export DMESH_BOOT_RECOVERY_SDK_VERSION="v6.0.2"
export DMESH_BOOT_RECOVERY_ESP_ROOT="${DMESH_BOOT_RECOVERY_ESP_ROOT_OVERRIDE:-${DMESH_REPO}/target/esp32-6.0}"
export CARGO_TARGET_DIR="${DMESH_CARGO_TARGET_DIR:-${DMESH_REPO}/target}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-${DMESH_REPO}/target/gradle}"
export TMPDIR="${TMPDIR:-${DMESH_REPO}/target/tmp}"
export NIX_PROFILE="${DMESH_NIX_PROFILE:-${DMESH_REPO}/target/nix/profile}"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"
# Android tooling is repository-local too.  Keep platform-tools available to
# interactive callers after sourcing env.sh, not only inside build-android.sh.
# Do not set or replace HOME here: ADB must use the caller's normal trust-key
# location, while DMesh-specific build state stays in the XDG/target paths.
export ANDROID_HOME="${ANDROID_HOME:-${DMESH_REPO}/target/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME}}"

# Keep the default catalog and the lab lmesh endpoint in one sourced place;
# callers may override either for another component.
export MESH_TOOLS="${MESH_TOOLS:-${DMESH_REPO}/crates/lmesh/resources/tools.json}"
# Service names such as `lmesh` resolve through mesh-init definitions. This is
# runtime discovery, not a build input; deployments can supply another catalog.
export MESH_SERVICE_DIR="${MESH_SERVICE_DIR:-/home/system/etc/mesh-init}"
export LMESH_CONTROL_SOCKET="${LMESH_CONTROL_SOCKET:-/run/mesh/lmesh/mesh.sock}"
export DMESH_LMESH_CONTROL_ENDPOINT="${DMESH_LMESH_CONTROL_ENDPOINT:-unix://${LMESH_CONTROL_SOCKET}}"
# NAN gateway routing is experimental/WIP and disabled by default. The
# role-to-device map is retained only for isolated gateway experiments.
# NAN gateway routing is experimental/WIP and disabled by default.
export LMESH_ESP_GATEWAY="${LMESH_ESP_GATEWAY:-}"
export LMESH_ESP_TARGETS="${LMESH_ESP_TARGETS:-lora2=1d4c5e1d,lora3=8e0742c5,lora4=f6fc543d,e5=fcf5c40ef1e8}"

# DMesh consumes the generic mesh/ssh crates from a sibling checkout when it
# is available. This is discovery only: an explicitly supplied path wins.
if [ -z "${DMESH_SSH_MESH_DIR:-}" ]; then
    for _dmesh_ssh_candidate in "$DMESH_REPO/../rust/ssh-mesh" "$DMESH_REPO/../ssh-mesh"; do
        if [ -f "$_dmesh_ssh_candidate/crates/mesh-cli/Cargo.toml" ]; then
            export DMESH_SSH_MESH_DIR="$_dmesh_ssh_candidate"
            break
        fi
    done
fi

# Python mesh tools are part of the sibling ssh-mesh checkout.  Make them
# available to checked-in DMesh scripts without every caller spelling out a
# PYTHONPATH export.  Deployments without that checkout can still provide an
# explicit SSH_MESH_PYTHON.
if [ -z "${SSH_MESH_PYTHON:-}" ] && [ -n "${DMESH_SSH_MESH_DIR:-}" ] \
    && [ -d "$DMESH_SSH_MESH_DIR/python" ]; then
    export SSH_MESH_PYTHON="$DMESH_SSH_MESH_DIR/python"
fi
if [ -n "${SSH_MESH_PYTHON:-}" ]; then
    export PYTHONPATH="$SSH_MESH_PYTHON${PYTHONPATH:+:$PYTHONPATH}"
fi

# `mesh` is owned and built by the ssh-mesh checkout. DMesh selects it through
# PATH; there is no separate binary override that can select a stale copy.
_dmesh_ssh_mesh_release="${DMESH_SSH_MESH_DIR:-${DMESH_REPO}/../rust/ssh-mesh}/target/x86_64-unknown-linux-musl/release"
if [ -d "$_dmesh_ssh_mesh_release" ]; then
    _dmesh_ssh_mesh_release="$(cd "$_dmesh_ssh_mesh_release" && pwd -P)"
fi

mkdir -p "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" \
    "$XDG_STATE_HOME" "$CARGO_HOME" "$RUSTUP_HOME" "$GRADLE_USER_HOME" "$TMPDIR" \
    "$(dirname "$NIX_PROFILE")"

if [ -d "$NIX_PROFILE/bin" ]; then
    # The repo profile contains a BusyBox compatibility `timeout`.  Keep the
    # profile tools available, but let GNU coreutils provide the normal shell
    # utilities (notably `timeout`, whose `--foreground` behaviour is needed
    # by the test harness).
    export PATH="/usr/bin:/bin:$NIX_PROFILE/bin:$PATH"
fi
export PATH="$CARGO_HOME/bin:$PATH"
if [ -d "$ANDROID_HOME/platform-tools" ]; then
    export PATH="$ANDROID_HOME/platform-tools:$PATH"
fi
if [ -d "$ANDROID_HOME/emulator" ]; then
    export PATH="$ANDROID_HOME/emulator:$PATH"
fi

# Some ssh-mesh service environments prepend their BusyBox runtime bundle.
# It is not a DMesh build toolchain and causes ordinary commands such as
# `find`, `ps`, and `sed` to silently use the reduced BusyBox implementations.
# Keep the actual ssh-mesh release directory below; remove only this runtime
# bundle from the inherited PATH.
_dmesh_path_clean=""
_dmesh_old_ifs="$IFS"
IFS=:
for _dmesh_path_entry in $PATH; do
    [ "$_dmesh_path_entry" = "/opt/ssh-mesh/bin" ] && continue
    if [ -n "$_dmesh_path_clean" ]; then
        _dmesh_path_clean="$_dmesh_path_clean:$_dmesh_path_entry"
    else
        _dmesh_path_clean="$_dmesh_path_entry"
    fi
done
IFS="$_dmesh_old_ifs"
export PATH="$_dmesh_path_clean"

# Firmware dependencies and toolchains are repo-local too. Source the
# generated ESP-IDF environment once here so normal shells do not need a
# second firmware-specific env script. Restore DMesh Cargo locations after it:
# ESP tooling is selected by RUST_ESP_TOOLCHAIN_BIN/PATH, while all Cargo cache
# and build state remains under the one top-level target/ directory.
# Clear SDK-owned variables first so a previously sourced SDK cannot leak into
# this invocation when its generated env fragment is absent or incomplete.
unset IDF_PATH IDF_TOOLS_PATH IDF_PYTHON_ENV_PATH RUST_ESP_TOOLCHAIN_BIN \
    ESP_PYTHON DMESH_PYTHON
if [ -f "$DMESH_ESP_ROOT/env.sh" ]; then
    _dmesh_cargo_home="$CARGO_HOME"
    _dmesh_rustup_home="$RUSTUP_HOME"
    # The generated activation script is part of the environment contract and
    # must be silent when successful. Do not hide output here: a banner or
    # warning means the generated SDK environment needs fixing, not that every
    # caller should redirect it.
    . "$DMESH_ESP_ROOT/env.sh"
    export CARGO_HOME="$_dmesh_cargo_home"
    export RUSTUP_HOME="$_dmesh_rustup_home"
fi
if [ -n "${RUST_ESP_TOOLCHAIN_BIN:-}" ] && [ -d "$RUST_ESP_TOOLCHAIN_BIN" ]; then
    export PATH="$RUST_ESP_TOOLCHAIN_BIN:$PATH"
fi
# ESP-IDF's component manager is installed in its managed virtual environment.
# The Nix profile also provides Python, but it intentionally lacks ESP-IDF
# modules, so firmware CMake must resolve this interpreter first.
if [ -n "${IDF_PYTHON_ENV_PATH:-}" ] && [ -x "$IDF_PYTHON_ENV_PATH/bin/python" ]; then
    export PATH="$IDF_PYTHON_ENV_PATH/bin:$PATH"
    export PYTHON="$IDF_PYTHON_ENV_PATH/bin/python"
fi
# Firmware scripts use one explicit interpreter for esptool, pyserial, and
# the Recovery TCP helpers.  Source env.sh instead of rediscovering it in each
# script.
if [ -z "${DMESH_PYTHON:-}" ] && [ -n "${IDF_PYTHON_ENV_PATH:-}" ] \
    && [ -x "$IDF_PYTHON_ENV_PATH/bin/python" ]; then
    export DMESH_PYTHON="$IDF_PYTHON_ENV_PATH/bin/python"
fi
export DMESH_FW_TOOLS="${DMESH_FW_TOOLS:-$DMESH_REPO/fw/esp32/rust/tools}"
export PYTHONPATH="$DMESH_REPO${PYTHONPATH:+:$PYTHONPATH}"

# Defaults for the Wi-Fi flash control plane.  Scripts can be read and run
# without repeating the AP/server details; override these for another lab.
export DMESH_FLASH_SERVER="${DMESH_FLASH_SERVER:-10.78.0.1}"
export DMESH_FLASH_PORT="${DMESH_FLASH_PORT:-3336}"
export DMESH_FLASH_DEVICE_IP="${DMESH_FLASH_DEVICE_IP:-10.78.84.60}"
export DMESH_FLASH_LOG="${DMESH_FLASH_LOG:-$DMESH_REPO/target/recovery-server/all-${DMESH_FLASH_PORT}.log}"
export DMESH_TIMING_DIR="${DMESH_TIMING_DIR:-$DMESH_REPO/target/evidence}"

# `mesh` is an ssh-mesh artifact. The directory may not exist until the first
# build; keeping it first on PATH lets the same sourced shell use it afterwards.
export PATH="$_dmesh_ssh_mesh_release:$PATH"

# Cargo's rustup proxy must find the matching rustc before the Nix profile's
# host-only rustc, otherwise cross-target standard libraries are ignored.
_dmesh_rust_bin="$RUSTUP_HOME/toolchains/stable-x86_64-unknown-linux-gnu/bin"
if [ -d "$_dmesh_rust_bin" ]; then
    export PATH="$_dmesh_rust_bin:$PATH"
fi

unset _dmesh_env_dir
unset _dmesh_rust_bin
unset _dmesh_ssh_candidate
unset _dmesh_ssh_mesh_release
unset _dmesh_cargo_home
unset _dmesh_rustup_home
unset _dmesh_path_clean
unset _dmesh_old_ifs
unset _dmesh_path_entry
export DMESH_ENV_LOADED=1
