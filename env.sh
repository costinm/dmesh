# Source from the DMesh repository root before Cargo, Nix, Android, or firmware
# commands. All mutable build state stays under target/.

if [ -n "${BASH_SOURCE:-}" ]; then
    _dmesh_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _dmesh_env_dir="$(pwd)"
fi

export DMESH_REPO="${DMESH_REPO:-${_dmesh_env_dir}}"
export HOME="${DMESH_LOCAL_HOME:-${DMESH_REPO}/target/home}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${DMESH_REPO}/target/cache}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-${DMESH_REPO}/target/config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-${DMESH_REPO}/target/share}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-${DMESH_REPO}/target/state}"
export CARGO_HOME="${DMESH_CARGO_HOME:-${DMESH_REPO}/target/cargo}"
export RUSTUP_HOME="${DMESH_RUSTUP_HOME:-${DMESH_REPO}/target/rustup}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-${DMESH_REPO}/target/gradle}"
export TMPDIR="${TMPDIR:-${DMESH_REPO}/target/tmp}"
export NIX_PROFILE="${DMESH_NIX_PROFILE:-${DMESH_REPO}/target/nix/profile}"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"

mkdir -p "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" \
    "$XDG_STATE_HOME" "$CARGO_HOME" "$RUSTUP_HOME" "$GRADLE_USER_HOME" "$TMPDIR" \
    "$(dirname "$NIX_PROFILE")"

if [ -d "$NIX_PROFILE/bin" ]; then
    export PATH="$NIX_PROFILE/bin:$PATH"
fi
export PATH="$CARGO_HOME/bin:$PATH"

unset _dmesh_env_dir
