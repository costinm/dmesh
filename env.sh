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

# Keep the default catalog and the lab lmesh endpoint in one sourced place;
# callers may override either for another component.
export MESH_TOOLS="${MESH_TOOLS:-${DMESH_REPO}/crates/lmesh/resources/tools.json}"
# Service names such as `lmesh` resolve through mesh-init definitions. This is
# runtime discovery, not a build input; deployments can supply another catalog.
export MESH_SERVICE_DIR="${MESH_SERVICE_DIR:-/home/system/etc/mesh-init}"
export LMESH_CONTROL_SOCKET="${LMESH_CONTROL_SOCKET:-/run/mesh/lmesh/mesh.sock}"
export DMESH_LMESH_CONTROL_ENDPOINT="${DMESH_LMESH_CONTROL_ENDPOINT:-unix://${LMESH_CONTROL_SOCKET}}"

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

# `mesh` is built in its ssh-mesh source workspace (and may later be supplied
# by the repo-local Nix profile). An explicit binary path still wins.
export DMESH_MESH_BIN="${DMESH_MESH_BIN:-${DMESH_SSH_MESH_DIR:-${DMESH_REPO}/../rust/ssh-mesh}/target/x86_64-unknown-linux-musl/release/mesh}"

mkdir -p "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" \
    "$XDG_STATE_HOME" "$CARGO_HOME" "$RUSTUP_HOME" "$GRADLE_USER_HOME" "$TMPDIR" \
    "$(dirname "$NIX_PROFILE")"

if [ -d "$NIX_PROFILE/bin" ]; then
    export PATH="$NIX_PROFILE/bin:$PATH"
fi
export PATH="$CARGO_HOME/bin:$PATH"

# `mesh` is an ssh-mesh artifact. The directory may not exist until the first
# build; keeping it first on PATH lets the same sourced shell use it afterwards.
export PATH="${DMESH_MESH_BIN%/*}:$PATH"

# Cargo's rustup proxy must find the matching rustc before the Nix profile's
# host-only rustc, otherwise cross-target standard libraries are ignored.
_dmesh_rust_bin="$RUSTUP_HOME/toolchains/stable-x86_64-unknown-linux-gnu/bin"
if [ -d "$_dmesh_rust_bin" ]; then
    export PATH="$_dmesh_rust_bin:$PATH"
fi

unset _dmesh_env_dir
unset _dmesh_rust_bin
unset _dmesh_ssh_candidate
