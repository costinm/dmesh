#!/bin/bash
# Build DMesh Linux MUSL binaries and manage the repo-local Nix profile.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"
cd "$DMESH_REPO"

profile="${DMESH_NIX_PROFILE:-$DMESH_REPO/target/nix/profile}"
ssh_mesh_url="${SSH_MESH_GIT_URL:-https://github.com/costinm/ssh-mesh}"

configure_ssh_mesh_override() {
    local override_dir="${DMESH_SSH_MESH_DIR:-}"
    local config="$CARGO_HOME/config.toml"

    if [ -z "$override_dir" ]; then
        for candidate in "$DMESH_REPO/../rust/ssh-mesh" "$DMESH_REPO/../ssh-mesh"; do
            if [ -f "$candidate/crates/ssh-mesh/Cargo.toml" ]; then
                override_dir="$candidate"
                break
            fi
        done
    fi

    if [ -z "$override_dir" ] ||
       [ ! -f "$override_dir/crates/ssh-mesh/Cargo.toml" ] ||
       [ ! -f "$override_dir/crates/mesh/Cargo.toml" ]; then
        return
    fi
    mkdir -p "$CARGO_HOME"
    if [ -f "$config" ]; then
        sed -i '/# BEGIN DMESH SSH_MESH OVERRIDE/,/# END DMESH SSH_MESH OVERRIDE/d' "$config"
    fi
    cat >>"$config" <<EOF
# BEGIN DMESH SSH_MESH OVERRIDE
[patch."$ssh_mesh_url"]
ssh-mesh = { path = "$override_dir/crates/ssh-mesh" }
mesh = { path = "$override_dir/crates/mesh" }
# END DMESH SSH_MESH OVERRIDE
EOF
}

deps() {
    mkdir -p "$(dirname "$profile")"
    nix profile install --profile "$profile" "path:$DMESH_REPO#deps"
}

configure_musl() {
    export PATH="$profile/bin:$PATH"
    local linker
    linker="$(command -v x86_64-unknown-linux-musl-gcc || true)"
    if [ -z "$linker" ]; then
        echo "Missing MUSL toolchain; run scripts/build.sh deps" >&2
        return 1
    fi
    export CC_x86_64_unknown_linux_musl="$linker"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$linker"
}

musl() {
    configure_ssh_mesh_override
    configure_musl
    cargo build --workspace --bins --release --target x86_64-unknown-linux-musl
}

check() {
    configure_ssh_mesh_override
    cargo check --workspace
}

case "${1:-musl}" in
    deps) deps ;;
    musl) musl ;;
    check) check ;;
    *) echo "Usage: scripts/build.sh {deps|musl|check}" >&2; exit 2 ;;
esac
