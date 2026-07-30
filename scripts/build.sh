#!/bin/bash
# Build DMesh Linux MUSL binaries and manage the repo-local Nix profile.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"
cd "$DMESH_REPO"

profile="${DMESH_NIX_PROFILE:-$DMESH_REPO/target/nix/profile}"
ssh_mesh_url="${SSH_MESH_GIT_URL:-https://github.com/costinm/ssh-mesh}"

ensure_rust_toolchain() {
    local rustup_bin="$profile/bin/rustup"

    if ! "$rustup_bin" toolchain list | grep -q '^stable-'; then
        "$rustup_bin" toolchain install stable --profile minimal
    fi
    if ! "$rustup_bin" target list --installed | grep -qx 'x86_64-unknown-linux-musl'; then
        "$rustup_bin" target add x86_64-unknown-linux-musl
    fi
    export PATH="$RUSTUP_HOME/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
}

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
    # `install` leaves an already-present local flake entry unchanged.  Refresh
    # it so edits to flake.nix (new tools or toolchain revisions) take effect.
    nix profile upgrade --profile "$profile" --all
    ensure_rust_toolchain
}

configure_musl() {
    local linker
    linker="$profile/bin/x86_64-unknown-linux-musl-gcc"
    if [ ! -x "$linker" ]; then
        linker="$(command -v x86_64-unknown-linux-musl-gcc || true)"
    fi
    if [ -z "$linker" ]; then
        echo "Missing MUSL toolchain; run scripts/build.sh deps" >&2
        return 1
    fi
    export CC_x86_64_unknown_linux_musl="$linker"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$linker"
}

musl() {
    ensure_rust_toolchain
    configure_ssh_mesh_override
    configure_musl
    # Android JNI/UI crates are libraries, not Linux MUSL binaries. Build the
    # device services and terminal UI explicitly so NativeActivity backends
    # are not pulled into the static Linux artifact set.
    cargo build --release --target x86_64-unknown-linux-musl \
        -p lmesh \
        -p mesh-tun \
        -p dmeshtui

    # `mesh` is the generic client from ssh-mesh, not an lmesh-specific
    # wrapper. Let Cargo retain the artifact under ssh-mesh/target, beside its
    # source workspace; DMesh only supplies the generated lmesh catalog.
    local ssh_mesh_dir="${DMESH_SSH_MESH_DIR:-}"
    if [ -z "$ssh_mesh_dir" ]; then
        for candidate in "$DMESH_REPO/../rust/ssh-mesh" "$DMESH_REPO/../ssh-mesh"; do
            if [ -f "$candidate/crates/mesh-cli/Cargo.toml" ]; then
                ssh_mesh_dir="$candidate"
                break
            fi
        done
    fi
    if [ -z "$ssh_mesh_dir" ] || [ ! -f "$ssh_mesh_dir/crates/mesh-cli/Cargo.toml" ]; then
        echo "Missing ssh-mesh mesh-cli source; set DMESH_SSH_MESH_DIR" >&2
        return 1
    fi
    cargo build --manifest-path "$ssh_mesh_dir/Cargo.toml" \
        --release --target x86_64-unknown-linux-musl -p mesh-cli
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
