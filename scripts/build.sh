#!/bin/bash
# Build DMesh Linux MUSL binaries and manage the repo-local Nix profile.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"
cd "$DMESH_REPO"

profile="${DMESH_NIX_PROFILE:-$DMESH_REPO/target/nix/profile}"
ssh_mesh_url="${SSH_MESH_GIT_URL:-https://github.com/costinm/ssh-mesh}"

resolve_cargo() {
    local cargo_bin

    cargo_bin="$(command -v cargo || true)"
    if [ -z "$cargo_bin" ]; then
        echo "Missing Cargo in the DMesh environment; run scripts/build.sh deps" >&2
        return 1
    fi
    printf '%s\n' "$cargo_bin"
}

DMESH_CARGO_BIN="$(resolve_cargo 2>/dev/null || true)"

require_dmesh_cargo() {
    if [ -z "$DMESH_CARGO_BIN" ]; then
        DMESH_CARGO_BIN="$(resolve_cargo)"
    fi
}

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
    require_dmesh_cargo
    ensure_rust_toolchain
    configure_ssh_mesh_override
    configure_musl
    # Android JNI/UI crates are libraries, not Linux MUSL binaries. Build the
    # device services and terminal UI explicitly so NativeActivity backends
    # are not pulled into the static Linux artifact set.
    "$DMESH_CARGO_BIN" build --release --target x86_64-unknown-linux-musl \
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
    (
        cd "$ssh_mesh_dir"
        # ssh-mesh owns its target directory, Cargo cache, and tool selection.
        # Do not let the DMesh environment make this sibling build write into
        # target/ or use a DMesh-local Cargo cache.
        if [ -f ./env.sh ]; then
            . ./env.sh
        fi
        local ssh_mesh_cargo
        ssh_mesh_cargo="$(command -v cargo || true)"
        if [ -z "$ssh_mesh_cargo" ]; then
            echo "Missing Cargo in the ssh-mesh environment" >&2
            exit 1
        fi
        "$ssh_mesh_cargo" build --release --target x86_64-unknown-linux-musl -p mesh-cli
    )
}

check() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" check --workspace
}

lmesh_check() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" check -p lmesh
}

lmesh_test() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p lmesh
}

object_store_test() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p dmesh-object-store
}

recovery_test() {
    PYTHONPATH="$DMESH_REPO/fw/recovery/tools" "$DMESH_PYTHON" \
        "$DMESH_REPO/scripts/test_recovery_protocol.py"
}

object_store_udp() {
    shift || true
    require_dmesh_cargo
    configure_ssh_mesh_override
    DMESH_UDP_SERVER_PORT="${DMESH_UDP_SERVER_PORT:-3336}" \
    DMESH_UDP_SERVER_BIND="${DMESH_UDP_SERVER_BIND:-0.0.0.0}" \
    DMESH_OBJECT_STORE_ROOT="${DMESH_OBJECT_STORE_ROOT:-$DMESH_REPO/target/flash}" \
        "$DMESH_CARGO_BIN" run -p dmesh-object-store --bin udp-server -- "$@"
}

object_store_udp_status() {
    shift || true
    require_dmesh_cargo
    configure_ssh_mesh_override
    DMESH_UDP_STATUS_PORT="${DMESH_UDP_STATUS_PORT:-3338}" \
    DMESH_UDP_STATUS_BIND="${DMESH_UDP_STATUS_BIND:-0.0.0.0}" \
        "$DMESH_CARGO_BIN" run -p dmesh-object-store --bin udp-status-server -- "$@"
}

lmesh_restart() {
    local binary="$DMESH_REPO/target/x86_64-unknown-linux-musl/release/lmesh"
    local old=""
    local new=""
    if [ ! -x "$binary" ]; then
        echo "Missing lmesh binary; run scripts/build.sh musl" >&2
        return 1
    fi
    old="$(pgrep -n -f "^$binary$" || true)"
    if [ -n "$old" ]; then
        kill -TERM "$old"
    fi
    for _ in $(seq 1 30); do
        new="$(pgrep -n -f "^$binary$" || true)"
        if [ -n "$new" ] && [ "$new" != "$old" ]; then
            echo "lmesh restarted pid=$new"
            return 0
        fi
        sleep 1
    done
    echo "lmesh did not restart after pid=${old:-none}" >&2
    return 1
}

case "${1:-musl}" in
    deps) deps ;;
    musl) musl ;;
    check) check ;;
    lmesh-check) lmesh_check ;;
    lmesh-test) lmesh_test ;;
    object-store-test) object_store_test ;;
    object-store-udp) object_store_udp "$@" ;;
    object-store-udp-status) object_store_udp_status "$@" ;;
    lmesh-restart) lmesh_restart ;;
    recovery-test) recovery_test ;;
    *) echo "Usage: scripts/build.sh {deps|musl|check|lmesh-check|lmesh-test|object-store-test|object-store-udp|object-store-udp-status|lmesh-restart|recovery-test}" >&2; exit 2 ;;
esac
