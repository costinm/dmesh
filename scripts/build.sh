#!/bin/bash
# Build DMesh Linux MUSL binaries and manage the repo-local Nix profile.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/env.sh"
cd "$DMESH_REPO"

profile="${NIX_PROFILE:-${DMESH_NIX_PROFILE:-$DMESH_REPO/target/nix/profile}}"
ssh_mesh_url="${SSH_MESH_GIT_URL:-https://github.com/costinm/ssh-mesh}"
CARGO_LOCK_BACKUP=""

# A local ssh-mesh patch can make Cargo select path packages and rewrite the
# checked-in lockfile.  That selection is an operator-local build input, not a
# source change; leaving it behind makes the next firmware or Android command
# rebuild for a lockfile change it did not request.
restore_cargo_lock() {
    if [ -n "${CARGO_LOCK_BACKUP:-}" ] && [ -f "$CARGO_LOCK_BACKUP" ]; then
        if ! cmp -s "$CARGO_LOCK_BACKUP" "$DMESH_REPO/Cargo.lock"; then
            # Preserve the original lockfile timestamp as well as its bytes:
            # Cargo fingerprints the lockfile and a restore must not look like
            # a dependency-graph change to the next target build.
            cp -p "$CARGO_LOCK_BACKUP" "$DMESH_REPO/Cargo.lock"
        fi
        rm -f "$CARGO_LOCK_BACKUP"
        CARGO_LOCK_BACKUP=""
    fi
}

preserve_cargo_lock_for_override() {
    if [ "${SSH_MESH_OVERRIDE_ACTIVE:-0}" != "1" ] || [ ! -f "$DMESH_REPO/Cargo.lock" ]; then
        return
    fi
    CARGO_LOCK_BACKUP="$CARGO_HOME/Cargo.lock.before-ssh-mesh-override"
    cp -p "$DMESH_REPO/Cargo.lock" "$CARGO_LOCK_BACKUP"
    trap restore_cargo_lock EXIT
}

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
    if [ ! -x "$rustup_bin" ]; then
        rustup_bin="$(command -v rustup || true)"
    fi
    if [ -z "$rustup_bin" ]; then
        echo "Missing rustup; run scripts/build.sh deps or install rustup" >&2
        return 1
    fi

    if ! "$rustup_bin" toolchain list | grep -q '^stable-'; then
        "$rustup_bin" toolchain install stable --profile minimal
    fi
    if ! "$rustup_bin" target list --installed | grep -qx 'x86_64-unknown-linux-musl'; then
        "$rustup_bin" target add x86_64-unknown-linux-musl
    fi
    if [ -d "$RUSTUP_HOME/toolchains/stable-x86_64-unknown-linux-gnu/bin" ]; then
        export PATH="$RUSTUP_HOME/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
    fi
}

configure_ssh_mesh_override() {
    SSH_MESH_OVERRIDE_ACTIVE=0
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
    SSH_MESH_OVERRIDE_ACTIVE=1
}

check_lmesh_api() {
    local ssh_mesh_dir="${DMESH_SSH_MESH_DIR:-}"
    if [ -z "$ssh_mesh_dir" ]; then
        for candidate in "$DMESH_REPO/../rust/ssh-mesh" "$DMESH_REPO/../ssh-mesh"; do
            if [ -f "$candidate/crates/mesh-api-gen/Cargo.toml" ]; then
                ssh_mesh_dir="$candidate"
                break
            fi
        done
    fi
    if [ -z "$ssh_mesh_dir" ] || [ ! -f "$ssh_mesh_dir/crates/mesh-api-gen/Cargo.toml" ]; then
        echo "Missing ssh-mesh mesh-api-gen source; set DMESH_SSH_MESH_DIR" >&2
        return 1
    fi
    (
        cd "$ssh_mesh_dir"
        # The generator is owned by this sibling checkout; keep its Cargo
        # cache and target policy separate from DMesh just like mesh-cli.
        unset CARGO_TARGET_DIR
        if [ -f ./env.sh ]; then
            . ./env.sh
        fi
        local generated
        generated="$(mktemp)"
        cargo run -p mesh-api-gen -- \
            --api "$DMESH_REPO/crates/dmesh-server/API.md" \
            --out-tools "$generated"
        # The versioned firmware schema is the runtime catalog authority.
        # API.md documents a reviewed subset, so check that every generated
        # wire name and numeric tag agrees with that schema instead of
        # overwriting the composed lmesh catalog (which also carries local
        # controller operations).
        jq -e --slurpfile schema "$DMESH_REPO/crates/lmesh/resources/firmware-schema.json" '
            all(.[]; . as $tool |
                any($schema[0].methods[];
                    .name == $tool.name and
                    .component == $tool["x-component-index"] and
                    .id == $tool["x-method-index"]))
        ' "$generated" >/dev/null
        rm -f "$generated"
    )
}

# Generated tagged-CBOR request types are reviewed from API.md and checked in.
# Keep generation behind the repository harness so contributors never need to
# invoke the sibling mesh-api-gen Cargo project by hand.
lmesh_api_generate() {
    local ssh_mesh_dir="${DMESH_SSH_MESH_DIR:-}"
    if [ -z "$ssh_mesh_dir" ]; then
        for candidate in "$DMESH_REPO/../rust/ssh-mesh" "$DMESH_REPO/../ssh-mesh"; do
            if [ -f "$candidate/crates/mesh-api-gen/Cargo.toml" ]; then
                ssh_mesh_dir="$candidate"
                break
            fi
        done
    fi
    if [ -z "$ssh_mesh_dir" ] || [ ! -f "$ssh_mesh_dir/crates/mesh-api-gen/Cargo.toml" ]; then
        echo "Missing ssh-mesh mesh-api-gen source; set DMESH_SSH_MESH_DIR" >&2
        return 1
    fi
    (
        cd "$ssh_mesh_dir"
        unset CARGO_TARGET_DIR
        if [ -f ./env.sh ]; then . ./env.sh; fi
        local generated
        generated="$(mktemp)"
        cargo run -p mesh-api-gen -- \
            --api "$DMESH_REPO/crates/dmesh-server/API.md" \
            --out-tools "$generated"
        # `firmware-schema.json` is the checked-in catalog source.  This
        # command validates the API projection; it must never replace that
        # schema with a partial generated list.
        jq -e --slurpfile schema "$DMESH_REPO/crates/lmesh/resources/firmware-schema.json" '
            all(.[]; . as $tool |
                any($schema[0].methods[];
                    .name == $tool.name and
                    .component == $tool["x-component-index"] and
                    .id == $tool["x-method-index"]))
        ' "$generated" >/dev/null
        echo "lmesh API projection matches firmware-schema.json; no catalog file rewritten"
        rm -f "$generated"
    )
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
    preserve_cargo_lock_for_override
    configure_musl
    # Android JNI/UI crates are libraries, not Linux MUSL binaries. Build the
    # device services and terminal UI explicitly so NativeActivity backends
    # are not pulled into the static Linux artifact set.
    "$DMESH_CARGO_BIN" build --release --target x86_64-unknown-linux-musl \
        -p lmesh \
        -p lmesh-wifi \
        -p dmesh-cli \
        -p mesh-tun \
        -p dmeshtui

    # Keep mesh-init service homes uniform: /home/<service> is provisioned as
    # a symlink to target/home/<service> during development.
    for service in lmesh lmesh-wifi; do
        mkdir -p "$DMESH_REPO/target/home/$service/bin"
        ln -sfn \
            "$DMESH_REPO/target/x86_64-unknown-linux-musl/release/$service" \
            "$DMESH_REPO/target/home/$service/bin/$service"
    done

    # `mesh` and `mesh-init` are owned by ssh-mesh. Let its checked-in build
    # wrapper retain both artifacts under ssh-mesh/target; DMesh only supplies
    # the generated lmesh catalog.
    local ssh_mesh_dir="${DMESH_SSH_MESH_DIR:-}"
    if [ -z "$ssh_mesh_dir" ]; then
        for candidate in "$DMESH_REPO/../rust/ssh-mesh" "$DMESH_REPO/../ssh-mesh"; do
            if [ -x "$candidate/scripts/build.sh" ]; then
                ssh_mesh_dir="$candidate"
                break
            fi
        done
    fi
    if [ -z "$ssh_mesh_dir" ] || [ ! -x "$ssh_mesh_dir/scripts/build.sh" ]; then
        echo "Missing ssh-mesh build source; set DMESH_SSH_MESH_DIR" >&2
        return 1
    fi
    "$ssh_mesh_dir/scripts/build.sh" rust mesh-cli
    "$ssh_mesh_dir/scripts/build.sh" rust mesh-init
    restore_cargo_lock
    trap - EXIT
}

check() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" check --workspace
}

lmesh_check() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    # The UDS control loop lives in the lmesh binary, not its library. Keep
    # the local gate from falsely passing after only checking shared helpers.
    "$DMESH_CARGO_BIN" check -p lmesh --all-targets
    "$DMESH_CARGO_BIN" check -p lmesh-wifi --all-targets
    check_lmesh_api
}

lmesh_test() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p lmesh
    "$DMESH_CARGO_BIN" test -p lmesh-wifi --bin lmesh-wifi
    "$DMESH_CARGO_BIN" test -p lmesh-wifi
    check_lmesh_api
}

# Only dmesh-cli may own a physical board UART. Keep this as a dependency
# gate, rather than trusting that retired forwarding code stays unused at
# runtime: lmesh and lmesh-wifi must not regain the old client or codec.
check_host_uart_ownership() {
    for package in lmesh lmesh-wifi; do
        if "$DMESH_CARGO_BIN" tree -p "$package" -e normal | grep -Eq '(^| )((dmesh-cli|lmesh-uart|uart-codec) v)'; then
            echo "$package must not link a host UART owner or codec; dmesh-cli owns direct UART sessions" >&2
            return 1
        fi
    done
}

lmesh_control_test() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p lmesh --bin lmesh
    "$DMESH_CARGO_BIN" test -p lmesh-wifi --bin lmesh-wifi
    "$DMESH_CARGO_BIN" test -p lmesh-wifi json_rpc_gateway_flattens_params_for_existing_handlers --lib
    check_host_uart_ownership
    "$DMESH_CARGO_BIN" test -p dmesh-cli --test firmware_e2e host_control_
    check_lmesh_api
}

object_store_test() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p dmesh-server
}

transport_test() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p quic-lite
    "$DMESH_CARGO_BIN" test -p dmesh-server --features udp --lib
    "$DMESH_CARGO_BIN" test -p dmesh-server --features udp --test object_store_stream
}

# Hardware E2E stays behind the repository build harness so operators never
# need to invoke Cargo directly. The selected test owns the configured serial
# endpoints exclusively; the generic default is the NAN-first pair prober.
firmware_e2e() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    local test_name="${DMESH_E2E_TEST:-firmware_pair_prober}"
    "$DMESH_CARGO_BIN" test -p dmesh-cli --test firmware_e2e "$test_name" \
        -- --ignored --nocapture --test-threads=1
}

transport_coverage() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    local llvm_cov_version
    llvm_cov_version="$($DMESH_CARGO_BIN llvm-cov --version 2>/dev/null || true)"
    if [ "$llvm_cov_version" != "cargo-llvm-cov 0.8.7" ]; then
        echo "Requires cargo-llvm-cov 0.8.7 in the development environment" >&2
        return 2
    fi
    mkdir -p "$DMESH_REPO/target/coverage"
    "$DMESH_CARGO_BIN" llvm-cov test -p quic-lite --no-default-features \
        --lcov --output-path "$DMESH_REPO/target/coverage/quic-lite-core.lcov"
    "$DMESH_CARGO_BIN" llvm-cov test -p dmesh-server --features udp \
        --lcov --output-path "$DMESH_REPO/target/coverage/dmesh-server-udp.lcov"
    # Keep the crate-wide gates executable in CI. Module/scenario coverage is
    # reviewed from the emitted LCOV and the protocol matrix; these totals are
    # the non-negotiable backstop against silently losing broad coverage.
    "$DMESH_CARGO_BIN" llvm-cov report -p quic-lite \
        --fail-under-lines 80 \
        --fail-under-regions 85
}

transport_fuzz_smoke() {
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p quic-lite --features std
}

transport_loopback() {
    shift || true
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p quic-lite memory_stream_stress \
        -- --ignored --nocapture --test-threads=1 "$@"
}

transport_tcp_loopback() {
    shift || true
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p dmesh-server tcp_memory_stream_64m_baseline \
        -- --ignored --nocapture --test-threads=1 "$@"
}

transport_compare() {
    shift || true
    local bytes="${DMESH_STREAM_BYTES:-67108864}"
    DMESH_STREAM_BYTES="$bytes" transport_loopback
    DMESH_STREAM_BYTES="$bytes" transport_tcp_loopback
}

object_store_tcp_loopback() {
    shift || true
    require_dmesh_cargo
    configure_ssh_mesh_override
    "$DMESH_CARGO_BIN" test -p dmesh-server tcp_16m_baseline \
        -- --ignored --nocapture --test-threads=1 "$@"
}

lmesh_restart() {
    restart_managed_service lmesh
}

lmesh_wifi_restart() {
    restart_managed_service lmesh-wifi
}


target_triple() {
    case "$1" in
        arm64-v8a) echo "aarch64-linux-android" ;;
        armeabi-v7a) echo "armv7-linux-androideabi" ;;
        x86) echo "i686-linux-android" ;;
        x86_64) echo "x86_64-linux-android" ;;
        *)
            echo "ERROR: unsupported Android ABI: $1" >&2
            exit 1
            ;;
    esac
}

detect_android_env() {
    if [ -f "$profile/bin/dmesh-setenv" ]; then
        . "$profile/bin/dmesh-setenv"
    elif command -v dmesh-setenv >/dev/null 2>&1; then
        . "$(command -v dmesh-setenv)"
    elif [ -d "$profile/bin" ]; then
        export PATH="$profile/bin:$PATH"
    fi

    if [ -z "${ANDROID_HOME:-}" ]; then
        echo "ERROR: ANDROID_HOME is unset. Run scripts/build-android.sh deps, then source env.sh." >&2
        exit 1
    fi

    if [ -z "${ANDROID_NDK_HOME:-}" ]; then
        local ndk_dir
        ndk_dir=$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -1 || true)
        if [ -z "$ndk_dir" ]; then
            echo "ERROR: No Android NDK found under $ANDROID_HOME/ndk." >&2
            exit 1
        fi
        export ANDROID_NDK_HOME="$ndk_dir"
    fi
}

copy_android_lib() {
    local crate_name="$1"
    local lib_name="$2"
    local android_build_type="$3"
    local abi="$4"
    local triple
    triple="$(target_triple "$abi")"

    local rust_profile="release"
    local target_dir="${CARGO_TARGET_DIR:-$DMESH_REPO/target}"
    local so_path="$target_dir/$triple/$rust_profile/lib$lib_name.so"
    if [ ! -f "$so_path" ]; then
        echo "ERROR: Built library not found at $so_path" >&2
        exit 1
    fi

    local strip_libs="${DMESH_STRIP_ANDROID_LIBS:-}"
    if [ -z "$strip_libs" ]; then
        if [ "$android_build_type" = "release" ]; then
            strip_libs=1
        else
            strip_libs=0
        fi
    fi

    local strip_bin=""
    if [ "$strip_libs" = "1" ]; then
        strip_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
        if [ ! -x "$strip_bin" ]; then
            echo "ERROR: Android llvm-strip not found at $strip_bin" >&2
            exit 1
        fi
    fi

    local app
    for app in ${DMESH_JNILIB_APPS:-app-dmesh}; do
        local jnilib_dir="$DMESH_REPO/android/$app/src/main/jniLibs/$abi"
        local jnilib_so="$jnilib_dir/lib$lib_name.so"
        mkdir -p "$jnilib_dir"
        cp -f "$so_path" "$jnilib_so"
        local copied_size
        copied_size="$(stat -c%s "$jnilib_so")"
        if [ "$strip_libs" = "1" ]; then
            "$strip_bin" --strip-unneeded "$jnilib_so"
            local stripped_size
            stripped_size="$(stat -c%s "$jnilib_so")"
            echo "Copied $crate_name (rust $rust_profile, android $android_build_type) to: $jnilib_so"
            echo "Stripped $jnilib_so: $copied_size -> $stripped_size bytes"
        else
            echo "Copied $crate_name (rust $rust_profile, android $android_build_type, unstripped) to: $jnilib_so ($copied_size bytes)"
        fi
    done
}

clean_android_lib_outputs() {
    local lib_name="$1"
    local app
    for app in ${DMESH_JNILIB_APPS:-app-dmesh}; do
        local jnilib_dir="$DMESH_REPO/android/$app/src/main/jniLibs"
        if [ -d "$jnilib_dir" ]; then
            find "$jnilib_dir" -name "lib$lib_name.so" -type f -delete
        fi
    done
}

clean_app_dmesh_dmeshui() {
    local jnilib_dir="$DMESH_REPO/android/app-dmesh/src/main/jniLibs"
    if [ -d "$jnilib_dir" ]; then
        find "$jnilib_dir" -name 'libdmeshui.so' -type f -delete
    fi
}

copy_dmeshui_android_lib() {
    local requested_apps="${DMESH_UI_APPS:-app-chat}"
    local ui_apps=""
    local app

    for app in $requested_apps; do
        if [ "$app" = "app-dmesh" ]; then
            echo "Skipping dmeshui copy to app-dmesh; dmeshui is owned by app-chat."
            continue
        fi
        ui_apps="$ui_apps $app"
    done

    clean_app_dmesh_dmeshui
    if [ -z "${ui_apps// /}" ]; then
        ui_apps=" app-chat"
    fi

    DMESH_JNILIB_APPS="$ui_apps"         build_rust_android_package dmeshui dmeshui "$1" "$2"
}

build_rust_android_package() {
    local package="$1"
    local lib_name="$2"
    local android_build_type="$3"
    local abi_list="$4"
    local cargo_args=(build -p "$package" --lib --release)

    if [ "$android_build_type" != "debug" ] && [ "$android_build_type" != "release" ]; then
        echo "Usage: $0 android-libs [debug|release]" >&2
        exit 1
    fi

    clean_android_lib_outputs "$lib_name"
    for abi in $abi_list; do
        echo "=== Building $package for $abi (rust release, android $android_build_type) ==="
        cargo ndk -t "$abi" -P 28 "${cargo_args[@]}"
        copy_android_lib "$package" "$lib_name" "$android_build_type" "$abi"
    done
}

build_android_libs() {
    local build_type="${1:-debug}"
    detect_android_env
    ensure_rust_toolchain
    require_dmesh_cargo

    local rustup_bin="$profile/bin/rustup"
    if [ ! -x "$rustup_bin" ]; then
        rustup_bin="$(command -v rustup || true)"
    fi
    if [ -n "$rustup_bin" ]; then
        for target in aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android; do
            if ! "$rustup_bin" target list --installed | grep -qx "$target"; then
                "$rustup_bin" target add "$target"
            fi
        done
    fi

    echo "Using NDK: $ANDROID_NDK_HOME"
    echo "Using SDK: $ANDROID_HOME"
    echo ""
    configure_ssh_mesh_override
    clean_app_dmesh_dmeshui
    build_rust_android_package dmesh dmesh "$build_type" "${DMESH_ANDROID_ABIS:-arm64-v8a}"
    copy_dmeshui_android_lib "$build_type" "${DMESH_UI_ANDROID_ABIS:-arm64-v8a}"
    clean_app_dmesh_dmeshui
}

restart_managed_service() {
    local service="$1"
    local binary="$DMESH_REPO/target/x86_64-unknown-linux-musl/release/$service"
    local old=""
    local new=""
    if [ ! -x "$binary" ]; then
        echo "Missing $service binary; run scripts/build.sh musl" >&2
        return 1
    fi
    old="$(pgrep -n -x "$service" || true)"
    if [ -n "$old" ]; then
        kill -TERM "$old"
    fi
    for _ in $(seq 1 30); do
        new="$(pgrep -n -x "$service" || true)"
        if [ -n "$new" ] && [ "$new" != "$old" ]; then
            echo "$service restarted pid=$new"
            return 0
        fi
        sleep 1
    done
    echo "$service did not restart after pid=${old:-none}" >&2
    return 1
}

case "${1:-musl}" in
    deps) deps ;;
    musl) musl ;;
    check) check ;;
    lmesh-check) lmesh_check ;;
    lmesh-test) lmesh_test ;;
    lmesh-control-test) lmesh_control_test ;;
    lmesh-api-generate) lmesh_api_generate ;;
    object-store-test) object_store_test ;;
    transport-test) transport_test ;;
    firmware-e2e) firmware_e2e ;;
    transport-coverage) transport_coverage ;;
    transport-fuzz-smoke) transport_fuzz_smoke ;;
    transport-loopback) transport_loopback "$@" ;;
    transport-tcp-loopback) transport_tcp_loopback "$@" ;;
    transport-compare) transport_compare "$@" ;;
    object-store-tcp-loopback) object_store_tcp_loopback "$@" ;;
    lmesh-restart) lmesh_restart ;;
    lmesh-wifi-restart) lmesh_wifi_restart ;;
    android-libs|android-native) shift; build_android_libs "${1:-debug}" ;;
    *) echo "Usage: scripts/build.sh {deps|musl|android-libs|check|lmesh-check|lmesh-test|lmesh-control-test|lmesh-api-generate|object-store-test|transport-test|firmware-e2e|transport-coverage|transport-fuzz-smoke|transport-loopback|transport-tcp-loopback|transport-compare|object-store-tcp-loopback|lmesh-restart|lmesh-wifi-restart}" >&2; exit 2 ;;
esac
