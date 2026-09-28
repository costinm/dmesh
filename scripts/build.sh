#!/bin/bash

# Keep the Dockerfile in sync

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Keep Cargo, Rustup, HOME, and target selection repository-local.
# shellcheck disable=SC1091
source "${REPO_ROOT}/env.sh"

export CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc 

#RUST_FLAGS="-j 1"

export DEST=${DEST:-/opt/ssh-mesh}

CRATES="mesh-init ssh-mesh mesh mesh-cli mesh9p sftp-server ssh-config"
BIN_TARGETS="h2t meshkeys mesh-init ssh-mesh mesh mesh9p sftp-server ssh-config"
INSTALL_BIN_TARGETS="$BIN_TARGETS"
EXAMPLE_BIN_TARGETS="mesh-init ssh-mesh mesh mesh9p sftp-server h2t meshkeys"

help() {
    cat <<'EOF'
Usage: scripts/build.sh [command] [args...]

Default command:
  scripts/build.sh
      Build Rust musl release binaries and create distributable artifacts under
      target/dist, including target/dist/opt.

  docs/examples/start_all.sh
      Start host1, host2, host3-vm, and activated app environments.

Common commands:
  help                 Show this help.
  rust [PACKAGE]       Build all x86_64 musl release crates, or one package.
  test NAME            Build and run a focused test from tests/test_NAME.sh.
  deps [path]          Add missing build dependencies to the Nix profile.
  deploy_examples      Compatibility alias for dist.
  stage_examples       Compatibility alias for staging target/dist/opt.
  stage_example_tree   Refresh checked-in example files under target/examples.
  dist [path]          Build release binaries into an install-like tree.
  install [path]       Install runtime binaries and scripts. Default: /opt/ssh-mesh.

Note: VM builds (EROFS rootfs, kernel profile, vm-tools) and VM tests are now
      owned by the initos repo (https://github.com/costinm/initos).
      Use 'nix build ./vm#default' there for VM artifacts.

Environment:
  MESH_BUILD_TARGET        Rust target for `rust`; defaults to x86_64-unknown-linux-musl.
  SSH_MESH_BUSYBOX         Busybox path used for staged target/dist/opt/busybox.
  NIX_PROFILE              Nix profile used by examples. Default: target/nix/profile.
EOF
}

copy_runtime_bins() {
    local src="$1"
    local dest="$2"
    shift 2
    local bins="$*"
    local missing=0

    mkdir -p "$dest"
    for bin in $bins; do
        if [ -f "$src/$bin" ]; then
            cp -f "$src/$bin" "$dest/"
            chmod +x "$dest/$bin"
        else
            echo "Missing runtime binary: $src/$bin" >&2
            missing=1
        fi
    done

    return "$missing"
}

find_busybox() {
    local busybox="${1:-}"

    if [ -n "$busybox" ] && [ -x "$busybox" ]; then
        printf '%s\n' "$busybox"
        return 0
    fi
    if [ -n "${NIX_PROFILE:-}" ] && [ -x "${NIX_PROFILE}/opt/busybox/bin/busybox" ]; then
        printf '%s\n' "${NIX_PROFILE}/opt/busybox/bin/busybox"
        return 0
    fi
    if [ -x "$PWD/target/nix/profile/opt/busybox/bin/busybox" ]; then
        printf '%s\n' "$PWD/target/nix/profile/opt/busybox/bin/busybox"
        return 0
    fi
    if command -v busybox >/dev/null 2>&1; then
        command -v busybox
        return 0
    fi
    if [ -x "/usr/bin/busybox" ]; then
        printf '%s\n' "/usr/bin/busybox"
        return 0
    fi

    return 1
}

default_nix_profile() {
    printf '%s\n' "$PWD/target/nix/profile"
}

resolve_nix_profile() {
    local profile_path="${1:-$(default_nix_profile)}"

    if [ -d "$profile_path" ] && [ ! -d "$profile_path/bin" ] && [ -e "$profile_path/profile" ]; then
        profile_path="$profile_path/profile"
    fi

    printf '%s\n' "$profile_path"
}

prepend_nix_profile_path() {
    local profile_path

    profile_path="$(resolve_nix_profile "${1:-$(default_nix_profile)}")"

    if [ -d "$profile_path/bin" ]; then
        case ":${PATH:-}:" in
            *":$profile_path/bin:"*) ;;
            *) export PATH="$profile_path/bin:${PATH:-}" ;;
        esac
    fi
}

prepare_nix_profile_path() {
    local target_profile="$1"

    if [ -d "${target_profile}" ] && [ ! -L "${target_profile}" ]; then
        echo "Removing non-symlink directory at ${target_profile} so Nix can manage the profile..."
        rm -rf "${target_profile}"
    fi
}

configure_musl_toolchain() {
    local profile_path
    local linker
    local ar

    profile_path="$(resolve_nix_profile "${1:-$(default_nix_profile)}")"
    prepend_nix_profile_path "$profile_path"

    linker="$(command -v x86_64-unknown-linux-musl-gcc || true)"
    if [ -z "$linker" ]; then
        linker="$(command -v x86_64-linux-musl-gcc || true)"
    fi
    if [ -z "$linker" ]; then
        echo "Missing x86_64 musl gcc in PATH; run scripts/build.sh deps" >&2
        return 1
    fi

    export CC_x86_64_unknown_linux_musl="$linker"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$linker"

    ar="$(command -v x86_64-unknown-linux-musl-ar || true)"
    if [ -n "$ar" ]; then
        export AR_x86_64_unknown_linux_musl="$ar"
    fi
}

add_nix_profile_deps() {
    local target_profile="${1:-${NIX_PROFILE:-$(default_nix_profile)}}"
    shift || true
    local deps="${*:-build-deps runtime-deps}"
    local dep

    target_profile="$(resolve_nix_profile "$target_profile")"
    prepare_nix_profile_path "$target_profile"

    echo "Adding missing Nix profile dependencies to: ${target_profile}"
    for dep in $deps; do
        if nix profile list --profile "${target_profile}" 2>/dev/null | grep -q "$dep"; then
            echo "  ${dep}: already present"
        else
            echo "  ${dep}: nix profile add .#${dep}"
            nix profile add ".#${dep}" --profile "${target_profile}" || return $?
        fi
    done

    prepend_nix_profile_path "$target_profile"
}

deps() {
    add_nix_profile_deps "$@"
}

add_nix_profile_package() {
    local target_profile="$1"
    local dep="$2"
    local priority="${3:-5}"

    target_profile="$(resolve_nix_profile "$target_profile")"
    prepare_nix_profile_path "$target_profile"

    if nix profile list --profile "${target_profile}" 2>/dev/null | grep -q "$dep"; then
        echo "  ${dep}: already present"
    else
        echo "  ${dep}: nix profile add .#${dep} --priority ${priority}"
        nix profile add ".#${dep}" --profile "${target_profile}" --priority "${priority}" || return $?
    fi
}

ensure_musl_toolchain_profile() {
    local target_profile="${1:-${NIX_PROFILE:-$(default_nix_profile)}}"

    target_profile="$(resolve_nix_profile "$target_profile")"
    prepend_nix_profile_path "$target_profile"
    if ! command -v x86_64-unknown-linux-musl-gcc >/dev/null 2>&1 ||
       ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
        add_nix_profile_deps "$target_profile" musl-toolchain
    fi

    configure_musl_toolchain "$target_profile"
}

install_busybox_tree() {
    local busybox="$1"
    local dest="$2"

    rm -rf "$dest/bin"
    mkdir -p "$dest/bin"
    cp -f "$busybox" "$dest/bin/busybox"
    chmod +x "$dest/bin/busybox"
    (
        cd "$dest/bin"
        for applet in $(./busybox --list); do
            if [ "$applet" != "busybox" ] && [ ! -e "$applet" ]; then
                ln -s busybox "$applet"
            fi
        done
    )
}

stage_opt_tree() {
    local src="$1"
    local opt="$2"
    local busybox="$3"

    rm -rf "$opt/ssh-mesh" "$opt/busybox"
    mkdir -p "$opt/ssh-mesh/bin"

    copy_runtime_bins "$src" "$opt/ssh-mesh/bin" $EXAMPLE_BIN_TARGETS
    cp -f bin/run_bwrap.sh "$opt/ssh-mesh/bin/run_bwrap.sh"
    cp -f bin/run_podman.sh "$opt/ssh-mesh/bin/run_podman.sh"
    chmod +x "$opt/ssh-mesh/bin/"*

    install_busybox_tree "$busybox" "$opt/busybox"
}

stage_examples() {
    local src="${1:-}"
    local root="${2:-$PWD/target/dist}"
    local opt="$root/opt"
    local busybox

    if [ -z "$src" ]; then
        if [ -d "target/x86_64-unknown-linux-musl/release" ]; then
            src="target/x86_64-unknown-linux-musl/release"
        else
            src="target/debug"
        fi
    fi

    if [ ! -d "$src" ]; then
        echo "Example binary source does not exist: $src" >&2
        return 1
    fi

    busybox="$(find_busybox "${SSH_MESH_BUSYBOX:-}")" || {
        echo "Missing required busybox; set SSH_MESH_BUSYBOX=/path/to/busybox" >&2
        return 1
    }

    echo "Staging examples from $src"
    echo "  artifact root: $root"
    echo "  opt root:   $opt"

    mkdir -p "$root"
    stage_opt_tree "$src" "$opt" "$busybox"

    echo "Artifacts staged under $root"
}

stage_example_tree() {
    local root="${1:-$PWD/target/examples}"
    local opt="${2:-$PWD/target/dist/opt}"

    if [ ! -d "docs/examples" ]; then
        echo "Missing docs/examples source tree" >&2
        return 1
    fi
    if [ ! -d "$opt/ssh-mesh/bin" ]; then
        echo "Missing staged /opt tree under $opt; run scripts/build.sh first" >&2
        return 1
    fi

    echo "Refreshing example tree under $root"
    rm -rf "$root"
    mkdir -p "$root" "$root/bin"
    cp -a docs/examples/. "$root/"
    cp -a "$opt/ssh-mesh/bin/." "$root/bin/"
    if [ -x "$opt/busybox/bin/busybox" ]; then
        cp -f "$opt/busybox/bin/busybox" "$root/bin/busybox"
        chmod +x "$root/bin/busybox"
    fi
}

rust() {
    local target="${MESH_BUILD_TARGET:-x86_64-unknown-linux-musl}"
    if [ "$#" -gt 1 ]; then
        echo "Usage: scripts/build.sh rust [PACKAGE]" >&2
        return 2
    fi
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    if [ "$#" -eq 1 ]; then
        echo "Building release package $1 with musl..."
        cargo build --target "$target" --release -p "$1"
    else
        echo "Building release binaries with musl..."
        cargo build --target "$target" --release --workspace
    fi
}

deploy_examples() {
    local src="${1:-target/x86_64-unknown-linux-musl/release}"
    local root="${2:-$PWD/target/dist}"

    stage_examples "$src" "$root"
    stage_example_tree "$PWD/target/examples" "$root/opt"
}

default() {
    rust
    dist "$PWD/target/dist" "target/x86_64-unknown-linux-musl/release"
    stage_example_tree "$PWD/target/examples" "$PWD/target/dist/opt"
}

setup() {
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
}
debug() {
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    cargo build --target x86_64-unknown-linux-musl --workspace

    #_all x86_64-unknown-linux-musl 
}

release() {

    _all x86_64-unknown-linux-musl --release
}

arm() {
    _all aarch64-unknown-linux-musl --release
}

_all() {
    local target=$1
    local mode=$2

    if [ "$target" = "x86_64-unknown-linux-musl" ]; then
        ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    fi
    
    for bin in $CRATES; do
        cargo build ${RUST_FLAGS} --target $target ${mode} -p $bin
    done


    #cargo build --target $target ${mode} -p ssh-mesh
}

# upstream unpfs
unpfs() {
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    cargo install --target x86_64-unknown-linux-musl unpfs
}

push() {
    # Can't push debug builds - the embeded files are loaded from disk.
    release
    scp target/x86_64-unknown-linux-musl/release/{mesh-init,ssh-mesh} a1:/data/INITOS/bin
}

dist() {
    local dest="${1:-$PWD/target/dist}"
    local release_dir="${2:-target/x86_64-unknown-linux-musl/release}"
    local busybox

    if [ ! -x "$release_dir/ssh-mesh" ]; then
        rust
    fi

    busybox="$(find_busybox "${SSH_MESH_BUSYBOX:-}")" || {
        echo "Missing required busybox; set SSH_MESH_BUSYBOX=/path/to/busybox" >&2
        return 1
    }

    echo "Creating dist artifacts under $dest"
    mkdir -p "$dest"
    stage_opt_tree "$release_dir" "$dest/opt" "$busybox"

    echo "Dist completed at $dest"
}

install() {
    local dest="${1:-/opt/ssh-mesh}"
    local release_dir="target/x86_64-unknown-linux-musl/release"
    
    mkdir -p "$dest/bin"

    rust

    echo "Installing runtime binaries to $dest/bin..."
    copy_runtime_bins "$release_dir" "$dest/bin" $BIN_TARGETS
    
    echo "Copying scripts..."
    cp -r bin/* "$dest/bin/"
    chmod +x "$dest/bin/"*

    echo "Install completed at $dest"
}

# Build aarch64 release binaries into a separate dist directory.
arm_release() {
    local dest="${1:-target/dist-aarch64}"
    mkdir -p "$dest/bin" "$dest/lib/arm64-v8a"

    echo "Building aarch64 release (musl) for runtime crates..."
    cargo build --target aarch64-unknown-linux-musl --release --workspace

    echo "Copying aarch64 binaries..."
    for bin in $BIN_TARGETS; do
        if [ -f "target/aarch64-unknown-linux-musl/release/$bin" ]; then
            cp "target/aarch64-unknown-linux-musl/release/$bin" "$dest/bin/"
        fi
    done

    echo "Copying scripts..."
    cp -r bin/* "$dest/bin/"
    chmod +x "$dest/bin/"*

    echo "aarch64 release completed at $dest"
}

# VM EROFS image, kernel profile, and vm-tools commands have moved to the initos repo.
# See https://github.com/costinm/initos — use 'nix build ./vm#default' there for VM artifacts.
# Use 'nix build ./vm#vm-scripts' for vrun and initos-init-vm.

build() {
    # Default NIX_PROFILE target path
    local target_profile="${1:-${NIX_PROFILE:-$(default_nix_profile)}}"
    
    echo "=== 1. Building release binaries with musl ==="
    rust

    echo "=== 2. Creating dist artifacts ==="
    dist "$PWD/target/dist" "target/x86_64-unknown-linux-musl/release"

    echo "=== 3. Refreshing example tree ==="
    stage_example_tree "$PWD/target/examples" "$PWD/target/dist/opt"
}

test_cmd() {
    local name="${1:-}"
    if [ -z "$name" ]; then
        echo "Usage: scripts/build.sh test NAME" >&2
        echo "Known tests: examples, ssh_mesh_activation, trace, cert_terminal_mesh_init, docker" >&2
        echo "Note: VM tests (test_vm_*) have moved to the initos repo." >&2
        return 2
    fi
    shift

    case "$name" in
        examples)
            build
            export PATH="$PWD/target/dist/opt/ssh-mesh/bin:$PWD/target/dist/opt/busybox/bin:${PATH:-}"
            tests/test_examples.sh
            ;;
        ssh_mesh_activation)
            rust
            stage_examples "target/x86_64-unknown-linux-musl/release" "$PWD/target/dist"
            export PATH="$PWD/target/dist/opt/ssh-mesh/bin:$PWD/target/dist/opt/busybox/bin:${PATH:-}"
            tests/test_ssh_mesh_activation.sh
            ;;
        trace)
            rust
            stage_examples "target/x86_64-unknown-linux-musl/release" "$PWD/target/dist"
            export PATH="$PWD/target/dist/opt/ssh-mesh/bin:$PWD/target/dist/opt/busybox/bin:${PATH:-}"
            tests/test_trace.sh "$@"
            ;;
        cert_terminal_mesh_init)
            rust
            stage_examples "target/x86_64-unknown-linux-musl/release" "$PWD/target/dist"
            export PATH="$PWD/target/dist/opt/ssh-mesh/bin:$PWD/target/dist/opt/busybox/bin:${PATH:-}"
            python3 tests/test_cert_terminal_mesh_init.py "$@"
            ;;
        docker)
            rust
            stage_examples "target/x86_64-unknown-linux-musl/release" "$PWD/target/dist"
            export PATH="$PWD/target/dist/opt/ssh-mesh/bin:$PWD/target/dist/opt/busybox/bin:${PATH:-}"
            tests/test_docker.sh "$@"
            ;;
        *)
            echo "Unknown test: $name" >&2
            echo "Run scripts/build.sh test with no NAME to list known tests." >&2
            echo "Note: VM tests (test_vm_*) have moved to the initos repo." >&2
            return 2
            ;;
    esac
}

main() {
    local cmd="${1:-default}"
    if [ "$#" -gt 0 ]; then
        shift
    fi

    case "$cmd" in
        -h|--help|help)
            help
            ;;
        default|rust|deps|deploy_examples|stage_examples|stage_example_tree|setup|debug|release|arm|unpfs|push|dist|install|arm_release|build)
            "$cmd" "$@"
            ;;
        test)
            test_cmd "$@"
            ;;
        *)
            echo "Unknown command: $cmd" >&2
            echo >&2
            help >&2
            return 2
            ;;
    esac
}

main "$@"
