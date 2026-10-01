# Source from the repository root before starting Codex or running repo scripts.
# It keeps Codex auth/config in the real home while moving general tool state
# into repo-local target/ paths.

if [ -n "${BASH_SOURCE:-}" ]; then
    _env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    _env_dir="$(pwd)"
fi

# This checkout owns its build/cache roots. Do not inherit another project's
# REPO_ROOT when env.sh is sourced from a parent shell.
export REPO_ROOT="${_env_dir}"
export REAL_HOME="${REAL_HOME:-${HOME:-}}"

_ssh_mesh_target_base="${REPO_ROOT}/target"
_ssh_mesh_cache_base="${REAL_HOME:-${HOME:-/tmp}}/.cache/ws/ssh-mesh"
_ssh_mesh_cargo_target_dir="${REPO_ROOT}/target"

# Auto-detect shared VirtioFS / Android FUSE storage mounts (/storage/emulated, /mnt, etc.)
# and automatically create and redirect build caches/targets to native ext4 filesystem under ~/.cache.
if [ -d "$_ssh_mesh_cache_base" ]; then
    _ssh_mesh_target_base="$_ssh_mesh_cache_base"
    _ssh_mesh_cargo_target_dir="$_ssh_mesh_cache_base/target"
elif [[ "$REPO_ROOT" == /storage/* || "$REPO_ROOT" == /mnt/* ]]; then
    mkdir -p "$_ssh_mesh_cache_base" 2>/dev/null || true
    if [ -d "$_ssh_mesh_cache_base" ]; then
        _ssh_mesh_target_base="$_ssh_mesh_cache_base"
        _ssh_mesh_cargo_target_dir="$_ssh_mesh_cache_base/target"
    fi
fi

export HOME="${SSH_MESH_LOCAL_HOME:-${_ssh_mesh_target_base}/home}"
export CODEX_HOME="${CODEX_HOME:-${REAL_HOME}/.codex}"

export XDG_CACHE_HOME="${SSH_MESH_XDG_CACHE_HOME:-${_ssh_mesh_target_base}/cache}"
export XDG_CONFIG_HOME="${SSH_MESH_XDG_CONFIG_HOME:-${_ssh_mesh_target_base}/config}"
export XDG_DATA_HOME="${SSH_MESH_XDG_DATA_HOME:-${_ssh_mesh_target_base}/share}"
export XDG_STATE_HOME="${SSH_MESH_XDG_STATE_HOME:-${_ssh_mesh_target_base}/state}"

export NIX_PROFILE="${SSH_MESH_NIX_PROFILE:-${_ssh_mesh_target_base}/nix/profile}"
export NIX_CONFIG="${NIX_CONFIG:-experimental-features = nix-command flakes}"

export MESH_HOME="${SSH_MESH_MESH_HOME:-${_ssh_mesh_target_base}/mesh}"
export SSH_MESH_STATE_ROOT="${SSH_MESH_STATE_ROOT:-${_ssh_mesh_target_base}/ssh-mesh-state}"
export TMPDIR="${SSH_MESH_TMPDIR:-${_ssh_mesh_target_base}/tmp}"

export CARGO_TARGET_DIR="${SSH_MESH_CARGO_TARGET_DIR:-${_ssh_mesh_cargo_target_dir}}"
export CARGO_HOME="${SSH_MESH_CARGO_HOME:-${_ssh_mesh_target_base}/cargo}"
export RUSTUP_HOME="${SSH_MESH_RUSTUP_HOME:-${_ssh_mesh_target_base}/rustup}"

mkdir -p \
    "${HOME}" \
    "${XDG_CACHE_HOME}" \
    "${XDG_CONFIG_HOME}" \
    "${XDG_DATA_HOME}" \
    "${XDG_STATE_HOME}" \
    "${TMPDIR}" \
    "${MESH_HOME}" \
    "${SSH_MESH_STATE_ROOT}" \
    "$(dirname "${NIX_PROFILE}")" \
    "${CARGO_TARGET_DIR}" \
    "${CARGO_HOME}" \
    "${RUSTUP_HOME}"

_path_prepend() {
    if [ -d "$1" ]; then
        case ":${PATH:-}:" in
            *":$1:"*) ;;
            *) PATH="$1:${PATH:-}" ;;
        esac
    fi
}

_path_force_prepend() {
    if [ -d "$1" ]; then
        PATH="$1:${PATH:-}"
    fi
}

_path_prepend "/nix/var/nix/profiles/default/bin"
_path_prepend "${NIX_PROFILE}/bin"
_path_prepend "${CARGO_HOME}/bin"
_path_prepend "${CARGO_TARGET_DIR}/x86_64-unknown-linux-musl/release"
export PATH

_path_force_prepend "/nix/var/nix/profiles/default/bin"
_path_force_prepend "${NIX_PROFILE}/bin"
_path_force_prepend "${CARGO_HOME}/bin"
_path_force_prepend "${CARGO_TARGET_DIR}/x86_64-unknown-linux-musl/release"
export PATH

unset _env_dir
unset -f _path_prepend
unset -f _path_force_prepend
