#!/usr/bin/env bash
# start_bwrap.sh - start mesh-init inside a read-mostly bwrap sandbox, then
# run a command in the same namespace once the mesh-init control socket is up.
#
# Production- and test-oriented: components run from a staged package tree
# (target/dist/opt after scripts/build.sh, or `result-sshm` from a nix
# build); /run, /home and /tmp are fresh tmpfs. When the mesh-init control
# socket appears, the requested command runs and the sandbox exits.
#
# Usage:
#   scripts/start_bwrap.sh [options] -- CMD [ARG...]
#
# Everything after `--` runs inside the sandbox once mesh-init is ready; no
# extra quoting/escaping of the command is needed. With no --app-dir, --bin
# or --mesh-init-config the script picks the first runtime it finds under
# SSH_MESH_TEST_BIN, target/x86_64-unknown-linux-musl/release,
# target/dist/opt and /opt.
#
# Options:
#   --app-dir DIR          application package tree, mounted read-only at
#                          /opt/ssh-mesh. bin/ provides the binaries at
#                          /opt/ssh-mesh/bin, and etc/mesh-init (when
#                          present) is mounted at /run/mesh-init-etc as
#                          MESH_INIT_DIR: copy service configs or binaries
#                          into this tree before the run.
#   --bin DIR              directory with the release binaries (ssh-mesh,
#                          mesh-init, mesh). Defaults to the --app-dir
#                          tree, else the discovered runtime. Mounted
#                          read-only at /opt/ssh-mesh/bin.
#   --opt-dir DIR          staged opt tree mounted read-only at /opt (adds
#                          /opt/busybox); optional.
#   --mount SRC:DST[:ro]   extra bind mount, repeatable, for per-app assets
#                          and state paths.
#   --mesh-init-config DIR directory of mesh-init service toml files, bind
#                          mounted at /run/mesh-init-etc with MESH_INIT_DIR
#                          set there. Without it mesh-init starts with the
#                          default (seeded) config of the app tree.
#   --user UID[:GID]       run the payload as UID:GID; needs util-linux
#                          /usr/bin/unshare --map-auto (subuid namespace).
#                          Without it the sandbox runs as mapped root
#                          (bwrap --unshare-user).
#   --no-wait              do not wait for the mesh-init control socket.
#
# Environment: RUST_LOG, MESH_INIT_SOCK (default
# /run/mesh/mesh-init/mesh.sock), SSH_PORT, HTTP_PORT, plus whatever the
# command needs. All are propagated into the sandbox.
set -euo pipefail

app_dir=""
bin_dir=""
opt_dir=""
mesh_init_config=""
user_spec=""
do_wait="yes"
extra_mount_args=()

MESH_INIT_SOCK="${MESH_INIT_SOCK:-/run/mesh/mesh-init/mesh.sock}"
MESH_INIT_CONFIG_DIR_IN_NS="${MESH_INIT_CONFIG_DIR_IN_NS:-/run/mesh-init-etc}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app-dir) app_dir="$2"; shift 2 ;;
    --bin) bin_dir="$2"; shift 2 ;;
    --opt-dir) opt_dir="$2"; shift 2 ;;
    --mesh-init-config) mesh_init_config="$2"; shift 2 ;;
    --user) user_spec="$2"; shift 2 ;;
    --no-wait) do_wait="no"; shift ;;
    --mount) extra_mount_args+=("$2"); shift 2 ;;
    --)
      shift
      break
      ;;
    -h|--help|help)
      awk '
        /^# / { sub(/^# /, ""); print }
      ' "$0"
      exit 0
      ;;
    *)
      printf 'start_bwrap.sh: unknown argument %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [ "$#" -eq 0 ]; then
  printf 'start_bwrap.sh: nothing to --exec\n' >&2
  exit 2
fi
exec_args=("$@")

# Resolve the application tree first: it provides the default bin dir and
# the mesh-init service config dir. The order is SSH_MESH_TEST_BIN, the
# cargo release tree of this repo, the staged dist tree from
# scripts/build.sh, then the installed /opt/ssh-mesh package.
if [ -z "${app_dir}" ]; then
  for candidate in \
    "${SSH_MESH_TEST_BIN:-}" \
    "${REPO_ROOT}/target/x86_64-unknown-linux-musl/release" \
    "${REPO_ROOT}/target/dist/opt/ssh-mesh" \
    /opt/ssh-mesh \
    ; do
    if [ -n "${candidate}" ] && [ -x "${candidate}/bin/mesh-init" ]; then
      app_dir="$(readlink -f "${candidate}")"
      break
    fi
  done
  [ -n "${app_dir}" ] || {
    printf 'start_bwrap.sh: no application tree found; run scripts/build.sh or pass --app-dir\n' >&2
    exit 1
  }
fi
app_dir="$(readlink -f "${app_dir}")"

if [ -z "${bin_dir}" ]; then
  bin_dir="${app_dir}/bin"
  if [ ! -x "${bin_dir}/mesh-init" ] && [ -x "${app_dir}/mesh-init" ]; then
    # The cargo release tree holds the binaries at the top level.
    bin_dir="${app_dir}"
  fi
fi
if [ -z "${mesh_init_config}" ] && [ -d "${app_dir}/etc/mesh-init" ]; then
  mesh_init_config="${app_dir}/etc/mesh-init"
fi

if [ ! -x "${bin_dir}/mesh-init" ]; then
  printf 'start_bwrap.sh: %s does not contain mesh-init (use --bin)\n' "${bin_dir}" >&2
  exit 1
fi

if [ -n "${user_spec}" ] && [ ! -x /usr/bin/unshare ]; then
  printf 'start_bwrap.sh: --user requires /usr/bin/unshare --map-auto\n' >&2
  exit 1
fi

bin_dir="$(readlink -f "${bin_dir}")"
[ -n "${opt_dir}" ] && opt_dir="$(readlink -f "${opt_dir}")"
[ -n "${mesh_init_config}" ] && mesh_init_config="$(readlink -f "${mesh_init_config}")"

# Host-side scratch: everything under target/tmp (never /tmp), fresh per run.
runtime_root="${TMPDIR:-${REPO_ROOT:-/tmp}/target/tmp}"
mkdir -p "${runtime_root}"
scratch_dir="$(mktemp -d "${runtime_root}/ssh-mesh-start-bwrap.XXXXXX")"
trap 'rm -rf "${scratch_dir:-}"' EXIT

cat > "${scratch_dir}/entry.sh" <<'ENTRY'
#!/usr/bin/env bash
# Inner PID 1: start mesh-init, wait for the control socket, exec CMD.
set -euo pipefail

export PATH="/opt/ssh-mesh/bin:/usr/bin:/bin"

mesh-init &
mesh_init_pid=$!
trap 'kill "${mesh_init_pid}" 2>/dev/null || true' EXIT

for _ in $(seq 1 200); do
  [ -S "${MESH_INIT_SOCK}" ] && break
  kill -0 "${mesh_init_pid}" 2>/dev/null || {
    printf 'start_bwrap.sh: mesh-init exited before %s appeared\n' "${MESH_INIT_SOCK}" >&2
    exit 1
  }
  sleep 0.25
done

[ -S "${MESH_INIT_SOCK}" ] || {
  printf 'start_bwrap.sh: mesh-init control socket never appeared: %s\n' "${MESH_INIT_SOCK}" >&2
  exit 1
}

if [ "${START_BWRAP_DO_WAIT:-yes}" != "no" ]; then
  # Run the payload, then take mesh-init down so the PID 1 exits and the
  # sandbox unwinds with the payload's exit status.
  "$@" &
  payload_pid=$!
  wait "${payload_pid}"
  payload_status=$?
  kill "${mesh_init_pid}" 2>/dev/null || true
  exit "${payload_status}"
else
  "$@" &
  payload_pid=$!
  set +e
  wait "${payload_pid}"
  payload_status=$?
  set -e
  kill "${mesh_init_pid}" 2>/dev/null || true
  exit "${payload_status}"
fi
ENTRY

chmod 755 "${scratch_dir}/entry.sh"

# 1. Base mounts: bin dirs, device/proc, fresh tmpfs. Identical layout every
#    run; the staged bin dir lands at /opt/ssh-mesh/bin, and the payload root
#    dir at /opt (for /opt/busybox) when --opt-dir was passed.
bwrap_args=(
  --ro-bind /bin /bin
  --ro-bind /usr /usr
  --ro-bind /lib /lib
  --ro-bind-try /lib64 /lib64
  --ro-bind /etc /etc
  $(if [ "${bin_dir}" = "${app_dir}" ]; then
       printf -- '--ro-bind %s /opt/ssh-mesh/bin' "${bin_dir}"
     else
       printf -- '--ro-bind %s /opt/ssh-mesh' "${app_dir}"
     fi)
  --dev /dev
  --proc /proc
  --tmpfs /tmp
  --tmpfs /home
  --tmpfs /run
  --dir /run/mesh
  --bind "${scratch_dir}" /run/start-bwrap
)

# 2. Staged opt tree (build.sh outcome), if the caller mounted one.
if [ -n "${opt_dir}" ]; then
  if [ -d "${opt_dir}" ]; then
    bwrap_args+=(--ro-bind "${opt_dir}" /opt)
  else
    printf 'start_bwrap.sh: --opt-dir %s missing\n' "${opt_dir}" >&2
    exit 1
  fi
fi

# 3. Additional per-component mounts; DST defaults to rw.
for mount_arg in "${extra_mount_args[@]:-}"; do
  [ -n "${mount_arg}" ] || continue
  mount_src="${mount_arg%%:*}"
  mount_rest="${mount_arg#*:}"
  case "${mount_rest}" in
    *:ro)
      bwrap_args+=(--ro-bind "${mount_src}" "${mount_rest%:*}")
      ;;
    *)
      bwrap_args+=(--bind "${mount_src}" "${mount_rest}")
      ;;
  esac
done

# 4. Environment passed into the sandbox.
env_args=(
  --setenv PATH "/opt/ssh-mesh/bin:/usr/bin:/bin"
  --setenv RUST_LOG "${RUST_LOG:-info}"
  --setenv MESH_INIT_SOCK "${MESH_INIT_SOCK}"
  --setenv START_BWRAP_DO_WAIT "${do_wait}"
)
if [ -n "${SSH_PORT:-}" ]; then
  env_args+=(--setenv SSH_PORT "${SSH_PORT}")
fi
if [ -n "${HTTP_PORT:-}" ]; then
  env_args+=(--setenv HTTP_PORT "${HTTP_PORT}")
fi

# 4b. mesh-init config dir: mount the caller's staging directory read-only and
#    point MESH_INIT_DIR there. Defaults to the app tree's etc/mesh-init.
if [ -n "${mesh_init_config}" ]; then
  if [ -d "${mesh_init_config}" ]; then
    bwrap_args+=(--ro-bind "${mesh_init_config}" "${MESH_INIT_CONFIG_DIR_IN_NS}")
    env_args+=(--setenv MESH_INIT_DIR "${MESH_INIT_CONFIG_DIR_IN_NS}")
  else
    printf 'start_bwrap.sh: --mesh-init-config %s is not a directory\n' "${mesh_init_config}" >&2
    exit 1
  fi
fi

# 5. Payload identity: mapped root (bwrap --unshare-user) unless --user.
if [ -n "${user_spec}" ]; then
  user_uid="${user_spec%%:*}"
  user_gid="${user_spec##*:}"
  [ -n "${user_gid}" ] || user_gid="${user_uid}"
else
  user_uid=""
  user_gid=""
  bwrap_args+=(--unshare-user --uid 0 --gid 0)
fi

# Launch. Root runs the entry directly; subuid namespaces run through the
# util-linux unshare wrapper.
if [ "${user_spec:-}" != "" ]; then
  /usr/bin/unshare \
    --user \
    --map-auto \
    --propagation private \
    --pid \
    --fork \
    --kill-child \
    --setuid 0 \
    --setgid 0 \
    --mount-proc \
    -- \
    bwrap "${bwrap_args[@]}" \
      "${env_args[@]:-}" \
      --setenv START_BWRAP_UID "${user_uid}" \
      /bin/bash /run/start-bwrap/entry.sh \
      setpriv --reuid "${user_uid}" --regid "${user_gid}" --clear-groups \
      -- \
      "${exec_args[@]}"
else
  bwrap "${bwrap_args[@]}" \
    "${env_args[@]}" \
    /bin/bash /run/start-bwrap/entry.sh \
    "${exec_args[@]}"
fi
