#!/usr/bin/env bash
# start_podman.sh - the container counterpart of start_bwrap.sh: run mesh-init
# as PID 1 of a container (podman or docker), then run the payload command
# inside the container once the mesh-init control socket is ready.
#
# The container runs from a staged package tree: scripts/build.sh fills
# target/dist/opt/ssh-mesh/bin; `result-sshm/bin` works equally after a nix
# build. When the control socket appears the requested command runs via
# `podman exec` / `docker exec`, and the container is removed.
#
# Usage:
#   scripts/start_podman.sh --bin DIR [--exec CMD [ARG...]] [options]
#
# Options:
#   --bin DIR    required. Directory with the release binaries (ssh-mesh,
#                mesh-init, mesh), mounted read-only at /opt/ssh-mesh/bin.
#                With scripts/build.sh this is target/dist/opt/ssh-mesh/bin;
#                with a nix build pass result-sshm/bin.
#   --engine N   podman (default) or docker.
#   --image REF  image to run, default ssh-mesh-test built the first time by
#                the Dockerfile (target netshoot, which is nicolaka/netshoot
#                plus /opt/ssh-mesh and /home/system).
#   --mount SRC:DST[:ro]
#                extra bind mount, repeatable, for per-app assets and state.
#   --mesh-init-config DIR
#                directory with mesh-init service toml files, mounted
#                read-only at /run/mesh-init-etc with MESH_INIT_DIR set there.
#                Without it mesh-init runs with the packaged defaults
#                (/opt/ssh-mesh/share/mesh-init/defaults, /home/system home).
#   --network N  container network; default host-attached.
#   --no-publish skip publishing the SSH/HTTP ports on the loopback host.
#   --no-wait    do not wait for the mesh-init control socket.
#   --exec CMD   required. Command run inside the container once mesh-init is
#                up (the container's own namespace: SSH_PORT is the container
#                port, /certs etc. resolve inside it).

set -euo pipefail

bin_dir=""
engine="${ENGINE:-podman}"
image=""
mesh_init_config=""
network=""
publish="yes"
do_wait="yes"
extra_mount_args=()

MESH_INIT_SOCK="${MESH_INIT_SOCK:-/run/mesh/mesh-init/mesh.sock}"
MESH_INIT_CONFIG_DIR_IN_NS="${MESH_INIT_CONFIG_DIR_IN_NS:-/run/mesh-init-etc}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)}"
CONTAINER_SSH_PORT="${SSH_PORT:-15022}"
CONTAINER_HTTP_PORT="${HTTP_PORT:-15080}"

bin_dir=""
app_dir=""
image=""
exec_args=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app-dir) app_dir="$2"; shift 2 ;;
    --bin) bin_dir="$2"; shift 2 ;;
    --engine) engine="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    --mesh-init-config) mesh_init_config="$2"; shift 2 ;;
    --mount) extra_mount_args+=("$2"); shift 2 ;;
    --no-publish) publish="no"; shift ;;
    --no-wait) do_wait="no"; shift ;;
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
      printf 'start_podman.sh: unknown argument %s\n' "$1" >&2
      exit 2
      ;;
  esac
done
if [ "$#" -eq 0 ]; then
  printf 'start_podman.sh: nothing to --exec\n' >&2
  exit 2
fi
exec_args=("$@")

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
    printf 'start_podman.sh: no application tree found; run scripts/build.sh or pass --app-dir\n' >&2
    exit 1
  }
fi
app_dir="$(readlink -f "${app_dir}")"
if [ -z "${bin_dir}" ]; then
  bin_dir="${app_dir}/bin"
  if [ ! -x "${bin_dir}/mesh-init" ] && [ -x "${app_dir}/mesh-init" ]; then
    bin_dir="${app_dir}"
  fi
fi
if [ ! -x "${bin_dir}/mesh-init" ]; then
  printf 'start_podman.sh: %s does not contain mesh-init (use --bin)\n' "${bin_dir}" >&2
  exit 1
fi
if [ -z "${mesh_init_config}" ] && [ -d "${app_dir}/etc/mesh-init" ]; then
  mesh_init_config="${app_dir}/etc/mesh-init"
fi
if ! command -v "${engine}" >/dev/null 2>&1; then
  printf 'start_podman.sh: %s is not installed\n' "${engine}" >&2
  exit 1
fi

bin_dir="$(readlink -f "${bin_dir}")"
[ -n "${mesh_init_config}" ] && mesh_init_config="$(readlink -f "${mesh_init_config}")"

# Scratch only under the repo's target/tmp tree (never /tmp).
runtime_root="${TMPDIR:-$PWD/target/tmp}"
mkdir -p "${runtime_root}"
scratch_dir="$(mktemp -d "${runtime_root}/ssh-mesh-start-podman.XXXXXX")"
trap 'rm -rf "${scratch_dir:-}"' EXIT

container_name="ssh-mesh-start-$$"
run_args=()
[ -n "${network}" ] && run_args+=(--network "${network}")
if [ "${publish}" = "yes" ]; then
  if [ -n "${SSH_HOST_PORT:-}" ]; then
    run_args+=(--publish "127.0.0.1:${SSH_HOST_PORT}:${CONTAINER_SSH_PORT}")
  else
    run_args+=(--publish "${CONTAINER_SSH_PORT}")
  fi
  if [ -n "${HTTP_HOST_PORT:-}" ]; then
    run_args+=(--publish "127.0.0.1:${HTTP_HOST_PORT}:${CONTAINER_HTTP_PORT}")
  else
    run_args+=(--publish "${CONTAINER_HTTP_PORT}")
  fi
fi
run_args+=(--volume "${bin_dir}:/opt/ssh-mesh/bin:ro")
for mount_arg in "${extra_mount_args[@]:-}"; do
  [ -n "${mount_arg}" ] || continue
  src="${mount_arg%%:*}"
  dst="${mount_arg#*:}"
  mode="rw"
  case "${dst}" in
    *:ro)
      dst="${dst%:ro}"
      mode="ro"
      ;;
  esac
  run_args+=(--volume "${src}:${dst}:${mode},rslave")
done
if [ -n "${mesh_init_config}" ]; then
  run_args+=(--volume "${mesh_init_config}:${MESH_INIT_CONFIG_DIR_IN_NS}:ro,rslave")
fi

image_name="${image:-ssh-mesh-test}"
if [ -z "${image}" ]; then
  if ! "${engine}" image inspect "${image_name}" >/dev/null 2>&1; then
    "${engine}" build \
      --network "${CONTAINER_BUILD_NETWORK:-host}" \
      --target netshoot \
      --tag "${image_name}" \
      "$PWD" >/dev/null
  fi
fi

"${engine}" rm -f "${container_name}" >/dev/null 2>&1 || true
cleanup_container() {
  "${engine}" rm -f "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup_container EXIT

"${engine}" run -d \
  --name "${container_name}" \
  "${run_args[@]}" \
  --hostname "${container_name}" \
  --env "MESH_INIT_DIR=${MESH_INIT_CONFIG_DIR_IN_NS}" \
  --env "MESH_INIT_SOCK=${MESH_INIT_SOCK}" \
  --env "RUST_LOG=${RUST_LOG:-info}" \
  --env "PATH=/opt/ssh-mesh/bin:/usr/local/bin:/usr/bin:/bin" \
  --entrypoint /bin/sh \
  "${image_name}" \
  -c 'mkdir -p /run /home /opt/ssh-mesh/bin 2>/dev/null; exec /opt/ssh-mesh/bin/mesh-init' >/dev/null

if [ "${do_wait}" = "yes" ]; then
  for _ in $(seq 1 200); do
    if "${engine}" exec "${container_name}" /bin/sh -c "test -S ${MESH_INIT_SOCK}" >/dev/null 2>&1; then
      break
    fi
    if ! "${engine}" inspect "${container_name}" >/dev/null 2>&1; then
      "${engine}" logs --tail 50 "${container_name}" >&2 || true
      printf 'start_podman.sh: container exited before the control socket appeared\n' >&2
      exit 1
    fi
    sleep 0.25
  done
  if ! "${engine}" exec "${container_name}" /bin/sh -c "test -S ${MESH_INIT_SOCK}"; then
    printf 'start_podman.sh: mesh-init control socket never appeared: %s\n' "${MESH_INIT_SOCK}" >&2
    exit 1
  fi
fi

# Run the payload inside the container (podman exec), with the container's
# own loopback ports. On a failure exit the status; the trap removes the
# container either way.
set +e
"${engine}" exec \
  --user 0 \
  --env "PATH=/opt/ssh-mesh/bin:/usr/local/bin:/usr/bin:/bin" \
  --env "MESH_INIT_SOCK=${MESH_INIT_SOCK}" \
  --env "SSH_PORT=${CONTAINER_SSH_PORT}" \
  --env "HTTP_PORT=${CONTAINER_HTTP_PORT}" \
  --env "MESH_INIT_DIR=${MESH_INIT_CONFIG_DIR_IN_NS}" \
  "${container_name}" \
  "${exec_args[@]}"
payload_status=$?
set -e
exit "${payload_status}"
