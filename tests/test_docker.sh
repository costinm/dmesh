#!/usr/bin/env bash
# Backward-compatible entry point: the container test now lives in
# tests/test_cert_terminal_mesh_init.py (podman case, same pattern as the
# bwrap cases: mesh-init PID 1, socket-activated ssh-mesh, cert + plain key
# logins delegated through mesh-init's terminal path). This shim keeps the
# original direct invocation working.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

engine="${ENGINE:-}"
if [ -z "${engine}" ]; then
  if command -v podman >/dev/null 2>&1; then
    engine=podman
  elif command -v docker >/dev/null 2>&1; then
    engine=docker
  else
    echo "error: neither podman nor docker is installed" >&2
    exit 1
  fi
fi

# The test builds the staged release tree when it is missing
# (scripts/build.sh test cert_terminal_mesh_init).
exec python3 "${REPO_ROOT}/tests/test_cert_terminal_mesh_init.py" \
  --case podman --engine "${engine}"
