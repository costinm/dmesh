#!/bin/bash
# Start app-dmesh in an emulator/device, forward its Rust SSH port, and
# verify that the host can read an SSH banner through adb.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

export CARGO_HOME="${CARGO_HOME:-$SCRIPT_DIR/target/.cargo}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$SCRIPT_DIR/target/.gradle}"

if [ -z "${ANDROID_HOME:-}" ] && [ -d "$HOME/Android/Sdk" ]; then
    export ANDROID_HOME="$HOME/Android/Sdk"
fi
if [ -n "${ANDROID_HOME:-}" ]; then
    export PATH="$ANDROID_HOME/platform-tools:$PATH"
fi

APP_DMESH_PKG="${APP_DMESH_PKG:-com.github.costinm.dmesh.lm}"
APP_DMESH_SERVICE="${APP_DMESH_SERVICE:-.DMService}"
DMESH_DEVICE_SSH_PORT="${DMESH_DEVICE_SSH_PORT:-15022}"
DMESH_HOST_SSH_PORT="${DMESH_HOST_SSH_PORT:-11522}"

adb_serial() {
    if [ -n "${DMESH_ADB_SERIAL:-}" ]; then
        echo "$DMESH_ADB_SERIAL"
        return
    fi
    adb devices | awk 'NR > 1 && $2 == "device" { print $1; exit }'
}

serial="$(adb_serial)"
if [ -z "$serial" ]; then
    echo "ERROR: no active adb device/emulator found."
    exit 1
fi

adb_cmd=(adb -s "$serial")

echo "Using adb device: $serial"
echo "Starting app-dmesh foreground service"
"${adb_cmd[@]}" shell am start-foreground-service \
    -n "$APP_DMESH_PKG/$APP_DMESH_SERVICE" >/dev/null 2>&1 || \
    "${adb_cmd[@]}" shell am startservice \
        -n "$APP_DMESH_PKG/$APP_DMESH_SERVICE" >/dev/null

sleep "${DMESH_SERVICE_START_DELAY:-3}"

echo "Forwarding host tcp:$DMESH_HOST_SSH_PORT to device tcp:$DMESH_DEVICE_SSH_PORT"
"${adb_cmd[@]}" forward "tcp:$DMESH_HOST_SSH_PORT" "tcp:$DMESH_DEVICE_SSH_PORT" >/dev/null

python3 - "$DMESH_HOST_SSH_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.settimeout(5)
    banner = sock.recv(128)

text = banner.decode("utf-8", "replace").strip()
print(f"Received banner: {text}")
if not text.startswith("SSH-"):
    raise SystemExit("ERROR: forwarded port did not return an SSH banner")
PY

echo "adb forward is active: localhost:$DMESH_HOST_SSH_PORT -> device:$DMESH_DEVICE_SSH_PORT"
