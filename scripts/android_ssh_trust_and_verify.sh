#!/bin/bash
# Provision an SSH public key or CA into app-dmesh and verify SSH auth through
# adb-forwarded ports.

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
DMESH_DEVICE_ADMIN_PORT="${DMESH_DEVICE_ADMIN_PORT:-18480}"
DMESH_HOST_SSH_PORT="${DMESH_HOST_SSH_PORT:-11522}"
DMESH_HOST_ADMIN_PORT="${DMESH_HOST_ADMIN_PORT:-18080}"
DMESH_SSH_USER="${DMESH_SSH_USER:-dmesh}"
DMESH_SSH_AUTH_MODE="${DMESH_SSH_AUTH_MODE:-key}"
KEY_DIR="${DMESH_SSH_KEY_DIR:-$SCRIPT_DIR/target/android-ssh}"
KEY="${DMESH_SSH_KEY:-$KEY_DIR/id_ed25519}"
CA_KEY="${DMESH_SSH_CA_KEY:-$KEY_DIR/ca_ed25519}"
REMOTE_KEY="/data/local/tmp/dmesh-ssh-trust.pub"
APP_FILES="/data/user/0/$APP_DMESH_PKG/files"

usage() {
    cat <<EOF
Usage: $0 [key|ca]

Environment:
  DMESH_ADB_SERIAL       adb serial. Defaults to first connected device.
  DMESH_SSH_AUTH_MODE    key or ca. Defaults to key.
  DMESH_SSH_KEY          private key path. Defaults to target/android-ssh/id_ed25519.
  DMESH_HOST_SSH_PORT    host forwarded SSH port. Defaults to 11522.
  DMESH_HOST_ADMIN_PORT  host forwarded admin HTTP port. Defaults to 18080.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi
if [ -n "${1:-}" ]; then
    DMESH_SSH_AUTH_MODE="$1"
fi
if [ "$DMESH_SSH_AUTH_MODE" != "key" ] && [ "$DMESH_SSH_AUTH_MODE" != "ca" ]; then
    echo "ERROR: auth mode must be 'key' or 'ca'"
    exit 1
fi

for bin in adb ssh ssh-keygen python3; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "ERROR: $bin not found"
        exit 1
    fi
done

adb_serial() {
    if [ -n "${DMESH_ADB_SERIAL:-}" ]; then
        echo "$DMESH_ADB_SERIAL"
        return
    fi
    adb devices | awk 'NR > 1 && $2 == "device" { print $1; exit }'
}

mkdir -p "$KEY_DIR"
if [ ! -f "$KEY" ]; then
    ssh-keygen -q -t ed25519 -N "" -f "$KEY" -C dmesh-android
fi

install_pub="$KEY.pub"
target_file="$APP_FILES/ssh-mesh/authorized_keys"
ssh_opts=()
if [ "$DMESH_SSH_AUTH_MODE" = "ca" ]; then
    if [ ! -f "$CA_KEY" ]; then
        ssh-keygen -q -t ed25519 -N "" -f "$CA_KEY" -C dmesh-android-ca
    fi
    rm -f "$KEY-cert.pub"
    ssh-keygen -q -s "$CA_KEY" \
        -I dmesh-android \
        -n "$DMESH_SSH_USER" \
        -V -5m:+1h \
        -z "$(date +%s)" \
        "$KEY.pub"
    install_pub="$CA_KEY.pub"
    target_file="$APP_FILES/ssh-mesh/authorized_cas"
    ssh_opts=(-o "CertificateFile=$KEY-cert.pub")
fi

serial="$(adb_serial)"
if [ -z "$serial" ]; then
    echo "ERROR: no active adb device/emulator found."
    exit 1
fi
adb_cmd=(adb -s "$serial")

echo "Using adb device: $serial"
echo "Installing SSH trust material: $DMESH_SSH_AUTH_MODE -> $target_file"
"${adb_cmd[@]}" shell am force-stop "$APP_DMESH_PKG" >/dev/null 2>&1 || true
"${adb_cmd[@]}" push "$install_pub" "$REMOTE_KEY" >/dev/null
"${adb_cmd[@]}" shell \
    "run-as '$APP_DMESH_PKG' sh -c \"mkdir -p '$APP_FILES/ssh-mesh' && touch '$target_file' && (grep -qxF -f '$REMOTE_KEY' '$target_file' || cat '$REMOTE_KEY' >> '$target_file') && chmod 600 '$target_file'\""
"${adb_cmd[@]}" shell rm -f "$REMOTE_KEY" >/dev/null 2>&1 || true

echo "Starting app-dmesh foreground service"
"${adb_cmd[@]}" shell am start-foreground-service \
    -n "$APP_DMESH_PKG/$APP_DMESH_SERVICE" >/dev/null 2>&1 || \
    "${adb_cmd[@]}" shell am startservice \
        -n "$APP_DMESH_PKG/$APP_DMESH_SERVICE" >/dev/null

sleep "${DMESH_SERVICE_START_DELAY:-3}"

echo "Forwarding SSH localhost:$DMESH_HOST_SSH_PORT -> device:$DMESH_DEVICE_SSH_PORT"
"${adb_cmd[@]}" forward "tcp:$DMESH_HOST_SSH_PORT" "tcp:$DMESH_DEVICE_SSH_PORT" >/dev/null

python3 - "$DMESH_HOST_SSH_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.settimeout(5)
    banner = sock.recv(128).decode("utf-8", "replace").strip()

print(f"Received SSH banner: {banner}")
if not banner.startswith("SSH-"):
    raise SystemExit("ERROR: forwarded SSH port did not return an SSH banner")
PY

echo "Forwarding admin localhost:$DMESH_HOST_ADMIN_PORT -> device:$DMESH_DEVICE_ADMIN_PORT"
"${adb_cmd[@]}" forward "tcp:$DMESH_HOST_ADMIN_PORT" "tcp:$DMESH_DEVICE_ADMIN_PORT" >/dev/null

python3 - "$DMESH_HOST_ADMIN_PORT" <<'PY'
import http.client
import sys

port = int(sys.argv[1])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("GET", "/_m/adm")
resp = conn.getresponse()
body = resp.read(256)
conn.close()
print(f"Admin HTTP status: {resp.status}")
if resp.status < 200 or resp.status >= 400:
    raise SystemExit(f"ERROR: admin endpoint failed with HTTP {resp.status}: {body!r}")
PY

verify_id="ssh-trust-$(date +%s)"
echo "Verifying authenticated SSH direct stream: $verify_id"
set +e
out="$(
    printf '%s\n' "{\"id\":\"$verify_id\",\"method\":\"wifi.scan\",\"data\":{\"reason\":\"android-ssh-trust\"}}" |
    timeout "${DMESH_SSH_VERIFY_TIMEOUT:-12}" ssh \
        -F /dev/null \
        -i "$KEY" \
        "${ssh_opts[@]}" \
        -p "$DMESH_HOST_SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ControlMaster=no \
        -o ControlPath=none \
        -o PreferredAuthentications=publickey \
        -o PasswordAuthentication=no \
        -o LogLevel=ERROR \
        "$DMESH_SSH_USER@127.0.0.1" \
        -W dmesh-msg:1
)"
ssh_rc=$?
set -e

echo "$out"
if ! printf '%s\n' "$out" | grep -q "\"id\":\"$verify_id\",\"ok\":true"; then
    echo "ssh exited with status $ssh_rc"
    echo "ERROR: authenticated SSH bridge command did not return the expected ack"
    exit 1
fi

echo "SSH trust verification passed"
echo "Key: $KEY"
echo "SSH: ssh -F /dev/null -i '$KEY' -p '$DMESH_HOST_SSH_PORT' $DMESH_SSH_USER@127.0.0.1 -W dmesh-msg:1"
echo "Admin: http://127.0.0.1:$DMESH_HOST_ADMIN_PORT/_m/adm"
