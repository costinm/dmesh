#!/bin/bash
# Provision a temporary SSH CA and send one JSON-Lines MsgMux command through
# an incoming ssh-mesh direct stream using a CA-signed user certificate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

export CARGO_HOME="${CARGO_HOME:-$SCRIPT_DIR/target/.cargo}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$SCRIPT_DIR/target/.gradle}"

APP_DMESH_PKG="${APP_DMESH_PKG:-com.github.costinm.dmesh.lm}"
APP_CHAT_PKG="${APP_CHAT_PKG:-com.github.costinm.dmesh.chat}"
APP_WEB_PKG="${APP_WEB_PKG:-com.github.costinm.dmesh.web}"
DMESH_HOST_SSH_PORT="${DMESH_HOST_SSH_PORT:-11522}"
DMESH_SSH_USER="${DMESH_SSH_USER:-dmesh}"
KEY_DIR="$SCRIPT_DIR/target/ssh-jsonl-smoke"
KEY="$KEY_DIR/id_ecdsa"
CA_KEY="$KEY_DIR/ca_ecdsa"
REMOTE_CA="/data/local/tmp/dmesh-jsonl-ca.pub"
APP_FILES="/data/user/0/$APP_DMESH_PKG/files"

if ! command -v ssh >/dev/null 2>&1; then
    echo "ERROR: ssh not found"
    exit 1
fi
if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "ERROR: ssh-keygen not found"
    exit 1
fi

mkdir -p "$KEY_DIR"
if [ ! -f "$KEY" ]; then
    ssh-keygen -q -t ecdsa -b 256 -N "" -f "$KEY" -C dmesh-jsonl-smoke
fi
if [ ! -f "$CA_KEY" ]; then
    ssh-keygen -q -t ecdsa -b 256 -N "" -f "$CA_KEY" -C dmesh-jsonl-test-ca
fi
rm -f "$KEY-cert.pub"
ssh-keygen -q -s "$CA_KEY" \
    -I dmesh-jsonl-smoke \
    -n "$DMESH_SSH_USER" \
    -V -5m:+1h \
    -z "$(date +%s)" \
    "$KEY.pub"

serial="${DMESH_ADB_SERIAL:-$(adb devices | awk 'NR > 1 && $2 == "device" { print $1; exit }')}"
if [ -z "$serial" ]; then
    echo "ERROR: no active adb device/emulator found."
    exit 1
fi
adb_cmd=(adb -s "$serial")

echo "Installing temporary SSH CA for app-dmesh"
"${adb_cmd[@]}" shell am force-stop "$APP_DMESH_PKG" >/dev/null 2>&1 || true
"${adb_cmd[@]}" shell am force-stop "$APP_CHAT_PKG" >/dev/null 2>&1 || true
"${adb_cmd[@]}" shell am force-stop "$APP_WEB_PKG" >/dev/null 2>&1 || true
"${adb_cmd[@]}" push "$CA_KEY.pub" "$REMOTE_CA" >/dev/null
"${adb_cmd[@]}" shell run-as "$APP_DMESH_PKG" mkdir -p \
    "$APP_FILES/ssh-mesh"
"${adb_cmd[@]}" shell run-as "$APP_DMESH_PKG" cp "$REMOTE_CA" \
    "$APP_FILES/ssh-mesh/authorized_cas"
"${adb_cmd[@]}" shell run-as "$APP_DMESH_PKG" chmod 600 \
    "$APP_FILES/ssh-mesh/authorized_cas"
"${adb_cmd[@]}" shell rm -f "$REMOTE_CA" >/dev/null 2>&1 || true

send_bridge_lines() {
    echo "Sending JSONL, human, telemetry, app-chat, and app-web commands over ssh -W dmesh-msg:1"
    set +e
    out="$(
        {
            printf '%s\n' '{"id":"jsonl-smoke-1","method":"wifi.scan","data":{"reason":"ssh-jsonl-smoke"}}'
            printf '%s\n' 'wifi.scan --id human-smoke-1 --reason ssh-human-smoke'
            printf '%s\n' 'app.chat.send --id chat-smoke-1 --text ssh-to-chat'
            printf '%s\n' 'app.web.open --id web-smoke-1 --url https://example.invalid/dmesh-smoke'
            printf '%s\n' 'telemetry.history --id telemetry-smoke-1 --limit 8'
        } | timeout "${DMESH_JSONL_TIMEOUT:-12}" ssh \
        -i "$KEY" \
        -p "$DMESH_HOST_SSH_PORT" \
        -o CertificateFile="$KEY-cert.pub" \
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
    for expect in '"id":"jsonl-smoke-1".*"ok":true' '"id":"human-smoke-1".*"ok":true' 'chat[.]message' 'web[.]received' '"id":"telemetry-smoke-1".*"method":"telemetry.history"'; do
        if printf '%s\n' "$out" | grep -Eq "$expect"; then
            continue
        fi
        echo "ssh exited with status $ssh_rc"
        echo "ERROR: bridge command stream did not return expected output: $expect"
        exit 1
    done
}

send_stream_upgrade() {
    echo "Checking JSONL-to-binary stream upgrade"
    set +e
    out="$(
        {
            printf '%s\n' '{"id":"stream-upgrade-1","method":"mesh.stream.open","data":{"mode":"binary","kind":"shell"}}'
            printf 'raw-stream-bytes-after-upgrade'
        } | timeout "${DMESH_JSONL_TIMEOUT:-12}" ssh \
        -i "$KEY" \
        -p "$DMESH_HOST_SSH_PORT" \
        -o CertificateFile="$KEY-cert.pub" \
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
    if ! printf '%s\n' "$out" | grep -q '"method":"mesh.stream.opened"'; then
        echo "ssh exited with status $ssh_rc"
        echo "ERROR: stream upgrade did not return mesh.stream.opened"
        exit 1
    fi
}

shell_command() {
    "${adb_cmd[@]}" shell "content call --uri content://com.github.costinm.dmesh.lm.shell --method command --arg '$1'" || true
}

check_shell_scan_messages() {
    echo "Checking shell-visible WiFi, BLE, and NAN scan messages"

    shell_command "wifi.scan reason=shell-smoke" >/dev/null
    shell_command "ble.scan reason=shell-smoke" >/dev/null
    shell_command "wifi.nan.start reason=shell-smoke" >/dev/null
    sleep 4

    wifi_out="$(shell_command "history durationMs=1500 limit=32 keys=net,wifi")"
    printf '%s\n' "$wifi_out"
    if ! printf '%s\n' "$wifi_out" | grep -Eq '"method":"(net[.]status|wifi[.])'; then
        echo "ERROR: shell history did not contain WiFi/net scan messages"
        exit 1
    fi

    ble_out="$(shell_command "history durationMs=1500 limit=32 keys=BLE,wifi.BLE")"
    printf '%s\n' "$ble_out"
    if ! printf '%s\n' "$ble_out" | grep -Eq '"method":"(BLE[.](scan|start|ERR[.])|wifi[.]BLE[.]DISC)'; then
        echo "ERROR: shell history did not contain BLE scan status, error, or discovery messages"
        exit 1
    fi

    nan_out="$(shell_command "history durationMs=1500 limit=32 keys=net.NAN,wifi.nan")"
    printf '%s\n' "$nan_out"
    if ! printf '%s\n' "$nan_out" | grep -Eq '"method":"(net[.]NAN[.]|wifi[.]nan)'; then
        echo "ERROR: shell history did not contain NAN status, error, or discovery messages"
        exit 1
    fi
    shell_command "wifi.nan.stop reason=shell-smoke" >/dev/null
}

"$SCRIPT_DIR/scripts/test_emulator_ssh_forward.sh"

echo "Checking app-dmesh shell message subscription"
shell_sub_out="$("${adb_cmd[@]}" shell "content call --uri content://com.github.costinm.dmesh.lm.shell --method command --arg 'subscribe durationMs=1500 limit=8 keys=messages,net,wifi,BLE'" || true)"
printf '%s\n' "$shell_sub_out"
if ! printf '%s\n' "$shell_sub_out" | grep -q 'messages='; then
    echo "ERROR: shell subscription did not return captured messages"
    exit 1
fi

send_bridge_lines
check_shell_scan_messages
send_stream_upgrade
echo "JSONL bridge smoke passed"
