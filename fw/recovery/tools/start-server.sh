#!/usr/bin/env bash
# Start or inspect the repo-local Wi-Fi Main-update TCP server.
#
# This is a Main/Recovery network service only. It never opens a UART and never
# invokes esptool. Runtime state and logs stay under target/.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091
. "$repo_dir/env.sh"

family="${DMESH_RECOVERY_FAMILY:-all}"
bind_addr="${DMESH_RECOVERY_BIND:-10.78.0.1}"
port="${DMESH_RECOVERY_PORT:-3336}"
image="${DMESH_RECOVERY_IMAGE:-$DMESH_REPO/target/flash}"
target="${DMESH_RECOVERY_TARGET:-main}"
state_dir="${DMESH_RECOVERY_STATE_DIR:-$DMESH_REPO/target/recovery-server}"
pid_file="$state_dir/$family-$port.pid"
log_file="$state_dir/$family-$port.log"

case "${1:-start}" in
status)
    if [[ -s "$pid_file" ]] && kill -0 "$(<"$pid_file")" 2>/dev/null; then
        echo "running pid=$(<"$pid_file") bind=$bind_addr port=$port image=$image log=$log_file"
    elif command -v ss >/dev/null 2>&1; then
        # Adopt a listener left by an earlier invocation so status/start remain
        # truthful after a shell or mesh-init restart.
        listener_pid="$(ss -ltnp 2>/dev/null | awk -v addr="$bind_addr:$port" '$4 == addr && match($NF, /pid=([0-9]+)/, m) { print m[1]; exit }')"
        if [[ -n "$listener_pid" ]] && kill -0 "$listener_pid" 2>/dev/null; then
            printf '%s\n' "$listener_pid" >"$pid_file"
            echo "running pid=$listener_pid bind=$bind_addr port=$port image=$image log=$log_file"
            exit 0
        fi
        echo "stopped bind=$bind_addr port=$port image=$image log=$log_file"
        exit 1
    else
        echo "stopped bind=$bind_addr port=$port image=$image log=$log_file"
        exit 1
    fi
    ;;
start)
    mkdir -p "$state_dir"
    if [[ -s "$pid_file" ]] && kill -0 "$(<"$pid_file")" 2>/dev/null; then
        echo "already running pid=$(<"$pid_file") bind=$bind_addr port=$port"
        exit 0
    fi
    if command -v ss >/dev/null 2>&1; then
        listener_pid="$(ss -ltnp 2>/dev/null | awk -v addr="$bind_addr:$port" '$4 == addr && match($NF, /pid=([0-9]+)/, m) { print m[1]; exit }')"
        if [[ -n "$listener_pid" ]] && kill -0 "$listener_pid" 2>/dev/null; then
            printf '%s\n' "$listener_pid" >"$pid_file"
            echo "already running pid=$listener_pid bind=$bind_addr port=$port"
            exit 0
        fi
    fi
    [[ -d "$image" || -f "$image" ]] || { echo "image path not found: $image" >&2; exit 2; }
    # Start a new session so mesh-init/shell teardown cannot kill the listener.
    nohup setsid "$DMESH_PYTHON" "$DMESH_REPO/fw/recovery/tools/flash-server.py" \
        "$image" --target "$target" --bind "$bind_addr" --port "$port" \
        --fast-unsigned --forever \
        >>"$log_file" 2>&1 < /dev/null &
    server_pid=$!
    echo "$server_pid" >"$pid_file"
    for _ in 1 2 3 4 5; do
        if kill -0 "$server_pid" 2>/dev/null; then
            echo "started pid=$server_pid bind=$bind_addr port=$port target=$target image=$image log=$log_file"
            exit 0
        fi
        sleep 1
    done
    echo "recovery server failed to start; see $log_file" >&2
    exit 1
    ;;
stop)
    if [[ -s "$pid_file" ]]; then
        server_pid="$(<"$pid_file")"
        if kill -0 "$server_pid" 2>/dev/null; then
            kill -TERM "$server_pid"
        fi
        rm -f "$pid_file"
    fi
    echo "stopped bind=$bind_addr port=$port"
    ;;
*)
    echo "usage: $0 [start|status|stop]" >&2
    exit 2
    ;;
esac
