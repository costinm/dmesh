#!/usr/bin/env python3
"""Live Android BLE/NAN smoke test for app-dmesh.

The script drives two Android devices through shared HTTP mesh services and
optionally records attached firmware serial logs. It intentionally
does not build or flash firmware.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import termios
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


PKG = "com.github.costinm.dmesh.lm"
SERVICE = "com.github.costinm.dmesh.lm/.DMService"
PERMISSIONS = [
    "POST_NOTIFICATIONS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "NEARBY_WIFI_DEVICES",
    "BLUETOOTH_CONNECT",
    "BLUETOOTH_SCAN",
    "BLUETOOTH_ADVERTISE",
]
REPO_ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], timeout: float = 20, check: bool = False) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"{shlex.join(cmd)} failed with {proc.returncode}\n{proc.stdout}")
    return proc


def adb_path() -> str:
    for candidate in [
        os.environ.get("ADB"),
        str(REPO_ROOT / "target/android-sdk/platform-tools/adb"),
    ]:
        if candidate and Path(candidate).exists():
            return candidate
    return "adb"


def adb(adb_bin: str, serial: str, *args: str, timeout: float = 20, check: bool = False):
    return run([adb_bin, "-s", serial, *args], timeout=timeout, check=check)


def list_devices(adb_bin: str) -> list[str]:
    out = run([adb_bin, "devices"], check=True).stdout.splitlines()
    serials = []
    for line in out[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def mesh_cmd(adb_bin: str, serial: str, method: str, *fields: str, timeout: float = 20) -> str:
    port = adb(adb_bin, serial, "forward", "tcp:0", "tcp:18480", check=True).stdout.strip()
    try:
        return run(["dmesh-cli", f"http://127.0.0.1:{port}", method, *fields], timeout=timeout).stdout
    finally:
        adb(adb_bin, serial, "forward", "--remove", f"tcp:{port}")


def ble_http(
    adb_bin: str,
    serial: str,
    index: int,
    method: str,
    payload: dict | None = None,
) -> str:
    host_port = 28500 + index
    run(
        [adb_bin, "-s", serial, "forward", f"tcp:{host_port}", "tcp:18480"],
        timeout=10,
        check=True,
    )
    body = json.dumps(payload or {"id": 1}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{host_port}/_m/mesh/services/ble/call/{method}",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode()
    except Exception as exc:
        return f"error={exc}"


def grant_permissions(adb_bin: str, serial: str) -> None:
    for permission in PERMISSIONS:
        adb(
            adb_bin,
            serial,
            "shell",
            "pm",
            "grant",
            "--user",
            "0",
            PKG,
            f"android.permission.{permission}",
            timeout=8,
        )


def package_summary(adb_bin: str, serial: str) -> str:
    return adb(
        adb_bin,
        serial,
        "shell",
        f"dumpsys package {PKG} | grep -E 'versionName|versionCode|signatures|firstInstallTime|lastUpdateTime'",
        timeout=10,
    ).stdout


def ensure_service(adb_bin: str, serial: str) -> str:
    adb(adb_bin, serial, "shell", "am", "start-foreground-service", "-n", SERVICE, timeout=10)
    time.sleep(1)
    pid = adb(adb_bin, serial, "shell", f"pidof {PKG} || true", timeout=5).stdout.strip()
    if not pid:
        raise RuntimeError(f"{serial}: {PKG} service did not stay running")
    return pid


def read_serial(port: str, baud: int, stop: threading.Event, out_path: Path) -> None:
    try:
        with open(port, "rb", buffering=0) as tty, out_path.open("ab") as out:
            fd = tty.fileno()
            old = termios.tcgetattr(fd)
            attrs = termios.tcgetattr(fd)
            attrs[0] = 0
            attrs[1] = 0
            attrs[2] = attrs[2] | termios.CLOCAL | termios.CREAD
            attrs[3] = 0
            speed = getattr(termios, f"B{baud}", termios.B115200)
            attrs[4] = speed
            attrs[5] = speed
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            try:
                while not stop.is_set():
                    chunk = os.read(fd, 4096)
                    if chunk:
                        out.write(chunk)
                    else:
                        time.sleep(0.05)
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old)
    except Exception as exc:  # noqa: BLE001 - preserve best-effort logs.
        with out_path.open("ab") as out:
            out.write(f"\n[serial-reader-error] {exc}\n".encode())


def collect_logcat(adb_bin: str, serial: str, out_dir: Path) -> None:
    tags = "WifiAwareService:D WifiAwareNativeApi:D WifiAwareStateManager:D LM-BLE:D DM-SVC:D AndroidRuntime:E ActivityManager:I *:S"
    out = adb(adb_bin, serial, "shell", f"logcat -d -v time -t 800 {tags}", timeout=15).stdout
    (out_dir / f"{serial}-logcat.txt").write_text(out)


def analyze_history(history: str, ble_scan_active: bool) -> dict[str, bool]:
    return {
        "ble_status": ble_scan_active
        or "ble_scan_results" in history,
        "nan_status": "android_nan_event" in history,
        "ble_peer": "ble_scan_results" in history and '"count":0' not in history,
        "nan_peer": "service_discovered" in history or "message_received" in history,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", default=adb_path())
    parser.add_argument("--device", action="append", help="ADB serial; pass twice")
    parser.add_argument("--serial-port", action="append", default=[])
    parser.add_argument("--auto-serial", action="store_true", help="record /dev/ttyUSB* logs")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--duration", type=float, default=12.0)
    parser.add_argument("--out-dir", default="")
    args = parser.parse_args()

    devices = args.device or list_devices(args.adb)
    if len(devices) < 2:
        raise SystemExit(f"need at least two ADB devices, found: {devices}")
    devices = devices[:2]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir or f"target/live-tests/android-radio-{stamp}")
    out_dir.mkdir(parents=True, exist_ok=True)

    serial_ports = list(args.serial_port)
    if args.auto_serial:
        serial_ports.extend(sorted(glob.glob("/dev/ttyUSB*")))
    serial_ports = sorted(dict.fromkeys(serial_ports))

    stop = threading.Event()
    readers: list[threading.Thread] = []
    for port in serial_ports:
        log_name = port.strip("/").replace("/", "-") + ".log"
        t = threading.Thread(
            target=read_serial,
            args=(port, args.baud, stop, out_dir / log_name),
            daemon=True,
        )
        t.start()
        readers.append(t)

    try:
        for serial in devices:
            (out_dir / f"{serial}-package.txt").write_text(package_summary(args.adb, serial))
            grant_permissions(args.adb, serial)
            pid = ensure_service(args.adb, serial)
            print(f"{serial}: service pid {pid}")

        ble_scan_active: dict[str, bool] = {}
        for idx, serial in enumerate(devices):
            ble_scan_response = ble_http(
                args.adb, serial, idx, "ble.scan", {"id": 1}
            )
            (out_dir / f"{serial}-ble-scan.json").write_text(ble_scan_response)
            ble_status_response = ble_http(
                args.adb, serial, idx, "ble.status", {"id": 2}
            )
            (out_dir / f"{serial}-ble-status.json").write_text(ble_status_response)
            ble_scan_active[serial] = '"scan":true' in ble_status_response
            mesh_cmd(args.adb, serial, "transport.set", "--mode=6")
            mesh_cmd(args.adb, serial, "radio.history", "--limit=16")

        # Discovery is asynchronous; after the requested dwell give every
        # capture another shared-service observation.
        time.sleep(args.duration)
        for idx, serial in enumerate(devices):
            mesh_cmd(args.adb, serial, "radio.history", "--limit=16")
        time.sleep(3)

        failures: list[str] = []
        pair_status: list[dict[str, bool]] = []
        for serial in devices:
            hist = mesh_cmd(
                args.adb,
                serial,
                "radio.history", "--limit=200", "--keys=nan,ble",
                f"--since_ms={int(time.time() * 1000) - 20000}",
                timeout=30,
            )
            (out_dir / f"{serial}-history.txt").write_text(hist)
            status = analyze_history(hist, ble_scan_active.get(serial, False))
            pair_status.append(status)
            print(f"{serial}: {status}")
            if not status["ble_status"]:
                failures.append(f"{serial}: no BLE scan status or discovery history")
            if not status["nan_status"]:
                failures.append(f"{serial}: no NAN status history")
            collect_logcat(args.adb, serial, out_dir)

        # This is a two-node interoperability row, not an attach smoke test:
        # every selected Android node must have discovered its counterpart and
        # observed reciprocal discovery. Follow-up delivery needs a separate
        # service-level test; discovery alone is not message completion.
        for serial, status in zip(devices, pair_status):
            if not status["nan_peer"]:
                failures.append(f"{serial}: no Android NAN peer discovery")

        for idx, serial in enumerate(devices):
            ble_http(args.adb, serial, idx, "ble.scan_stop", {"id": 3})
            # NAN is the service's always-on discovery plane. The smoke test
            # must not undo it during cleanup; service lifecycle and explicit
            # signed control requests own any future stop.
            mesh_cmd(args.adb, serial, "transport.set", "--mode=6", "--ap=0")

        print(f"logs: {out_dir}")
        if failures:
            print("FAIL:")
            for failure in failures:
                print(f"  {failure}")
            return 1
        return 0
    finally:
        stop.set()
        for t in readers:
            t.join(timeout=1)


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    sys.exit(main())
