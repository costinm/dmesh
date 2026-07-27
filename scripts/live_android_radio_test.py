#!/usr/bin/env python3
"""Live Android BLE/NAN smoke test for app-dmesh.

The script drives two Android devices through the app-dmesh shell content
provider and optionally records attached firmware serial logs. It intentionally
does not build or flash firmware.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shlex
import signal
import subprocess
import sys
import termios
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


PKG = "com.github.costinm.dmesh.lm"
SERVICE = "com.github.costinm.dmesh.lm/.DMService"
SHELL_URI = "content://com.github.costinm.dmesh.lm.shell"
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


def shell_cmd(adb_bin: str, serial: str, command: str, timeout: float = 20) -> str:
    quoted = (
        f"content call --uri {SHELL_URI} --method command --arg {shlex.quote(command)}"
    )
    return adb(adb_bin, serial, "shell", quoted, timeout=timeout).stdout


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


def analyze_history(history: str) -> dict[str, bool]:
    return {
        "ble_status": bool(re.search(r"BLE[.](scan|start|DISC|ERR)", history)),
        "nan_status": bool(re.search(r"net[.]NAN[.]", history)),
        "ble_peer": "BLE.DISC" in history and "proto=dmesh" in history,
        "nan_peer": "ServiceDiscovered" in history or "FollowupRx" in history,
        "nan_followup": "FollowupRx" in history or "FollowupTx" in history,
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

        for idx, serial in enumerate(devices):
            shell_cmd(args.adb, serial, f"ble.scan reason=live-python-{idx}")
            shell_cmd(args.adb, serial, f"wifi.nan.start reason=live-python-{idx}")
            shell_cmd(args.adb, serial, f"wifi.adv on=1 p2p=0 id4=A{idx:03d}")

        time.sleep(args.duration)

        failures: list[str] = []
        for serial in devices:
            hist = shell_cmd(
                args.adb,
                serial,
                "history durationMs=20000 limit=200 keys=net,wifi,BLE",
                timeout=30,
            )
            (out_dir / f"{serial}-history.txt").write_text(hist)
            status = analyze_history(hist)
            print(f"{serial}: {status}")
            if not status["ble_status"]:
                failures.append(f"{serial}: no BLE status/discovery history")
            if not status["nan_status"]:
                failures.append(f"{serial}: no NAN status history")
            collect_logcat(args.adb, serial, out_dir)

        for serial in devices:
            shell_cmd(args.adb, serial, "wifi.nan.stop reason=live-python-cleanup")
            shell_cmd(args.adb, serial, "wifi.adv on=0 p2p=0")

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
