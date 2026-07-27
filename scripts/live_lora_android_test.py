#!/usr/bin/env python3
"""Live LoRa-to-Android smoke test.

Flow:
  ESP32 LoRa TX -> ESP32 LoRa RX/repeater -> Android receives via BLE/NAN.

This script uses only the app-dmesh shell history and firmware console
logs/messages. It does not use logcat, pyserial, or firmware flashing tools.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
import termios
import time
from datetime import datetime, timezone
from pathlib import Path


PROMPT = b"dm-rs> "
PKG = "com.github.costinm.dmesh.lm"
SERVICE = "com.github.costinm.dmesh.lm/.DMService"
SHELL_URI = "content://com.github.costinm.dmesh.lm.shell"


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


REPO_ROOT = Path(__file__).resolve().parents[1]


def adb_path() -> str:
    for candidate in [
        os.environ.get("ADB"),
        str(REPO_ROOT / "target/android-sdk/platform-tools/adb"),
    ]:
        if candidate and Path(candidate).exists():
            return candidate
    return "adb"


def adb(adb_bin: str, serial: str, *args: str, timeout: float = 20) -> str:
    return run([adb_bin, "-s", serial, *args], timeout=timeout).stdout


def shell_cmd(adb_bin: str, serial: str, command: str, timeout: float = 20) -> str:
    quoted = f"content call --uri {SHELL_URI} --method command --arg {shlex.quote(command)}"
    return adb(adb_bin, serial, "shell", quoted, timeout=timeout)


def ensure_android(adb_bin: str, serial: str) -> None:
    for permission in [
        "POST_NOTIFICATIONS",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "NEARBY_WIFI_DEVICES",
        "BLUETOOTH_CONNECT",
        "BLUETOOTH_SCAN",
        "BLUETOOTH_ADVERTISE",
    ]:
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
    adb(adb_bin, serial, "shell", "am", "start-foreground-service", "-n", SERVICE, timeout=10)
    time.sleep(1)
    pid = adb(adb_bin, serial, "shell", f"pidof {PKG} || true", timeout=5).strip()
    if not pid:
        raise RuntimeError(f"{serial}: app-dmesh service is not running")
    print(f"[android {serial}] pid={pid}")


class Console:
    def __init__(self, port: str, baud: int, timeout: float) -> None:
        self.port = port
        self.timeout = timeout
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        self.old_attrs = termios.tcgetattr(self.fd)
        attrs = termios.tcgetattr(self.fd)
        attrs[0] = 0
        attrs[1] = 0
        attrs[2] = attrs[2] | termios.CLOCAL | termios.CREAD
        attrs[3] = 0
        speed = getattr(termios, f"B{baud}", termios.B115200)
        attrs[4] = speed
        attrs[5] = speed
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)

    def close(self) -> None:
        termios.tcsetattr(self.fd, termios.TCSANOW, self.old_attrs)
        os.close(self.fd)

    def sync(self) -> str:
        self._drain()
        os.write(self.fd, b"\n")
        return self._read_until_prompt(self.timeout)

    def cmd(self, command: str, timeout: float | None = None) -> str:
        print(f"[{self.port}] $ {command}", flush=True)
        os.write(self.fd, (command + "\n").encode())
        out = self._read_until_prompt(timeout or self.timeout)
        print(out.rstrip(), flush=True)
        if re.search(r"(^|\n)error ", out.strip()):
            raise RuntimeError(f"{self.port}: command failed: {command}")
        return out

    def _drain(self) -> None:
        deadline = time.monotonic() + 0.4
        while time.monotonic() < deadline:
            try:
                if not os.read(self.fd, 4096):
                    break
            except BlockingIOError:
                time.sleep(0.05)

    def _read_until_prompt(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            try:
                chunk = os.read(self.fd, 4096)
            except BlockingIOError:
                time.sleep(0.05)
                continue
            if chunk:
                buf.extend(chunk)
                if PROMPT in buf:
                    break
            else:
                time.sleep(0.05)
        return bytes(buf).decode("utf-8", "replace").replace("\r", "")


def value_for(text: str, key: str) -> int:
    match = re.search(rf"\b{re.escape(key)}=(-?\d+)\b", text)
    return int(match.group(1)) if match else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=adb_path())
    parser.add_argument("--android", action="append", required=True, help="Android ADB serial")
    parser.add_argument("--tx", required=True, help="LoRa sender ESP32 serial port")
    parser.add_argument("--rx", required=True, help="LoRa receiver/repeater ESP32 serial port")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--lora-freq", type=int, default=913_125_000)
    parser.add_argument("--sync-word", default="0x2b")
    parser.add_argument("--nan-channel", type=int, default=6)
    parser.add_argument("--nan-backend", choices=["raw", "official"], default="raw")
    parser.add_argument("--payload-hex", default="444d4553482d4c4f52412d414e44524f4944")
    parser.add_argument("--wait", type=float, default=10.0)
    parser.add_argument("--out-dir", default="")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir or f"target/live-tests/lora-android-{stamp}")
    out_dir.mkdir(parents=True, exist_ok=True)

    for serial in args.android:
        ensure_android(args.adb, serial)
        shell_cmd(args.adb, serial, "ble.scan reason=lora-android")
        shell_cmd(args.adb, serial, "wifi.nan.start reason=lora-android")

    tx = Console(args.tx, args.baud, args.timeout)
    rx = Console(args.rx, args.baud, args.timeout)
    try:
        (out_dir / "tx-sync.txt").write_text(tx.sync())
        (out_dir / "rx-sync.txt").write_text(rx.sync())

        for dev in [tx, rx]:
            dev.cmd("stats reset=true")
            dev.cmd("logs clear=true")
            dev.cmd("messages clear=true")
            dev.cmd("lora rx=false", timeout=10)
            dev.cmd(
                f"lora preset=medium_fast freq={args.lora_freq} "
                f"sync_word={args.sync_word} apply=true",
                timeout=10,
            )

        rx.cmd("ble mode=listen", timeout=10)
        rx.cmd(
            f"nan start=true backend={args.nan_backend} role=both service=dmesh channel={args.nan_channel}",
            timeout=10,
        )
        if args.nan_backend == "raw":
            rx.cmd(f"wifi raw_monitor=true filter=action channel={args.nan_channel}", timeout=10)
        rx.cmd("lora rx=true", timeout=10)
        time.sleep(1)
        rx.cmd("logs clear=true")
        rx.cmd("messages clear=true")

        tx.cmd(f"lorasend data=hex:{args.payload_hex}", timeout=10)
        time.sleep(args.wait)

        rx_logs = rx.cmd("logs count=80", timeout=10)
        rx_stats = rx.cmd("stats", timeout=10)
        rx_messages = rx.cmd("messages count=30", timeout=10)
        rx_transcript = "\n".join([rx_logs, rx_stats, rx_messages])
        (out_dir / "rx-logs.txt").write_text(rx_logs)
        (out_dir / "rx-stats.txt").write_text(rx_stats)
        (out_dir / "rx-messages.txt").write_text(rx_messages)
        (out_dir / "rx-transcript.txt").write_text(rx_transcript)

        android_histories: dict[str, str] = {}
        for serial in args.android:
            hist = shell_cmd(
                args.adb,
                serial,
                "history durationMs=30000 limit=240 keys=net,wifi,BLE",
                timeout=30,
            )
            android_histories[serial] = hist
            (out_dir / f"{serial}-history.txt").write_text(hist)

        failures: list[str] = []
        if value_for(rx_transcript, "lora_rx") < 1 and "ev=lora.rx" not in rx_transcript:
            failures.append("receiver did not record LoRa RX")
        if "transport=ble" not in rx_transcript and "t=ble" not in rx_transcript:
            failures.append("receiver did not log LoRa forwarding to BLE")
        if "transport=nan" not in rx_transcript and "t=nan" not in rx_transcript:
            failures.append("receiver did not log LoRa forwarding to NAN")

        any_android_ble = any("BLE.DISC" in h and "proto=dmesh" in h for h in android_histories.values())
        any_android_nan = any("FollowupRx" in h or "ServiceDiscovered" in h for h in android_histories.values())
        if not any_android_ble:
            failures.append("Android did not record DMesh BLE discovery from receiver")
        if not any_android_nan:
            failures.append("Android did not record NAN discovery/followup from receiver")

        print(f"logs: {out_dir}")
        for serial, hist in android_histories.items():
            ble = "BLE.DISC" in hist and "proto=dmesh" in hist
            nan = "FollowupRx" in hist or "ServiceDiscovered" in hist
            print(f"[android {serial}] ble_dmesh={ble} nan_peer_or_followup={nan}")

        if failures:
            print("FAIL")
            for failure in failures:
                print(f"- {failure}")
            return 1
        print("PASS")
        return 0
    finally:
        try:
            rx.cmd("nan stop=true", timeout=5)
            rx.cmd("wifi raw_stop=true", timeout=5)
        except Exception:
            pass
        tx.close()
        rx.close()


if __name__ == "__main__":
    sys.exit(main())
