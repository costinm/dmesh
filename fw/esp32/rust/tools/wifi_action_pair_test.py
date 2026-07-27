#!/usr/bin/env python3
"""Exercise ESP raw action-frame command/response behavior over two serial ports."""

from __future__ import annotations

import argparse
import os
import re
import select
import termios
import time
from dataclasses import dataclass


PROMPT = b"dm-rs> "
MAC_RE = re.compile(r"\b(?:sta_mac|ap_mac)=([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b")
BYTES_RE = re.compile(r"raw_action sent bytes=(\d+)")


@dataclass
class CommandResult:
    command: str
    text: str


class Console:
    def __init__(self, port: str, baud: int = 460800, timeout: float = 2.0) -> None:
        self.port = port
        self.timeout = timeout
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        configure_serial(self.fd, baud)

    def close(self) -> None:
        os.close(self.fd)

    def sync(self) -> str:
        termios.tcflush(self.fd, termios.TCIFLUSH)
        os.write(self.fd, b"\n")
        return self.read_for(self.timeout, stop_on_prompt=True)

    def cmd(self, command: str, timeout: float | None = None) -> CommandResult:
        os.write(self.fd, (command + "\n").encode())
        return CommandResult(command, self.read_for(timeout or self.timeout, stop_on_prompt=True))

    def read_for(self, timeout: float, stop_on_prompt: bool = False) -> str:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            remaining = max(0.0, min(0.05, deadline - time.monotonic()))
            readable, _, _ = select.select([self.fd], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = os.read(self.fd, 4096)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            buf.extend(chunk)
            if stop_on_prompt and PROMPT in buf:
                break
        return bytes(buf).decode("utf-8", "replace").replace("\r", "")


def configure_serial(fd: int, baud: int) -> None:
    speeds = {
        115200: termios.B115200,
        230400: termios.B230400,
        460800: termios.B460800,
        921600: termios.B921600,
    }
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    attrs[4] = speeds[baud]
    attrs[5] = speeds[baud]
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def run(console: Console, command: str, timeout: float = 2.0) -> str:
    result = console.cmd(command, timeout)
    print(f"\n[{console.port}] $ {command}")
    print(result.text.rstrip())
    return result.text


def find_mac(status: str) -> str:
    match = MAC_RE.search(status)
    if not match:
        raise RuntimeError(f"no MAC in status: {status!r}")
    return match.group(1)


def raw_action(console: Console, dst: str, payload: str, channel: int, timeout: float = 2.0) -> int:
    out = run(
        console,
        f"wifi raw_action={quote_value(payload)} dst={dst} channel={channel}",
        timeout=timeout,
    )
    match = BYTES_RE.search(out)
    if not match:
        raise RuntimeError(f"raw_action did not report sent bytes: {out!r}")
    return int(match.group(1))


def quote_value(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace('"', '\\"')
    )
    return f'"{escaped}"'


def make_payload(prefix: str, size: int) -> str:
    if size <= len(prefix):
        return prefix[:size]
    return prefix + ("x" * (size - len(prefix)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a", required=True, help="First ESP serial port")
    parser.add_argument("--b", required=True, help="Second ESP serial port")
    parser.add_argument("--channel", type=int, default=6)
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--max-payload", type=int, default=1500)
    parser.add_argument("--skip-nan", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    a = Console(args.a, args.baud)
    b = Console(args.b, args.baud)
    try:
        print(f"Sync A {args.a}")
        print(a.sync().rstrip())
        print(f"Sync B {args.b}")
        print(b.sync().rstrip())

        run(a, f"wifi mode=raw channel={args.channel} filter=dmesh")
        run(b, f"wifi mode=raw channel={args.channel} filter=dmesh")
        a_status = run(a, "wifi")
        b_status = run(b, "wifi")
        a_mac = find_mac(a_status)
        b_mac = find_mac(b_status)
        print(f"\nmac_a={a_mac} mac_b={b_mac}")

        raw_action(a, b_mac, "wifi raw_stats=true", args.channel)
        print("\n[A async]")
        print(a.read_for(1.5).rstrip())
        print("\n[B async]")
        print(b.read_for(0.5).rstrip())
        run(a, "wifi raw_stats=true")
        run(b, "wifi raw_stats=true")

        raw_action(a, b_mac, "button status=true", args.channel)
        print("\n[A notify/resp async]")
        print(a.read_for(1.5).rstrip())

        print("\nPayload size probe")
        for size in [64, 256, 512, 900, 1200, 1400, args.max_payload]:
            payload = make_payload("resp size-probe-", size)
            try:
                frame_len = raw_action(a, b_mac, payload, args.channel, timeout=3.0)
                print(f"payload_len={size} frame_len={frame_len}")
            except Exception as exc:  # noqa: BLE001
                print(f"payload_len={size} error={exc}")
                break
            time.sleep(0.15)
            _ = b.read_for(0.2)

        if not args.skip_nan:
            print("\nNAN / raw action channel probe")
            run(a, "nan start=true backend=official role=publisher service=dmesh channel=6", 6.0)
            run(a, "nan stats=true")
            run(a, "wifi raw_stats=true")
            run(a, "wifi")
            raw_action(b, a_mac, "wifi raw_stats=true", args.channel)
            print("\n[A post-NAN action RX async]")
            print(a.read_for(1.0).rstrip())
            print("\n[B post-NAN response async]")
            print(b.read_for(1.5).rstrip())
            run(a, "wifi raw_stats=true")
            run(b, "wifi raw_stats=true")
            run(a, f"wifi mode=raw channel={args.channel} filter=dmesh")
            run(a, "wifi raw_stats=true")

        return 0
    finally:
        a.close()
        b.close()


if __name__ == "__main__":
    raise SystemExit(main())
