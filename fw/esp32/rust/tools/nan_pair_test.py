#!/usr/bin/env python3
"""Legacy focused raw-NAN check; prefer tools/presubmit.py for submissions."""

from __future__ import annotations

import argparse
import re
import time

from serial_cmd import Console, encode_firmware_command


STAT_RE = re.compile(
    r"\b(fup_rx|fup_tx|match|raw_sdf|raw_action|raw_beacon|raw_mgmt|raw_cmd_rx|raw_resp_rx|raw_resp_tx|queue_len)=(\d+)\b"
)


def run(console: Console, command: str, timeout: float | None = None) -> str:
    out = console.cbor_cmd(command, timeout)
    print(f"\n[{console.port}] $ {command}")
    print(out.rstrip())
    if "\nerror " in out or out.strip().startswith("error "):
        raise RuntimeError(f"{console.port} command failed: {command}")
    return out


def nan_stats(console: Console) -> dict[str, int]:
    out = run(console, "nan stats=true")
    return {key: int(value) for key, value in STAT_RE.findall(out)}


def wait_for_raw_discovery(a: Console, b: Console, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        a_stats = nan_stats(a)
        b_stats = nan_stats(b)
        a_seen = (
            a_stats.get("raw_beacon", 0)
            + a_stats.get("raw_sdf", 0)
            + a_stats.get("raw_action", 0)
            + a_stats.get("raw_matched", 0)
        )
        b_seen = (
            b_stats.get("raw_beacon", 0)
            + b_stats.get("raw_sdf", 0)
            + b_stats.get("raw_action", 0)
            + b_stats.get("raw_matched", 0)
        )
        if a_seen > 0 and b_seen > 0:
            return
        time.sleep(0.5)
    raise RuntimeError("timed out waiting for raw NAN discovery frames")


def start_pair(a: Console, b: Console, channel: int, backend: str, disable_lora: bool) -> None:
    for console in (a, b):
        console.wake_probe()
        run(console, "wifi mode=off")
        if disable_lora:
            try:
                run(console, "lora rx=false")
            except Exception as exc:  # noqa: BLE001 - NAN tests can run on no-LoRa boards.
                print(f"[{console.port}] ignoring lora disable failure: {exc}")
        run(
            console,
            f"nan start=true backend={backend} service=dmesh channel={channel}",
            8.0,
        )


def stop_extra(port: str, baud: int, timeout: float) -> None:
    console = Console(port, baud, timeout)
    try:
        run(console, "nan stop=true")
        run(console, "wifi mode=off")
        run(console, "lora rx=false")
    finally:
        console.close()


def assert_counter_increased(
    before: dict[str, int], after: dict[str, int], key: str, label: str
) -> None:
    if after.get(key, 0) <= before.get(key, 0):
        raise RuntimeError(f"{label} {key} did not increase: before={before} after={after}")


def mac_suffix4(mac: str) -> str:
    parts = [part.lower() for part in mac.split(":")]
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError(f"invalid MAC: {mac}")
    return "".join(parts[-4:])


def run_raw_command_round(
    a: Console,
    b: Console,
    payload: str,
    a_mac: str,
    b_mac: str,
    channel: int,
    expect_response: bool,
    settle_sec: float,
) -> None:
    run(a, f"nan start=true backend=raw service=dmesh channel={channel}", 8.0)
    run(b, f"nan start=true backend=raw service=dmesh channel={channel}", 8.0)
    a0 = nan_stats(a)
    b0 = nan_stats(b)
    # The outer NAN command queues an opaque, unframed compact-CBOR command.
    # Addressing belongs to the raw-NAN frame, not the text command payload.
    # Strip UART's stream header and metadata from the inner command.
    inner = encode_firmware_command(payload)[8:]
    print(f"\n[{a.port}] $ nan payload=<CBOR {payload!r}>")
    out = a.cbor_cmd_payload("nan", inner)
    print(out.rstrip())
    if "queued=true" not in out:
        raise RuntimeError(f"raw NAN command was not queued: {out}")
    time.sleep(settle_sec)
    a1 = nan_stats(a)
    b1 = nan_stats(b)
    assert_counter_increased(b0, b1, "raw_cmd_rx", f"raw receiver after {payload}")
    if expect_response:
        assert_counter_increased(b0, b1, "raw_resp_tx", f"raw receiver response after {payload}")
        assert_counter_increased(a0, a1, "raw_resp_rx", f"raw sender response after {payload}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a", required=True, help="First ESP serial port")
    parser.add_argument("--b", required=True, help="Second ESP serial port")
    parser.add_argument("--a-mac", help="First ESP Wi-Fi MAC, required for raw b->a tests")
    parser.add_argument("--b-mac", help="Second ESP Wi-Fi MAC, required for raw a->b tests")
    parser.add_argument("--backend", choices=["raw"], default="raw")
    parser.add_argument("--stop", action="append", default=[], help="Extra ESP port to stop NAN on")
    parser.add_argument("--channel", type=int, default=6)
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--settle-sec", type=float, default=1.0)
    parser.add_argument("--no-expect-response", action="store_true")
    parser.add_argument("--keep-lora", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for port in args.stop:
        stop_extra(port, args.baud, args.timeout)

    a = Console(args.a, args.baud, args.timeout)
    b = Console(args.b, args.baud, args.timeout)
    try:
        start_pair(a, b, args.channel, args.backend, not args.keep_lora)
        if not args.a_mac or not args.b_mac:
            raise RuntimeError("--a-mac and --b-mac are required for raw NAN")
        wait_for_raw_discovery(a, b, args.timeout)

        expect_response = not args.no_expect_response
        for idx in range(args.iterations):
            run_raw_command_round(
                a,
                b,
                "status",
                args.a_mac,
                args.b_mac,
                args.channel,
                expect_response,
                args.settle_sec,
            )
            run_raw_command_round(
                a,
                b,
                "radio status=true",
                args.a_mac,
                args.b_mac,
                args.channel,
                expect_response,
                args.settle_sec,
            )

        print(f"\nNAN {args.backend} command/response OK iterations={args.iterations}")
        return 0
    finally:
        a.close()
        b.close()


if __name__ == "__main__":
    raise SystemExit(main())
