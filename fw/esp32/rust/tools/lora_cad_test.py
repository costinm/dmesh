#!/usr/bin/env python3
"""Regression test for LoRa CAD receive between two ESP32 firmware consoles."""

from __future__ import annotations

import argparse
import re
import time

from serial_cmd import Console


PROMPT = b"dm-rs> "


def require_ok(output: str, context: str) -> None:
    text = output.strip()
    if text.startswith("error ") or "\nerror " in text:
        raise RuntimeError(f"{context} returned error")


def run(console: Console, command: str, timeout: float | None = None) -> str:
    print(f"[{console.port}] $ {command}", flush=True)
    out = console.cmd(command, timeout)
    print(out.rstrip(), flush=True)
    return out


def value_for(text: str, key: str) -> int:
    matches = re.findall(rf"\b{re.escape(key)}=(-?\d+)\b", text)
    return int(matches[-1]) if matches else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rx", required=True, help="Receiver serial port")
    parser.add_argument("--tx", required=True, help="Sender serial port")
    parser.add_argument("--packets", type=int, default=8)
    parser.add_argument("--spacing", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--freq", type=int, default=913_125_000)
    parser.add_argument("--bw", type=int, default=250_000)
    parser.add_argument("--sf", type=int, default=9)
    parser.add_argument("--cr", type=int, default=5)
    parser.add_argument("--sync-word", default="0x2b")
    parser.add_argument("--preamble", type=int, default=16)
    parser.add_argument("--cad-interval-ms", type=int, default=2000)
    parser.add_argument("--cad-rx-ms", type=int, default=1000)
    parser.add_argument("--min-rx", type=int, default=1)
    parser.add_argument(
        "--expect-all",
        action="store_true",
        help="Require every sent packet to be received.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rx = Console(args.rx, 460800, args.timeout)
    tx = Console(args.tx, 460800, args.timeout)
    try:
        print("[rx] sync")
        print(rx.sync().rstrip())
        print("[tx] sync")
        print(tx.sync().rstrip())

        base_config = (
            f"lora freq={args.freq} bw={args.bw} sf={args.sf} cr={args.cr} "
            f"sync_word={args.sync_word} preamble={args.preamble} crc=true apply=true"
        )
        for console, context in [(rx, "rx config"), (tx, "tx config")]:
            require_ok(run(console, "lora rx=false", args.timeout), f"{context} stop")
            require_ok(run(console, base_config, args.timeout), context)

        require_ok(run(rx, "stats reset=true", args.timeout), "stats reset")
        require_ok(
            run(
                rx,
                "lora cad_interval_ms={} cad_rx_ms={} cad_tx_tries=4".format(
                    args.cad_interval_ms, args.cad_rx_ms
                ),
                args.timeout,
            ),
            "cad config",
        )
        require_ok(run(rx, "lora rx=true", args.timeout), "rx start")
        time.sleep(0.5)

        for idx in range(1, args.packets + 1):
            payload = f"cad16_{int(time.time())}_{idx}"
            require_ok(run(tx, f"lorasend text={payload} hop=0", args.timeout), "tx send")
            time.sleep(args.spacing)

        status = run(rx, "lora status=true", args.timeout)
        stats = run(rx, "stats", args.timeout)
        require_ok(status, "rx status")
        require_ok(stats, "rx stats")

        detected = value_for(status, "cad_detected")
        received = value_for(stats, "lora_rx")
        print(
            f"summary sent={args.packets} cad_detected={detected} lora_rx={received}",
            flush=True,
        )
        if args.expect_all and received != args.packets:
            raise RuntimeError(f"expected {args.packets} packets, received {received}")
        if received < args.min_rx:
            raise RuntimeError(f"expected at least {args.min_rx} packets, received {received}")
        print("PASS")
        return 0
    finally:
        rx.close()
        tx.close()


if __name__ == "__main__":
    raise SystemExit(main())
