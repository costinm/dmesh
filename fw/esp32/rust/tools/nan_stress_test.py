#!/usr/bin/env python3
"""Run repeatable NAN firmware stress tests.

This is a thin orchestrator around nan_pair_test.py. It keeps the low-level
pair checks focused while making longer runs easy to reproduce from CI, tmux, or
another agent.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
PAIR_TEST = THIS_DIR / "nan_pair_test.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a", required=True, help="Sender serial port")
    parser.add_argument("--b", required=True, help="Receiver serial port")
    parser.add_argument("--a-mac", required=True, help="Sender Wi-Fi MAC for from= suffix")
    parser.add_argument("--b-mac", required=True, help="Receiver Wi-Fi MAC for raw NAN")
    parser.add_argument("--channel", type=int, default=6)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--batch", type=int, default=20)
    parser.add_argument("--settle-sec", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--backend", choices=["raw"], default="raw")
    parser.add_argument("--pause-sec", type=float, default=1.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    remaining = args.iterations
    batch_idx = 0
    started = time.monotonic()
    while remaining > 0:
        count = min(args.batch, remaining)
        batch_idx += 1
        print(
            f"nan stress batch={batch_idx} iterations={count} remaining={remaining - count}",
            flush=True,
        )
        subprocess.run(
            [
                sys.executable,
                str(PAIR_TEST),
                "--backend",
                args.backend,
                "--a",
                args.a,
                "--b",
                args.b,
                "--a-mac",
                args.a_mac,
                "--b-mac",
                args.b_mac,
                "--channel",
                str(args.channel),
                "--iterations",
                str(count),
                "--settle-sec",
                str(args.settle_sec),
                "--timeout",
                str(args.timeout),
            ],
            check=True,
        )
        remaining -= count
        if remaining > 0 and args.pause_sec > 0:
            time.sleep(args.pause_sec)
    elapsed = time.monotonic() - started
    print(f"nan stress OK iterations={args.iterations} elapsed_sec={elapsed:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
