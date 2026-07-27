#!/usr/bin/env python3
"""Probe likely battery ADC pins on ESP32 firmware devices."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


DEFAULT_ADC1_PINS = "32,33,34,35,36,39"
DEFAULT_ADC2_PINS = "1,2,4,12,13,14,15,25,26,27"


def run_serial_cmd(port: str, commands: list[str], timeout: float) -> str:
    cmd = [
        sys.executable,
        "tools/serial_cmd.py",
        "--port",
        port,
        "--timeout",
        str(timeout),
    ]
    for command in commands:
        cmd.extend(["--cmd", command])
    proc = subprocess.run(
        cmd,
        cwd=".",
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.stdout


def max_mv(output: str) -> int:
    values = [int(match) for match in re.findall(r"gpio\d+_mv=(\d+)", output)]
    return max(values) if values else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", action="append", required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--interval-ms", type=int, default=200)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--adc1-pins", default=DEFAULT_ADC1_PINS)
    parser.add_argument("--adc2-pins", default=DEFAULT_ADC2_PINS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rc = 0
    for port in args.port:
        commands = [
            "adcprobe pins={} interval_ms={} count={}".format(
                args.adc1_pins, args.interval_ms, args.count
            ),
            "adcprobe pins={} interval_ms={} count=1".format(
                args.adc2_pins, args.interval_ms
            ),
            "battery status=true",
        ]
        output = run_serial_cmd(port, commands, args.timeout)
        print(output.rstrip())
        peak = max_mv(output)
        if peak < 100:
            print(f"{port}: no ADC pin above 100 mV; battery voltage not found")
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
