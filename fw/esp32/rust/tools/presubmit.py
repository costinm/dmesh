#!/usr/bin/env python3
"""Run the ESP firmware hardware pre-submit suite through local mesh sockets."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
PYTHON = REPO / "python"
sys.path.insert(0, str(PYTHON))

from dmesh.lab import LabConfig  # noqa: E402
from dmesh.presubmit import PresubmitSuite  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", required=True, help="JSON lab topology")
    parser.add_argument("--profile", choices=["quick", "full", "stress"], default="quick")
    parser.add_argument(
        "--case",
        action="append",
        choices=["uart_wake_reliability", "command_reliability", "active_transfer_window", "nan_pair", "beacon_sync", "ap_sync", "lora_pair", "lora_cad"],
        help="Run only the named scenario; inventory, power capture, and restore still run.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=12.0,
        help="Per-command timeout; must cover a four-second duty wake plus response.",
    )
    parser.add_argument(
        "--artifacts",
        help="Result directory; defaults under target/esp32-presubmit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    artifacts = args.artifacts or str(REPO / "target" / "esp32-presubmit" / stamp)
    suite = PresubmitSuite(
        LabConfig.load(args.topology),
        artifacts,
        profile=args.profile,
        timeout=args.timeout,
    )
    try:
        summary = suite.run(selected=args.case)
    except Exception as error:  # Report the artifact path on every failure.
        print("FAIL artifacts={} error={}".format(artifacts, error), file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("PASS artifacts={}".format(artifacts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
