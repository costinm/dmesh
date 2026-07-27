#!/usr/bin/env python3
"""Run and summarize managed LoRa and host-NAN discovery stability checks."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / "python"))

from dmesh.client import MeshClient  # noqa: E402


def response_data(response):
    if response.get("success") is False:
        raise RuntimeError(response.get("error", response))
    return response.get("data", response.get("result", response))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="lora1")
    parser.add_argument("--expected", help="comma-separated LoRa role names")
    parser.add_argument("--interval-sec", type=int, default=120)
    parser.add_argument("--wait-sec", type=int, default=12)
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument(
        "--no-host-nan",
        action="store_false",
        dest="host_nan",
        help="skip the host WPA NAN/USD CBOR command and reply-path check",
    )
    parser.set_defaults(host_nan=True)
    parser.add_argument("--timeout-sec", type=float, default=90.0)
    parser.add_argument("--artifacts", help="optional JSON result path")
    return parser.parse_args()


def main():
    args = parse_args()
    params = {
        "source": args.source,
        "interval_sec": args.interval_sec,
        "wait_sec": args.wait_sec,
        "cycles": args.cycles,
        "host_nan": args.host_nan,
    }
    if args.expected:
        params["expected"] = args.expected
    with MeshClient("lmesh") as client:
        response_data(client.request("esp.stability.start", params))
        deadline = time.monotonic() + args.timeout_sec
        while time.monotonic() < deadline:
            status = response_data(client.request("esp.stability.status"))
            if not status.get("running") and status.get("cycles_completed", 0) >= args.cycles:
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("stability runner did not finish within {} seconds".format(args.timeout_sec))
    last = status.get("last") or {}
    host_nan = last.get("host_nan")
    host_nan_ok = bool(host_nan and host_nan.get("response_observed"))
    result = {
        "ok": bool(last.get("ok")) and (not args.host_nan or host_nan_ok),
        "cycles_completed": status.get("cycles_completed", 0),
        "source": status.get("source"),
        "expected": last.get("expected", {}),
        "observed": last.get("observed", []),
        "missing": last.get("missing", []),
        "host_nan": host_nan,
        "host_nan_ok": host_nan_ok if args.host_nan else None,
        "raw": status,
    }
    if args.artifacts:
        target = Path(args.artifacts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
