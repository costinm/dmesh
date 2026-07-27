#!/usr/bin/env python3
"""Summarize append-only lmesh LoRa stability JSONL for hourly review."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


DEFAULT_LOG = Path("target/lmesh-radio-build/log/lora-stability.jsonl")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--last", type=int, help="only summarize the last N cycles")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    rows = [json.loads(line) for line in args.log.read_text().splitlines() if line.strip()]
    if args.last:
        rows = rows[-args.last :]
    roles = Counter()
    observed = Counter()
    missing = Counter()
    rssi = defaultdict(list)
    snr = defaultdict(list)
    uptime_regressions = []
    last_uptime = {}
    unresolved = 0
    for row in rows:
        result = row.get("last", {})
        expected = result.get("expected", {})
        for role, mac in expected.items():
            roles[role] += 1
            if mac is None:
                unresolved += 1
        by_mac = {mac: role for role, mac in expected.items() if mac}
        for pong in result.get("observed", []):
            mac = pong.get("from", "unknown")
            role = by_mac.get(mac, mac)
            observed[role] += 1
            for name, target in (("link_rssi_dbm", rssi), ("snr", snr)):
                try:
                    target[role].append(float(pong[name]))
                except (KeyError, TypeError, ValueError):
                    pass
            try:
                uptime = int(pong["uptime_ms"])
            except (KeyError, TypeError, ValueError):
                continue
            if role in last_uptime and uptime < last_uptime[role]:
                uptime_regressions.append({"role": role, "before": last_uptime[role], "after": uptime})
            last_uptime[role] = uptime
        for role in result.get("missing", []):
            missing[role] += 1
    devices = {}
    for role in sorted(set(roles) | set(observed) | set(missing)):
        devices[role] = {
            "expected_cycles": roles[role],
            "observed_pongs": observed[role],
            "reported_missing": missing[role],
            "delivery_ratio": round(observed[role] / roles[role], 4) if roles[role] else None,
            "rssi_dbm": summary(rssi[role]),
            "snr": summary(snr[role]),
        }
    result = {
        "cycles": len(rows),
        "first_completed_ms": rows[0].get("last_completed_ms") if rows else None,
        "last_completed_ms": rows[-1].get("last_completed_ms") if rows else None,
        "unresolved_role_samples": unresolved,
        "uptime_regressions": uptime_regressions,
        "devices": devices,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if uptime_regressions else 0


def summary(values):
    if not values:
        return None
    return {"min": min(values), "mean": round(sum(values) / len(values), 2), "max": max(values)}


if __name__ == "__main__":
    raise SystemExit(main())
