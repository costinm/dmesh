#!/usr/bin/env python3
"""Characterize major ESP32 firmware power modes through lmesh and a meter."""

from __future__ import annotations

import argparse
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from dmesh.lab import ArtifactWriter, LabNode, NodeConfig, PowerCollector, PowerMeterConfig


BASE_COMMANDS = (
    "ble companion=false",
    "ble stop=true",
    "nan stop=true",
    "wifi mode=off",
    "lora rx=false",
)

PROFILES = {
    "light_sleep": ("power profile=auto",),
    "light_raw_nan": ("power profile=auto", "mode raw_nan=true lora=false channel=6"),
    "active": ("power profile=dfs",),
    "active_wifi": ("power profile=dfs", "wifi mode=raw channel=6 filter=dmesh"),
    "active_ble": ("power profile=dfs", "ble start=true"),
    "active_lora_rx": ("power profile=dfs", "lora cad_rx=false", "lora rx=true"),
    "light_lora_rx": ("power profile=auto", "lora cad_rx=false", "lora rx=true"),
    "light_lora_cad": (
        "power profile=auto",
        "lora cad_rx=true cad_interval_ms=5 cad_rx_ms=1000 cad_tx_tries=0",
        "lora rx=true",
    ),
}

BOOT_MARKERS = ("rst:0x", "boot: ESP-IDF", "boot: Partition Table", "dm-rs boot step=wake")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    # lora1 is the board wired through the power meter (power1). Keep this
    # explicit: logical roles are stable while /dev/ttyUSB numbering is not.
    parser.add_argument("--device", default="lora1.lmesh")
    parser.add_argument("--meter", default="power1.lmesh")
    parser.add_argument("--profiles", default=",".join(PROFILES))
    parser.add_argument("--settle-sec", type=float, default=2.0)
    parser.add_argument("--sample-sec", type=float, default=30.0)
    parser.add_argument("--boot-wait-sec", type=float, default=8.0)
    parser.add_argument(
        "--no-reset",
        action="store_true",
        help="Use an already-running firmware console instead of issuing lmesh rst.",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output")
    return parser.parse_args()


def fields(result, record_type: str) -> dict:
    return result.record(record_type)["fields"]


def summarize(samples) -> dict:
    if not samples:
        return {"count": 0}
    values = sorted(sample.current_ma for sample in samples)
    index = lambda fraction: values[round((len(values) - 1) * fraction)]
    return {
        "count": len(values),
        "mean_ma": round(statistics.mean(values), 3),
        "min_ma": values[0],
        "p50_ma": index(0.50),
        "p95_ma": index(0.95),
        "max_ma": values[-1],
        "energy_delta": samples[-1].energy_counter - samples[0].energy_counter,
        "meter_wakeup_delta": samples[-1].wakeups - samples[0].wakeups,
    }


def residency(before: dict, after: dict) -> dict:
    tracked = max(0, int(after.get("ls_tracked_us", 0)) - int(before.get("ls_tracked_us", 0)))
    slept = max(0, int(after.get("ls_us", 0)) - int(before.get("ls_us", 0)))
    slept = min(slept, tracked)
    return {
        "attempts": max(0, int(after.get("ls_attempts", 0)) - int(before.get("ls_attempts", 0))),
        "entries": max(0, int(after.get("ls_entries", 0)) - int(before.get("ls_entries", 0))),
        "tracked_us": tracked,
        "slept_us": slept,
        "awake_us": tracked - slept,
        "sleep_pct": round(100.0 * slept / tracked, 3) if tracked else 0.0,
    }


def write_tldr(path: Path, results: list[dict]) -> None:
    lines = [
        "# ESP32 Power Mode Matrix",
        "",
        "| Profile | Mean mA | p50 | p95 | Light sleep | Entries |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        power = result["power"]
        sleep = result["sleep_residency"]
        lines.append(
            "| {profile} | {mean} | {p50} | {p95} | {pct}% | {entries} |".format(
                profile=result["profile"],
                mean=power.get("mean_ma", "n/a"),
                p50=power.get("p50_ma", "n/a"),
                p95=power.get("p95_ma", "n/a"),
                pct=sleep["sleep_pct"],
                entries=sleep["entries"],
            )
        )
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    args = parse_args()
    selected = [name for name in args.profiles.split(",") if name]
    unknown = sorted(set(selected) - set(PROFILES))
    if unknown:
        raise ValueError("unknown profiles: {}".format(",".join(unknown)))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(args.output or "target/esp32-power-matrix/{}".format(stamp))
    artifacts = ArtifactWriter(output)
    node = LabNode(NodeConfig("device", args.device), artifacts, timeout=args.timeout)
    meter = PowerCollector(PowerMeterConfig("power1", args.meter, "device", required=True), artifacts)
    manifest = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "device": args.device,
        "meter": args.meter,
        "profiles": selected,
        "settle_sec": args.settle_sec,
        "sample_sec": args.sample_sec,
        "reset": not args.no_reset,
    }
    artifacts.write_json("manifest.json", manifest)
    results = []
    failure = None
    meter.start()
    try:
        if args.no_reset:
            # The caller is responsible for opening the UART window first.
            # Do not pulse DTR here: some USB-UART/reset circuits interpret it
            # as EN rather than PRG and restart the board.
            node.command("status", timeout=args.timeout)
        else:
            node.radio.reset(timeout=args.timeout)
            time.sleep(args.boot_wait_sec)
        for index, profile in enumerate(selected):
            print("=== {} ===".format(profile), flush=True)
            meter.set_phase(profile + ".configure")
            for command_index, command in enumerate((*BASE_COMMANDS, *PROFILES[profile])):
                node.command(
                    command,
                    timeout=args.timeout,
                    wake=True if index and command_index == 0 else False,
                )
            node.command("stats reset=true", timeout=args.timeout)
            before = fields(node.command("power status=true", timeout=args.timeout), "power")
            node.command("power quiet=true", timeout=args.timeout)
            node.radio.read_available(0.05)
            meter.set_phase(profile + ".settle")
            time.sleep(args.settle_sec)
            meter.set_phase(profile + ".sample")
            time.sleep(args.sample_sec)
            meter.set_phase(profile + ".control")
            passive = node.radio.read_available(0.25)
            artifacts.append_jsonl(
                "passive/device.jsonl",
                {"ts_unix_ms": int(time.time() * 1000), "profile": profile, "raw": passive},
            )
            if any(marker in passive for marker in BOOT_MARKERS):
                raise RuntimeError("device rebooted during {}: {!r}".format(profile, passive[-600:]))
            node.radio.wake(timeout=args.timeout)
            after = fields(node.command("power status=true", timeout=args.timeout), "power")
            locks = node.command("power locks=true", timeout=args.timeout)
            result = {
                "profile": profile,
                "commands": list(PROFILES[profile]),
                "power": summarize(meter.phase_samples.get(profile + ".sample", [])),
                "sleep_residency": residency(before, after),
                "power_before": before,
                "power_after": after,
                "pm_locks": locks.raw,
                "status": fields(node.command("status", timeout=args.timeout), "status"),
                "stats": fields(node.command("stats", timeout=args.timeout), "stats"),
                "radio_status": {
                    "ble": fields(node.command("ble", timeout=args.timeout), "ble"),
                    "wifi": fields(node.command("wifi", timeout=args.timeout), "wifi"),
                    "lora": fields(
                        node.command("lora status=true", timeout=args.timeout), "lora"
                    ),
                },
            }
            results.append(result)
            artifacts.write_json("results.json", results)
            print(
                "result profile={} mean_ma={} sleep_pct={}".format(
                    profile, result["power"].get("mean_ma"), result["sleep_residency"]["sleep_pct"]
                ),
                flush=True,
            )
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        try:
            node.radio.reset(timeout=args.timeout)
        except Exception as error:
            artifacts.append_jsonl("restore-errors.jsonl", {"error": str(error)})
        node.close()
        meter.stop()
        artifacts.write_json(
            "summary.json",
            {"manifest": manifest, "results": results, "power": meter.summary(), "failure": failure},
        )
        write_tldr(output / "TLDR.md", results)
        print("artifacts={}".format(output), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
