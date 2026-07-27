#!/usr/bin/env python3
"""Measure SX127x CAD receive intervals against continuous RX delivery and power."""

from __future__ import annotations

import argparse
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from dmesh.lab import (
    ArtifactWriter,
    LabNode,
    NodeConfig,
    PowerCollector,
    PowerMeterConfig,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", default="lora2.lmesh")
    parser.add_argument("--sender", default="lora1.lmesh")
    parser.add_argument("--meter", default="power1.lmesh")
    parser.add_argument("--intervals-ms", default="5,10,15")
    parser.add_argument("--idle-sec", type=float, default=30.0)
    parser.add_argument(
        "--settle-sec",
        type=float,
        default=22.0,
        help="Wait for the receiver UART active window to expire before measuring",
    )
    parser.add_argument("--frames", type=int, default=4)
    parser.add_argument("--spacing-sec", type=float, default=1.0)
    parser.add_argument("--post-send-sec", type=float, default=3.0)
    parser.add_argument("--cad-rx-ms", type=int, default=1000)
    parser.add_argument("--frequency", type=int, default=913_125_000)
    parser.add_argument(
        "--power-profile",
        default="auto",
        choices=("auto", "dfs"),
        help="Receiver PM profile; auto enables automatic light sleep",
    )
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--boot-wait-sec", type=float, default=8.0)
    parser.add_argument("--no-reset", action="store_true")
    parser.add_argument("--no-restore", action="store_true")
    parser.add_argument(
        "--output",
        help="Artifact directory (default: target/esp32-lora-power/<UTC timestamp>)",
    )
    return parser.parse_args()


def fields(result, record_type: str) -> dict:
    return result.record(record_type)["fields"]


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def summarize_samples(samples) -> dict:
    if not samples:
        return {"count": 0}
    currents = [sample.current_ma for sample in samples]
    return {
        "count": len(samples),
        "duration_sec": round(
            (samples[-1].received_unix_ms - samples[0].received_unix_ms) / 1000.0,
            3,
        ),
        "mean_ma": round(statistics.mean(currents), 3),
        "min_ma": round(min(currents), 3),
        "p50_ma": round(percentile(currents, 0.50), 3),
        "p95_ma": round(percentile(currents, 0.95), 3),
        "max_ma": round(max(currents), 3),
        "energy_delta": round(
            samples[-1].energy_counter - samples[0].energy_counter, 6
        ),
        "wakeup_delta": samples[-1].wakeups - samples[0].wakeups,
    }


def sleep_residency(before: dict, after: dict) -> dict:
    tracked_us = max(
        0,
        int(after.get("ls_tracked_us", 0))
        - int(before.get("ls_tracked_us", 0)),
    )
    slept_us = max(
        0, int(after.get("ls_us", 0)) - int(before.get("ls_us", 0))
    )
    slept_us = min(slept_us, tracked_us)
    return {
        "attempts": max(
            0,
            int(after.get("ls_attempts", 0))
            - int(before.get("ls_attempts", 0)),
        ),
        "entries": max(
            0,
            int(after.get("ls_entries", 0)) - int(before.get("ls_entries", 0)),
        ),
        "skipped": max(
            0,
            int(after.get("ls_skipped", 0)) - int(before.get("ls_skipped", 0)),
        ),
        "tracked_us": tracked_us,
        "slept_us": slept_us,
        "awake_us": tracked_us - slept_us,
        "sleep_pct": round(slept_us * 100.0 / tracked_us, 3) if tracked_us else 0.0,
        "max_us": int(after.get("ls_max_us", 0)),
    }


def mode_name(interval_ms: int | None) -> str:
    return "continuous" if interval_ms is None else "cad_{}ms".format(interval_ms)


def configure_quiet(
    node: LabNode,
    frequency: int,
    power_profile: str,
    timeout: float,
    wake_first: bool | str = False,
) -> None:
    commands = (
        "ble companion=false",
        "ble stop=true",
        "nan stop=true",
        "wifi mode=off",
        "power profile={}".format(power_profile),
        "lora rx=false",
        "lora preset=medium_fast freq={} apply=true".format(frequency),
    )
    for index, command in enumerate(commands):
        node.command(
            command,
            timeout=timeout,
            wake=wake_first if index == 0 else False,
        )


def restore_node(node: LabNode, timeout: float, wake: bool | str = True) -> None:
    commands = (
        "power profile=dfs",
        "lora rx=false",
        "lora cad_rx=true cad_tx=true cad_interval_ms=2000 cad_rx_ms=1000 cad_tx_tries=4",
        "nan start=true backend=raw role=both service=dmesh channel=6",
        "lora rx=true",
    )
    for index, command in enumerate(commands):
        node.command(command, timeout=timeout, wake=wake if index == 0 else False)


def write_tldr(path: Path, manifest: dict, modes: list[dict]) -> None:
    lines = [
        "# SX127x LoRa RX Power Matrix",
        "",
        "Receiver `{}` was measured by `{}` after NAN, Wi-Fi, and BLE were stopped.".format(
            manifest["receiver"], manifest["meter"]
        ),
        "Power profile `{}` was verified before each mode. Each mode used a {:.0f} s UART settle, {:.0f} s idle sample, and {} transmitted frames.".format(
            manifest["power_profile"],
            manifest["settle_sec"],
            manifest["idle_sec"],
            manifest["frames"],
        ),
        "",
        "| Mode | Idle mean mA | p50 | p95 | Sleep | Entries | RX/sent | Delivery | CAD detections |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in modes:
        power = result["idle_power"]
        sent = result["sent"]
        received = result["received"]
        ratio = received / sent if sent else 0.0
        lines.append(
            "| {mode} | {mean} | {p50} | {p95} | {sleep}% | {entries} | {rx}/{sent} | {ratio:.0%} | {cad} |".format(
                mode=result["mode"],
                mean=power.get("mean_ma", "n/a"),
                p50=power.get("p50_ma", "n/a"),
                p95=power.get("p95_ma", "n/a"),
                sleep=result.get("sleep_residency", {}).get("sleep_pct", "n/a"),
                entries=result.get("sleep_residency", {}).get("entries", "n/a"),
                rx=received,
                sent=sent,
                ratio=ratio,
                cad=result.get("cad_detected", "n/a"),
            )
        )
    lines.extend(
        [
            "",
            "Raw meter samples are in `power/power1.jsonl`; command transcripts are in `commands/`.",
            "The meter energy counter is preserved as reported because its unit is meter-specific.",
            "",
        ]
    )
    path.write_text("\n".join(lines))


def main() -> int:
    args = parse_args()
    intervals = [int(value) for value in args.intervals_ms.split(",") if value]
    if any(value < 5 for value in intervals):
        raise ValueError("firmware clamps CAD intervals below 5 ms")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(args.output or "target/esp32-lora-power/{}".format(run_id))
    artifacts = ArtifactWriter(output)
    receiver = LabNode(
        NodeConfig("receiver", args.receiver, capabilities=["lora"]),
        artifacts,
        timeout=args.timeout,
    )
    sender = LabNode(
        NodeConfig("sender", args.sender, capabilities=["lora"]),
        artifacts,
        timeout=args.timeout,
    )
    meter = PowerCollector(
        PowerMeterConfig("power1", args.meter, "receiver", required=True), artifacts
    )
    manifest = {
        "run_id": run_id,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "receiver": args.receiver,
        "sender": args.sender,
        "meter": args.meter,
        "intervals_ms": intervals,
        "continuous_rx": True,
        "idle_sec": args.idle_sec,
        "settle_sec": args.settle_sec,
        "frames": args.frames,
        "spacing_sec": args.spacing_sec,
        "post_send_sec": args.post_send_sec,
        "cad_rx_ms": args.cad_rx_ms,
        "frequency": args.frequency,
        "power_profile": args.power_profile,
        "nan_wifi_ble_disabled": True,
    }
    artifacts.write_json("manifest.json", manifest)
    meter.start()
    results = []
    failure = None
    try:
        if not args.no_reset:
            print("Resetting receiver and sender; waiting for boot windows", flush=True)
            receiver.radio.reset(timeout=args.timeout)
            sender.radio.reset(timeout=args.timeout)
            time.sleep(args.boot_wait_sec)

        print("Disabling NAN, Wi-Fi, BLE, and background RX", flush=True)
        configure_quiet(
            receiver,
            args.frequency,
            args.power_profile,
            args.timeout,
        )
        configure_quiet(
            sender, args.frequency, "dfs", args.timeout, wake_first=True
        )
        sender.command("lora cad_tx=false", timeout=args.timeout)

        for mode_index, interval_ms in enumerate([*intervals, None]):
            name = mode_name(interval_ms)
            print("\n=== {} ===".format(name), flush=True)
            meter.set_phase(name + ".configure")
            receiver.command(
                "lora rx=false",
                timeout=args.timeout,
                wake=True if mode_index else False,
            )
            baseline_stats = fields(
                receiver.command("stats reset=true", timeout=args.timeout), "stats"
            )
            if interval_ms is None:
                receiver.command("lora cad_rx=false", timeout=args.timeout)
                baseline_lora = {}
            else:
                baseline_lora = fields(
                    receiver.command(
                        "lora cad_rx=true cad_interval_ms={} cad_rx_ms={} cad_tx_tries=0".format(
                            interval_ms, args.cad_rx_ms
                        ),
                        timeout=args.timeout,
                    ),
                    "lora",
                )
            receiver.command("lora rx=true", timeout=args.timeout)
            power_before = fields(
                receiver.command("power status=true", timeout=args.timeout), "power"
            )
            if args.power_profile == "auto" and power_before.get("light") is not True:
                raise RuntimeError(
                    "receiver did not enable automatic light sleep: {}".format(power_before)
                )
            # Keep this stream open but passive. Reconnecting after the sample
            # pulses DTR in lmesh and obscures whether the board reset during
            # the sample or while being woken for counter collection.
            receiver.radio.read_available(duration=0.05)

            meter.set_phase(name + ".settle")
            print("settling {:.0f}s for UART window".format(args.settle_sec), flush=True)
            time.sleep(args.settle_sec)
            meter.set_phase(name + ".idle")
            print("measuring idle {:.0f}s".format(args.idle_sec), flush=True)
            time.sleep(args.idle_sec)

            meter.set_phase(name + ".traffic")
            sent_packet_ids = []
            for sequence in range(1, args.frames + 1):
                payload = "rxpower_{}_{}_{}".format(run_id, name, sequence)
                sent = sender.command(
                    "lorasend text={} hop=0".format(payload),
                    timeout=args.timeout,
                    wake=True,
                )
                sent_packet_ids.append(int(fields(sent, "lorasend")["n"]))
                print("sent {}/{}".format(sequence, args.frames), flush=True)
                time.sleep(args.spacing_sec)
            time.sleep(args.post_send_sec)

            meter.set_phase(name + ".control")
            passive_output = receiver.radio.read_available(duration=0.25)
            artifacts.append_jsonl(
                "passive/{}.jsonl".format(receiver.config.name),
                {
                    "ts_unix_ms": int(time.time() * 1000),
                    "phase": name,
                    "raw": passive_output,
                },
            )
            boot_markers = (
                "rst:0x",
                "boot: ESP-IDF",
                "boot: Partition Table",
                "dm-rs boot step=wake",
            )
            if any(marker in passive_output for marker in boot_markers):
                raise RuntimeError(
                    "receiver rebooted during {} measurement; passive tail={!r}".format(
                        name, passive_output[-600:]
                    )
                )
            power_after = fields(
                receiver.command(
                    "power status=true", timeout=args.timeout, wake=True
                ),
                "power",
            )
            stats = fields(
                receiver.command("stats", timeout=args.timeout), "stats"
            )
            raw_received = int(stats.get("lora_rx", 0)) - int(
                baseline_stats.get("lora_rx", 0)
            )
            received_packet_ids = []
            if raw_received > 0:
                messages = receiver.command(
                    "messages count=32 max_bytes=16000",
                    timeout=args.timeout,
                    expected="msg",
                )
                received_packet_ids = [
                    int(record["fields"]["n"])
                    for record in messages.records
                    if record["type"] == "msg"
                    and record["fields"].get("t") == "lora"
                    and record["fields"].get("dir") == "rx"
                    and isinstance(record["fields"].get("n"), int)
                ]
            receiver.command("lora rx=false", timeout=args.timeout)
            lora = fields(
                receiver.command("lora status=true", timeout=args.timeout), "lora"
            )
            matched_packet_ids = sorted(
                set(sent_packet_ids).intersection(received_packet_ids)
            )
            received = len(matched_packet_ids)
            mode_result = {
                "mode": name,
                "cad_interval_ms": interval_ms,
                "sent": args.frames,
                "received": received,
                "delivery_ratio": received / args.frames if args.frames else 0.0,
                "sent_packet_ids": sent_packet_ids,
                "received_packet_ids": received_packet_ids,
                "matched_packet_ids": matched_packet_ids,
                "raw_lora_rx_delta": raw_received,
                "cad_samples": (
                    int(lora.get("cad_samples", 0))
                    - int(baseline_lora.get("cad_samples", 0))
                    if interval_ms is not None
                    else None
                ),
                "cad_detected": (
                    int(lora.get("cad_detected", 0))
                    - int(baseline_lora.get("cad_detected", 0))
                    if interval_ms is not None
                    else None
                ),
                "power_before": power_before,
                "power_after": power_after,
                "sleep_residency": sleep_residency(power_before, power_after),
                "stats": stats,
                "lora": lora,
                "idle_power": summarize_samples(
                    meter.phase_samples.get(name + ".idle", [])
                ),
                "traffic_power": summarize_samples(
                    meter.phase_samples.get(name + ".traffic", [])
                ),
            }
            results.append(mode_result)
            artifacts.write_json("results.json", results)
            print(
                "result mode={} idle_mean_ma={} received={}/{} cad_detected={}".format(
                    name,
                    mode_result["idle_power"].get("mean_ma"),
                    received,
                    args.frames,
                    mode_result["cad_detected"],
                ),
                flush=True,
            )
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error)}
        artifacts.write_json("failure.json", failure)
        raise
    finally:
        meter.set_phase("restore")
        if not args.no_restore:
            for node in (receiver, sender):
                try:
                    restore_node(
                        node,
                        args.timeout,
                        wake=True,
                    )
                except Exception as error:
                    artifacts.append_jsonl(
                        "restore-errors.jsonl",
                        {"node": node.config.name, "error": str(error)},
                    )
        receiver.close()
        sender.close()
        meter.stop()
        summary = {
            "manifest": manifest,
            "results": results,
            "power": meter.summary(),
            "failure": failure,
        }
        artifacts.write_json("summary.json", summary)
        write_tldr(output / "TLDR.md", manifest, results)
        print("artifacts={}".format(output), flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
