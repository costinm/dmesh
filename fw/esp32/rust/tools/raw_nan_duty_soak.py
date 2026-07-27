#!/usr/bin/env python3
"""Exercise raw-NAN duty light sleep with traffic, console checks, and a meter.

The sender uses the firmware's persistent ``test cnt=...`` generator.  It
queues each ping for the next raw-NAN active window, so this checks the path
used when a device sleeps with Wi-Fi off between discovery windows.
"""

from __future__ import annotations

import argparse
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from dmesh.lab import ArtifactWriter, PowerCollector, PowerMeterConfig
from dmesh.radio import RadioClient


RAW_NAN_SETTINGS = (
    "nvs op=set mode=infra wifi.mode=nan power.profile=auto "
    "nan.backend=raw nan.boot=true nan.role=both nan.service=dmesh nan.channel={channel} "
    "nan.wake_ms={wake_ms} nan.active_ms={active_ms} nan.light_sleep=true "
    "nan.early_ms=5 nan.dw_tu=512 nan.dw_off_tu=0 lora.enabled=false"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", default="lora1.lmesh")
    parser.add_argument("--receiver", default="lora2.lmesh")
    parser.add_argument("--meter", default="power1.lmesh")
    parser.add_argument("--channel", type=int, default=6)
    parser.add_argument("--wake-ms", type=int, default=4000)
    parser.add_argument("--active-ms", type=int, default=250)
    parser.add_argument("--duration-sec", type=float, default=80.0)
    parser.add_argument(
        "--quiet-settle-sec",
        type=float,
        default=22.0,
        help="Exclude the post-console UART active window from the traffic power phase.",
    )
    parser.add_argument(
        "--console-interval-sec",
        type=float,
        default=25.0,
        help="Periodic status cadence; zero disables interim console checks.",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--no-configure", action="store_true")
    parser.add_argument("--output")
    return parser.parse_args()


def fresh_command(client: RadioClient, command: str, timeout: float, *, expected: str | None = None):
    """Issue one control request through a fresh lmesh-managed UART stream.

    A new UDS connection invokes lmesh's DTR/preflight sequence. Do not send a
    second in-band ``dtr`` request here: that turns one diagnostic snapshot
    into two nested wake windows and makes the power soak spend most of its
    time waiting for the console rather than observing the duty cycle.
    """
    client.close()
    client.connect()
    return client.command(command, timeout=timeout, expected=expected)


def stats(client: RadioClient, timeout: float) -> dict:
    return fresh_command(client, "nan stats=true", timeout).record("nan")["fields"]


def sleep(client: RadioClient, timeout: float) -> dict:
    return fresh_command(client, "sleep status=true", timeout).record("sleep")["fields"]


def delta(after: dict, before: dict, field: str) -> int:
    return int(after.get(field, 0)) - int(before.get(field, 0))


def phase_summary(samples) -> dict:
    values = [sample.current_ma for sample in samples]
    if not values:
        return {"count": 0}
    values.sort()
    return {
        "count": len(values),
        "mean_ma": round(statistics.mean(values), 3),
        "min_ma": values[0],
        "p50_ma": values[len(values) // 2],
        "p95_ma": values[round((len(values) - 1) * 0.95)],
        "max_ma": values[-1],
    }


def configure(client: RadioClient, args: argparse.Namespace) -> None:
    fresh_command(
        client,
        RAW_NAN_SETTINGS.format(
            channel=args.channel,
            wake_ms=args.wake_ms,
            active_ms=args.active_ms,
        ),
        expected="set",
        timeout=args.timeout,
    )
    fresh_command(client, "power profile=auto", timeout=args.timeout)
    mode_command = "mode raw_nan=true lora=false channel={}".format(args.channel)
    try:
        fresh_command(client, mode_command, timeout=args.timeout)
    except TimeoutError:
        # Starting a duty window may suspend UART before its own response has
        # left the device. Reopen a console window and verify the resulting
        # radio state instead of retrying the state-changing command.
        state = stats(client, args.timeout)
        if not state.get("running"):
            raise RuntimeError("raw-NAN start lost its response and did not take effect")
    fresh_command(client, "power reset=true", timeout=args.timeout)


def main() -> int:
    args = parse_args()
    if args.active_ms < 50 or args.active_ms > args.wake_ms:
        raise ValueError("active-ms must be at least 50 and no greater than wake-ms")
    if args.duration_sec < args.wake_ms / 1000.0 * 3:
        raise ValueError("duration-sec must cover at least three raw-NAN duty windows")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(args.output or "target/esp32-raw-nan-soak/{}".format(stamp))
    artifacts = ArtifactWriter(output)
    sender = RadioClient(args.sender, timeout=args.timeout)
    receiver = RadioClient(args.receiver, timeout=args.timeout)
    meter = PowerCollector(
        PowerMeterConfig("power1", args.meter, "sender", required=True), artifacts
    )
    artifacts.write_json(
        "manifest.json",
        {
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "sender": args.sender,
            "receiver": args.receiver,
            "meter": args.meter,
            "channel": args.channel,
            "wake_ms": args.wake_ms,
            "active_ms": args.active_ms,
            "duration_sec": args.duration_sec,
            "quiet_settle_sec": args.quiet_settle_sec,
            "console_interval_sec": args.console_interval_sec,
            "configure": not args.no_configure,
        },
    )

    meter.start()
    failure = None
    try:
        if not args.no_configure:
            meter.set_phase("configure")
            configure(sender, args)
            configure(receiver, args)

        meter.set_phase("baseline")
        before_sender = stats(sender, args.timeout)
        before_receiver = stats(receiver, args.timeout)
        before_sender_sleep = sleep(sender, args.timeout)
        before_receiver_sleep = sleep(receiver, args.timeout)

        count = max(
            4,
            int((args.duration_sec + args.quiet_settle_sec) * 1000 / args.wake_ms) + 2,
        )
        fresh_command(
            sender,
            "test cnt={} wake_ms={} active_ms={} discovery=2".format(
                count, args.wake_ms, args.active_ms
            ),
            timeout=args.timeout,
        )
        # Firmware UART input intentionally keeps a short active window after
        # configuration. Let that expire before using the meter samples as the
        # raw-NAN duty-cycle measurement.
        meter.set_phase("uart_window")
        time.sleep(max(0.0, args.quiet_settle_sec))
        meter.set_phase("traffic")
        deadline = time.monotonic() + args.duration_sec
        next_console = (
            time.monotonic() + args.console_interval_sec
            if args.console_interval_sec > 0
            else None
        )
        console_samples = []
        while time.monotonic() < deadline:
            now = time.monotonic()
            if next_console is None or now < next_console:
                until_console = deadline - now if next_console is None else next_console - now
                time.sleep(min(0.5, deadline - now, until_console))
                continue
            meter.set_phase("console")
            for name, client in (("sender", sender), ("receiver", receiver)):
                status = fresh_command(client, "status", args.timeout).record("status")["fields"]
                sample = {"elapsed_sec": round(args.duration_sec - (deadline - time.monotonic()), 3),
                          "node": name, "status": status}
                console_samples.append(sample)
                artifacts.append_jsonl("console.jsonl", sample)
            meter.set_phase("traffic")
            next_console += args.console_interval_sec

        meter.set_phase("final")
        after_sender = stats(sender, args.timeout)
        after_receiver = stats(receiver, args.timeout)
        after_sender_sleep = sleep(sender, args.timeout)
        after_receiver_sleep = sleep(receiver, args.timeout)
        test = fresh_command(sender, "test status=true", args.timeout).record("test")["fields"]

        result = {
            "sent": int(test.get("sent", 0)),
            "remaining": int(test.get("remaining", 0)),
            # `test cnt=...` emits application discovery/status pings. They
            # are raw-NAN action frames, not embedded remote-CBOR commands,
            # so raw_cmd_rx is deliberately not the delivery signal here.
            "receiver_raw_action_delta": delta(after_receiver, before_receiver, "raw_action"),
            "receiver_raw_resp_tx_delta": delta(after_receiver, before_receiver, "raw_resp_tx"),
            "sender_raw_resp_rx_delta": delta(after_sender, before_sender, "raw_resp_rx"),
            "sender_raw_action_delta": delta(after_sender, before_sender, "raw_action"),
            "sender_raw_nan_light_runs_delta": delta(
                after_sender_sleep, before_sender_sleep, "raw_nan_light_runs"
            ),
            "sender_raw_nan_light_ok_delta": delta(
                after_sender_sleep, before_sender_sleep, "raw_nan_light_ok"
            ),
            "sender_raw_nan_light_fail_delta": delta(
                after_sender_sleep, before_sender_sleep, "raw_nan_light_fail"
            ),
            "receiver_raw_nan_light_runs_delta": delta(
                after_receiver_sleep, before_receiver_sleep, "raw_nan_light_runs"
            ),
            "receiver_raw_nan_light_ok_delta": delta(
                after_receiver_sleep, before_receiver_sleep, "raw_nan_light_ok"
            ),
            "receiver_raw_nan_light_fail_delta": delta(
                after_receiver_sleep, before_receiver_sleep, "raw_nan_light_fail"
            ),
            "sender_rx_queue_drop_delta": delta(after_sender, before_sender, "rx_queue_drop"),
            "receiver_rx_queue_drop_delta": delta(after_receiver, before_receiver, "rx_queue_drop"),
            "console_samples": console_samples,
            "meter": meter.summary(),
            "meter_traffic": phase_summary(meter.phase_samples.get("traffic", [])),
        }
        artifacts.write_json("result.json", result)
        ok = (
            result["receiver_raw_action_delta"] > 0
            and result["receiver_raw_resp_tx_delta"] > 0
            and result["sender_raw_nan_light_ok_delta"] > 0
            and result["receiver_raw_nan_light_ok_delta"] > 0
            and result["sender_raw_nan_light_fail_delta"] == 0
            and result["receiver_raw_nan_light_fail_delta"] == 0
        )
        (output / "TLDR.md").write_text(
            "# Raw-NAN Duty Soak\n\n"
            "- result: {}\n"
            "- pings sent/received/responses: {}/{}/{}\n"
            "- raw-NAN light-sleep ok (sender/receiver): {}/{}\n"
            "- raw-NAN light-sleep failures (sender/receiver): {}/{}\n"
            "- traffic power mean/p50/p95 mA: {}/{}/{}\n"
            "- queue drops (sender/receiver): {}/{}\n".format(
                "PASS" if ok else "FAIL",
                result["sent"],
                result["receiver_raw_action_delta"],
                result["sender_raw_resp_rx_delta"],
                result["sender_raw_nan_light_ok_delta"],
                result["receiver_raw_nan_light_ok_delta"],
                result["sender_raw_nan_light_fail_delta"],
                result["receiver_raw_nan_light_fail_delta"],
                result["meter_traffic"].get("mean_ma"),
                result["meter_traffic"].get("p50_ma"),
                result["meter_traffic"].get("p95_ma"),
                result["sender_rx_queue_drop_delta"],
                result["receiver_rx_queue_drop_delta"],
            ),
            encoding="utf-8",
        )
        print((output / "TLDR.md").read_text(), flush=True)
        return 0 if ok else 1
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error)}
        artifacts.write_json("failure.json", failure)
        raise
    finally:
        meter.stop()
        sender.close()
        receiver.close()
        artifacts.write_json("summary.json", {"meter": meter.summary(), "failure": failure})
        print("artifacts={}".format(output), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
