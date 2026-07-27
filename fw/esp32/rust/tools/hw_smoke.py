#!/usr/bin/env python3
"""Serial smoke tests for the ESP32 Rust firmware.

Pass explicit serial ports because ttyUSB enumeration changes after resets.
The script detects LoRa at runtime and, when possible, uses two LoRa boards plus
one non-LoRa witness to verify LoRa receive forwarding into BLE and raw NAN.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import time
from dataclasses import dataclass

import serial


PROMPT = "dm-rs> "


@dataclass
class CommandResult:
    command: str
    output: str


@dataclass
class Board:
    label: str
    port: str
    mac: str
    device: "Device"
    has_lora: bool = False
    nan_support: str = "unknown"


class Device:
    def __init__(self, label: str, port: str, baud: int, timeout: float) -> None:
        self.label = label
        self.port = port
        self.timeout = timeout
        self.serial = serial.Serial(port, baud, timeout=0.2, write_timeout=2)

    def close(self) -> None:
        self.serial.close()

    def sync_prompt(self) -> str:
        self.serial.reset_input_buffer()
        self.serial.write(b"\n")
        self.serial.flush()
        return self._read_until_prompt(self.timeout)

    def run(self, command: str, timeout: float | None = None) -> CommandResult:
        self.serial.write((command + "\n").encode("utf-8"))
        self.serial.flush()
        output = self._read_until_prompt(timeout or self.timeout)
        return CommandResult(command, output)

    def _read_until_prompt(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            chunk = self.serial.read(4096)
            if chunk:
                buf.extend(chunk)
                if PROMPT.encode("utf-8") in buf:
                    break
            else:
                time.sleep(0.05)
        return bytes(buf).decode("utf-8", "replace").replace("\r", "")


def show(device: Device, result: CommandResult) -> None:
    print(f"[{device.label}] $ {result.command}")
    print(result.output.rstrip())


def require_ok(device: Device, result: CommandResult, contains: str | None = None) -> str:
    show(device, result)
    stripped = result.output.strip()
    if stripped.startswith("error ") or "\nerror " in stripped:
        raise AssertionError(f"{device.label}: command returned error: {result.command}")
    if contains and contains not in result.output:
        raise AssertionError(
            f"{device.label}: command {result.command!r} did not contain {contains!r}"
        )
    return result.output


def value_for(text: str, key: str, default: int = 0) -> int:
    match = re.search(rf"\b{re.escape(key)}=(-?\d+)\b", text)
    return int(match.group(1)) if match else default


def chip_mac(port: str) -> str:
    proc = subprocess.run(
        ["esptool.py", "--port", port, "chip_id"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    matches = re.findall(r"MAC:\s*([0-9a-fA-F:]{17})", proc.stdout)
    if not matches:
        raise RuntimeError(f"could not read MAC from esptool output on {port}")
    return matches[-1].lower()


def common_checks(board: Board, timeout: float) -> None:
    prompt = board.device.sync_prompt()
    print(f"[{board.label}] sync")
    print(prompt.rstrip())
    if PROMPT not in prompt:
        raise AssertionError(f"{board.label}: prompt not found on {board.port}")

    for command, contains in [
        ("help", "wifi:"),
        ("wifi", "mode="),
        ("gpio pin=2 mode=output level=1", "gpio pin=2"),
        ("i2cconfig", "sda="),
        ("ble stats=true", "ble started="),
    ]:
        require_ok(board.device, board.device.run(command, timeout), contains)

    nan_stats = require_ok(board.device, board.device.run("nan stats=true", timeout), "nan ")
    support = re.search(r"\bsupport=([a-z_=-]+)", nan_stats)
    board.nan_support = support.group(1) if support else "unknown"


def detect_lora(board: Board, timeout: float) -> None:
    lora_state = require_ok(board.device, board.device.run("lora", timeout), "freq=")
    logs = require_ok(board.device, board.device.run("logs count=50", timeout), None)
    board.has_lora = (
        "event type=lora.probe found=true" in logs
        or "ev=lora.probe found=true" in logs
        or "ev=lora.probe ok=true" in logs
    )
    if board.has_lora and "sync_word=0x2b" not in lora_state:
        print(f"[{board.label}] warning=lora_detected_but_settings_unexpected")
    print(f"[{board.label}] detected_lora={board.has_lora} nan_support={board.nan_support}")


def clear_buffers(board: Board) -> None:
    for command in ["stats reset=true", "logs clear=true", "messages clear=true"]:
        require_ok(board.device, board.device.run(command), None)


def start_ble_nan_listener(board: Board, channel: int) -> None:
    require_ok(board.device, board.device.run("ble mode=listen"), "ble listen started")
    require_ok(
        board.device,
        board.device.run(f"nan start=true backend=raw role=both service=dmesh channel={channel}"),
        "nan started",
    )
    require_ok(
        board.device,
        board.device.run(f"wifi raw_monitor=true filter=action channel={channel}"),
        "wifi raw monitor started",
    )


def stop_nan_wifi(board: Board) -> None:
    board.device.run("nan stop=true")
    board.device.run("wifi raw_stop=true")


def run_nan_peer_smoke(boards: list[Board], channel: int, timeout: float) -> None:
    candidates = [board for board in boards if board.nan_support == "official"]
    if len(candidates) < 2:
        print("[nan-peer] skipped=true reason=need two official NAN boards")
        return
    peers = candidates[:3]
    print("[nan-peer] boards=" + ",".join(board.label for board in peers))
    for board in peers:
        stop_nan_wifi(board)
    for board in peers:
        require_ok(
            board.device,
            board.device.run(
                f"nan start=true backend=official role=both service=dmesh channel={channel}",
                timeout=timeout,
            ),
            "nan started",
        )
    time.sleep(6.0)
    matched = 0
    for board in peers:
        stats = require_ok(board.device, board.device.run("nan stats=true"), "match=")
        matched += value_for(stats, "match") + value_for(stats, "replied")
    if matched < 1:
        raise AssertionError("official NAN peer check saw no match/replied events")
    for board in peers:
        stop_nan_wifi(board)


def configure_lora(board: Board, freq: int, sync_word: str) -> None:
    require_ok(board.device, board.device.run("lora rx=false"), "lora rx=false")
    time.sleep(0.5)
    require_ok(
        board.device,
        board.device.run(
            f"lora preset=medium_fast freq={freq} sync_word={sync_word} apply=true",
            timeout=8.0,
        ),
        "sf=9",
    )


def run_cross_radio_smoke(boards: list[Board], args: argparse.Namespace) -> None:
    lora_boards = [board for board in boards if board.has_lora]
    witnesses = [board for board in boards if not board.has_lora]
    if len(lora_boards) < 2:
        print("[cross] skipped=true reason=need at least two LoRa boards")
        return
    if not witnesses:
        print("[cross] skipped_witness=true reason=need one non-LoRa board")

    sender = lora_boards[0]
    receiver = lora_boards[1]
    witness = witnesses[0] if witnesses else None
    print(
        f"[cross] sender={sender.label} receiver={receiver.label} "
        f"witness={witness.label if witness else 'none'}"
    )

    active = [sender, receiver] + ([witness] if witness else [])
    for board in active:
        stop_nan_wifi(board)
        clear_buffers(board)
        start_ble_nan_listener(board, args.nan_channel)

    for board in [sender, receiver]:
        configure_lora(board, args.lora_freq, args.sync_word)

    require_ok(receiver.device, receiver.device.run("lora rx=true", timeout=8.0), "lora rx=true")
    time.sleep(1.0)
    for board in active:
        clear_buffers(board)

    payload = args.payload_hex.lower()
    require_ok(
        sender.device,
        sender.device.run(f"lorasend data=hex:{payload}", timeout=8.0),
        "lorasend",
    )
    time.sleep(args.forward_wait)

    receiver_logs = require_ok(receiver.device, receiver.device.run("logs count=50"), None)
    receiver_stats = require_ok(receiver.device, receiver.device.run("stats"), "stats ")
    if (
        "event type=lora.rx " not in receiver_logs
        and "ev=lora.rx " not in receiver_logs
        and value_for(receiver_stats, "lora_rx") < 1
    ):
        raise AssertionError("receiver did not record a LoRa RX packet")
    if "transport=ble" not in receiver_logs and "t=ble" not in receiver_logs:
        raise AssertionError("receiver did not log LoRa to BLE forwarding")
    if "transport=nan" not in receiver_logs and "t=nan" not in receiver_logs:
        raise AssertionError("receiver did not log LoRa to NAN forwarding")

    if witness:
        ble_stats = require_ok(witness.device, witness.device.run("ble stats=true"), "announce_rx=")
        nan_stats = require_ok(witness.device, witness.device.run("nan stats=true"), "raw_matched=")
        wifi_stats = require_ok(
            witness.device,
            witness.device.run("wifi raw_stats=true"),
            "matched=",
        )
        ble_messages = require_ok(
            witness.device,
            witness.device.run("messages count=20 transport=ble direction=rx"),
            None,
        )
        wifi_messages = require_ok(
            witness.device,
            witness.device.run("messages count=20 transport=wifi direction=rx"),
            None,
        )
        witness_logs = require_ok(witness.device, witness.device.run("logs count=50"), None)
        if value_for(ble_stats, "announce_rx") < 1 and "ble.announce_rx" not in witness_logs:
            raise AssertionError("witness did not observe BLE LoRa announcement")
        if value_for(nan_stats, "raw_matched") < 1 and "source=nan" not in wifi_messages:
            raise AssertionError("witness did not observe raw NAN forwarding")
        if value_for(wifi_stats, "matched") < 1 and "wifi.raw_rx" not in witness_logs:
            raise AssertionError("witness did not observe raw Wi-Fi forwarding")
        if "messages count=0" in ble_messages:
            raise AssertionError("witness BLE message buffer is empty")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", action="append", default=[], help="Serial port to test.")
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--lora-freq", type=int, default=913_125_000)
    parser.add_argument("--sync-word", default="0x2b")
    parser.add_argument("--nan-channel", type=int, default=6)
    parser.add_argument("--payload-hex", default="444d4553482d534d4f4b45")
    parser.add_argument("--forward-wait", type=float, default=6.0)
    parser.add_argument("--skip-cross-radio", action="store_true")
    parser.add_argument("--skip-nan-peer", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.port:
        raise SystemExit("pass at least one --port")
    ports = list(dict.fromkeys(args.port))
    failures: list[str] = []
    boards: list[Board] = []

    for port in ports:
        try:
            mac = chip_mac(port)
            label = f"{port} {mac}"
            device = Device(label, port, args.baud, args.timeout)
            board = Board(label=label, port=port, mac=mac, device=device)
            boards.append(board)
            common_checks(board, args.timeout)
            detect_lora(board, args.timeout)
        except Exception as exc:  # noqa: BLE001 - report all device-test failures.
            failures.append(f"{port}: {exc}")

    if not failures and not args.skip_nan_peer:
        try:
            run_nan_peer_smoke(boards, args.nan_channel, args.timeout)
        except Exception as exc:  # noqa: BLE001 - report all device-test failures.
            failures.append(f"nan-peer: {exc}")

    if not failures and not args.skip_cross_radio:
        try:
            run_cross_radio_smoke(boards, args)
        except Exception as exc:  # noqa: BLE001 - report all device-test failures.
            failures.append(f"cross-radio: {exc}")

    for board in boards:
        board.device.close()

    if failures:
        print("\nFAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nPASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
