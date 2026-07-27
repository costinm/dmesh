#!/usr/bin/env python3
"""Exercise framed-CBOR GFSK send/receive between two ESP32 firmware ports."""

from __future__ import annotations

import argparse
import threading
import time

from serial_cmd import Console


def require_ok(output: str, context: str) -> None:
    if "error " in output:
        raise RuntimeError(f"{context} returned error: {output.strip()}")


def run(console: Console, command: str, timeout: float) -> str:
    print(f"[{console.port}] $ {command}", flush=True)
    output = console.cbor_cmd(command, timeout)
    print(output.rstrip(), flush=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rx", required=True, help="receiver serial/UDS port")
    parser.add_argument("--tx", required=True, help="sender serial/UDS port")
    parser.add_argument("--channel", type=int, default=31)
    parser.add_argument("--payload", default="hex:46534b2d504149522d54455354")
    parser.add_argument("--listen-ms", type=int, default=3_000)
    parser.add_argument("--tx-timeout-ms", type=int, default=1_000)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    rx = Console(args.rx, 460800, args.timeout)
    tx = Console(args.tx, 460800, args.timeout)
    try:
        rx.wake_probe()
        tx.wake_probe()
        result: dict[str, str] = {}
        listener_error: list[BaseException] = []

        def listen() -> None:
            try:
                result["output"] = run(
                    rx,
                    f"radio op=listen channel={args.channel} ms={args.listen_ms}",
                    args.timeout + args.listen_ms / 1_000 + 2,
                )
            except BaseException as exc:
                listener_error.append(exc)

        listener = threading.Thread(target=listen)
        listener.start()
        try:
            time.sleep(0.4)
            tx_out = run(
                tx,
                f"radio op=send channel={args.channel} payload={args.payload} "
                f"timeout={args.tx_timeout_ms}",
                max(args.timeout, args.tx_timeout_ms / 1_000 + 2),
            )
            require_ok(tx_out, "FSK send")
        finally:
            listener.join(args.timeout + args.listen_ms / 1_000 + 3)
        if listener.is_alive():
            raise RuntimeError("FSK receiver did not return")
        if listener_error:
            raise RuntimeError("FSK listener failed") from listener_error[0]
        rx_out = result.get("output", "")
        require_ok(rx_out, "FSK listen")
        if "none=true" in rx_out:
            raise RuntimeError("FSK receiver saw no packet")
        print("PASS")
        return 0
    finally:
        rx.close()
        tx.close()


if __name__ == "__main__":
    raise SystemExit(main())
