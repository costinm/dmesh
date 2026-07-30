#!/usr/bin/env python3
"""Transitional helper for direct UART capture and flash-fleet provisioning.

Normal firmware commands must use the generic ``mesh`` CLI with lmesh's
generated ``resources/tools.json`` catalog.  This helper is retained only
until the direct post-flash provisioning handoff is migrated; it must not be
used as a DTR wake wrapper for normal commands or tests.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import select
import socket
import json
import struct
import sys
import termios
import time
from urllib.parse import urlparse

PROMPT = b"dm-rs> "
FIRMWARE_FATAL_MARKERS = ("Guru Meditation", "Interrupt wdt timeout", "Rebooting...")


class Console:
    def __init__(
        self,
        port: str,
        baud: int,
        timeout: float,
    ) -> None:
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.endpoint: Endpoint | None = open_endpoint(port, baud)
        self.uart_wire = is_physical_uart(port)
        # Passive boot/application-baud capture is intentionally supported on
        # a direct physical UART after its managed forward is stopped.  Only
        # firmware commands need a logical lmesh adapter name.
        self.adapter = None if self.uart_wire else adapter_name(port)

    def close(self) -> None:
        if self.endpoint is not None:
            self.endpoint.close()
            self.endpoint = None

    def sync(self) -> str:
        # Classic ESP32 UART0 wakes from light sleep after a few RX edges and
        # consumes or corrupts those bytes. Send separate disposable lines so
        # a wake transition cannot merge the tail of the preamble into the
        # first real command. A single bulk write previously produced records
        # such as "!tus" when the receiver resumed mid-frame.
        if self.endpoint is None:
            self.endpoint = open_endpoint(self.port, self.baud)
        endpoint = self.endpoint
        time.sleep(0.55)
        for _ in range(4):
            endpoint.write(b"\n")
            time.sleep(0.06)
        endpoint.flush_input()
        time.sleep(0.20)
        endpoint.write(b"status\n")
        return self.read_until_prompt(self.timeout, require_prompt=True)

    def wake_probe(self, settle_sec: float = 4.5) -> None:
        """Consume a UART RX wake transition before a test command.

        The forward uses a bounded DTR wake rather than a speculative firmware
        command, so a sleeping UART cannot consume a side-effecting request.
        """
        del settle_sec
        self.pulse_lmesh_dtr(120)

    def pulse_lmesh_dtr(self, hold_ms: int) -> None:
        """Request lmesh's explicit bounded DTR wake on a managed UDS/TCP forward.

        This is a local lmesh control record, never firmware text.  It is used
        only when the raw-NAN profile has UART heartbeats disabled and a host
        command needs the documented console wake/flush window.
        """
        if self.uart_wire:
            raise ValueError("--dtr requires a managed lmesh UDS/TCP endpoint")
        if self.endpoint is None:
            self.endpoint = open_endpoint(self.port, self.baud)
        endpoint = self.require_endpoint()
        endpoint.flush_input()
        endpoint.write(f"dtr {hold_ms}\n".encode("ascii"))
        # lmesh arms a bounded flush window after releasing DTR. Let the local
        # acknowledgement arrive before the subsequent JSONL command.
        time.sleep(0.20)
        endpoint.flush_input()
        # The managed forward accepts input from its first client by default.
        # Close this one-shot DTR client before `esp.serial.command` opens its
        # own lmesh-managed exchange.
        endpoint.close()
        self.endpoint = None

    def reset_run(self) -> None:
        """Reset a directly opened ESP USB-UART into normal application mode.

        This mirrors lmesh's `usb.serial.reset mode=run` sequence and is for
        the documented boot-baud capture after that one managed forward has
        been stopped.  It deliberately preserves DTR while toggling RTS, so a
        CP210x wiring cannot accidentally select the bootloader.
        """
        if not self.uart_wire:
            raise ValueError("--reset-run requires a direct physical UART endpoint")
        endpoint = self.require_endpoint()
        set_modem_line(endpoint.fd, termios.TIOCM_DTR, False)
        set_modem_line(endpoint.fd, termios.TIOCM_RTS, True)
        time.sleep(0.120)
        set_modem_line(endpoint.fd, termios.TIOCM_RTS, False)
        time.sleep(0.500)
        set_modem_line(endpoint.fd, termios.TIOCM_DTR, False)

    def command(self, command: str, timeout: float | None = None) -> str:
        """Run a text command through lmesh; this tool never encodes CBOR."""
        if self.uart_wire:
            raise ValueError(
                "physical UART commands are unsupported: use a managed lmesh socket "
                "(for example uds:///run/mesh/lmesh/lora2.sock)"
            )
        assert self.adapter is not None
        return lmesh_serial_command(self.adapter, command, timeout or self.timeout)

    def cmd(self, command: str, timeout: float | None = None) -> str:
        if not self.uart_wire:
            return self.command(command, timeout)
        self.require_endpoint().write((command + "\n").encode("utf-8"))
        return self.read_until_prompt(timeout or self.timeout, require_prompt=True)

    def require_endpoint(self) -> "Endpoint":
        if self.endpoint is None:
            raise RuntimeError("the temporary managed-forward connection is closed")
        return self.endpoint

    def read_until_prompt(self, timeout: float, *, require_prompt: bool = False) -> str:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        saw_prompt = False
        while time.monotonic() < deadline:
            remaining = max(0.0, min(0.05, deadline - time.monotonic()))
            endpoint = self.require_endpoint()
            readable, _, _ = select.select([endpoint.fd], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = endpoint.read(4096)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            buf.extend(chunk)
            if PROMPT in buf:
                saw_prompt = True
                break
        if require_prompt and not saw_prompt:
            preview = bytes(buf[-240:]).decode("utf-8", "replace").replace("\r", "")
            raise TimeoutError(f"console prompt not seen after {timeout:.1f}s; tail={preview!r}")
        return bytes(buf).decode("utf-8", "replace").replace("\r", "")


class Endpoint:
    def __init__(self, fd: int) -> None:
        self.fd = fd

    def read(self, size: int) -> bytes:
        return os.read(self.fd, size)

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def flush_input(self) -> None:
        try:
            termios.tcflush(self.fd, termios.TCIFLUSH)
        except termios.error:
            drain_socket_input(self.fd)

    def close(self) -> None:
        os.close(self.fd)


class SocketEndpoint(Endpoint):
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        super().__init__(sock.fileno())

    def read(self, size: int) -> bytes:
        return self.sock.recv(size)

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        self.sock.close()


def open_endpoint(port: str, baud: int) -> Endpoint:
    if port.endswith(".lmesh") and "/" not in port:
        port = f"/run/mesh/lmesh/{port.removesuffix('.lmesh')}.sock"
    if port.startswith(("uds://", "unix://")) or port.endswith(".sock"):
        path = parse_uds_path(port)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        sock.setblocking(False)
        return SocketEndpoint(sock)
    if port.startswith(("tcp://", "socket://")):
        host, tcp_port = parse_tcp_target(port)
        sock = socket.create_connection((host, tcp_port), timeout=5.0)
        sock.setblocking(False)
        return SocketEndpoint(sock)
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    configure_serial(fd, baud)
    return Endpoint(fd)


def is_physical_uart(port: str) -> bool:
    return not (
        port.endswith(".lmesh")
        or port.startswith(("uds://", "unix://", "tcp://", "socket://"))
        or port.endswith(".sock")
    )


def parse_uds_path(port: str) -> str:
    if port.endswith(".sock") and "://" not in port:
        return port
    parsed = urlparse(port)
    if parsed.scheme == "uds":
        if parsed.netloc and parsed.path:
            return f"/{parsed.netloc}{parsed.path}"
        return parsed.path
    if parsed.scheme == "unix":
        return parsed.path
    raise ValueError(f"unsupported UDS target {port}")


def parse_tcp_target(port: str) -> tuple[str, int]:
    parsed = urlparse(port)
    if parsed.scheme not in {"tcp", "socket"} or not parsed.hostname or not parsed.port:
        raise ValueError(f"unsupported TCP target {port}")
    return parsed.hostname, parsed.port


def drain_socket_input(fd: int) -> None:
    while True:
        readable, _, _ = select.select([fd], [], [], 0)
        if not readable:
            return
        try:
            if not os.read(fd, 4096):
                return
        except BlockingIOError:
            return


def configure_serial(fd: int, baud: int) -> None:
    speeds = {
        9600: termios.B9600,
        19200: termios.B19200,
        38400: termios.B38400,
        57600: termios.B57600,
        115200: termios.B115200,
        230400: termios.B230400,
        460800: termios.B460800,
        921600: termios.B921600,
    }
    if baud not in speeds:
        raise ValueError(f"unsupported baud rate {baud}")
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    attrs[4] = speeds[baud]
    attrs[5] = speeds[baud]
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def set_modem_line(fd: int, line: int, enabled: bool) -> None:
    """Set one UART modem-control bit without clobbering the other line."""
    bits = struct.pack("I", int(line))
    request = termios.TIOCMBIS if enabled else termios.TIOCMBIC
    fcntl.ioctl(fd, request, bits)


def adapter_name(port: str) -> str:
    """Resolve a managed lmesh socket spelling to its configured adapter name."""
    if port.endswith(".lmesh") and "/" not in port:
        return port.removesuffix(".lmesh")
    if port.startswith(("uds://", "unix://")) or port.endswith(".sock"):
        return os.path.basename(parse_uds_path(port)).removesuffix(".sock")
    raise ValueError(f"cannot resolve managed lmesh adapter from {port!r}")


def lmesh_serial_command(adapter: str, command: str, timeout: float) -> str:
    """Call the lmesh text API; lmesh owns all firmware CBOR translation."""
    control_socket = os.environ.get("LMESH_CONTROL_SOCKET", "/run/mesh/lmesh/mesh.sock")
    request = {
        "id": "serial-cmd",
        "method": "esp.serial.command",
        "port": adapter,
        "command": command,
        "timeout_sec": timeout,
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.settimeout(timeout + 1.0)
        control.connect(control_socket)
        control.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
        response = bytearray()
        while b"\n" not in response:
            chunk = control.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    if not response:
        raise TimeoutError(f"no JSONL response from lmesh control socket {control_socket}")
    reply = json.loads(bytes(response).split(b"\n", 1)[0])
    if reply.get("error"):
        raise RuntimeError(str(reply["error"]))
    data = reply.get("data", reply.get("result", {}))
    if not isinstance(data, dict):
        return json.dumps(data, sort_keys=True)
    if not data.get("ok", True):
        raise RuntimeError(str(data.get("error", data)))
    messages = data.get("messages", [])
    lines = [entry["console"] for entry in messages if isinstance(entry, dict) and "console" in entry]
    return "\n".join(lines) if lines else json.dumps(data, sort_keys=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        action="append",
        required=True,
        help=(
            "Endpoint to query: /dev/ttyUSB0, uds:///run/.../USB0.sock, "
            "lora1.lmesh, tcp://127.0.0.1:3330, socket://127.0.0.1:3330, "
            "or a bare .sock path. Commands require a managed lmesh UDS socket; "
            "direct physical UART is only available for reset/capture diagnostics."
        ),
    )
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--dtr",
        type=int,
        default=0,
        metavar="MS",
        help=(
            "Pulse managed lmesh DTR when used alone (1..10000 ms). Firmware "
            "commands request their own one-connection wake through lmesh."
        ),
    )
    parser.add_argument(
        "--reset-run",
        action="store_true",
        help=(
            "Reset a direct physical ESP UART into normal application mode "
            "before capture/commands; use only after its managed forward is stopped."
        ),
    )
    parser.add_argument(
        "--cmd", action="append", help="Command to run. Repeat for multiple commands in order."
    )
    parser.add_argument("--no-sync", action="store_true", help="Skip initial prompt sync.")
    parser.add_argument(
        "--capture-ms",
        type=int,
        default=0,
        help="After wake/reset, print raw UART output for this long without sending a command.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Repeat the complete connect/command round for each port.",
    )
    parser.add_argument(
        "--repeat-delay-ms",
        type=int,
        default=250,
        help="Delay between repeated rounds (default: 250).",
    )
    parser.add_argument(
        "--repeat-cmds",
        type=int,
        default=1,
        help=(
            "Run the complete command set this many times on each open connection; "
            "unlike --repeat this does not toggle modem-control lines between sets."
        ),
    )
    parser.add_argument(
        "--assert-uptime-monotonic",
        action="store_true",
        help=(
            "Fail when a status/xstatus response reports uptime_ms that does not increase; "
            "use with --repeat to detect firmware resets during console stress."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.cmd and args.capture_ms <= 0 and args.dtr <= 0 and not args.reset_run:
        raise SystemExit("at least one --cmd, --dtr, --reset-run, or a positive --capture-ms is required")
    if (
        args.capture_ms < 0
        or args.repeat_delay_ms < 0
    ):
        raise SystemExit("timing arguments must be non-negative")
    if args.dtr and not 1 <= args.dtr <= 10_000:
        raise SystemExit("--dtr must be between 1 and 10000 milliseconds")
    if args.repeat < 1 or args.repeat_cmds < 1:
        raise SystemExit("--repeat and --repeat-cmds must be at least one")
    rc = 0
    for port in args.port:
        print(f"=== {port} ===", flush=True)
        previous_uptime_ms: int | None = None
        for iteration in range(args.repeat):
            if args.repeat > 1:
                print(f"--- round {iteration + 1}/{args.repeat} ---", flush=True)
            console = Console(
                port,
                args.baud,
                args.timeout,
            )
            try:
                if args.dtr and not args.cmd:
                    print(f"[{port}] $ lmesh dtr {args.dtr}", flush=True)
                    console.pulse_lmesh_dtr(args.dtr)
                if args.reset_run:
                    print(f"[{port}] $ reset run", flush=True)
                    console.reset_run()
                if args.capture_ms:
                    print(console.read_until_prompt(args.capture_ms / 1000.0).rstrip(), flush=True)
                    if not args.cmd:
                        continue
                for command_set in range(args.repeat_cmds):
                    if args.repeat_cmds > 1:
                        print(
                            f"--- command set {command_set + 1}/{args.repeat_cmds} ---",
                            flush=True,
                        )
                    for command in args.cmd or []:
                        print(f"[{port}] $ {command}", flush=True)
                        out = console.command(command, args.timeout)
                        print(out.rstrip(), flush=True)
                        assert_no_firmware_fault(out, args.assert_uptime_monotonic)
                        text = out.strip()
                        if text.startswith("error ") or "\nerror " in text:
                            rc = 1
                        previous_uptime_ms = assert_monotonic_uptime(
                            out,
                            previous_uptime_ms,
                            args.assert_uptime_monotonic,
                        )
            except Exception as exc:  # noqa: BLE001 - serial tooling should report all failures.
                print(f"{port}: {exc}", file=sys.stderr, flush=True)
                rc = 1
            finally:
                console.close()
            if iteration + 1 < args.repeat and args.repeat_delay_ms:
                time.sleep(args.repeat_delay_ms / 1000.0)
    return rc


def assert_monotonic_uptime(
    output: str, previous_uptime_ms: int | None, enabled: bool
) -> int | None:
    """Extract status uptime and reject a reboot during a repeated stress run."""
    match = re.search(r"\buptime_ms=(\d+)", output)
    if not match:
        return previous_uptime_ms
    current = int(match.group(1))
    if enabled and previous_uptime_ms is not None and current <= previous_uptime_ms:
        raise RuntimeError(
            "firmware uptime regressed or stalled: "
            f"previous={previous_uptime_ms}ms current={current}ms"
        )
    return current


def assert_no_firmware_fault(output: str, enabled: bool) -> None:
    """Turn a watchdog/reset banner into a deterministic stress-test failure."""
    if not enabled:
        return
    for marker in FIRMWARE_FATAL_MARKERS:
        if marker in output:
            raise RuntimeError(f"firmware fault marker seen: {marker}")


if __name__ == "__main__":
    raise SystemExit(main())
