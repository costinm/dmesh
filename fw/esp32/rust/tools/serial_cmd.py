#!/usr/bin/env python3
"""Run compact-CBOR ESP32 firmware commands over UART or lmesh forwards."""

from __future__ import annotations

import argparse
import os
import re
import select
import socket
import sys
import termios
import time
from urllib.parse import urlparse

PROMPT = b"dm-rs> "
FIRMWARE_FATAL_MARKERS = ("Guru Meditation", "Interrupt wdt timeout", "Rebooting...")
# Matches `mesh::cbor::ESP_RECORD_MAX` and the firmware UART contract. Status
# and sleep records commonly exceed the historical 512-byte debug limit.
FIRMWARE_RECORD_MAX = 4_000
UART_FLAG = 0x7E
UART_ESCAPE = 0x7D
UART_ESCAPE_XOR = 0x20


class Console:
    def __init__(
        self,
        port: str,
        baud: int,
        timeout: float,
    ) -> None:
        self.port = port
        self.timeout = timeout
        self.endpoint = open_endpoint(port, baud)
        self.uart_wire = is_physical_uart(port)

    def close(self) -> None:
        self.endpoint.close()

    def sync(self) -> str:
        # Classic ESP32 UART0 wakes from light sleep after a few RX edges and
        # consumes or corrupts those bytes. Send separate disposable lines so
        # a wake transition cannot merge the tail of the preamble into the
        # first real command. A single bulk write previously produced records
        # such as "!tus" when the receiver resumed mid-frame.
        time.sleep(0.55)
        for _ in range(4):
            self.endpoint.write(b"\n")
            time.sleep(0.06)
        self.endpoint.flush_input()
        time.sleep(0.20)
        self.endpoint.write(b"status\n")
        return self.read_until_prompt(self.timeout, require_prompt=True)

    def cbor_cmd(self, command: str, timeout: float | None = None) -> str:
        """Send one firmware stream frame and return decoded response records.

        Firmware UART is binary-only.  This intentionally bypasses lmesh's
        text convenience adapter so it can validate exactly the physical
        modem protocol used by UART, BLE, and radio command transports.
        """
        self.endpoint.flush_input()
        self.endpoint.write(self.encode_command(command))
        return self.read_cbor_records(timeout or self.timeout)

    def cbor_cmd_payload(
        self, command: str, payload: bytes, timeout: float | None = None
    ) -> str:
        """Send a compact-CBOR command with an opaque binary payload."""
        self.endpoint.flush_input()
        self.endpoint.write(self.encode_command(command, payload=payload))
        return self.read_cbor_records(timeout or self.timeout)

    def wake_probe(self, settle_sec: float = 4.5) -> None:
        """Consume a UART RX wake transition before a test command.

        A sleeping ESP may consume the first compact-CBOR record while its
        UART clock resumes. The default also covers the four-second raw-NAN
        duty cycle used by the battery test profile. The probe is a harmless ``status``
        request whose response is discarded; callers must still send their
        actual command normally.  This avoids retrying a potentially
        side-effecting command after an ambiguous timeout.
        """
        self.endpoint.flush_input()
        self.endpoint.write(self.encode_command("status"))
        time.sleep(settle_sec)
        self.endpoint.flush_input()

    def read_cbor_records(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        pending = bytearray()
        uart_decoder = UartDecoder()
        events: list[str] = []
        while time.monotonic() < deadline:
            readable, _, _ = select.select([self.endpoint.fd], [], [], 0.05)
            if not readable:
                continue
            try:
                chunk = self.endpoint.read(4096)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            if self.uart_wire:
                for cbor in uart_decoder.push(chunk):
                    rendered = render_cbor(cbor)
                    if is_event_cbor(cbor):
                        events.append(rendered)
                    else:
                        return rendered
                continue
            pending.extend(chunk)
            while len(pending) >= 4:
                body_len = int.from_bytes(pending[:4], "big")
                if not 4 <= body_len <= FIRMWARE_RECORD_MAX + 4:
                    # Boot ROM diagnostics are not valid command frames.
                    del pending[:1]
                    continue
                frame_len = 4 + body_len
                if len(pending) < frame_len:
                    break
                body = bytes(pending[4:frame_len])
                del pending[:frame_len]
                if not body.startswith(b"\x00\xcb\x00\x00"):
                    continue
                rendered = render_cbor(body[4:])
                if is_event_cbor(body[4:]):
                    events.append(rendered)
                else:
                    return rendered
        tail = pending[-96:].hex()
        event_tail = " | ".join(events[-2:])
        raise TimeoutError(
            f"no framed CBOR response after {timeout:.1f}s; tail={tail} events={event_tail}"
        )

    def encode_command(self, command: str, *, payload: bytes | None = None) -> bytes:
        frame = encode_firmware_command(command, payload=payload)
        return encode_uart_frame(frame[8:]) if self.uart_wire else frame

    def cmd(self, command: str, timeout: float | None = None) -> str:
        self.endpoint.write((command + "\n").encode("utf-8"))
        return self.read_until_prompt(timeout or self.timeout, require_prompt=True)

    def read_until_prompt(self, timeout: float, *, require_prompt: bool = False) -> str:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        saw_prompt = False
        while time.monotonic() < deadline:
            remaining = max(0.0, min(0.05, deadline - time.monotonic()))
            readable, _, _ = select.select([self.endpoint.fd], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = self.endpoint.read(4096)
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


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    raise ValueError(f"CBOR value too large: {value}")


def cbor_uint(value: int) -> bytes:
    return cbor_head(0, value)


def cbor_text(value: str) -> bytes:
    data = value.encode("utf-8")
    return cbor_head(3, len(data)) + data


def cbor_bytes(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def encode_firmware_command(command: str, *, payload: bytes | None = None) -> bytes:
    words = command.split()
    if not words:
        raise ValueError("empty firmware command")
    fields: list[tuple[str, bytes]] = []
    for word in words[1:]:
        key, value = word.split("=", 1) if "=" in word else (word, "true")
        if key == "payload":
            raw = bytes.fromhex(value.removeprefix("hex:"))
            fields.append(("data", cbor_bytes(raw)))
        else:
            fields.append((key, cbor_text(value)))
    if payload is not None:
        fields.append(("data", cbor_bytes(payload)))
    cbor = bytearray(cbor_head(5, 1 + bool(fields)))
    cbor.extend(cbor_uint(0))
    cbor.extend(cbor_text(words[0]))
    if fields:
        cbor.extend(cbor_uint(6))
        cbor.extend(cbor_head(5, len(fields)))
        for key, encoded_value in fields:
            cbor.extend(cbor_text(key))
            cbor.extend(encoded_value)
    body = b"\x00\xcb\x00\x00" + bytes(cbor)
    return len(body).to_bytes(4, "big") + body


def encode_uart_frame(cbor: bytes) -> bytes:
    if not 1 <= len(cbor) <= FIRMWARE_RECORD_MAX:
        raise ValueError(f"UART CBOR frame must be 1..{FIRMWARE_RECORD_MAX} bytes")
    output = bytearray([UART_FLAG])
    for byte in cbor:
        if byte in (UART_FLAG, UART_ESCAPE):
            output.extend((UART_ESCAPE, byte ^ UART_ESCAPE_XOR))
        else:
            output.append(byte)
    output.append(UART_FLAG)
    return bytes(output)


class UartDecoder:
    """Bounded HDLC/PPP-style decoder for the physical UART payload."""

    def __init__(self) -> None:
        self.in_frame = False
        self.escaped = False
        self.discard_until_flag = False
        self.payload = bytearray()

    def push(self, bytes_: bytes) -> list[bytes]:
        records: list[bytes] = []
        for byte in bytes_:
            if byte == UART_FLAG:
                if not self.in_frame:
                    self.in_frame = True
                    self.escaped = False
                    self.discard_until_flag = False
                    self.payload.clear()
                    continue
                if self.escaped:
                    self.payload.clear()
                    self.escaped = False
                    self.discard_until_flag = False
                    continue
                if not self.discard_until_flag and self.payload:
                    records.append(bytes(self.payload))
                self.payload.clear()
                self.discard_until_flag = False
                continue
            if not self.in_frame or self.discard_until_flag:
                continue
            if self.escaped:
                self.payload.append(byte ^ UART_ESCAPE_XOR)
                self.escaped = False
            elif byte == UART_ESCAPE:
                self.escaped = True
                continue
            else:
                self.payload.append(byte)
            if len(self.payload) > FIRMWARE_RECORD_MAX:
                self.payload.clear()
                self.escaped = False
                self.discard_until_flag = True
        return records


def decode_cbor(data: bytes, offset: int = 0) -> tuple[object, int]:
    if offset >= len(data):
        raise ValueError("truncated CBOR")
    head = data[offset]
    offset += 1
    major, extra = head >> 5, head & 0x1F
    if extra < 24:
        length = extra
    elif extra == 24:
        length = data[offset]
        offset += 1
    elif extra == 25:
        length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
    else:
        raise ValueError(f"unsupported CBOR additional info {extra}")
    if major == 0:
        return length, offset
    if major in (2, 3):
        end = offset + length
        raw = data[offset:end]
        if len(raw) != length:
            raise ValueError("truncated CBOR string")
        return (raw if major == 2 else raw.decode("utf-8", "replace")), end
    if major == 5:
        out: dict[object, object] = {}
        for _ in range(length):
            key, offset = decode_cbor(data, offset)
            value, offset = decode_cbor(data, offset)
            out[key] = value
        return out, offset
    raise ValueError(f"unsupported CBOR major type {major}")


def render_cbor(data: bytes) -> str:
    try:
        value, used = decode_cbor(data)
        if used != len(data):
            raise ValueError("trailing bytes")
        if not isinstance(value, dict):
            return repr(value)
        payload = value.get(6)
        if isinstance(payload, dict) and isinstance(payload.get(32), str):
            return payload[32]
        if isinstance(value.get(5), str):
            return f"error message={value[5]}"
        if isinstance(value.get(4), str):
            return f"status={value[4]}"
        return repr(value)
    except (UnicodeDecodeError, ValueError, IndexError):
        return f"cbor_hex={data.hex()}"


def is_event_cbor(data: bytes) -> bool:
    try:
        value, used = decode_cbor(data)
        if used != len(data) or not isinstance(value, dict):
            return False
        payload = value.get(6)
        return isinstance(payload, dict) and payload.get(4) == "event"
    except (UnicodeDecodeError, ValueError, IndexError):
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        action="append",
        required=True,
        help=(
            "Endpoint to query: /dev/ttyUSB0, uds:///run/.../USB0.sock, "
            "lora1.lmesh, tcp://127.0.0.1:3330, socket://127.0.0.1:3330, "
            "or a bare .sock path. UDS/TCP endpoints use the mesh stream; "
            "physical UART endpoints use escaped delimiter-framed CBOR."
        ),
    )
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument(
        "--text-debug",
        action="store_true",
        help="Use obsolete newline/prompt console mode instead of framed CBOR.",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
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
    if not args.cmd and args.capture_ms <= 0:
        raise SystemExit("at least one --cmd or a positive --capture-ms is required")
    if (
        args.capture_ms < 0
        or args.repeat_delay_ms < 0
    ):
        raise SystemExit("timing arguments must be non-negative")
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
                if args.capture_ms:
                    print(console.read_until_prompt(args.capture_ms / 1000.0).rstrip(), flush=True)
                    if not args.cmd:
                        continue
                if not args.no_sync and args.text_debug:
                    print(console.sync().rstrip(), flush=True)
                for command_set in range(args.repeat_cmds):
                    if args.repeat_cmds > 1:
                        print(
                            f"--- command set {command_set + 1}/{args.repeat_cmds} ---",
                            flush=True,
                        )
                    for command in args.cmd:
                        print(f"[{port}] $ {command}", flush=True)
                        out = (
                            console.cmd(command, args.timeout)
                            if args.text_debug
                            else console.cbor_cmd(command, args.timeout)
                        )
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
