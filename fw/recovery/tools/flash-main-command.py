#!/usr/bin/env python3
"""Flash a partition through Main's control command and negotiated TCP stream."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = ROOT / "target" / "flash-devices" / "network.json"


def load_network_config() -> dict:
    path = Path(os.environ.get("DMESH_FLASH_NETWORK_CONFIG", str(DEFAULT_CONFIG)))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"defaults": {}, "boards": {}}
    return value if isinstance(value, dict) else {"defaults": {}, "boards": {}}


def save_network_config(config: dict) -> None:
    path = Path(os.environ.get("DMESH_FLASH_NETWORK_CONFIG", str(DEFAULT_CONFIG)))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def call_lmesh(
    role: str,
    command: str,
    timeout: float,
    direct_adapter: bool = False,
    request_sent: threading.Event | None = None,
) -> dict:
    request = {
        "id": "main-flash",
        "method": "esp.serial.command",
        "command": command,
        "timeout_sec": timeout,
    }
    # Only a routed/sleepy request needs an explicit active window.  A direct
    # USB command is already on the board's UART and must not invoke Main's
    # active-mode handler: that handler is product/runtime logic and has
    # previously crashed lora4 immediately before the Recovery request.
    if not direct_adapter:
        request["active_ms"] = 60_000
    # Supplying adapter explicitly bypasses lmesh's default remote route. This
    # is required for a board that is physically attached to this host and is
    # also useful when validating the direct UART/TCP maintenance path without
    # involving a gateway or NAN.
    request["adapter" if direct_adapter else "port"] = role
    if direct_adapter:
        # `adapter=` selects the local managed forward; force_direct is the
        # per-request delivery escape that bypasses an unknown/sleepy mode
        # queue while verifying a board that is expected to be awake.
        request["force_direct"] = True
    return call_control(request, role, command, timeout, request_sent=request_sent)


def flush_forward(role: str) -> dict:
    """Request delivery of a command queued by lmesh's mode classifier."""
    return call_control({
        "id": "main-flash-forward-flush",
        "method": "usb.serial.forward.flush",
        "port": role,
    }, role, "flush managed UART forward", 5.0)


def call_lmesh_and_flush(
    role: str, command: str, timeout: float, direct_adapter: bool = False
) -> dict:
    """Send one bounded command and release it from a sleepy/unknown queue."""
    result: dict[str, dict] = {}
    failure: list[BaseException] = []
    request_sent = threading.Event()

    def run() -> None:
        try:
            result["value"] = call_lmesh(
                role, command, timeout, direct_adapter=direct_adapter,
                request_sent=request_sent
            )
        except BaseException as error:
            failure.append(error)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    request_sent.wait(min(1.0, timeout))
    try:
        flush_forward(role)
    except BaseException as error:
        if not result and not failure:
            failure.append(error)
    worker.join(timeout + 2.0)
    if worker.is_alive():
        raise TimeoutError(f"{role}: command worker did not finish")
    if failure:
        raise failure[0]
    return result.get("value", {})


def status_uptime(data: dict) -> int | None:
    """Extract Main's monotonic uptime from a framed status response."""
    for message in data.get("messages", []):
        if not isinstance(message, dict):
            continue
        console = message.get("console")
        if not isinstance(console, str):
            continue
        marker = "uptime_ms="
        position = console.find(marker)
        if position < 0:
            continue
        value = console[position + len(marker):].split(None, 1)[0]
        try:
            return int(value)
        except ValueError:
            continue
    return None


def probe_main_status(role: str, timeout: float = 2.0) -> tuple[dict | None, int | None]:
    """Probe Main without requesting an active window."""
    try:
        data = call_lmesh(role, "status", timeout, direct_adapter=True)
    except (OSError, RuntimeError, TimeoutError, socket.timeout):
        return None, None
    return data, status_uptime(data)


def forward_reset_counters(role: str) -> tuple[int, int] | None:
    """Read lmesh reset execution/failure counters without touching UART."""
    try:
        data = call_control(
            {"id": "main-flash-reset-stats", "method": "usb.serial.forward.list"},
            role,
            "read managed reset counters",
            3.0,
        )
    except (OSError, RuntimeError, TimeoutError, socket.timeout):
        return None
    for forward in data.get("forwards", []):
        if isinstance(forward, dict) and forward.get("id") == role:
            stats = forward.get("stats", {})
            if isinstance(stats, dict):
                pulses = stats.get("reset_pulses")
                failures = stats.get("reset_failures")
                if isinstance(pulses, int) and isinstance(failures, int):
                    return pulses, failures
    return None


def reset_and_wait_for_main(
    role: str, description: str, timeout: float = 8.0, expect_main: bool = True
) -> dict:
    """Pulse RTS and require observable reboot evidence.

    The lmesh reset RPC only queues the physical pulse, so its successful RPC
    response is not proof that the board reset. Capture uptime before the
    pulse and require a later status response with a lower uptime. For the
    final handoff to Recovery, Main is expected not to return; in that case a
    sustained status gap is the positive evidence available through lmesh.
    """
    before_uptime = None
    probe_deadline = time.monotonic() + 5.0
    while time.monotonic() < probe_deadline:
        _, before_uptime = probe_main_status(role)
        if before_uptime is not None:
            break
        time.sleep(0.2)
    if before_uptime is None:
        raise RuntimeError(f"{role}: cannot establish Main uptime before {description}")
    counters_before = forward_reset_counters(role)
    pulses_before = counters_before[0] if counters_before is not None else None
    failures_before = counters_before[1] if counters_before is not None else None
    call_control({
        "id": "main-flash-reset",
        "method": "usb.serial.reset",
        "port": role,
    }, role, description, 5.0)

    deadline = time.monotonic() + timeout
    gap_started: float | None = None
    saw_gap = False
    last_uptime = before_uptime
    pulses_after = pulses_before
    while time.monotonic() < deadline:
        observed_counters = forward_reset_counters(role)
        if observed_counters is not None:
            pulses_after, failures_after = observed_counters
            if failures_before is not None and failures_after > failures_before:
                raise RuntimeError(
                    f"{role}: managed reset rejected; reset_failures "
                    f"{failures_before}->{failures_after}; "
                    "reset was not observed"
                )
        pulse_seen = (
            pulses_before is None
            or pulses_after is not None and pulses_after > pulses_before
        )
        current, current_uptime = probe_main_status(role, timeout=1.0)
        if current is None:
            saw_gap = True
            if gap_started is None:
                gap_started = time.monotonic()
            if pulse_seen and not expect_main and time.monotonic() - gap_started >= 1.0:
                return {
                    "before_uptime_ms": before_uptime,
                    "after_uptime_ms": None,
                    "saw_status_gap": True,
                    "main_returned": False,
                    "reset_pulses_before": pulses_before,
                    "reset_pulses_after": pulses_after,
                }
        elif current_uptime is not None:
            gap_started = None
            last_uptime = current_uptime
            # A lower uptime is definitive even if the UART forward did not
            # expose a complete no-response gap during the short reboot.
            if pulse_seen and current_uptime < before_uptime:
                return {
                    "before_uptime_ms": before_uptime,
                    "after_uptime_ms": current_uptime,
                    "saw_status_gap": saw_gap,
                    "reset_pulses_before": pulses_before,
                    "reset_pulses_after": pulses_after,
                }
            # If the board disappeared and then returned, require a fresh
            # low-uptime status response.  This avoids accepting a response
            # that was queued before the pulse.
            if pulse_seen and expect_main and saw_gap and current_uptime <= 10_000:
                return {
                    "before_uptime_ms": before_uptime,
                    "after_uptime_ms": current_uptime,
                    "saw_status_gap": True,
                    "reset_pulses_before": pulses_before,
                    "reset_pulses_after": pulses_after,
                }
        time.sleep(0.15)
    raise RuntimeError(
        f"{role}: reset not observed after {description}; "
        f"before_uptime_ms={before_uptime} last_uptime_ms={last_uptime} "
        f"saw_status_gap={saw_gap} reset_pulses_before={pulses_before} "
        f"reset_pulses_after={pulses_after}"
    )


def call_control(
    request: dict,
    role: str,
    description: str,
    timeout: float,
    request_sent: threading.Event | None = None,
) -> dict:
    """Send one bounded request and normalize the lmesh response."""
    control_path = os.environ.get("LMESH_CONTROL_SOCKET", "/run/mesh/lmesh/mesh.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.settimeout(timeout + 2.0)
        control.connect(control_path)
        control.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
        if request_sent is not None:
            request_sent.set()
        response = bytearray()
        while b"\n" not in response:
            chunk = control.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    if not response:
        raise RuntimeError(f"no lmesh response for {role}: {description}")
    reply = json.loads(bytes(response).split(b"\n", 1)[0])
    data = reply.get("data", reply.get("result", reply))
    if not isinstance(data, dict) or data.get("ok") is False:
        raise RuntimeError(f"{role}: {data}")
    for message in data.get("messages", []):
        if not isinstance(message, dict):
            continue
        console = message.get("console")
        if console:
            print(f"{role}: {console}", flush=True)
            # lmesh can return a transport-level success while the firmware
            # reports a command error inside its framed console messages.
            # Do not wait for a TCP peer after such a rejected request.
            if isinstance(console, str) and console.strip().lower().startswith("error"):
                raise RuntimeError(f"{role}: firmware rejected command: {console}")
    return data


def flash_preflight(roles: list[str], gateway: str, port: int, timeout: float) -> dict:
    """Check the complete Main-flash path without touching a device."""
    checks: dict[str, object] = {
        "server": {"endpoint": f"{gateway}:{port}", "reachable": False},
        "forwards": {},
        "images": {},
        "boards": {},
    }
    errors: list[str] = []

    try:
        with socket.create_connection((gateway, port), timeout=min(timeout, 5.0)):
            checks["server"] = {
                "endpoint": f"{gateway}:{port}",
                "reachable": True,
            }
    except OSError as error:
        errors.append(f"flash server {gateway}:{port} is unreachable: {error}")

    try:
        forward_data = call_control(
            {"id": "main-flash-preflight-forwards", "method": "usb.serial.forward.list"},
            "preflight",
            "list managed forwards",
            min(timeout, 5.0),
        )
        forwards = {
            item.get("id"): item
            for item in forward_data.get("forwards", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
    except (OSError, RuntimeError, TimeoutError, socket.timeout) as error:
        forwards = {}
        errors.append(f"cannot list managed forwards: {error}")

    config = load_network_config()
    boards = config.get("boards", {})
    if not isinstance(boards, dict):
        boards = {}
    forward_report: dict[str, object] = {}
    board_report: dict[str, object] = {}
    for role in roles:
        forward = forwards.get(role)
        running = isinstance(forward, dict) and forward.get("running") is True
        forward_report[role] = {
            "running": running,
            "socket": forward.get("socket") if isinstance(forward, dict) else None,
            "client_drops": (forward.get("stats", {}).get("client_drops")
                              if isinstance(forward, dict) and isinstance(forward.get("stats"), dict)
                              else None),
        }
        if not running:
            errors.append(f"managed forward is not running: {role}")
        board = boards.get(role, {})
        board_report[role] = board if isinstance(board, dict) else {}

    image_report: dict[str, object] = {}
    for family in ("esp32", "esp32s3"):
        image = ROOT / "target" / "flash" / family / "main-app.bin"
        if image.is_file():
            image_report[family] = {
                "path": str(image),
                "size": image.stat().st_size,
                "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            }
        else:
            image_report[family] = {"path": str(image), "present": False}
            errors.append(f"missing CPU image: {image}")

    checks["forwards"] = forward_report
    checks["boards"] = board_report
    checks["images"] = image_report
    checks["ok"] = not errors
    if errors:
        checks["errors"] = errors
    return checks


def reset_then_main_command(role: str, command: str) -> dict:
    """Write the request, wait for its ACK, then reset through lmesh.

    Rebooting from inside the firmware command races the framed response: the
    device can reset successfully while lmesh is still waiting for the ACK.
    Keep the request and reset as two bounded operations so the caller has a
    positive confirmation that NVS was written before stage2 selects
    Recovery. Do not reset before the request: a healthy Main is already the
    owner of the control plane, and an unnecessary first reset creates a
    second observation window in which an otherwise valid handoff can fail.
    """
    # `force_direct` is used by call_lmesh() for this local maintenance
    # operation. Main receives the request while fully running and can return
    # the NVS-write acknowledgement before the reset begins.
    acknowledged = call_lmesh_and_flush(role, command, 20.0, direct_adapter=True)
    reset_evidence = reset_and_wait_for_main(
        role, "reset after acknowledged Recovery request", expect_main=False
    )
    acknowledged["reset_evidence"] = reset_evidence
    return acknowledged


def record_attempt(
    role: str,
    transport: str,
    ok: bool,
    error: str = "",
    details: dict | None = None,
) -> None:
    """Leave a small durable transport-fallback audit trail per board."""
    path = ROOT / "target" / "flash-devices" / role / "upgrade-attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "transport": transport,
        "ok": ok,
    }
    if error:
        entry["error"] = error[:500]
    if details:
        entry["details"] = details
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(entry, sort_keys=True) + "\n")


def find_transfer(role: str, started_at: float, target: str = "main") -> dict | None:
    """Return a new Main session, or None while the server is still idle."""
    devices = ROOT / "target" / "flash-devices"
    for device_file in devices.glob("*/device.json"):
        try:
            device = json.loads(device_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        probe = device.get("probe", {})
        if not isinstance(probe, dict) or probe.get("port") != role:
            continue
        sessions = sorted(device_file.parent.glob("flashes/*.json"), key=lambda p: p.stat().st_mtime)
        for session in reversed(sessions):
            if session.stat().st_mtime < started_at:
                break
            try:
                record = json.loads(session.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if record.get("target") != target:
                continue
            status = record.get("status")
            if status == "success":
                return record
            if status in {"failed", "error", "timeout"}:
                raise RuntimeError(f"server session failed: {record}")
    return None


def wait_for_transfer(role: str, started_at: float, timeout: float = 45.0,
                      target: str = "main") -> dict:
    """Verify the server-side session, not merely the command acknowledgement."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = find_transfer(role, started_at, target)
        if result is not None:
            return result
        time.sleep(1.0)
    raise TimeoutError(f"no completed Main transfer recorded within {timeout:.0f}s")


def start_recovery_from_stage2(
    role: str,
    gateway: str,
    port: int,
    board_ip: str,
    ssid: str,
    password: str,
    started_at: float,
) -> dict:
    """Give a freshly selected Recovery its STA/server request over lmesh."""
    request = f"cmd:STA {gateway}:{port} {board_ip} {ssid}"
    if password:
        request += f" {password}"
    last = None
    for attempt in range(8):
        time.sleep(1.5 if attempt == 0 else 3.0)
        # Older Recovery images may accept STA and start TCP without sending
        # the textual acknowledgement that newer images emit.  Check the
        # server first on every pass so a completed transfer wins over a
        # silent UART response.
        completed = find_success_transfer(role, started_at)
        if completed is not None:
            print(f"{role}: Recovery transfer already completed while waiting for STA acknowledgement", flush=True)
            return {"server_transfer": completed}
        data = call_control({
            "id": "recovery-sta-after-stage2",
            "method": "usb.serial.handshake",
            "port": role,
            "profile": request,
            "timeout_sec": 2.0,
            "baud": 115200,
        }, role, "Recovery STA handoff after stage2", 6.0)
        last = data
        raw = str(data.get("exchanges", [{}])[0].get("raw", ""))
        if "STA request saved" in raw:
            return data
        print(f"{role}: Recovery STA handoff attempt {attempt + 1} incomplete: {data}", flush=True)
        completed = find_success_transfer(role, started_at)
        if completed is not None:
            print(f"{role}: Recovery transfer completed despite missing STA acknowledgement", flush=True)
            return {"server_transfer": completed}
    # A legacy Recovery can remain silent for the whole UART handshake loop
    # while its STA association and TCP worker finish.  Keep one bounded
    # server-observation window before reporting the handoff as failed.
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        completed = find_success_transfer(role, started_at)
        if completed is not None:
            print(f"{role}: Recovery transfer completed during late STA observation", flush=True)
            return {"server_transfer": completed}
        time.sleep(1.0)
    raise RuntimeError(f"{role}: Recovery did not accept STA request after retries: {last}")


def find_success_transfer(role: str, started_at: float, target: str = "main") -> dict | None:
    """Find a successful transfer without treating an earlier retry as fatal.

    Stage2 handoff can produce a short-lived connection-reset record before a
    later silent Recovery retry succeeds.  During that handoff window the
    server's success record is authoritative; failed intermediate sessions
    must not hide it.
    """
    devices = ROOT / "target" / "flash-devices"
    for device_file in devices.glob("*/device.json"):
        try:
            device = json.loads(device_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        probe = device.get("probe", {})
        if not isinstance(probe, dict) or probe.get("port") != role:
            continue
        sessions = sorted(
            device_file.parent.glob("flashes/*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for session in sessions:
            if session.stat().st_mtime < started_at:
                break
            try:
                record = json.loads(session.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if record.get("target") == target and record.get("status") == "success":
                return record
    return None


def rapid_reset_recovery(role: str, count: int = 3) -> None:
    """Use the stage2 rapid-reset selector as an explicit last resort."""
    for index in range(count):
        call_control({
            "id": f"rapid-reset-{index + 1}",
            "method": "usb.serial.reset",
            "port": role,
        }, role, f"rapid recovery reset {index + 1}/{count}", 5.0)
        # Keep the boots inside stage2's RTC rapid-reboot window while giving
        # the reset line and boot ROM time to settle.
        time.sleep(0.35)
    time.sleep(1.0)


def parse_roles(values: list[str], board_ips: list[str]) -> dict[str, str]:
    addresses: dict[str, str] = {}
    for item in board_ips:
        role, separator, address = item.partition("=")
        if not separator or not role or not address:
            raise SystemExit(f"invalid --board-ip {item!r}; expected ROLE=IP")
        addresses[role] = address
    missing = [role for role in values if role not in addresses]
    if missing:
        raise SystemExit("missing --board-ip for: " + ", ".join(missing))
    return addresses


def flash_one(
    role: str,
    port: int,
    board_ip: str,
    gateway: str,
    netmask: str,
    ssid: str,
    password: str,
    direct_adapter: bool,
    use_nan: bool,
    rapid_reset_last_resort: bool,
) -> None:
    fields = [
        "recovery",
        f"ssid={ssid}",
        f"password={password}",
        f"server={gateway}",
        f"mask={netmask}",
        f"port={port}",
        # Main must acknowledge the NVS write before we reset it.  A
        # reboot=true request can reset before lmesh receives the framed ACK,
        # producing a false timeout and unnecessary fallback resets.
        "reboot=false",
    ]
    if board_ip:
        fields.insert(2, f"ip={board_ip}")
    command = " ".join(fields)
    # Keep the normal path quiet and fast: Main asks Recovery to start, using
    # the managed lmesh/NAN route.  A local USB adapter is the first fallback
    # because it does not depend on Main's route being healthy.  Finally use
    # the second-stage fixed boot command, which is the recovery path even
    # when Main is crash-looping and cannot parse a command.
    if direct_adapter:
        attempts = [
            ("usb-main", lambda: reset_then_main_command(role, command)),
        ]
    else:
        attempts = []
        if use_nan:
            attempts.append(("lmesh-nan", lambda: call_lmesh_and_flush(
                role, command, 20.0, direct_adapter=False)))
        attempts.append(("usb-main", lambda: reset_then_main_command(role, command)))
    for transport, attempt in attempts:
        transfer_started = time.time()
        try:
            # Ask Main for the bounded interactive window before the Recovery
            # handoff.  Sleepy profiles may otherwise queue the request until
            # a later wake, making a healthy board look unreachable.
            if use_nan and not direct_adapter:
                try:
                    call_lmesh_and_flush(role, "active ms=60000", 12.0, direct_adapter=False)
                except (OSError, RuntimeError, TimeoutError, socket.timeout) as active_error:
                    print(f"{role}: active-window hint unavailable: {active_error}", flush=True)
            handoff = attempt()
            result = wait_for_transfer(role, transfer_started)
            evidence = handoff.get("reset_evidence") if isinstance(handoff, dict) else None
            record_attempt(
                role,
                transport,
                True,
                details={"reset_evidence": evidence} if evidence else None,
            )
            print(
                f"{role}: recovery start sent over {transport}; "
                f"sha256={result.get('image_sha256', 'unknown')} "
                f"blocks_sent={result.get('blocks_sent', 'unknown')} "
                f"elapsed={result.get('elapsed_sec', 'unknown')}s", flush=True,
            )
            return
        except (OSError, RuntimeError, TimeoutError, socket.timeout) as error:
            record_attempt(role, transport, False, str(error))
            print(f"{role}: {transport} recovery request failed: {error}", flush=True)

            # The UART command can time out after Main has already handed off
            # to Recovery.  Check the unified server before sending another
            # reset or selector; otherwise a delayed response creates
            # duplicate flash sessions and unnecessary reboots.
            try:
                result = wait_for_transfer(role, transfer_started, timeout=35.0)
                record_attempt(role, f"{transport}-server-confirmed", True)
                print(
                    f"{role}: transfer was already started by {transport}; "
                    f"server verified status={result.get('status')} "
                    f"sha256={result.get('image_sha256', 'unknown')} "
                    f"blocks_sent={result.get('blocks_sent', 'unknown')} "
                    f"elapsed={result.get('elapsed_sec', 'unknown')}s", flush=True,
                )
                return
            except (OSError, RuntimeError, TimeoutError, socket.timeout) as transfer_error:
                print(f"{role}: no completed server transfer after {transport}: {transfer_error}", flush=True)

            # A board that was left in the ROM downloader or a crash loop may
            # not have a live Main command window.  The managed lmesh reset is
            # an explicit recovery action (never an implicit runtime
            # transport); retry the same Main request once after it boots.
            if direct_adapter and transport == "usb-main":
                retry_started = time.time()
                try:
                    reset = reset_and_wait_for_main(
                        role, "managed reset before Main retry"
                    )
                    print(f"{role}: managed reset verified: {reset}", flush=True)
                    handoff = attempt()
                    result = wait_for_transfer(role, retry_started)
                    evidence = handoff.get("reset_evidence") if isinstance(handoff, dict) else None
                    record_attempt(
                        role,
                        "usb-main-reset-retry",
                        True,
                        details={"reset_evidence": evidence} if evidence else None,
                    )
                    print(
                        f"{role}: recovery start sent over usb-main-reset-retry; "
                        f"transfer verified status={result.get('status')} "
                        f"sha256={result.get('image_sha256', 'unknown')} "
                        f"blocks_sent={result.get('blocks_sent', 'unknown')} "
                        f"elapsed={result.get('elapsed_sec', 'unknown')}s", flush=True,
                    )
                    return
                except (OSError, RuntimeError, TimeoutError, socket.timeout) as retry_error:
                    record_attempt(role, "usb-main-reset-retry", False, str(retry_error))
                    print(f"{role}: usb-main-reset-retry failed: {retry_error}", flush=True)

    started_at = time.time()
    try:
        if rapid_reset_last_resort:
            print(f"{role}: trying stage2 rapid-reset Recovery selector (last resort)", flush=True)
            rapid_reset_recovery(role)
            record_attempt(role, "stage2-rapid-reset", True)
            print(f"{role}: stage2 rapid-reset Recovery selector completed", flush=True)
        else:
            data = call_control({
                "id": "main-flash-stage2",
                "method": "usb.serial.boot",
                "port": role,
                "command": "recovery",
                "reset": True,
                "timeout_sec": 3.0,
            }, role, "stage2 recovery", 8.0)
            record_attempt(role, "stage2", True)
            print(f"{role}: stage2 RECOVER handoff completed: {data}", flush=True)
        started_at = time.time()
        request = start_recovery_from_stage2(
            role, gateway, port, board_ip, ssid, password, started_at,
        )
        print(f"{role}: Recovery STA request sent after stage2: {request}", flush=True)
        result = wait_for_transfer(role, started_at)
        record_attempt(role, "stage2-recovery", True)
        print(
            f"{role}: stage2 Recovery transfer verified "
            f"sha256={result.get('image_sha256', 'unknown')} "
            f"blocks_sent={result.get('blocks_sent', 'unknown')} "
            f"elapsed={result.get('elapsed_sec', 'unknown')}s", flush=True,
        )
    except (OSError, RuntimeError, TimeoutError, socket.timeout) as error:
        # Recovery may have accepted the request and rebooted before the final
        # UART exchange was returned. Confirm the durable server record before
        # declaring the board failed or attempting another selector.
        try:
            result = wait_for_transfer(role, started_at, timeout=35.0)
            record_attempt(role, "stage2-recovery-server-confirmed", True)
            print(
                f"{role}: stage2 Recovery transfer completed despite handoff error "
                f"sha256={result.get('image_sha256', 'unknown')} "
                f"blocks_sent={result.get('blocks_sent', 'unknown')} "
                f"elapsed={result.get('elapsed_sec', 'unknown')}s", flush=True,
            )
            return
        except (OSError, RuntimeError, TimeoutError, socket.timeout) as transfer_error:
            print(f"{role}: no completed server transfer after stage2 handoff: {transfer_error}", flush=True)
        record_attempt(role, "stage2", False, str(error))
        raise RuntimeError(f"{role}: all recovery-start transports failed: {error}") from error


def flash_main_target(
    role: str,
    target: str,
    port: int,
    board_ip: str,
    gateway: str,
    netmask: str,
    ssid: str,
    password: str,
) -> None:
    """Flash Stage2 or Recovery directly from Main over Wi-Fi.

    Main remains running while its asynchronous STA/TCP worker writes the
    requested non-running target. This path deliberately does not select
    Recovery or reset the board; the server selects the requested artifact
    from the extended HELLO.
    """
    if target == "main":
        raise ValueError("Main target uses the normal Recovery handoff")
    if not board_ip:
        raise RuntimeError(f"{role}: no saved board IP for target={target}")
    started_at = time.time()
    command = (
        f"recovery op=connect target={target} server={gateway} ip={board_ip} "
        f"mask={netmask} port={port} ssid={ssid} password={password} reboot=false"
    )
    try:
        try:
            call_lmesh_and_flush(role, "active ms=60000", 12.0, direct_adapter=False)
        except (OSError, RuntimeError, TimeoutError, socket.timeout) as error:
            print(f"{role}: active-window hint unavailable: {error}", flush=True)
        # Main target updates use lmesh's queued path. This is important for
        # sleepy boards: the command must wait for the firmware heartbeat
        # rather than requiring a live direct UART session.
        call_lmesh_and_flush(role, command, 30.0, direct_adapter=False)
        result = wait_for_transfer(role, started_at, timeout=120.0, target=target)
        record_attempt(role, f"main-{target}", True)
        print(
            f"{role}: target={target} transfer verified "
            f"sha256={result.get('image_sha256', 'unknown')} "
            f"blocks_sent={result.get('blocks_sent', 'unknown')} "
            f"elapsed={result.get('elapsed_sec', 'unknown')}s",
            flush=True,
        )
    except (OSError, RuntimeError, TimeoutError, socket.timeout) as error:
        late = find_success_transfer(role, started_at, target)
        if late is not None:
            record_attempt(role, f"main-{target}-server-confirmed", True)
            print(
                f"{role}: target={target} transfer completed during late observation "
                f"sha256={late.get('image_sha256', 'unknown')} "
                f"blocks_sent={late.get('blocks_sent', 'unknown')} "
                f"elapsed={late.get('elapsed_sec', 'unknown')}s",
                flush=True,
            )
            return
        record_attempt(role, f"main-{target}", False, str(error))
        raise SystemExit(f"{role}: Main target={target} transfer failed: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roles", nargs="+", help="managed lmesh roles")
    parser.add_argument("--check", action="store_true",
                        help="read-only preflight; do not reset, hand off, or flash")
    parser.add_argument("--board-ip", action="append", default=[], metavar="ROLE=IP",
                        help="optional Recovery static IP; default is MAC-derived")
    parser.add_argument("--port", type=int,
                        help="persistent DRS2 server port for Main updates")
    parser.add_argument("--ssid",
                        help="optional open STA SSID; default scans Direct-*-Dmesh")
    parser.add_argument("--password", default="",
                        help="optional Recovery STA password")
    parser.add_argument(
        "--target",
        choices=("main", "stage2", "boot", "recovery", "partition", "partition-table"),
        default="main",
        help="resource requested from Main; non-main targets do not reset",
    )
    parser.add_argument("--use-nan", action="store_true",
                        help="EXPERIMENTAL: try the NAN gateway first (disabled by default)")
    parser.add_argument("--rapid-reset-last-resort", action="store_true",
                        help="last resort: use three RTS-only resets to trigger stage2 Recovery")
    parser.add_argument("--gateway",
                        help="Recovery server address (default: 10.78.0.1)")
    parser.add_argument("--netmask",
                        help="Recovery STA netmask (default: 255.255.0.0)")
    args = parser.parse_args()
    config = load_network_config()
    defaults = config.get("defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    boards = config.get("boards", {})
    if not isinstance(boards, dict):
        boards = {}
    cli_addresses = parse_roles(args.roles, args.board_ip) if args.board_ip else {}
    saved_addresses = {
        role: value.get("ip", "")
        for role, value in boards.items()
        if isinstance(value, dict) and isinstance(value.get("ip", ""), str)
    }
    addresses = {role: cli_addresses.get(role, saved_addresses.get(role, ""))
                 for role in args.roles}
    # Managed direct lmesh is the normal path.  NAN is an explicit experiment.
    direct_adapter = not args.use_nan
    ssid = args.ssid if args.ssid is not None else defaults.get("ssid", "")
    gateway = args.gateway if args.gateway is not None else defaults.get("gateway", "10.78.0.1")
    netmask = args.netmask if args.netmask is not None else str(
        defaults.get("netmask", "255.255.0.0")
    )
    port = args.port if args.port is not None else int(defaults.get("port", 3336))
    if args.target != "main":
        for role in args.roles:
            flash_main_target(
                role, args.target, port, addresses[role], gateway, netmask,
                ssid, args.password,
            )
        return 0
    if args.check:
        result = flash_preflight(args.roles, gateway, port, 5.0)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("ok") is True else 1
    # Make the safe preflight part of the normal command as well. A human
    # should not have to remember a separate check before a state-changing
    # handoff; this catches a dead managed forward, missing server, or missing
    # CPU image before any reset or NVS write occurs.
    preflight = flash_preflight(args.roles, gateway, port, 5.0)
    print(json.dumps(preflight, indent=2, sort_keys=True), flush=True)
    if preflight.get("ok") is not True:
        return 2
    if args.ssid is not None:
        defaults["ssid"] = args.ssid
    if args.gateway is not None:
        defaults["gateway"] = args.gateway
    if args.port is not None:
        defaults["port"] = args.port
    if args.netmask is not None:
        defaults["netmask"] = args.netmask
    for role, address in cli_addresses.items():
        entry = boards.setdefault(role, {})
        if isinstance(entry, dict):
            entry["ip"] = address
    config["defaults"] = defaults
    config["boards"] = boards
    if (args.ssid is not None or args.gateway is not None or args.port is not None
            or args.netmask is not None or cli_addresses):
        save_network_config(config)
    for role in args.roles:
        flash_one(
            role,
            port,
            addresses[role],
            gateway,
            netmask,
            ssid,
            args.password,
            direct_adapter,
            args.use_nan,
            args.rapid_reset_last_resort,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
