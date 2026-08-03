#!/usr/bin/env python3
"""Flash a partition through Main's control command and negotiated TCP stream."""

from __future__ import annotations

import argparse
import json
import os
import socket
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


def call_lmesh(role: str, command: str, timeout: float) -> dict:
    control_path = os.environ.get("LMESH_CONTROL_SOCKET", "/run/mesh/lmesh/mesh.sock")
    request = {
        "id": "main-flash",
        "method": "esp.serial.command",
        "port": role,
        "command": command,
        "timeout_sec": timeout,
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.settimeout(timeout + 2.0)
        control.connect(control_path)
        control.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
        response = bytearray()
        while b"\n" not in response:
            chunk = control.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    if not response:
        raise RuntimeError(f"no lmesh response for {role}: {command}")
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
    ssid: str,
    password: str,
) -> None:
    fields = [
        "recovery",
        f"ssid={ssid}",
        f"password={password}",
        f"server={gateway}",
        f"port={port}",
        "reboot=true",
    ]
    if board_ip:
        fields.insert(2, f"ip={board_ip}")
    command = " ".join(fields)
    call_lmesh(role, command, 30.0)
    print(
        f"{role}: recovery start sent over managed lmesh; "
        f"permanent DRS2 server should handle port {port}",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roles", nargs="+", help="managed lmesh roles")
    parser.add_argument("--board-ip", action="append", default=[], metavar="ROLE=IP",
                        help="optional Recovery static IP; default is MAC-derived")
    parser.add_argument("--port", type=int,
                        help="persistent DRS2 server port for Main updates")
    parser.add_argument("--ssid",
                        help="optional open STA SSID; default scans Direct-*-Dmesh")
    parser.add_argument("--password", default="",
                        help="optional Recovery STA password")
    parser.add_argument("--gateway",
                        help="Recovery server address (default: 10.78.0.1)")
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
    ssid = args.ssid if args.ssid is not None else defaults.get("ssid", "")
    gateway = args.gateway if args.gateway is not None else defaults.get("gateway", "10.78.0.1")
    port = args.port if args.port is not None else int(defaults.get("port", 3336))
    if args.ssid is not None:
        defaults["ssid"] = args.ssid
    if args.gateway is not None:
        defaults["gateway"] = args.gateway
    if args.port is not None:
        defaults["port"] = args.port
    for role, address in cli_addresses.items():
        entry = boards.setdefault(role, {})
        if isinstance(entry, dict):
            entry["ip"] = address
    config["defaults"] = defaults
    config["boards"] = boards
    if args.ssid is not None or args.gateway is not None or args.port is not None or cli_addresses:
        save_network_config(config)
    for role in args.roles:
        flash_one(
            role,
            port,
            addresses[role],
            gateway,
            ssid,
            args.password,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
