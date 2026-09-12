#!/usr/bin/env python3
"""Copy an NVS dump while removing one-shot Recovery request markers.

The raw NVS target is intentionally a byte-for-byte flash operation.  This
helper makes a safe test/emergency image from a previously read partition:
transport settings and product settings are retained, while the transient
Recovery request is omitted so restoring the image cannot re-arm an old
update.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TYPE_MAP = {
    "uint8_t": "u8",
    "int8_t": "i8",
    "uint16_t": "u16",
    "int16_t": "i16",
    "uint32_t": "u32",
    "int32_t": "i32",
    "uint64_t": "u64",
    "int64_t": "i64",
    "string": "string",
    "blob_data": "base64",
}
TRANSIENT_RECOVERY_KEYS = {"request_magic", "request_version", "flags"}
STAGE2_NAMESPACE = "stg2"
STA_PROFILE_KEYS = {
    "sta_ssid",
    "sta_server_ll",
    "sta_server_port",
}
STA_SECRET_NAMESPACE = "sec"
STA_SECRET_KEY = "sta"
STA_SECRET_PROFILE_KEY = "__sec_sta"
CONTROL_PLANE_KEY = "cp"
SHARED_SECRET_KEY = "key"
CONTROL_PLANE_PROFILE_KEY = "__blob_cp"
SHARED_SECRET_PROFILE_KEY = "__blob_sec_key"
DEVICE_NAME = "name"
DEVICE_DOMAIN = "domain"


def base64_key(value: object, field: str, lengths: tuple[int, ...]) -> str:
    """Validate a binary catalog value represented as base64."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError(f"{field} is not valid base64") from error
    if len(decoded) not in lengths:
        raise ValueError(f"{field} must encode {', '.join(map(str, lengths))} bytes")
    return value


def load_device_security(catalog: Path, role: str) -> dict[str, str]:
    """Load one ESP security record from the shared test device catalog.

    The catalog's device name is the single provisioning authority.  Its
    shared secret deliberately remains host-side in this first milestone;
    checking it here prevents a half-populated device record from being used.
    """
    if not catalog.is_file():
        raise ValueError(f"device catalog not found: {catalog}")
    with catalog.open("rb") as stream:
        document = tomllib.load(stream)
    security = document.get("security")
    if not isinstance(security, dict):
        raise ValueError("device catalog is missing [security]")
    control_plane = base64_key(
        security.get("control_plane_public_key_b64"),
        "security.control_plane_public_key_b64", (33,),
    )
    devices = document.get("devices")
    if not isinstance(devices, list):
        raise ValueError("device catalog has no [[devices]] entries")
    matches = [device for device in devices if isinstance(device, dict) and device.get("name") == role]
    if len(matches) != 1:
        raise ValueError(f"device catalog must contain exactly one device named {role!r}")
    device = matches[0]
    if device.get("kind") != "esp":
        raise ValueError(f"catalog device {role!r} is not an ESP device")
    name = device.get("name")
    if not isinstance(name, str) or not 1 <= len(name.encode("ascii")) <= 8:
        raise ValueError("catalog ESP name must be 1..8 ASCII bytes for announce")
    domain = document.get("domain", "test.webinf.info")
    if not isinstance(domain, str) or not 1 <= len(domain.encode("ascii")) <= 16:
        raise ValueError("catalog domain must be 1..16 ASCII bytes for announce")
    # ESP private keys are generated on-device by the P-256 hardware-backed
    # identity path. The catalog contains only public/control-plane material.
    shared_secret = base64_key(
        device.get("shared_secret_b64"), f"devices.{role}.shared_secret_b64", (32,),
    )
    return {
        DEVICE_NAME: name,
        DEVICE_DOMAIN: domain,
        CONTROL_PLANE_PROFILE_KEY: control_plane,
        SHARED_SECRET_PROFILE_KEY: shared_secret,
    }


def load_sta_profile(path: Path, ssid: str | None, server_ll: str | None,
                     server_port: int | None) -> dict[str, str]:
    """Load one private WPA profile without rendering its credential.

    The host's `infra-sta.toml` is an authority for selecting the SSID and
    credential only. An optional Recovery server address is retained for that
    workflow, but Main can discover peers through multicast/NAN and therefore
    does not require one.
    """
    if not path.is_file():
        raise ValueError(f"STA profile file not found: {path}")
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    networks = document.get("networks")
    if networks is None:
        networks = [{
            "ssid": document.get("ssid"),
            "password": document.get("password"),
        }]
    if not isinstance(networks, list):
        raise ValueError("STA profile networks must be an array")
    matches = [network for network in networks if isinstance(network, dict)
               and (ssid is None or network.get("ssid") == ssid)]
    if len(matches) != 1:
        selector = ssid if ssid is not None else "default"
        raise ValueError(f"STA profile selection {selector!r} is missing or ambiguous")
    network = matches[0]
    name = network.get("ssid")
    password = network.get("password")
    if not isinstance(name, str) or not 1 <= len(name.encode()) <= 32 or "\0" in name:
        raise ValueError("STA profile has an invalid SSID")
    if not isinstance(password, str) or not 8 <= len(password) <= 63 or "\0" in password:
        raise ValueError("STA profile has an invalid WPA credential")
    result = {
        "sta_ssid": name,
        # Keep the credential in `sec:sta`; `dmesh` retains only connection
        # selection metadata. The internal marker is consumed before CSV
        # output and is never printed.
        STA_SECRET_PROFILE_KEY: password,
    }
    if server_ll is not None:
        import ipaddress
        address = ipaddress.IPv6Address(server_ll)
        if not address.is_link_local:
            raise ValueError("--sta-server-ll must be an IPv6 link-local address")
        if not server_port or not 1 <= server_port <= 65535:
            raise ValueError("STA profile requires --sta-server-port in 1..65535")
        result["sta_server_ll"] = address.compressed
        result["sta_server_port"] = str(server_port)
    return result


def nvs_tool() -> Path:
    idf = os.environ.get("IDF_PATH")
    if not idf:
        raise SystemExit("IDF_PATH must be set; source env.sh first")
    return Path(idf) / "components" / "nvs_flash" / "nvs_partition_tool" / "nvs_tool.py"


def read_entries(source: Path) -> list[dict]:
    python = os.environ.get("DMESH_PYTHON", sys.executable)
    tool = nvs_tool()
    result = subprocess.run(
        [python, str(tool), str(source.resolve()), "-d", "minimal", "-f", "json", "--color", "never"],
        cwd=tool.parent,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def write_csv(
    entries: list[dict], destination: Path, uart_boot: int | None = None,
    boot_target: int | None = None, device_profile: dict[str, str] | None = None,
    clear_boot_target: bool = False, mode: str | None = None,
    clear_sta_profile: bool = False,
) -> int:
    # nvs_partition_gen assigns a numeric namespace id at each `namespace`
    # row. A decoded dump can revisit `phy` later for blob chunks; emitting it
    # again creates a second id and silently moves following values into the
    # wrong namespace. Group entries first, then emit each namespace once.
    namespaces: dict[str, list[dict]] = {}
    for entry in entries:
        namespaces.setdefault(entry["namespace"], []).append(entry)
    removed = 0
    saw_uart_boot = False
    saw_boot_target = False
    saw_dmesh = False
    saw_secret_namespace = False
    saw_secret_keys: set[str] = set()
    saw_mode = False
    seen_profile: set[str] = set()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("key", "type", "encoding", "value"))
        for current, grouped_entries in namespaces.items():
            writer.writerow((current, "namespace", "", ""))
            if current == "dmesh":
                saw_dmesh = True
            if current == STA_SECRET_NAMESPACE:
                saw_secret_namespace = True
            for entry in grouped_entries:
                # Older generated images accidentally stored `mode` under
                # stg2. It is a dmesh policy key; discard the misplaced copy
                # so it cannot survive another preserve-and-update cycle.
                if entry["key"] == "mode" and current != "dmesh":
                    continue
                if current == STAGE2_NAMESPACE and entry["key"] == "uart_boot":
                    saw_uart_boot = True
                    if uart_boot is not None:
                        writer.writerow(("uart_boot", "data", "u32", str(uart_boot)))
                        continue
                if current == STAGE2_NAMESPACE and entry["key"] == "boot_target":
                    saw_boot_target = True
                    if clear_boot_target:
                        continue
                    if boot_target is not None:
                        writer.writerow(("boot_target", "data", "u32", str(boot_target)))
                        continue
                # Correct a short-lived host-tool bug that wrote the lab
                # override under dmesh. It is a Stage2 key, not a profile key.
                if current == "dmesh" and entry["key"] == "boot_target" and (
                    boot_target is not None or clear_boot_target
                ):
                    continue
                if current == "dmesh" and clear_sta_profile and entry["key"] in STA_PROFILE_KEYS:
                    removed += 1
                    continue
                if current == STA_SECRET_NAMESPACE and clear_sta_profile and entry["key"] == STA_SECRET_KEY:
                    removed += 1
                    continue
                if current == "dmesh" and device_profile is not None and entry["key"] in device_profile:
                    writer.writerow((entry["key"], "data", "string", device_profile[entry["key"]]))
                    seen_profile.add(entry["key"])
                    continue
                if current == "dmesh" and device_profile is not None and entry["key"] == CONTROL_PLANE_KEY and CONTROL_PLANE_PROFILE_KEY in device_profile:
                    writer.writerow((CONTROL_PLANE_KEY, "data", "base64", device_profile[CONTROL_PLANE_PROFILE_KEY]))
                    seen_profile.add(CONTROL_PLANE_KEY)
                    continue
                if current == STA_SECRET_NAMESPACE and device_profile is not None:
                    secret_profile_key = {
                        STA_SECRET_KEY: STA_SECRET_PROFILE_KEY,
                        SHARED_SECRET_KEY: SHARED_SECRET_PROFILE_KEY,
                    }.get(entry["key"])
                    if secret_profile_key is not None and secret_profile_key in device_profile:
                        encoding = "base64" if entry["key"] == SHARED_SECRET_KEY else "string"
                        writer.writerow((entry["key"], "data", encoding, device_profile[secret_profile_key]))
                        saw_secret_keys.add(entry["key"])
                        continue
                if current == "dmesh" and mode is not None and entry["key"] == "mode":
                    # A preserved NVS dump can contain duplicate historical
                    # mode rows. Emit exactly one replacement; nvs_partition_gen
                    # otherwise applies the last row silently and makes the
                    # next-boot policy depend on flash history.
                    if not saw_mode:
                        writer.writerow(("mode", "data", "string", mode))
                        saw_mode = True
                    continue
                    continue
                if current == "recovery" and entry["key"] in TRANSIENT_RECOVERY_KEYS:
                    removed += 1
                    continue
                encoding = TYPE_MAP.get(entry["encoding"])
                if encoding is None:
                    raise RuntimeError(
                        f"unsupported NVS encoding {entry['encoding']} for "
                        f"{current}:{entry['key']}"
                    )
                writer.writerow((entry["key"], "data", encoding, entry["data"]))
            if current == "dmesh":
                if mode is not None and not saw_mode:
                    writer.writerow(("mode", "data", "string", mode))
                    saw_mode = True
                if device_profile is not None:
                    for key, value in device_profile.items():
                        if key not in (STA_SECRET_PROFILE_KEY, CONTROL_PLANE_PROFILE_KEY, SHARED_SECRET_PROFILE_KEY) and key not in seen_profile:
                            writer.writerow((key, "data", "string", value))
                    if CONTROL_PLANE_PROFILE_KEY in device_profile and CONTROL_PLANE_KEY not in seen_profile:
                        writer.writerow((CONTROL_PLANE_KEY, "data", "base64", device_profile[CONTROL_PLANE_PROFILE_KEY]))
                        seen_profile.add(CONTROL_PLANE_KEY)
            if current == STA_SECRET_NAMESPACE and device_profile is not None:
                for key, profile_key in ((STA_SECRET_KEY, STA_SECRET_PROFILE_KEY), (SHARED_SECRET_KEY, SHARED_SECRET_PROFILE_KEY)):
                    if profile_key in device_profile and key not in saw_secret_keys:
                        writer.writerow((key, "data", "base64" if key == SHARED_SECRET_KEY else "string", device_profile[profile_key]))
                        saw_secret_keys.add(key)
        namespace = next(reversed(namespaces), None)
        if uart_boot is not None and not saw_uart_boot:
            if namespace != STAGE2_NAMESPACE:
                writer.writerow((STAGE2_NAMESPACE, "namespace", "", ""))
                namespace = STAGE2_NAMESPACE
            writer.writerow(("uart_boot", "data", "u32", str(uart_boot)))
        if boot_target is not None and not saw_boot_target:
            if namespace != STAGE2_NAMESPACE:
                writer.writerow((STAGE2_NAMESPACE, "namespace", "", ""))
                namespace = STAGE2_NAMESPACE
            writer.writerow(("boot_target", "data", "u32", str(boot_target)))
        if device_profile is not None and not saw_dmesh:
            if namespace != "dmesh":
                writer.writerow(("dmesh", "namespace", "", ""))
                namespace = "dmesh"
            for key, value in device_profile.items():
                if key not in (STA_SECRET_PROFILE_KEY, CONTROL_PLANE_PROFILE_KEY, SHARED_SECRET_PROFILE_KEY) and key not in seen_profile:
                    writer.writerow((key, "data", "string", value))
            if CONTROL_PLANE_PROFILE_KEY in device_profile and CONTROL_PLANE_KEY not in seen_profile:
                writer.writerow((CONTROL_PLANE_KEY, "data", "base64", device_profile[CONTROL_PLANE_PROFILE_KEY]))
        # A selector/IP update carries a non-secret `dmesh` profile.  Only a
        # Private inputs are represented only by internal markers. Neither the
        # CSV nor status output reveals their source names or values.
        if device_profile is not None and any(
            key in device_profile for key in (STA_SECRET_PROFILE_KEY, SHARED_SECRET_PROFILE_KEY)
        ):
            if not saw_secret_namespace:
                writer.writerow((STA_SECRET_NAMESPACE, "namespace", "", ""))
                namespace = STA_SECRET_NAMESPACE
            for key, profile_key in ((STA_SECRET_KEY, STA_SECRET_PROFILE_KEY), (SHARED_SECRET_KEY, SHARED_SECRET_PROFILE_KEY)):
                if profile_key in device_profile and key not in saw_secret_keys:
                    writer.writerow((key, "data", "base64" if key == SHARED_SECRET_KEY else "string", device_profile[profile_key]))
        if mode is not None and not saw_mode:
            if not saw_dmesh:
                writer.writerow(("dmesh", "namespace", "", ""))
            writer.writerow(("mode", "data", "string", mode))
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("csv", type=Path)
    parser.add_argument("image", type=Path)
    parser.add_argument("--size", type=lambda value: int(value, 0), default=None)
    parser.add_argument(
        "--uart-boot", type=int, choices=(0, 1),
        help="set stg2:uart_boot in the generated NVS image; use 0 for production",
    )
    parser.add_argument(
        "--boot-target", type=int, choices=(1, 2),
        help="set stg2:boot_target (1=Main, 2=Recovery); omit for normal policy",
    )
    parser.add_argument(
        "--clear-boot-target", action="store_true",
        help="remove stg2:boot_target and use normal Stage2 selection",
    )
    parser.add_argument("--mode", choices=("active", "sleepy", "sleepy-soft"),
                        help="set dmesh:mode next-boot policy (sleepy-soft keeps the radio awake for transition tests)")
    parser.add_argument("--clear-sta-profile", action="store_true",
                        help="remove the persisted dmesh STA selector and its private credential")
    parser.add_argument("--server")
    parser.add_argument("--ip")
    parser.add_argument("--gw")
    parser.add_argument("--mask")
    parser.add_argument("--port", type=int)
    parser.add_argument("--sta-profile", type=Path,
                        help="private infra-sta.toml input; credentials are never printed")
    parser.add_argument("--sta-ssid",
                        help="select one SSID from --sta-profile")
    parser.add_argument("--sta-server-ll",
                        help="optional Recovery server IPv6 link-local address without an interface scope")
    parser.add_argument("--sta-server-port", type=int, default=3336,
                        help="Recovery server UDP port when --sta-server-ll is used")
    parser.add_argument("--device-catalog", type=Path,
                        help="shared test device catalog containing [security] and this ESP's key material")
    parser.add_argument("--device-role",
                        help="catalog ESP name selected by flash-device.py")
    args = parser.parse_args()
    if args.boot_target is not None and args.clear_boot_target:
        parser.error("--boot-target and --clear-boot-target are mutually exclusive")
    if not args.source.is_file():
        raise SystemExit(f"source not found: {args.source}")
    entries = read_entries(args.source)
    profile_values = {
        "server": args.server,
        "ip": args.ip,
        "gw": args.gw,
        "mask": args.mask,
        "port": str(args.port) if args.port else None,
    }
    device_profile = {key: value for key, value in profile_values.items() if value}
    if args.sta_profile is not None:
        try:
            sta_profile = load_sta_profile(
                args.sta_profile, args.sta_ssid, args.sta_server_ll, args.sta_server_port,
            )
        except ValueError as error:
            parser.error(str(error))
        device_profile.update(sta_profile)
    if (args.device_catalog is None) != (args.device_role is None):
        parser.error("--device-catalog and --device-role must be used together")
    if args.device_catalog is not None:
        try:
            device_profile.update(load_device_security(args.device_catalog, args.device_role))
        except ValueError as error:
            parser.error(str(error))
    removed = write_csv(
        entries, args.csv, args.uart_boot, args.boot_target, device_profile or None,
        args.clear_boot_target, args.mode, args.clear_sta_profile,
    )
    size = args.size or args.source.stat().st_size
    python = os.environ.get("DMESH_PYTHON", sys.executable)
    generator = nvs_tool().parent.parent / "nvs_partition_generator" / "nvs_partition_gen.py"
    subprocess.run(
        [python, str(generator), "generate", str(args.csv), str(args.image), hex(size)],
        check=True,
    )
    setting = ""
    if args.uart_boot is not None:
        setting = f"; stg2:uart_boot={args.uart_boot}"
    if args.boot_target is not None:
        setting += f"; stg2:boot_target={args.boot_target}"
    elif args.clear_boot_target:
        setting += "; stg2:boot_target cleared"
    if device_profile:
        setting += "; dmesh profile updated"
    if args.mode is not None:
        setting += f"; dmesh:mode={args.mode}"
    if args.clear_sta_profile:
        setting += "; STA profile cleared"
    print(f"removed {removed} transient Recovery keys{setting}; generated {args.image} ({size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
