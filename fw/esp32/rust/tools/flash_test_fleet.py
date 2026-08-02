#!/usr/bin/env python3
"""Build, flash, and configure ESP boards through lmesh USB forwarding.

Run from the repository root after sourcing the firmware environment:

    . env.sh
    python fw/esp32/rust/tools/flash_test_fleet.py

Defaults:
  * discover devices through lmesh usb.serial.list;
  * stop the selected lmesh forward and flash its physical USB-UART bridge;
  * configure infrastructure ports (normally lora1) as powered/always-on;
  * configure all other ESP targets as sleepy raw/custom NAN nodes with Wi-Fi
    off between discovery windows;
  * configure DFS and LoRa receive when the board has saved/probed LoRa pins.

Use explicit logical --port arguments such as lora1 or s3-1, or set
DMESH_FLASH_PORTS=lora1,lora2 when device roles matter. Numeric USB/ACM names
remain compatibility aliases.
Keep test-specific roles, such as sleepy raw-NAN or pretend-sleep timing loops,
in separate test scripts or manual serial commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))
SSH_MESH_ROOT = Path(
    os.environ.get("DMESH_SSH_MESH_DIR") or ROOT.parent / "rust" / "ssh-mesh"
).resolve()
sys.path.insert(0, str(SSH_MESH_ROOT / "python"))

from dmesh.radio import RadioClient

from device_flash_archive import append_event, device_dir, record_flash, update_device, utc_now

FW_RUST = ROOT / "fw" / "esp32" / "rust"
# build-fw.sh honors the repo-local CARGO_TARGET_DIR. Keep flashing on that
# same top-level target tree; falling back to target/fw would silently reuse
# stale images from the pre-containment layout.
FW_TARGET_ROOT = Path(
    os.environ.get("DMESH_FW_TARGET_DIR")
    or os.environ.get("CARGO_TARGET_DIR")
    or ROOT / "target"
).resolve()
MESH_ENV = ROOT / "scripts" / "with-env.sh"
NAN_PAIR_TEST = FW_RUST / "tools" / "nan_pair_test.py"
LORA_CAD_TEST = FW_RUST / "tools" / "lora_cad_test.py"
LORA_PAIR_TEST = FW_RUST / "tools" / "lora_pair_test.py"
PRESUBMIT = FW_RUST / "tools" / "presubmit.py"
ESP32_MERGED_IMAGE = FW_TARGET_ROOT / "flash" / "esp32" / "dmesh-rs-merged.bin"
ESP32S3_MERGED_IMAGE = FW_TARGET_ROOT / "flash" / "esp32s3" / "dmesh-rs-merged.bin"
ESP32S3_8MB_TARGET = FW_TARGET_ROOT
ESP32S3_8MB_MERGED_IMAGE = (
    FW_TARGET_ROOT / "flash" / "esp32s3-8mb" / "dmesh-rs-merged.bin"
)
SPARSE_FLASH_DIR = FW_TARGET_ROOT / "flash" / "sparse"
FLASH_BAUD = 460_800
DEFAULT_LMESH_CONFIG = Path("/home/system/etc/lmesh/lmesh.toml")
PREFLASH_FAILURE_MARKERS = (
    "Guru Meditation",
    "Interrupt wdt timeout",
    "rst:0x",
    "boot: ESP-IDF",
    "Rebooting...",
)


def esptool_python() -> str:
    """Use the ESP-IDF interpreter, not the host/lmesh test interpreter."""
    env_path = os.environ.get("IDF_PYTHON_ENV_PATH")
    if env_path:
        candidate = Path(env_path) / "bin" / "python"
        if candidate.is_file():
            return str(candidate)
    return sys.executable


@dataclass
class Device:
    port: str
    chip: str
    mac: str | None
    flash_size_mb: int | None = None

    @property
    def logical_port(self) -> str:
        return logical_usb_port(self.port)

    @property
    def is_s3(self) -> bool:
        return self.chip == "esp32s3"

    @property
    def is_classic(self) -> bool:
        return self.chip == "esp32"


@dataclass(frozen=True)
class ForwardSpec:
    """Persistent lmesh forward settings restored after a direct flash."""

    port: str
    path: str | None
    baud: int = FLASH_BAUD
    tcp_port: int | None = None
    tcp_mode: str = "framed"
    multi: bool = True


def run(
    argv: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(argv), flush=True)
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def run_logged(
    label: str,
    argv: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    tail_lines: int | None = None,
) -> str:
    print(f"{label}: + {' '.join(argv)}", flush=True)
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout or ""
        print_output_block(f"{label}: failed", output)
        raise
    output = proc.stdout or ""
    if output:
        if tail_lines is not None:
            output = "\n".join(output.rstrip().splitlines()[-tail_lines:]) + "\n"
        print_output_block(label, output)
    return proc.stdout or ""


def print_output_block(label: str, output: str) -> None:
    print(f"--- {label} output begin ---", flush=True)
    print(output.rstrip(), flush=True)
    print(f"--- {label} output end ---", flush=True)


def archive_usb_device(device: Device, port: str, baud: int) -> Path:
    """Read immutable device diagnostics before any USB flash write."""
    if not device.mac:
        raise RuntimeError(f"{device.port}: probe did not return a MAC address")
    path = device_dir(device.mac)
    chip = "esp32s3" if device.is_s3 else "esp32"
    table = path / "partition-table.bin"
    nvs = path / "nvs.bin"
    common = [
        esptool_python(), "-m", "esptool", "--chip", chip, "--port", port,
        "--baud", str(baud), "--before", "default_reset", "--after", "no_reset",
        "read_flash",
    ]
    run_logged(
        f"read partition table {device.port}",
        common + ["0x8000", "0x1000", str(table)],
        cwd=FW_RUST,
        tail_lines=12,
    )
    run_logged(
        f"read NVS {device.port}",
        common + ["0x9000", "0x6000", str(nvs)],
        cwd=FW_RUST,
        tail_lines=12,
    )
    update_device(
        device.mac,
        mac=device.mac.lower(),
        last_seen=utc_now(),
        source="usb-esptool",
        probe={
            "chip": device.chip,
            "flash_size_mb": device.flash_size_mb,
            "port": device.port,
        },
        partition_table_sha256=hashlib.sha256(table.read_bytes()).hexdigest(),
        nvs_sha256=hashlib.sha256(nvs.read_bytes()).hexdigest(),
        nvs_size=nvs.stat().st_size,
    )
    append_event(device.mac, {
        "event": "usb_snapshot",
        "at": utc_now(),
        "chip": device.chip,
        "partition_table_sha256": hashlib.sha256(table.read_bytes()).hexdigest(),
        "nvs_sha256": hashlib.sha256(nvs.read_bytes()).hexdigest(),
    })
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        action="append",
        help=(
            "Logical lmesh USB port to probe/flash, for example USB0 or ACM1. "
            "Repeatable. Defaults to DMESH_FLASH_PORTS, then lmesh usb.serial.list."
        ),
    )
    parser.add_argument(
        "--raw-nan-port",
        action="append",
        default=[],
        help=(
            "Deprecated compatibility flag. Raw-NAN is now the default for every ESP board."
        ),
    )
    parser.add_argument("--wifi-mode", default=os.environ.get("DMESH_DEFAULT_WIFI_MODE", "nan"))
    parser.add_argument("--nan-channel", type=int, default=int(os.environ.get("DMESH_NAN_CHANNEL", "6")))
    parser.add_argument("--nan-service", default=os.environ.get("DMESH_NAN_SERVICE", "dmesh"))
    parser.add_argument("--nan-role", default=os.environ.get("DMESH_NAN_ROLE", "both"))
    parser.add_argument(
        "--expected-lora-port",
        action="append",
        default=split_env_list("DMESH_EXPECTED_LORA_PORTS")
        or ["lora1", "lora2", "lora3", "lora4", "USB0", "USB1", "USB2"],
        help=(
            "Logical port expected to have a configured LoRa radio. Repeatable. "
            "Defaults to lora1..lora4 plus USB0..USB2, or DMESH_EXPECTED_LORA_PORTS."
        ),
    )
    parser.add_argument(
        "--infra-port",
        action="append",
        default=os.environ.get("DMESH_INFRA_PORTS", "lora1").split(","),
        help="Logical port(s) that remain powered infrastructure owners (default: lora1).",
    )
    parser.add_argument(
        "--heltec-v3-port",
        action="append",
        default=split_env_list("DMESH_HELTEC_V3_PORTS") or ["lora4"],
        help=(
            "Logical port using the Heltec V3 ESP32-S3/SX1262 preset. Repeatable. "
            "Defaults to lora4 or DMESH_HELTEC_V3_PORTS."
        ),
    )
    parser.add_argument(
        "--meshcore-port",
        action="append",
        default=split_env_list("DMESH_MESHCORE_PORTS") or ["USB2"],
        help=(
            "Logical port to configure with MeshCore LoRa mode "
            "(910.525 MHz, BW 62.5 kHz, SF 7). Repeatable. "
            "Defaults to USB2 or DMESH_MESHCORE_PORTS."
        ),
    )
    parser.add_argument(
        "--lmesh-mode",
        choices=("local-release",),
        default=os.environ.get("DMESH_LMESH_MODE", "local-release"),
        help=(
            "Stops lmesh, flashes the physical USB-UART bridge with esptool, then reopens UDS. "
            "TCP/RFC2217 flashing is intentionally unsupported."
        ),
    )
    parser.add_argument(
        "--restore-forwards",
        action="store_true",
        help="Start every configured lmesh serial forward, then exit without probing or flashing.",
    )
    parser.add_argument(
        "--lmesh-control-socket",
        default=os.environ.get("LMESH_CONTROL_SOCKET"),
        help="lmesh JSONL control UDS.",
    )
    parser.add_argument(
        "--lmesh-multi",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Allow multiple forwarded clients to write during test bring-up.",
    )
    parser.add_argument("--flash-size-esp32", default="4mb")
    parser.add_argument("--flash-size-s3", default="16mb")
    parser.add_argument(
        "--flash-baud",
        type=int,
        default=int(os.environ.get("DMESH_FLASH_BAUD", str(FLASH_BAUD))),
        help="esptool baud rate; use 115200 for a recovery flash on an unstable USB-UART link",
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-flash", action="store_true")
    parser.add_argument(
        "--erase-nvs",
        action="store_true",
        help="Emergency recovery only: erase the ESP NVS partition before flashing.",
    )
    parser.add_argument("--skip-config", action="store_true")
    parser.add_argument("--skip-sanity", action="store_true")
    parser.add_argument(
        "--skip-preflash-stability",
        action="store_true",
        help="Recovery only: flash without requiring the existing firmware to stay up.",
    )
    parser.add_argument(
        "--preflash-stability-samples",
        type=int,
        default=3,
        help="Number of status samples required before reset/flash (minimum 2).",
    )
    parser.add_argument(
        "--preflash-stability-interval-sec",
        type=float,
        default=2.0,
        help="Delay between pre-flash status samples.",
    )
    parser.add_argument(
        "--preflash-status-timeout-sec",
        type=float,
        default=75.0,
        help=(
            "Managed status timeout; sleepy nodes may answer only on their "
            "periodic UART heartbeat (default: 75 seconds)."
        ),
    )
    parser.add_argument(
        "--preflash-stability-dir",
        default=None,
        help="Directory for pre-flash per-board status transcripts.",
    )
    parser.add_argument(
        "--preflash-only",
        action="store_true",
        help=(
            "Run only the managed pre-flash lmesh status stability gate and exit. "
            "Does not stop lmesh forwards, probe, flash, or run feature tests."
        ),
    )
    parser.add_argument(
        "--skip-feature-tests",
        action="store_true",
        help="Skip post-flash NAN/LoRa discovery and basic message tests.",
    )
    parser.add_argument(
        "--feature-test-iterations",
        type=int,
        default=int(os.environ.get("DMESH_FEATURE_TEST_ITERATIONS", "1")),
    )
    parser.add_argument(
        "--presubmit-topology",
        default=os.environ.get("DMESH_PRESUBMIT_TOPOLOGY"),
        help=(
            "Run the common hardware suite with this topology after flashing. "
            "When set, it replaces the legacy post-flash feature scripts."
        ),
    )
    parser.add_argument(
        "--presubmit-profile",
        choices=("quick", "full", "stress"),
        default=os.environ.get("DMESH_PRESUBMIT_PROFILE", "quick"),
    )
    parser.add_argument(
        "--sleepy-port",
        default=os.environ.get("DMESH_SLEEPY_TEST_PORT", "USB1"),
        help="Preferred logical port for sleepy raw-NAN post-flash testing.",
    )
    parser.add_argument(
        "--sleepy-wake-ms",
        type=int,
        default=int(os.environ.get("DMESH_SLEEPY_WAKE_MS", "4000")),
    )
    parser.add_argument(
        "--sleepy-active-ms",
        type=int,
        default=int(os.environ.get("DMESH_SLEEPY_ACTIVE_MS", "500")),
    )
    parser.add_argument(
        "--sleepy-duration-sec",
        type=float,
        default=float(os.environ.get("DMESH_SLEEPY_DURATION_SEC", "30")),
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=int(os.environ.get("DMESH_FLASH_JOBS", "0")),
        help="Maximum parallel device jobs. Default 0 means one worker per device.",
    )
    parser.add_argument("--include-bad-probe", action="store_true")
    parser.add_argument(
        "--allow-local-physical-fallback",
        action="store_true",
        help="If TCP flashing fails, stop lmesh and retry the local /dev/ttyUSB* path.",
    )
    return parser.parse_args()


def default_ports(control_socket: str) -> list[str]:
    env_ports = split_env_list("DMESH_FLASH_PORTS")
    if env_ports:
        return [logical_usb_port(port) for port in env_ports]
    data = lmesh_request(control_socket, "usb.serial.list", handshake=False)
    devices = data.get("devices", [])
    if not isinstance(devices, list):
        return []
    ports = [
        item.get("port")
        for item in devices
        if isinstance(item, dict)
        and isinstance(item.get("port"), str)
        and not looks_like_android_acm(item)
    ]
    return list(dict.fromkeys(ports))


def configured_forward_specs() -> dict[str, ForwardSpec]:
    """Read persistent serial-forward settings used for automatic restoration."""
    path = Path(os.environ.get("LMESH_CONFIG_FILE", DEFAULT_LMESH_CONFIG))
    try:
        config = tomllib.loads(path.read_text())
    except (FileNotFoundError, OSError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError(f"cannot read lmesh forward config {path}: {exc}") from exc
    forwards = config.get("serial_forwards", [])
    if not isinstance(forwards, list):
        raise RuntimeError(f"invalid serial_forwards in {path}")
    specs: dict[str, ForwardSpec] = {}
    for item in forwards:
        if not isinstance(item, dict) or item.get("enabled") is False:
            continue
        port = item.get("port")
        if not isinstance(port, str) or not logical_usb_port(port):
            continue
        path_value = item.get("path")
        specs[port] = ForwardSpec(
            port=port,
            path=path_value if isinstance(path_value, str) else None,
            baud=int(item.get("baud", FLASH_BAUD)),
            tcp_port=int(item["tcp_port"]) if isinstance(item.get("tcp_port"), int) else None,
            tcp_mode=str(item.get("tcp_mode", "rfc2217" if item.get("tcp_port") else "framed")),
            multi=bool(item.get("multi", True)),
        )
    return specs


def configured_forward_spec(port: str) -> ForwardSpec | None:
    return configured_forward_specs().get(port)


def split_env_list(key: str) -> list[str]:
    value = os.environ.get(key, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def looks_like_android_acm(device: dict[str, object]) -> bool:
    text = " ".join(
        str(device.get(key, "")).lower() for key in ("by_id", "path", "kind")
    )
    return "android" in text or "samsung" in text


def logical_usb_port(port: str) -> str:
    if re.fullmatch(r"(USB|ACM)\d+", port):
        return port
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", port):
        return port
    name = Path(port).name
    if name.startswith("ttyUSB"):
        return f"USB{name.removeprefix('ttyUSB')}"
    if name.startswith("ttyACM"):
        return f"ACM{name.removeprefix('ttyACM')}"
    raise ValueError(f"cannot derive lmesh logical USB port from {port}")


def physical_usb_port(port: str) -> str:
    if port.startswith("/dev/"):
        return port
    if port.startswith("USB") and port[3:].isdigit():
        return f"/dev/ttyUSB{port[3:]}"
    if port.startswith("ACM") and port[3:].isdigit():
        return f"/dev/ttyACM{port[3:]}"
    return port


def physical_port_for(args: argparse.Namespace, logical_port_name: str) -> str:
    """Resolve lmesh role names for explicit local recovery flashing."""
    cached = getattr(args, "local_physical_ports", {}).get(logical_port_name)
    if cached:
        return cached
    forward = lmesh_forward_map(args).get(logical_port_name)
    if forward and isinstance(forward.get("port"), str):
        return str(forward["port"])
    try:
        spec = configured_forward_spec(logical_port_name)
    except RuntimeError:
        # A running lmesh may be configured by mesh-init rather than a host
        # /home/system file.  Explicit USBn/ACMn recovery targets remain safe
        # and must not make the direct-flash path depend on that absent file.
        spec = None
    if spec and spec.path:
        return spec.path
    return physical_usb_port(logical_port_name)


def lmesh_socket_path(logical_port_name: str) -> str:
    return f"/run/mesh/lmesh/{logical_port_name}.sock"


def lmesh_uds_url(logical_port_name: str) -> str:
    return f"uds://{lmesh_socket_path(logical_port_name)}"


def lmesh_request(control_socket: str, method: str, **params: object) -> dict[str, object]:
    request = {"method": method, **{k: v for k, v in params.items() if v is not None}}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    timeout_sec = float(os.environ.get("LMESH_CONTROL_TIMEOUT_SEC", "8"))
    try:
        sock.settimeout(timeout_sec)
        sock.connect(control_socket)
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = bytearray()
        while not response.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        sock.close()
    if not response:
        raise RuntimeError(f"empty lmesh response for {method}")
    decoded = json.loads(response.decode("utf-8"))
    if decoded.get("success") is False:
        raise RuntimeError(f"lmesh {method} failed: {decoded}")
    data = decoded.get("data", decoded.get("result", decoded))
    if isinstance(data, dict) and data.get("ok") is False:
        raise RuntimeError(f"lmesh {method} failed: {data}")
    if not isinstance(data, dict):
        return {"data": data}
    return data


def lmesh_stop_forward(args: argparse.Namespace, logical_port_name: str) -> None:
    assert args.lmesh_control_socket
    try:
        data = lmesh_request(
            args.lmesh_control_socket,
            "usb.serial.forward.stop",
            port=logical_port_name,
        )
        print(f"lmesh stop {logical_port_name}: {data}", flush=True)
    except Exception as exc:  # noqa: BLE001 - stale forwards should not block recovery.
        print(f"lmesh stop {logical_port_name}: {exc}", flush=True)


def lmesh_start_forward(
    args: argparse.Namespace,
    logical_port_name: str,
    *,
    direct: bool | None = None,
) -> dict[str, object]:
    assert args.lmesh_control_socket
    spec = configured_forward_spec(logical_port_name)
    multi = args.lmesh_multi if args.lmesh_multi is not None else (spec.multi if spec else True)
    baud = spec.baud if spec else FLASH_BAUD
    data = lmesh_request(
        args.lmesh_control_socket,
        "usb.serial.forward.start",
        port=logical_port_name,
        baud=baud,
        tcp_mode="framed",
        multi=multi,
        handshake=False,
        direct=direct,
    )
    print(f"lmesh start {logical_port_name}: {data}", flush=True)
    return data


def lmesh_forward_map(args: argparse.Namespace) -> dict[str, dict[str, object]]:
    assert args.lmesh_control_socket
    data = lmesh_request(args.lmesh_control_socket, "usb.serial.forward.list")
    forwards = data.get("forwards", [])
    if not isinstance(forwards, list):
        return {}
    mapped: dict[str, dict[str, object]] = {}
    for item in forwards:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            mapped[item["id"]] = item
    return mapped


def probe(
    port: str,
    baud: int,
    physical_port: str | None = None,
    before: str = "default_reset",
) -> Device | None:
    try:
        proc = run(
            [
                esptool_python(),
                "-m",
                "esptool",
                "--port",
                port,
                "--baud",
                str(baud),
                "--before",
                before,
                "--after",
                "no_reset",
                "--no-stub",
                "chip_id",
            ],
            capture=True,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout or ""
        print(f"skip {physical_port or port}: probe failed through {port}\n{output}", flush=True)
        return None
    output = proc.stdout or ""
    chip = None
    if "ESP32-S3" in output:
        chip = "esp32s3"
    elif "ESP32" in output:
        chip = "esp32"
    mac_match = re.search(r"MAC:\s*([0-9a-f:]{17})", output, re.IGNORECASE)
    flash_size_match = re.search(r"(?:Embedded Flash|Detected flash size)\s*(\d+)MB", output)
    if not chip:
        print(f"skip {physical_port or port}: unsupported probe output through {port}\n{output}", flush=True)
        return None
    return Device(
        port=physical_port or port,
        chip=chip,
        mac=mac_match.group(1).lower() if mac_match else None,
        flash_size_mb=int(flash_size_match.group(1)) if flash_size_match else None,
    )


def image_build_env(
    env: dict[str, str], sdkconfig: str, partition_file: str
) -> dict[str, str]:
    """Return an ESP-IDF build environment with a portable partition path."""
    config_dir = FW_RUST / "target" / "flash-config"
    config_dir.mkdir(parents=True, exist_ok=True)
    # Partition paths may be relative to the firmware crate (the 8 MB S3
    # profile uses ../../boot/...). Keep the generated overlay inside the
    # repo-local config directory instead of accidentally escaping it through
    # the path separators in the filename.
    overlay = config_dir / f"{Path(partition_file).name}.defaults"
    partition_path = (FW_RUST / partition_file).resolve()
    overlay.write_text(
        f'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="{partition_path}"\n', encoding="utf-8"
    )
    result = env.copy()
    # The root environment includes host development tools first. Fleet builds
    # must match scripts/build-fw.sh and select the repo-local ESP Rust
    # toolchain explicitly; otherwise cargo reaches the host sysroot and fails
    # with a misleading missing-core error for xtensa-esp32-espidf.
    toolchain_bin = result.get("RUST_ESP_TOOLCHAIN_BIN")
    cargo_home = result.get("CARGO_HOME")
    if not toolchain_bin or not cargo_home:
        raise RuntimeError("missing ESP Rust environment; run scripts/esp32-deps.sh")
    result["PATH"] = os.pathsep.join(
        [toolchain_bin, str(Path(cargo_home) / "bin"), result.get("PATH", "")]
    )
    result["ESP_IDF_SDKCONFIG_DEFAULTS"] = f"{sdkconfig};{overlay}"
    return result


def build_targets(env: dict[str, str], devices: list[Device]) -> None:
    """Build only the image families selected by the physical probe."""
    needs_esp32 = any(not device.is_s3 for device in devices)
    needs_s3_16mb = any(device.is_s3 and not s3_uses_8mb_image(device) for device in devices)
    needs_s3_8mb = any(device.is_s3 and s3_uses_8mb_image(device) for device in devices)

    for image, required in (
        (ESP32_MERGED_IMAGE, needs_esp32),
        (ESP32S3_MERGED_IMAGE, needs_s3_16mb),
        (ESP32S3_8MB_MERGED_IMAGE, needs_s3_8mb),
    ):
        if required:
            image.parent.mkdir(parents=True, exist_ok=True)

    if needs_esp32:
        esp32_env = image_build_env(env, "sdkconfig.defaults", "partitions_4mb_large_app.csv")
        run(
            ["cargo", "build", "--release", "--target", "xtensa-esp32-espidf"],
            cwd=FW_RUST,
            env=esp32_env,
        )
        run(
            ["cargo", "espflash", "save-image", "--release", "--target", "xtensa-esp32-espidf",
             "--chip", "esp32", "--flash-size", "4mb", "--merge", "--skip-padding",
             str(ESP32_MERGED_IMAGE)],
            cwd=FW_RUST,
            env=esp32_env,
        )

    if needs_s3_16mb:
        s3_env = image_build_env(
            env, "sdkconfig.heltec_v3.defaults", "partitions_16mb_large_app_store.csv"
        )
        run(
            ["cargo", "build", "--release", "--target", "xtensa-esp32s3-espidf"],
            cwd=FW_RUST,
            env=s3_env,
        )
        run(
            ["cargo", "espflash", "save-image", "--release", "--target", "xtensa-esp32s3-espidf",
             "--chip", "esp32s3", "--flash-size", "16mb", "--merge", "--skip-padding",
             str(ESP32S3_MERGED_IMAGE)],
            cwd=FW_RUST,
            env=s3_env,
        )

    if needs_s3_8mb:
        s3_8mb_env = image_build_env(
            env, "sdkconfig.esp32s3_8mb.defaults", "../../boot/partitions_recovery_8mb_store.csv"
        )
        s3_8mb_env["CARGO_TARGET_DIR"] = str(ESP32S3_8MB_TARGET)
        run(
            ["cargo", "build", "--release", "--target", "xtensa-esp32s3-espidf"],
            cwd=FW_RUST,
            env=s3_8mb_env,
        )
        run(
            ["cargo", "espflash", "save-image", "--release", "--target", "xtensa-esp32s3-espidf",
             "--chip", "esp32s3", "--flash-size", "8mb", "--target-app-partition", "main",
             "--merge", "--skip-padding",
             str(ESP32S3_8MB_MERGED_IMAGE)],
            cwd=FW_RUST,
            env=s3_8mb_env,
        )


def s3_uses_8mb_image(device: Device) -> bool:
    """Return whether a probed S3 needs the 8 MB partition table."""
    return device.is_s3 and device.flash_size_mb is not None and device.flash_size_mb <= 8


def merged_image_for(device: Device) -> Path:
    if not device.is_s3:
        return ESP32_MERGED_IMAGE
    return ESP32S3_8MB_MERGED_IMAGE if s3_uses_8mb_image(device) else ESP32S3_MERGED_IMAGE


def executable_for(device: Device) -> Path:
    if not device.is_s3:
        return FW_TARGET_ROOT / "xtensa-esp32-espidf" / "release" / "dmesh-rs"
    if s3_uses_8mb_image(device):
        return ESP32S3_8MB_TARGET / "xtensa-esp32s3-espidf" / "release" / "dmesh-rs"
    return FW_TARGET_ROOT / "xtensa-esp32s3-espidf" / "release" / "dmesh-rs"


def validate_prebuilt_images(devices: list[Device]) -> None:
    """Reject --skip-build when cargo output is newer than its merged image."""
    targets = {(executable_for(device), merged_image_for(device)) for device in devices}
    for executable, merged in targets:
        if not executable.exists() or not merged.exists():
            raise SystemExit(
                "--skip-build requires existing executable and merged image; run without --skip-build"
            )
        if merged.stat().st_mtime_ns < executable.stat().st_mtime_ns:
            raise SystemExit(
                "--skip-build refused stale merged image {} older than {}; "
                "run without --skip-build or regenerate it with cargo espflash save-image".format(
                    merged, executable
                )
            )


def flash(device: Device, args: argparse.Namespace, env: dict[str, str], port: str) -> None:
    # Always sparse-flash through the esptool RAM stub. This is both more
    # reliable on direct CP210x bridges than cargo-espflash's retained monitor
    # handle and protects NVS by omitting its partition entirely.
    archive_usb_device(device, port, args.flash_baud)
    chip = "esp32s3" if device.is_s3 else "esp32"
    flash_args, flash_files = sparse_flash_args(device)
    rfc2217 = port.startswith("rfc2217://")
    if args.erase_nvs:
        erase_cmd = [
            esptool_python(),
            "-m",
            "esptool",
            "--chip",
            chip,
            "--port",
            port,
            "--baud",
            str(args.flash_baud),
            "--before",
            "default_reset",
            "--after",
            "no_reset",
            "erase_region",
            "0x9000",
            "0x6000",
        ]
        run_logged(
            f"erase NVS {device.port}",
            erase_cmd,
            cwd=FW_RUST,
            env=env,
            tail_lines=24,
        )
    cmd = [
        esptool_python(),
        "-m",
        "esptool",
        "--chip",
        chip,
        "--port",
        port,
        "--baud",
        str(args.flash_baud),
        "--before",
        "no_reset" if rfc2217 else "default_reset",
        "--after",
        "no_reset" if rfc2217 else "hard_reset",
        "write_flash",
    ]
    cmd.extend(flash_args)
    for offset, image in flash_files:
        cmd.extend([offset, str(image)])
    run_logged(f"flash {device.port}", cmd, cwd=FW_RUST, env=env, tail_lines=24)

    # A successful transport exit is not sufficient evidence that every app
    # segment reached flash.  In particular, a partially written factory image
    # can look like a normal reset until the second-stage bootloader reaches a
    # later (blank) segment.  Verify the exact sparse ranges before restoring
    # lmesh's framed forward or declaring this board flashed.
    verify_cmd = [
        esptool_python(),
        "-m",
        "esptool",
        "--chip",
        chip,
        "--port",
        port,
        "--baud",
        str(args.flash_baud),
        "--before",
        "no_reset" if rfc2217 else "default_reset",
        "--after",
        "no_reset" if rfc2217 else "hard_reset",
        "verify_flash",
    ]
    # verify_flash applies the same bootloader-header normalization as
    # write_flash.  Keep these parameters here; removing them makes esptool
    # compare the original image header/hash with the patched bytes actually
    # written at the bootloader offset.
    verify_cmd.extend(flash_args)
    for offset, image in flash_files:
        verify_cmd.extend([offset, str(image)])
    run_logged(f"verify flash {device.port}", verify_cmd, cwd=FW_RUST, env=env, tail_lines=24)
    if device.mac:
        record_flash(device.mac, "main", flash_files)


def sparse_flash_args(device: Device) -> tuple[list[str], list[tuple[str, Path]]]:
    image = merged_image_for(device)
    flash_size = "8MB" if s3_uses_8mb_image(device) else "16MB" if device.is_s3 else "4MB"
    flash_freq = "80m" if device.is_s3 else "40m"
    boot_offset = 0x0 if device.is_s3 else 0x1000
    label = "esp32s3-8mb" if s3_uses_8mb_image(device) else "esp32s3" if device.is_s3 else "esp32"
    data = image.read_bytes()
    chunks = [
        (boot_offset, 0x8000, f"{label}-bootloader.bin"),
        (0x8000, 0x9000, f"{label}-partition-table.bin"),
        (0x10000, len(data), f"{label}-app.bin"),
    ]
    out_dir = SPARSE_FLASH_DIR / label
    out_dir.mkdir(parents=True, exist_ok=True)
    flash_files: list[tuple[str, Path]] = []
    for start, end, name in chunks:
        chunk = trim_trailing_ff(data[start:end])
        if not chunk:
            continue
        path = out_dir / name
        path.write_bytes(chunk)
        flash_files.append((hex(start), path))
    return (
        ["--flash_mode", "dio", "--flash_size", flash_size, "--flash_freq", flash_freq],
        flash_files,
    )


def trim_trailing_ff(data: bytes) -> bytes:
    end = len(data)
    while end > 0 and data[end - 1] == 0xFF:
        end -= 1
    return data[:end]


def mesh_command_argv(port: str, command: str, timeout: int = 20) -> list[str]:
    """Build the only supported firmware-command path: mesh -> lmesh."""
    return [
        str(MESH_ENV),
        "mesh",
        "lmesh",
        "esp.serial.command",
        f"port={logical_usb_port(port)}",
        f"command={command}",
        f"timeout_sec={timeout}",
    ]


def configure(device: Device, args: argparse.Namespace, port: str) -> None:
    channel = max(1, min(args.nan_channel, 13))
    infra = device.port in {logical_usb_port(item) for item in args.infra_port}
    # Keep the board in the continuously-serviced role while provisioning.
    # Writing `mode=sleepy` in the same bulk NVS request can stop UART before
    # its response is framed, leaving the remaining setup commands queued
    # behind the new heartbeat policy. The final role command below persists
    # the requested sleepy mode after all probes/configuration have completed.
    saved_mode = "infra"
    ap_owner = "true" if infra else "false"
    uart_heartbeat_every = 1
    commands = [
        (
            f"nvs op=set mode={saved_mode} wifi.mode={args.wifi_mode} power.profile=auto "
            f"nan.backend=raw nan.boot=true nan.role={args.nan_role} "
            f"nan.service={args.nan_service} nan.channel={channel} "
                f"nan.ap_owner={ap_owner} nan.ap_loss_ms=15000 nan.wake_ms=4000 nan.active_ms=64 nan.light_sleep=true nan.early_ms=40 nan.dw_tu=512 nan.dw_off_tu=0 nan.dw_stride=8 "
                f"uart.hb_every={uart_heartbeat_every}"
        ),
        "power profile=auto save=true",
        "nan stats=true",
        "lora status=true",
        "power status=true",
    ]
    if device.port in expected_lora_ports(args):
        if device.port in heltec_v3_ports(args):
            commands[0:0] = ["lora board=heltec_v3 apply=true", "nvs op=set lora.enabled=true"]
        else:
            commands[0:0] = [
                (
                    "loraprobe chip=sx127x spi_host=2 sck=5 miso=19 mosi=27 "
                    "cs=18 rst=23 dio0=26 save=true"
                ),
                "nvs op=set lora.enabled=true",
            ]
        meshcore_ports = {logical_usb_port(p) for p in args.meshcore_port}
        if device.port in meshcore_ports:
            commands.append("lora mode=meshcore")
        else:
            commands.append("lora mode=meshtastic")
    if not infra:
        # Apply the sparse heartbeat only after all radio probes have run
        # while UART is continuously serviced. The following role transition
        # then enters the requested light-sleep schedule.
        commands.append("nvs op=set uart.hb_every=16")
    # Sleepy nodes switch into their selected runtime role last because that
    # command may stop servicing UART immediately; infrastructure nodes are
    # inserted first below so they remain reachable during provisioning.
    role_command = "mode infra=true save=true" if infra else "mode sleepy=true save=true"
    # Infrastructure nodes must be made persistent before the provisioning
    # probe.  They remain awake and keep servicing the supervised UART, so
    # moving this command into the boot window avoids a probe timeout leaving
    # lora1 in a stale sleepy configuration.  Sleepy nodes still switch role
    # last because that command can intentionally stop UART service.
    if infra:
        commands.insert(0, role_command)
    else:
        # A board may retain the previous sleepy profile across a USB flash.
        # Wake it into the continuously-serviced role before provisioning so
        # the remaining NVS and radio commands do not queue behind the
        # intentionally sparse `uart.hb_every=16` diagnostic heartbeat.  The
        # final role command below restores the requested sleepy profile.
        commands.insert(0, "mode infra=true")
    if port.startswith("uds://"):
        # Use the same managed UDS command path as normal diagnostics. The
        # forward must remain supervised; only direct USB/esptool flashing
        # releases it temporarily.
        # A sleepy node may already have stopped its UART by the time a
        # The application starts its UART/mesh tasks after the bootloader has
        # printed its banner.  A command sent during that short interval can
        # be consumed by the boot console and never produce a framed reply.
        # Retry idempotent provisioning commands once; this is especially
        # important when a sleepy board still has the previous heartbeat
        # policy in NVS and the first role command arrives near boot.
        for item in commands:
            command_timeout = 90 if not infra else 20
            for attempt in range(2):
                output = run_logged(
                    f"configure {device.port} {item}"
                    + (" retry" if attempt else ""),
                    mesh_command_argv(device.port, item, timeout=command_timeout),
                    cwd=ROOT,
                )
                # mesh-cli deliberately exits zero for a valid JSON response
                # whose firmware command failed, so inspect the response as
                # well as the subprocess status before deciding to continue.
                if '"ok": false' not in output and '"ok":false' not in output:
                    break
                if attempt == 1:
                    raise RuntimeError(
                        f"configure {device.port} {item}: firmware returned ok=false"
                    )
                print(
                    f"configure {device.port} {item}: retry after UART boot window",
                    flush=True,
                )
                time.sleep(2.0)
        if not infra:
            try:
                run_logged(
                    f"configure role {device.port}",
                    mesh_command_argv(device.port, role_command, timeout=90),
                    cwd=ROOT,
                )
            except subprocess.CalledProcessError:
                # The sleepy transition intentionally stops servicing UART
                # before a response can be framed. NVS is written before the
                # transition; verify it after the next recovery/status pass
                # instead of marking an otherwise successful run as failed.
                print(f"configure role {device.port}: sleepy transition closed UART (expected)", flush=True)
        return

    raise RuntimeError("firmware provisioning requires a supervised lmesh UDS endpoint")


def sanity(device: Device, port: str) -> None:
    commands = [
        "status",
        "nan stats=true",
        "lora status=true",
        "power status=true",
        "logs count=20",
    ]
    print(f"sanity {device.port}: start", flush=True)
    for command in commands:
        run_logged(f"sanity {device.port} {command}", mesh_command_argv(device.port, command), cwd=ROOT)
    print(f"sanity {device.port}: done", flush=True)


def console_output(device: Device, command: str, timeout: int = 20) -> str:
    return run_logged(f"query {device.port} {command}", mesh_command_argv(device.port, command, timeout), cwd=ROOT)


def discover_mac_from_console(device: Device) -> str | None:
    try:
        out = console_output(device, "wifi", timeout=8)
    except subprocess.CalledProcessError:
        return None
    match = re.search(r"\bsta_mac=([0-9a-f:]{17})\b", out, re.IGNORECASE)
    return match.group(1).lower() if match else None


def console_commands(device: Device, commands: list[str], timeout: int = 20) -> str:
    outputs = []
    for command in commands:
        outputs.append(run_logged(f"cmd {device.port} {command}", mesh_command_argv(device.port, command, timeout), cwd=ROOT))
    return "\n".join(outputs)


def send_console_line_no_wait(device: Device, command: str) -> None:
    path = lmesh_socket_path(device.port)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
        sock.sendall(b"\n")
        time.sleep(0.1)
        sock.sendall((command + "\n").encode("utf-8"))
    finally:
        sock.close()


def stat_value(text: str, key: str) -> int:
    matches = re.findall(rf"\b{re.escape(key)}=(\d+)\b", text)
    return int(matches[-1]) if matches else 0


def preflash_stability_check(
    port: str,
    *,
    samples: int,
    interval_sec: float,
    status_timeout_sec: float,
    output_dir: Path,
) -> None:
    samples = max(2, samples)
    output_dir.mkdir(parents=True, exist_ok=True)
    transcript: list[str] = []
    uptimes: list[int] = []
    status_timeout_sec = max(20.0, status_timeout_sec)
    client = RadioClient(lmesh_uds_url(port), timeout=status_timeout_sec)
    sample_interval_sec = max(0.0, interval_sec)
    try:
        client.connect()
        for index in range(samples):
            result = client.command("status", timeout=status_timeout_sec)
            transcript.append("# sample {}\n{}".format(index + 1, result.raw))
            match = re.search(r"\buptime_ms=(\d+)\b", result.raw)
            if not match:
                raise RuntimeError("status response has no uptime_ms")
            uptimes.append(int(match.group(1)))
            # Sleepy nodes service the managed UART only on the periodic
            # heartbeat. Once identified, leave a full heartbeat interval
            # between samples so the stability gate does not queue commands
            # and mistake a healthy node for a dead one.
            if re.search(r"\bmode active=sleepy\b", result.raw):
                sample_interval_sec = max(sample_interval_sec, 70.0)
            if index + 1 < samples:
                time.sleep(sample_interval_sec)
    finally:
        client.close()
        path = output_dir / "{}.log".format(port)
        path.write_text("\n".join(transcript), encoding="utf-8")

    combined = "\n".join(transcript)
    markers = [marker for marker in PREFLASH_FAILURE_MARKERS if marker in combined]
    if markers:
        raise RuntimeError("firmware emitted reset/panic marker(s): {}".format(", ".join(markers)))
    if any(after <= before for before, after in zip(uptimes, uptimes[1:])):
        raise RuntimeError("uptime is not strictly increasing: {}".format(uptimes))
    print(
        "preflash stability {}: ok samples={} uptime_ms={}..{} transcript={}".format(
            port, samples, uptimes[0], uptimes[-1], output_dir / "{}.log".format(port)
        ),
        flush=True,
    )


def expected_lora_ports(args: argparse.Namespace) -> set[str]:
    return {logical_usb_port(port) for port in args.expected_lora_port}


def heltec_v3_ports(args: argparse.Namespace) -> set[str]:
    return {logical_usb_port(port) for port in args.heltec_v3_port}


def post_flash_feature_tests(devices: list[Device], args: argparse.Namespace) -> None:
    if args.presubmit_topology:
        run_logged(
            "feature presubmit",
            [
                sys.executable,
                str(PRESUBMIT),
                "--topology",
                args.presubmit_topology,
                "--profile",
                args.presubmit_profile,
            ],
            cwd=ROOT,
        )
        return
    nan_devices = [device for device in devices if device.mac and device.is_classic]
    if len(nan_devices) < 2:
        nan_devices = [
            device
            for device in devices
            if device.mac and device.port.startswith("USB")
        ]
    if len(nan_devices) < 2:
        nan_devices = [device for device in devices if device.mac]
    if len(nan_devices) >= 2:
        a, b = nan_devices[:2]
        argv = [
            sys.executable,
            str(NAN_PAIR_TEST),
            "--a",
            lmesh_uds_url(a.port),
            "--b",
            lmesh_uds_url(b.port),
            "--a-mac",
            a.mac or "",
            "--b-mac",
            b.mac or "",
            "--backend",
            "raw",
            "--channel",
            str(args.nan_channel),
            "--iterations",
            str(args.feature_test_iterations),
            "--settle-sec",
            "1.0",
            "--no-expect-response",
        ]
        run_logged(f"feature nan {a.port}->{b.port}", argv, cwd=FW_RUST)
    else:
        print("feature nan: skipped, need two devices with probed MACs", flush=True)

    sleepy_raw_nan_feature_test(devices, args)

    lora_devices: list[Device] = []
    expected_lora = expected_lora_ports(args)
    missing_expected_lora: list[str] = []
    for device in devices:
        try:
            out = console_output(device, "lora status=true")
        except subprocess.CalledProcessError:
            if device.port in expected_lora:
                missing_expected_lora.append(device.port)
            continue
        if re.search(r"\bconfigured=true\b", out) or re.search(r"\blora status=true\b", out):
            if not re.search(r"\bconfigured=false\b", out):
                lora_devices.append(device)
            elif device.port in expected_lora:
                missing_expected_lora.append(device.port)
        elif device.port in expected_lora:
            missing_expected_lora.append(device.port)
    if missing_expected_lora:
        raise RuntimeError(
            "expected LoRa ports are not configured: " + ", ".join(missing_expected_lora)
        )
    if len(lora_devices) >= 2:
        rx, tx = lora_devices[:2]
        argv = [
            sys.executable,
            str(LORA_PAIR_TEST),
            "--rx",
            lmesh_uds_url(rx.port),
            "--tx",
            lmesh_uds_url(tx.port),
        ]
        run_logged(f"feature lora {tx.port}->{rx.port}", argv, cwd=FW_RUST)
    else:
        print("feature lora: skipped, need two LoRa-configured devices", flush=True)


def sleepy_raw_nan_feature_test(devices: list[Device], args: argparse.Namespace) -> None:
    candidates = [device for device in devices if device.mac]
    if len(candidates) < 2:
        print("feature sleepy_nan: skipped, need two devices with probed MACs", flush=True)
        return
    sleepy = next((device for device in candidates if device.port == args.sleepy_port), None)
    if sleepy is None:
        sleepy = candidates[1]
    peer = next((device for device in candidates if device.port != sleepy.port), None)
    if peer is None:
        print("feature sleepy_nan: skipped, no awake peer", flush=True)
        return

    wake_ms = max(1000, args.sleepy_wake_ms)
    active_ms = max(100, min(args.sleepy_active_ms, wake_ms))
    duration = max(args.sleepy_duration_sec, 20.0)
    total = max(4, int(duration * 1000 / wake_ms) + 2)
    discovery = min(2, total)

    print(
        f"feature sleepy_nan: sleepy={sleepy.port} peer={peer.port} "
        f"wake_ms={wake_ms} active_ms={active_ms} duration_sec={duration}",
        flush=True,
    )
    before = console_output(peer, "nan stats=true")
    console_commands(
        sleepy,
        [
            (
                f"nvs op=set nan.wake_ms={wake_ms} nan.active_ms={active_ms} "
                f"nan.channel={args.nan_channel}"
            ),
            f"test cnt={total} wake_ms={wake_ms} active_ms={active_ms} discovery={discovery}",
        ],
    )
    send_console_line_no_wait(
        sleepy,
        (
            f"sleep mode=nan_raw wake_ms={wake_ms} active_ms={active_ms} "
            f"channel={args.nan_channel} serial=false ble=false lora=false start=true"
        ),
    )
    time.sleep(duration)
    after = console_output(peer, "nan stats=true")
    before_rx = stat_value(before, "raw_cmd_rx")
    after_rx = stat_value(after, "raw_cmd_rx")
    before_resp = stat_value(before, "raw_resp_tx")
    after_resp = stat_value(after, "raw_resp_tx")
    try:
        if after_rx <= before_rx:
            raise RuntimeError(
                f"peer raw_cmd_rx did not increase: before={before_rx} after={after_rx}"
            )
        if after_resp <= before_resp:
            raise RuntimeError(
                f"peer raw_resp_tx did not increase: before={before_resp} after={after_resp}"
            )
        print(
            "feature sleepy_nan: ok "
            f"raw_cmd_rx_delta={after_rx - before_rx} raw_resp_tx_delta={after_resp - before_resp}",
            flush=True,
        )
    finally:
        # The lmesh forward remains the runtime diagnostics owner.  Physical
        # reset/recovery is performed only by esptool in the flash path.
        pass


def run_parallel(
    label: str,
    devices: list[Device],
    jobs: int,
    func,
) -> tuple[list[Device], list[Device]]:
    if not devices:
        return ([], [])
    worker_count = jobs if jobs > 0 else len(devices)
    worker_count = max(1, min(worker_count, len(devices)))
    print(f"{label}: running {len(devices)} device job(s) with {worker_count} worker(s)", flush=True)
    ok: list[Device] = []
    failed: list[Device] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(func, device): device
            for device in devices
        }
        for future in as_completed(futures):
            device = futures[future]
            try:
                future.result()
                print(f"{label} {device.port}: ok", flush=True)
                ok.append(device)
            except Exception as exc:
                print(f"{label} {device.port}: failed: {exc}", flush=True)
                failed.append(device)
    return (ok, failed)


def main() -> int:
    args = parse_args()
    if not args.lmesh_control_socket:
        print("--lmesh-control-socket or LMESH_CONTROL_SOCKET is required", file=sys.stderr)
        return 1
    if args.restore_forwards:
        restored = 0
        for port in configured_forward_specs():
            try:
                lmesh_start_forward(args, port)
                restored += 1
            except RuntimeError as exc:
                if "already exists" not in str(exc):
                    raise
                print(f"lmesh restore {port}: already active", flush=True)
                restored += 1
        print(f"restored {restored} configured lmesh serial forward(s)", flush=True)
        return 0
    env = os.environ.copy()
    ports = [logical_usb_port(port) for port in (args.port or default_ports(args.lmesh_control_socket))]
    if not ports:
        print("no lmesh USB serial ports found", file=sys.stderr)
        return 1

    args.local_physical_ports = {
        port: str(forward["port"])
        for port, forward in lmesh_forward_map(args).items()
        if port in ports and isinstance(forward.get("port"), str)
    }

    if (not args.skip_flash or args.preflash_only) and not args.skip_preflash_stability:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        stability_dir = Path(
            args.preflash_stability_dir
            or FW_RUST / "target" / "esp32-preflash-stability" / stamp
        )
        print(
            "preflash stability: checking {} board(s), samples={} interval_sec={} timeout_sec={}".format(
                len(ports),
                max(2, args.preflash_stability_samples),
                args.preflash_stability_interval_sec,
                args.preflash_status_timeout_sec,
            ),
            flush=True,
        )
        failures: list[str] = []
        with ThreadPoolExecutor(max_workers=max(1, len(ports))) as executor:
            futures = {
                executor.submit(
                    preflash_stability_check,
                    port,
                    samples=args.preflash_stability_samples,
                    interval_sec=args.preflash_stability_interval_sec,
                    status_timeout_sec=args.preflash_status_timeout_sec,
                    output_dir=stability_dir,
                ): port
                for port in ports
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    future.result()
                except Exception as exc:  # noqa: BLE001 - report every bad board before stopping.
                    message = "{}: {}".format(port, exc)
                    print("preflash stability {}: failed: {}".format(port, exc), flush=True)
                    failures.append(message)
        if failures:
            raise SystemExit(
                "preflash stability failed; refusing to reset/flash. Transcripts: {}\n{}\n"
                "Use --skip-preflash-stability only for an intentional recovery flash.".format(
                    stability_dir, "\n".join(failures)
                )
            )

    if args.preflash_only:
        print("preflash stability: passed; no probe/flash requested", flush=True)
        return 0

    if args.lmesh_mode == "local-release":
        # Stability checks use the logical lmesh UDS forwards. Release them
        # only after that check passes, immediately before direct USB probing
        # and flashing need exclusive ownership of the physical bridge.
        for port in ports:
            lmesh_stop_forward(args, port)
        time.sleep(0.5)

    probed: list[Device] = []
    if args.skip_flash:
        probed = [Device(port=port, chip="unknown", mac=None) for port in ports]
    else:

        def probe_one(port: str) -> Device | None:
            probe_port = physical_port_for(args, port)
            return probe(
                probe_port,
                args.flash_baud,
                physical_port=port,
                before="default_reset",
            )

        with ThreadPoolExecutor(max_workers=max(1, len(ports))) as executor:
            futures = {executor.submit(probe_one, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                device = future.result()
                if device:
                    probed.append(device)
                elif args.include_bad_probe:
                    raise SystemExit(f"probe failed for {port}")

    devices = sorted(probed, key=lambda item: item.port)
    if args.skip_flash:
        devices = [
            Device(port=device.port, chip=device.chip, mac=discover_mac_from_console(device))
            for device in devices
        ]

    if not devices:
        print("no ESP devices detected", file=sys.stderr)
        return 1

    print("detected:", flush=True)
    for device in devices:
        print(f"  {device.port}: {device.chip} mac={device.mac or 'unknown'}", flush=True)

    if not args.skip_build:
        build_targets(env, devices)
    elif not args.skip_flash:
        validate_prebuilt_images(devices)

    direct_config_after_flash = (
        not args.skip_flash and not args.skip_config and args.lmesh_mode == "local-release"
    )
    flashed_devices: list[Device] = []
    if not args.skip_flash:
        def flash_one(device: Device) -> None:
            lmesh_stop_forward(args, device.port)
            flash(device, args, env, physical_port_for(args, device.port))
            if direct_config_after_flash:
                # The physical bridge is intentionally released after the
                # flash. Configuration must go through the supervised lmesh
                # forward; normal commands never use direct UART paths.
                lmesh_start_forward(args, device.port, direct=True)
                # Do not race the application boot sequence.  The bootloader
                # itself can finish in under a second, but the firmware does
                # not install the framed UART ingress task until its mode/
                # mesh initialization has completed.
                time.sleep(12.0)
                configure(device, args, lmesh_uds_url(device.port))

        flashed, flash_failed = run_parallel("flash", devices, args.jobs, flash_one)
        flashed_devices = list(flashed)
        devices = sorted(flashed, key=lambda item: item.port)
        if flash_failed:
            print(
                "flash: failed devices: " + ", ".join(device.port for device in flash_failed),
                flush=True,
            )
        if not devices:
            print("flash: no devices flashed successfully", file=sys.stderr)
            return 1

    if not args.skip_config and not direct_config_after_flash:
        def configure_one(device: Device) -> None:
            if args.lmesh_mode == "local-release":
                try:
                    lmesh_start_forward(args, device.port)
                except RuntimeError as exc:
                    if "already exists" not in str(exc):
                        raise
            configure(device, args, lmesh_uds_url(device.port))

        configured, config_failed = run_parallel("configure", devices, args.jobs, configure_one)
        devices = sorted(configured, key=lambda item: item.port)
        if config_failed:
            print(
                "configure: failed devices: " + ", ".join(device.port for device in config_failed),
                flush=True,
            )

    if args.lmesh_mode == "local-release" and not args.skip_flash:
        def restore_forward(device: Device) -> None:
            try:
                lmesh_start_forward(args, device.port)
            except RuntimeError as exc:
                if "already exists" not in str(exc):
                    raise
                print(f"lmesh restore {device.port}: already active", flush=True)

        _, restore_failed = run_parallel(
            "restore forwards",
            flashed_devices,
            args.jobs,
            restore_forward,
        )
        if restore_failed:
            print(
                "restore forwards: failed devices: "
                + ", ".join(device.port for device in restore_failed),
                flush=True,
            )
            return 1


    if not args.skip_sanity:
        _, sanity_failed = run_parallel(
            "sanity",
            devices,
            args.jobs,
            lambda device: sanity(device, lmesh_uds_url(device.port)),
        )
        if sanity_failed:
            print(
                "sanity: failed devices: " + ", ".join(device.port for device in sanity_failed),
                flush=True,
            )
            return 1

    if not args.skip_feature_tests:
        post_flash_feature_tests(devices, args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
