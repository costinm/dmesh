#!/usr/bin/env python3
"""Single entry point for ESP image deployment.

Legacy UART byte forwards are disabled. Direct USB/esptool deployment is the
current flashing path for every target, including Main. It opens only the
selected physical port through the repository's verified wrapper and never
starts, stops, or restores a managed serial forward. ESP-NOW/action and Wi-Fi
flashing remain future paths for devices without a UART connection.
"""

from __future__ import annotations

import argparse
import glob
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FW_RUST = ROOT / "fw" / "esp32" / "rust"
sys.path.insert(0, str(ROOT))

# Direct USB inventory used only by esptool provisioning. This intentionally
# has no lmesh-uart config or control-socket dependency. A lab override may
# set DMESH_SERIAL_<ROLE>, for example DMESH_SERIAL_LORA1=/dev/ttyUSB0.
BOARD_SERIAL_GLOBS = {
    "e5": "usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_DMESH-E5-*-if00-port0",
    "e6": "usb-Espressif_USB_JTAG_serial_debug_unit_14:C1:9F:E5:98:00-if00",
    "e7": "usb-Espressif_USB_JTAG_serial_debug_unit_14:C1:9F:E4:5D:48-if00",
    "lora1": "usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_DMESH-LORA1-*-if00-port0",
    "lora2": "usb-Silicon_Labs_CP2104_USB_to_UART_Bridge_Controller_01DC99BB-if00-port0",
    "lora3": "usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_DMESH-LORA3-*-if00-port0",
    "lora4": "usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_DMESH-LORA4-*-if00-port0",
    "s3-1": "usb-1a86_USB_Single_Serial_5C82104982-if00",
}

# The builtin USB-JTAG adapter exposes the eFuse MAC as its OpenOCD serial.
# Unlike ``direct_serial_port``, OpenOCD otherwise selects the first matching
# ESP USB-JTAG device; that is unsafe while both e6 and e7 are attached.
JTAG_ADAPTER_SERIAL = {
    "e6": "14:C1:9F:E5:98:00",
    "e7": "14:C1:9F:E4:5D:48",
}
# The builtin JTAG driver's serial-string query can fail after a C6 reset even
# while the physical USB device is present. These lab boards have dedicated
# hub ports, so OpenOCD's topology selector is the reliable disambiguator when
# both are attached. Keep the serial inventory above for human diagnostics.
JTAG_ADAPTER_LOCATION = {
    "e6": "1-2.3",
    "e7": "1-5",
}
# Recovery rescue values integrity over JTAG throughput. The builtin adapter
# defaults to 24 MHz; a wedged board on a long/noisy hub path is more reliable
# at this conservative debug-clock rate.
JTAG_RECOVERY_KHZ = 4_000


class DirectDevice:
    def __init__(self, chip: str) -> None:
        self.is_s3 = chip == "esp32s3"
        self.is_c6 = chip == "esp32c6"


def esptool_python() -> str:
    env_path = os.environ.get("IDF_PYTHON_ENV_PATH")
    if env_path:
        candidate = Path(env_path) / "bin" / "python"
        if candidate.is_file():
            return str(candidate)
    local_envs = sorted((ROOT / "target").glob("esp32-*/espressif/python_env/*/bin/python"))
    return str(local_envs[-1]) if local_envs else sys.executable


def direct_serial_port(role: str) -> str:
    if role.startswith("/dev/"):
        return role
    override = os.environ.get(f"DMESH_SERIAL_{role.upper().replace('-', '_')}")
    if override:
        return override
    pattern = BOARD_SERIAL_GLOBS.get(role)
    if pattern is None:
        raise RuntimeError(f"{role}: no direct USB inventory entry; set DMESH_SERIAL_<ROLE>")
    matches = sorted(glob.glob(f"/dev/serial/by-id/{pattern}"))
    if len(matches) != 1:
        raise RuntimeError(f"{role}: expected one direct USB port for {pattern}, found {matches}")
    return matches[0]


def probe_direct(port: str, baud: int, connect_attempts: int = 7) -> DirectDevice | None:
    command = [
        esptool_python(), "-m", "esptool", "--port", port, "--baud", str(baud),
        "--connect-attempts", str(connect_attempts),
        "--before", "default-reset", "--after", "no_reset", "--no-stub", "chip_id",
    ]
    completed = subprocess.run(command, cwd=FW_RUST, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        print(f"direct probe failed for {port}:\n{completed.stdout}", flush=True)
        return None
    output = completed.stdout
    chip = "esp32c6" if "ESP32-C6" in output else "esp32s3" if "ESP32-S3" in output else "esp32"
    return DirectDevice(chip)


def probe_direct_until(port: str, baud: int, timeout_s: float) -> DirectDevice | None:
    """Bounded managed probe for a board reset through a separate control path.

    Native C6 USB-JTAG has no RTS/DTR lines.  When a wedged application can
    only be restarted through JTAG, the ROM serial-download window is brief;
    retrying the *same* repository-owned esptool probe lets an operator reset
    the board while this command is already waiting.  Normal flashing keeps
    the one-shot probe by leaving ``timeout_s`` at zero.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        # One short esptool sync attempt per iteration has no long blind gap,
        # so an operator-issued JTAG reset can be caught during ROM startup.
        device = probe_direct(port, baud, connect_attempts=1)
        if device is not None or time.monotonic() >= deadline:
            return device
        time.sleep(0.25)


def board_ip_from_hosts(role: str) -> str:
    """Return the checked-in static STA address for one lab board.

    `hosts` is the fleet source of truth.  A stale generic default silently
    assigned e6 the former .200 address and made two boards collide, so an
    unknown role must be explicit rather than inheriting that old value.
    """
    hosts = ROOT / "hosts"
    for line in hosts.read_text().splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and role in fields[1:]:
            return fields[0]
    raise RuntimeError(f"{role}: no static address in {hosts}; pass --board-ip explicitly")


def deployment_transport(target: str, requested: str) -> str:
    """Resolve the requested provisioning path without involving any service."""
    transport = "usb" if requested == "auto" else requested
    if transport == "action" and target != "main":
        raise ValueError("ESP-NOW/action deployment currently supports Main only")
    return transport


def openocd_binary_and_scripts() -> tuple[Path, Path]:
    """Locate the ESP-IDF-pinned OpenOCD, never a host-global substitute."""
    candidates = sorted(
        ROOT.glob("target/esp32-*/espressif/tools/openocd-esp32/*/openocd-esp32/bin/openocd")
    )
    if candidates:
        binary = candidates[-1]
    else:
        discovered = shutil.which("openocd")
        if discovered is None:
            raise RuntimeError("ESP-IDF OpenOCD is unavailable; run env.sh/setup first")
        binary = Path(discovered)
    scripts = binary.parent.parent / "share" / "openocd" / "scripts"
    if not scripts.is_dir():
        raise RuntimeError(f"OpenOCD scripts not found beside {binary}")
    return binary, scripts


def jtag_adapter_location(role: str) -> str:
    """Return the exact USB topology of this board's builtin JTAG adapter.

    OpenOCD's serial-string selection is unreliable immediately after a C6
    reset, so the JTAG writer deliberately selects a USB topology instead.
    Hub enumeration can change its *bus* number across a host restart though;
    a checked-in topology alone then targets no adapter.  Derive the location
    from the already role-specific serial endpoint (for example ``5-1.1``),
    which retains the no-ambiguous-adapter property when e6 and e7 are both
    connected.  The historical inventory remains only as a diagnostic
    fallback for a board whose serial interface is temporarily absent.
    """
    try:
        port = Path(direct_serial_port(role)).resolve()
        interface = (Path("/sys/class/tty") / port.name / "device").resolve()
        usb_device = interface.parent
        bus = (usb_device / "busnum").read_text().strip()
        devpath = (usb_device / "devpath").read_text().strip()
        if bus and devpath:
            return f"{bus}-{devpath}"
    except (OSError, RuntimeError):
        pass
    return JTAG_ADAPTER_LOCATION[role]


def jtag_write_partition(role: str, image: Path, offset: str) -> None:
    """Write one verified C6 application partition through USB-JTAG.

    This is deliberately narrower than the normal serial path: only the
    The caller passes only a partition artifact and its checked fixed offset.
    Stage2, partition table, and NVS remain untouched. OpenOCD verifies the
    bounded write, then explicitly resets and runs the C6 before releasing
    its builtin-JTAG adapter.
    """
    if not image.is_file():
        raise RuntimeError(f"missing Recovery image: {image}")
    openocd, scripts = openocd_binary_and_scripts()
    adapter_location = jtag_adapter_location(role)
    # `program_esp ... reset exit` leaves this C6 builtin-JTAG target halted
    # at the reset vector. Keep the programming command separate so the final
    # reset has explicit `run` semantics before OpenOCD releases the adapter.
    # A crashed/partially flashed C6 may be halted at PC=0. OpenOCD can still
    # write Recovery through JTAG, but its optional flash-clock boost stub can
    # time out in that state. Recovery repair is bounded and infrequent, so
    # prefer the conservative clock path over transfer speed.
    # Do not run the optional existing-flash SHA phase. A corrupt Main can
    # reset the hart while that helper is resident, wedging the RISC-V abstract
    # command engine before Recovery erase begins. The final `verify` remains
    # the authoritative readback check after the bounded write.
    program = (
        f"program_esp {shlex.quote(str(image))} {offset} verify "
        "no_clock_boost no_skip_loaded"
    )
    subprocess.run(
        [
            str(openocd), "-s", str(scripts), "-f", "board/esp32c6-builtin.cfg",
            "-c", f"adapter usb location {adapter_location}",
            "-c", f"adapter speed {JTAG_RECOVERY_KHZ}",
            # A Recovery rescue must tolerate a bad/looping Main. `program_esp`
            # performs its own reset/init after OpenOCD has initialized the
            # target; only extend its abstract-memory command bound here.
            # This affects no normal serial provisioning.
            "-c", "riscv set_command_timeout_sec 30",
            "-c", program, "-c", "reset run", "-c", "shutdown",
        ],
        cwd=ROOT,
        check=True,
    )


def action_flash(role: str) -> None:
    """Refuse until the end-to-end action object path exists.

    This is intentionally a hard failure, not a silent fallback to another
    bearer. The future implementation calls lmesh-wifi's privileged action
    adapter and receives the object response in the shared Main/Recovery
    QUIC-lite callback path.
    """
    raise RuntimeError(
        f"{role}: ESP-NOW/action flashing is not available yet: "
        "wifi.object.action.flash and the shared Main/Recovery action object "
        "receiver must land together"
    )


def artifacts(device: object, target: str, module: str) -> tuple[str, list[tuple[str, Path]]]:
    is_s3 = bool(getattr(device, "is_s3", False))
    is_c6 = bool(getattr(device, "is_c6", False))
    if is_s3:
        family = "esp32s3"
    elif is_c6:
        family = "esp32c6"
    else:
        family = "esp32"
    stage2 = ROOT / "target" / "stage2" / family
    flash = ROOT / "target" / "flash" / family
    if target == "stage":
        boot_offset = "0x0" if is_s3 or is_c6 else "0x1000"
        return family, [
            (boot_offset, stage2 / "bootloader.bin"),
            ("0x8000", stage2 / "partition-table.bin"),
        ]
    if target in ("main", "oldmain"):
        # Must mirror fw/boot/partitions.csv.  The Stage2 update moves Main
        # after the 1 MiB Recovery partition, so a stale 0xe0000 write would
        # leave the selector with no valid Main image at its declared offset.
        image_root = flash if target == "main" else ROOT / "target" / "oldmain" / "flash" / family
        return family, [("0x110000", image_root / "main-app.bin")]
    if target == "recovery":
        return family, [(
            "0x10000",
            ROOT / "target" / "recovery-rust" / "flash" / family / "dmesh-recovery-rs-app.bin",
        )]
    if target == "module":
        # tag 44 is a temporary development slot for mod_flash.  It reuses
        # the lora data window, so Main must quiesce lora before the USB write.
        service_tags = {"lora": 43, "flash": 44, "hw": 45, "hello": 46}
        if module not in service_tags:
            raise RuntimeError(f"unknown module {module!r}; known={sorted(service_tags)}")
        image = ROOT / "target" / "modules" / {
            "esp32": "xtensa-esp32-espidf",
            "esp32s3": "xtensa-esp32s3-espidf",
            "esp32c6": "riscv32imac-esp-espidf",
        }[family] / f"mod_{module}.dmod"
        offset = 0x3C0000 + (service_tags[module] - 43) * 0x10000
        if offset >= 0x400000:
            raise RuntimeError(
                f"module {module!r} slot 0x{offset:x} is outside the fixed 4 MiB data partition"
            )
        return family, [(hex(offset), image)]
    raise RuntimeError(f"unsupported flash target={target}")


def read_flash_with_fallback(port: str, chip: str, offset: str, size: str, output: Path, baud: int) -> None:
    """Read a preserved flash range using the same conservative ladder as writes."""
    attempts = [(baud, False)]
    if (baud, False) != (115200, False):
        attempts.append((115200, False))
    attempts.append((115200, True))
    last: BaseException | None = None
    for attempt_baud, no_stub in attempts:
        command = [
            esptool_python(), "-m", "esptool", "--chip", chip, "--port", port,
            "--baud", str(attempt_baud),
        ]
        if no_stub:
            command.append("--no-stub")
        command += ["read-flash", offset, size, str(output)]
        try:
            subprocess.run(command, cwd=FW_RUST, check=True)
            return
        except subprocess.CalledProcessError as error:
            last = error
            print(
                f"NVS read failed baud={attempt_baud} no_stub={no_stub}: {error}; retrying",
                flush=True,
            )
    assert last is not None
    raise RuntimeError(f"unable to preserve NVS from {port}") from last


def nvs_boot_target_image(
    port: str, chip: str, role: str, boot_target: int | None, clear_boot_target: bool,
    uart_boot: int | None, mode: str | None,
    server: str, board_ip: str, server_port: int, flash_baud: int,
    source_override: Path | None = None,
) -> Path:
    """Preserve NVS contents while setting or removing the lab boot target."""
    output = ROOT / "target" / "nvs" / role
    output.mkdir(parents=True, exist_ok=True)
    source = output / "before.bin"
    csv = output / "boot-target.csv"
    image = output / "boot-target.bin"
    if source_override is not None:
        source = source_override.resolve()
        if not source.is_file():
            raise RuntimeError(f"NVS source not found: {source}")
    else:
        read_flash_with_fallback(port, chip, "0x9000", "0x6000", source, flash_baud)
    command = [
        sys.executable, str(ROOT / "scripts" / "prepare-nvs-image.py"),
        str(source), str(csv), str(image), "--size", "0x6000",
        "--server", server, "--ip", board_ip,
        "--gw", server, "--mask", "255.255.0.0", "--port", str(server_port),
    ]
    if clear_boot_target:
        command.append("--clear-boot-target")
    elif boot_target is not None:
        command.extend(("--boot-target", str(boot_target)))
    if uart_boot is not None:
        command.extend(("--uart-boot", str(uart_boot)))
    if mode is not None:
        command.extend(("--mode", mode))
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
    )
    return image


def write_verified(port: str, chip: str, pairs: list[tuple[str, Path]], baud: int,
                   reset_after: bool = False) -> None:
    for offset, image in pairs:
        if not image.is_file():
            raise RuntimeError(f"missing flash artifact: {image}")
    attempts = [(baud, "40m", False)]
    if (baud, "40m", False) != (115200, "20m", False):
        attempts.append((115200, "20m", False))
    attempts.append((115200, "20m", True))
    last: BaseException | None = None
    for attempt_baud, frequency, no_stub in attempts:
        command = [
            esptool_python(), "-m", "esptool", "--chip", chip, "--port", port,
            "--baud", str(attempt_baud), "--before", "default-reset",
            # A direct port has no service owner to reclaim, so let esptool
            # leave ROM through its normal hard reset.
            "--after", "hard_reset" if reset_after else "no_reset",
        ]
        if no_stub:
            command.append("--no-stub")
        flash_size = "8MB" if chip == "esp32s3" else "4MB"
        command += ["write-flash", "--flash_mode", "dio", "--flash_freq", frequency,
                    "--flash_size", flash_size]
        for offset, image in pairs:
            command.extend((offset, str(image)))
        try:
            subprocess.run(command, cwd=FW_RUST, check=True)
            return
        except (subprocess.CalledProcessError, OSError) as error:
            last = error
            print(f"flash attempt failed baud={attempt_baud} freq={frequency} no_stub={no_stub}: {error}", flush=True)
    assert last is not None
    raise last


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role")
    parser.add_argument("target", nargs="?", default="main",
                        choices=("stage", "main", "oldmain", "recovery", "module", "nvs"))
    parser.add_argument("--module", default="lora")
    parser.add_argument("--check", action="store_true",
                        help="probe the direct esptool port and report its chip without writing")
    parser.add_argument("--transport", choices=("auto", "usb", "action", "jtag"), default="auto",
                        help="default: direct USB/esptool; jtag is the explicit C6 Main/Recovery emergency path")
    parser.add_argument("--server", default="10.78.0.1",
                        help="with target=nvs: saved dmesh STA server address")
    parser.add_argument("--server-port", type=int, default=3336,
                        help="with target=nvs: saved dmesh server port")
    parser.add_argument("--board-ip",
                        help="with target=nvs: saved static STA address")
    parser.add_argument("--flash-baud", type=int, default=460800)
    parser.add_argument("--probe-timeout", type=float, default=0,
                        help="retry the managed direct probe for this many seconds; use with an external JTAG reset")
    parser.add_argument("--boot-target", type=int, choices=(1, 2),
                        help="with target=nvs: set Stage2 stg2:boot_target (1=Main, 2=Recovery)")
    parser.add_argument("--clear-boot-target", action="store_true",
                        help="with target=nvs: remove Stage2 boot target override")
    parser.add_argument("--uart-boot", type=int, choices=(0, 1),
                        help="with target=nvs: set Stage2 stg2:uart_boot (0 disables selector)")
    parser.add_argument("--nvs-source", type=Path,
                        help="with target=nvs: explicit preserved NVS source image")
    parser.add_argument("--mode", choices=("active", "sleepy", "sleepy-soft"),
                        help="with target=nvs: set dmesh:mode for next boot (sleepy-soft keeps the radio awake for transition tests)")
    args = parser.parse_args()
    try:
        args.transport = deployment_transport(args.target, args.transport)
    except ValueError as error:
        parser.error(str(error))
    if args.board_ip is None:
        args.board_ip = board_ip_from_hosts(args.role)

    if args.transport == "action":
        action_flash(args.role)
        return 0
    if args.transport == "jtag":
        if args.check or args.role not in JTAG_ADAPTER_SERIAL or args.target not in ("recovery", "main"):
            parser.error("--transport jtag is restricted to `flash-device.py <e6|e7> <recovery|main>`")
        _, pairs = artifacts(DirectDevice("esp32c6"), args.target, args.module)
        # This authority accepts exactly one checked app partition; retain the
        # partition-table offsets here so JTAG cannot overwrite Stage2 or NVS.
        expected_offset = {"recovery": "0x10000", "main": "0x110000"}[args.target]
        if len(pairs) != 1 or pairs[0][0] != expected_offset:
            raise RuntimeError(f"unexpected {args.role} {args.target} JTAG artifact: {pairs}")
        print(f"{args.role}: JTAG {args.target} write {pairs[0][1]}", flush=True)
        jtag_write_partition(args.role, pairs[0][1], expected_offset)
        print(f"{args.role}: JTAG verified {args.target} and reset", flush=True)
        return 0
    if args.boot_target is not None and args.clear_boot_target:
        parser.error("--boot-target and --clear-boot-target are mutually exclusive")
    if args.target == "nvs" and args.boot_target is None and not args.clear_boot_target and args.uart_boot is None and args.mode is None:
        parser.error("target=nvs requires a Stage2 override")

    physical = direct_serial_port(args.role)
    if args.check:
        device = probe_direct_until(physical, args.flash_baud, args.probe_timeout)
        if device is None:
            return 1
        chip = "esp32c6" if device.is_c6 else "esp32s3" if device.is_s3 else "esp32"
        print(f"{args.role}: direct USB probe ok chip={chip} port={physical}", flush=True)
        return 0
    # A local Main/module write must not race the raw NAN owner.  Keep this
    # transport-specific: Recovery/stage targets may already be running in a
    # non-Main boot partition, while future FSK/NAN object transports must not
    # be disabled merely because the module name is `flash`.
    provisioning_started = time.monotonic()
    print(f"{args.role}: direct USB provisioning on {physical}", flush=True)
    write_succeeded = False
    chip: str | None = None
    try:
        device = probe_direct_until(physical, args.flash_baud, args.probe_timeout)
        if device is None:
            raise RuntimeError(f"unable to identify ESP chip on {physical}")
        if args.target == "nvs":
            chip = "esp32c6" if bool(getattr(device, "is_c6", False)) else (
                "esp32s3" if bool(getattr(device, "is_s3", False)) else "esp32"
            )
            image = nvs_boot_target_image(
                physical, chip, args.role, args.boot_target, args.clear_boot_target, args.uart_boot,
                args.mode, args.server, args.board_ip, args.server_port, args.flash_baud,
                args.nvs_source,
            )
            pairs = [("0x9000", image)]
        else:
            chip, pairs = artifacts(device, args.target, args.module)
        print(f"{args.role}: flashing {args.target} chip={chip} port={physical}", flush=True)
        flash_started = time.monotonic()
        write_verified(physical, chip, pairs, args.flash_baud, reset_after=True)
        write_succeeded = True
        print(f"{args.role}: USB provisioning write+verify elapsed={time.monotonic() - flash_started:.3f}s", flush=True)
        print(f"{args.role}: verified {args.target}", flush=True)
    finally:
        pass
    if write_succeeded:
        print(f"{args.role}: direct USB provisioning reset elapsed={time.monotonic() - provisioning_started:.3f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
