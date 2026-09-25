#!/usr/bin/env python3
"""Single entry point for ESP image deployment.

Legacy UART byte forwards are disabled. Direct USB/espflash deployment is the
current flashing path for every target, including Main. It opens only the
selected physical port through the repository's verified wrapper and never
starts, stops, or restores a managed serial forward. ESP-NOW/action and Wi-Fi
flashing remain future paths for devices without a UART connection.

Before replacing a running Main image, the wrapper makes one bounded
best-effort `runtime.reset` request through dmesh-cli.  Main explicitly
leaves STA before restarting, so USB provisioning does not leave a stale AP
association or replace the provisioned STA profile with a temporary NAN mode.
The preflight never prevents a repair flash when the current firmware is
crashed or UART is unavailable.
"""

from __future__ import annotations

import argparse
import fcntl
import glob
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import sys
import termios
import time
import tomllib
from pathlib import Path

ROOT = Path(os.environ.get("DMESH_INSTALL_ROOT", Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
DEFAULT_DEVICE_CATALOG = ROOT / "crates" / "dmesh-cli" / "examples" / "device-catalog.toml"

# Direct USB/JTAG identities are resolved from the same TOML catalog as the
# CLI and hardware E2E. A literal /dev path remains an explicit override.
# Recovery rescue values integrity over JTAG throughput. The builtin adapter
# defaults to 24 MHz; a wedged board on a long/noisy hub path is more reliable
# at this conservative debug-clock rate.
JTAG_RECOVERY_KHZ = 4_000


class DirectDevice:
    def __init__(self, chip: str, flash_size_mb: int | None = None) -> None:
        self.is_s3 = chip == "esp32s3"
        self.is_c6 = chip == "esp32c6"
        self.flash_size_mb = flash_size_mb


def catalog_device(catalog: Path | None, role: str) -> dict:
    if catalog is None:
        raise RuntimeError(
            f"{role}: device catalog not selected"
        )
    if not catalog.is_file():
        raise RuntimeError(f"device catalog not found: {catalog}")
    with catalog.open("rb") as stream:
        document = tomllib.load(stream)
    devices = document.get("devices")
    if not isinstance(devices, list):
        raise RuntimeError("device catalog has no [[devices]] entries")
    matches = [device for device in devices if isinstance(device, dict) and device.get("name") == role]
    if len(matches) != 1:
        raise RuntimeError(f"device catalog must contain exactly one device named {role!r}")
    return matches[0]


def direct_serial_port(role: str, catalog: Path | None) -> str:
    if role.startswith("/dev/"):
        return role
    override = os.environ.get(f"DMESH_SERIAL_{role.upper().replace('-', '_')}")
    if override:
        return override
    device = catalog_device(catalog, role)
    pattern = device.get("serial_glob") or device.get("serial")
    if not isinstance(pattern, str) or not pattern:
        raise RuntimeError(f"{role}: catalog has no serial or serial_glob; set DMESH_SERIAL_<ROLE>")
    if pattern.startswith("/dev/"):
        return pattern
    matches = sorted(glob.glob(f"/dev/serial/by-id/{pattern}"))
    if len(matches) != 1:
        raise RuntimeError(f"{role}: expected one direct USB port for {pattern}, found {matches}")
    return matches[0]


def preflash_sta_off(role: str, target: str, physical: str) -> None:
    """Best-effort, observable Main STA teardown before USB flashing.

    Keep this outside the espflash path: entering the ROM loader first would
    make a correct control-plane request impossible.  The direct diagnostic
    client owns UART framing and is deliberately used instead of reintroducing
    a forwarding service.  A preflight failure is diagnostic evidence only;
    flashing is the recovery path for precisely that class of failure.
    """
    if target not in ("main", "oldmain", "module", "all") or role.startswith("/dev/"):
        return
    # The supported client is the release binary selected by `env.sh` on
    # PATH.  Do not revive a potentially stale target/debug copy: it may
    # speak an older stream envelope and make a successful STA teardown look
    # uncorrelated just before a USB reset.
    cli = shutil.which("dmesh-cli")
    if cli is None:
        print(f"{role}: STA-off preflight skipped (dmesh-cli is not on PATH)", flush=True)
        return
    # Reset is a normal correlated QUIC-lite service.  Keep it out of the
    # connectionless direct-control allowlist: a reset must not become an
    # unauthenticated radio-plane operation merely because this provisioning
    # helper happens to own a local USB cable.
    command = [cli, physical, "runtime.reset"]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"{role}: STA-off preflight unavailable: {error}", flush=True)
        return
    if completed.returncode:
        print(f"{role}: STA-off preflight failed (continuing to flash): {completed.stdout.strip()}", flush=True)
        return
    # The low-level UART stream renderer preserves this minimal handler reply
    # as a raw tagged record, so it does not currently attach the schema method
    # label.  Its fixed acknowledgement text is still correlated to this
    # one-request session and is the observable acceptance boundary.
    if "reset scheduled" not in completed.stdout:
        print(f"{role}: STA-off preflight response was not correlated (continuing to flash)", flush=True)
        return
    # Main returns its response before the owner performs the explicit STA
    # leave/restart. One second is ample for that bounded transition and
    # avoids asking the flash wrapper to become a Wi-Fi scan or association
    # status verifier.
    time.sleep(1)
    print(f"{role}: STA-off preflight accepted; waited 1s for STA teardown", flush=True)


def release_serial_modem_lines(port: str) -> None:
    """Return a CP210x serial adapter to an explicit idle line state.

    LoRa boards connect RTS to EN and DTR to GPIO0.  A previous serial owner
    may close while either line is asserted; entering espflash from that stale
    state can select the ROM downloader but leave its TX path unsynchronised.
    Clear both lines before starting espflash, then let espflash perform its
    normal reset/download handshake from a known state.  Native USB-JTAG C6
    endpoints do not expose these modem ioctls, so failure is intentionally a
    no-op rather than a reason to reject their direct provisioning path.
    """
    try:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError:
        return
    try:
        mask = termios.TIOCM_DTR | termios.TIOCM_RTS
        fcntl.ioctl(fd, termios.TIOCMBIC, mask.to_bytes(4, sys.byteorder, signed=True))
    except OSError:
        pass
    finally:
        os.close(fd)


def probe_direct(port: str, baud: int, no_stub: bool = True) -> DirectDevice | None:
    release_serial_modem_lines(port)
    executable = shutil.which("espflash")
    if executable is None:
        raise RuntimeError("espflash is not on PATH")
    command = [executable, "--skip-update-check", "board-info", "--port", port,
               "--baud", str(baud), "--non-interactive", "--after", "no-reset"]
    if no_stub:
        command.append("--no-stub")
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        print(f"direct probe failed for {port}:\n{completed.stdout}", flush=True)
        return None
    output = completed.stdout.lower()
    if "esp32-c6" in output or "esp32c6" in output:
        chip = "esp32c6"
    elif "esp32-s3" in output or "esp32s3" in output:
        chip = "esp32s3"
    elif "esp32" in output:
        chip = "esp32"
    else:
        print(f"direct probe did not identify a supported chip on {port}:\n{completed.stdout}", flush=True)
        return None
    size_match = re.search(r"Flash size:\s*(\d+)\s*MB", completed.stdout, re.IGNORECASE)
    flash_size_mb = int(size_match.group(1)) if size_match else None
    return DirectDevice(chip, flash_size_mb)


def probe_direct_until(port: str, baud: int, timeout_s: float) -> DirectDevice | None:
    """Bounded managed probe for a board reset through a separate control path.

    Native C6 USB-JTAG has no RTS/DTR lines.  When a wedged application can
    only be restarted through JTAG, the ROM serial-download window is brief;
    retrying the *same* repository-owned espflash probe lets an operator reset
    the board while this command is already waiting.  Normal flashing keeps
    the one-shot probe by leaving ``timeout_s`` at zero.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        # One short espflash sync attempt per iteration has no long blind gap,
        # so an operator-issued JTAG reset can be caught during ROM startup.
        # Keep chip identification as conservative as the later write path.
        # A CP210x may enter ROM at its normal fast baud yet only exchange a
        # reliable sync at 115200; the old one-shot probe aborted before the
        # write ladder could reach that fallback.  Do not drop the no-stub
        # variant: it is required by the CP2104 fleet board.
        attempts = [(baud, True)]
        if (baud, True) != (115200, True):
            attempts.append((115200, True))
        attempts.append((115200, False))
        for attempt_baud, no_stub in attempts:
            device = probe_direct(
                port, attempt_baud, no_stub=no_stub,
            )
            if device is not None:
                return device
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.25)


def board_ip_from_catalog(catalog: Path | None, role: str) -> str:
    """Return the static STA IPv4 configured for a catalog device."""
    value = catalog_device(catalog, role).get("ipv4")
    if not isinstance(value, str):
        raise RuntimeError(f"{role}: catalog has no IPv4 address; pass --board-ip explicitly")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as error:
        raise RuntimeError(f"{role}: catalog IPv4 address is invalid: {value!r}") from error


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


def jtag_adapter_location(role: str, catalog: Path | None) -> str:
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
        port = Path(direct_serial_port(role, catalog)).resolve()
        interface = (Path("/sys/class/tty") / port.name / "device").resolve()
        usb_device = interface.parent
        bus = (usb_device / "busnum").read_text().strip()
        devpath = (usb_device / "devpath").read_text().strip()
        if bus and devpath:
            return f"{bus}-{devpath}"
    except (OSError, RuntimeError):
        pass
    location = catalog_device(catalog, role).get("jtag_adapter_location")
    if not isinstance(location, str) or not location:
        raise RuntimeError(f"{role}: catalog has no jtag_adapter_location")
    return location


def jtag_write_partition(role: str, image: Path, offset: str, catalog: Path | None) -> None:
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
    adapter_location = jtag_adapter_location(role, catalog)
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


def artifacts(device: object, target: str, module: str,
              artifact_root: Path | None = None) -> tuple[str, list[tuple[str, Path]]]:
    is_s3 = bool(getattr(device, "is_s3", False))
    is_c6 = bool(getattr(device, "is_c6", False))
    if is_s3:
        family = "esp32s3"
    elif is_c6:
        family = "esp32c6"
    else:
        family = "esp32"
    if target == "all":
        main = artifacts(device, "main", module, artifact_root)[1]
        stage = artifacts(device, "stage", module, artifact_root)[1]
        recovery = artifacts(device, "recovery", module, artifact_root)[1]
        return family, main + stage + recovery
    flash_size_mb = getattr(device, "flash_size_mb", None)
    if target == "stage" and flash_size_mb not in (4, 8):
        raise RuntimeError(f"unsupported or unknown flash size {flash_size_mb!r} MB for {family}")
    if artifact_root is not None and target in ("stage", "main", "recovery"):
        cpu_root = artifact_root / family
        if target == "stage":
            cpu_root = cpu_root / f"{flash_size_mb}mb"
            return family, [
                ("0x1000" if family == "esp32" else "0x0", cpu_root / "stage2.bin"),
                ("0x8000", cpu_root / "partition-table.bin"),
            ]
        return family, [
            ("0x110000" if target == "main" else "0x10000",
             cpu_root / ("main-app.bin" if target == "main" else "recovery.bin")),
        ]
    stage2 = ROOT / "target" / "stage2" / family / f"{flash_size_mb}mb"
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
    executable = shutil.which("espflash")
    if executable is None:
        raise RuntimeError("espflash is not on PATH")
    attempts = [(baud, False)]
    if (baud, False) != (115200, False):
        attempts.append((115200, False))
    attempts.append((115200, True))
    last: BaseException | None = None
    for attempt_baud, no_stub in attempts:
        command = [
            executable, "--skip-update-check", "read-flash", "--chip", chip,
            "--port", port, "--baud", str(attempt_baud), "--non-interactive",
            "--after", "no-reset",
        ]
        if no_stub:
            command.append("--no-stub")
        command += [offset, size, str(output)]
        try:
            subprocess.run(command, check=True)
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
    mode: str | None, clear_sta_profile: bool, clear_pairing: bool,
    server: str, board_ip: str, server_port: int, flash_baud: int,
    source_override: Path | None = None, sta_profile: Path | None = None,
    sta_ssid: str | None = None, sta_server_ll: str | None = None,
    sta_server_port: int = 3336, device_catalog: Path | None = None,
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
    ]
    if device_catalog is not None:
        command.extend(("--server", server, "--ip", board_ip,
                        "--gw", server, "--mask", "255.255.0.0", "--port", str(server_port)))
    if clear_boot_target:
        command.append("--clear-boot-target")
    elif boot_target is not None:
        command.extend(("--boot-target", str(boot_target)))
    if mode is not None:
        command.extend(("--mode", mode))
    if clear_sta_profile:
        command.append("--clear-sta-profile")
    if clear_pairing:
        command.append("--clear-pairing")
    if sta_profile is not None:
        command.extend(("--sta-profile", str(sta_profile)))
        if sta_ssid is not None:
            command.extend(("--sta-ssid", sta_ssid))
        if sta_server_ll is not None:
            command.extend(("--sta-server-ll", sta_server_ll))
        command.extend(("--sta-server-port", str(sta_server_port)))
    if device_catalog is not None:
        command.extend(("--device-catalog", str(device_catalog), "--device-role", role))
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
    )
    return image


def write_verified(port: str, chip: str, pairs: list[tuple[str, Path]], baud: int,
                   reset_after: bool = False) -> None:
    import hashlib
    import tempfile

    executable = shutil.which("espflash")
    if executable is None:
        raise RuntimeError("espflash is not on PATH")
    for offset, image in pairs:
        if not image.is_file():
            raise RuntimeError(f"missing flash artifact: {image}")
    attempts = [(baud, False)]
    if (baud, False) != (115200, False):
        attempts.append((115200, False))
    attempts.append((115200, True))
    common = [executable, "--skip-update-check"]
    for offset, image in pairs:
        last: BaseException | None = None
        for attempt_baud, no_stub in attempts:
            release_serial_modem_lines(port)
            connection = ["--chip", chip, "--port", port,
                          "--baud", str(attempt_baud), "--non-interactive"]
            if no_stub:
                connection.append("--no-stub")
            try:
                subprocess.run(common + ["write-bin"] + connection +
                               ["--after", "no-reset", offset, str(image)], check=True)
                with tempfile.TemporaryDirectory(prefix="dmesh-espflash-verify-") as temporary:
                    readback = Path(temporary) / "readback.bin"
                    subprocess.run(common + ["read-flash"] + connection +
                                   ["--after", "no-reset", offset, str(image.stat().st_size),
                                    str(readback)], check=True)
                    if hashlib.sha256(readback.read_bytes()).digest() != hashlib.sha256(image.read_bytes()).digest():
                        raise RuntimeError(f"espflash readback mismatch at {offset}: {image}")
                break
            except (subprocess.CalledProcessError, OSError, RuntimeError) as error:
                last = error
                print(f"flash attempt failed offset={offset} baud={attempt_baud} "
                      f"no_stub={no_stub}: {error}", flush=True)
        else:
            assert last is not None
            raise last
    if reset_after:
        reset_direct(port, chip, baud)


def reset_direct(port: str, chip: str, baud: int) -> None:
    executable = shutil.which("espflash")
    if executable is None:
        raise RuntimeError("espflash is not on PATH")
    subprocess.run([executable, "--skip-update-check", "reset", "--chip", chip,
                    "--port", port, "--baud", str(baud), "--non-interactive"], check=True)


def installed_main() -> int:
    parser = argparse.ArgumentParser(
        description="Flash a DMesh device using the firmware bundled in this package."
    )
    parser.add_argument("port", help="USB serial port, such as /dev/ttyACM0")
    parser.add_argument("target", choices=("all", "stage", "recovery", "main"),
                        help="all writes Main, Stage2, the matching partition table, and Recovery")
    parser.add_argument("--check", action="store_true",
                        help="show the detected chip and flash size without writing")
    parser.add_argument("--baud", type=int, default=460800)
    args = parser.parse_args()
    if not args.port.startswith("/dev/"):
        parser.error("port must be a /dev/ serial device")
    artifact_root = ROOT / "share" / "dmesh" / "flash"
    if not artifact_root.is_dir():
        parser.error("this package has no firmware images; install the firmware-enabled package")
    device = probe_direct_until(args.port, args.baud, 0)
    if device is None:
        raise RuntimeError(f"unable to identify ESP chip on {args.port}")
    chip, pairs = artifacts(device, args.target, "lora", artifact_root)
    print(f"chip={chip} flash_size={device.flash_size_mb}MB port={args.port}", flush=True)
    if args.check:
        reset_direct(args.port, chip, args.baud)
        return 0
    write_verified(args.port, chip, pairs, args.baud, reset_after=True)
    print(f"verified {args.target}; device reset", flush=True)
    return 0


def main() -> int:
    if os.environ.get("DMESH_INSTALL_ROOT"):
        return installed_main()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role")
    parser.add_argument("target", nargs="?", default="main",
                        choices=("all", "stage", "main", "oldmain", "recovery", "module", "nvs"))
    parser.add_argument("--module", default="lora")
    parser.add_argument("--check", action="store_true",
                        help="probe the direct espflash port, chip, and flash size without writing")
    parser.add_argument("--transport", choices=("auto", "usb", "action", "jtag"), default="auto",
                        help="default: direct USB/espflash; jtag is the explicit C6 Main/Recovery emergency path")
    parser.add_argument("--server", default="10.78.0.1",
                        help="with target=nvs: saved dmesh STA server address")
    parser.add_argument("--server-port", type=int, default=3336,
                        help="with target=nvs: saved dmesh server port")
    parser.add_argument("--board-ip",
                        help="with target=nvs: saved static STA address")
    parser.add_argument("--flash-baud", type=int, default=460800)
    parser.add_argument("--flasher", choices=("espflash",), default="espflash",
                        help="USB write tool (espflash is the default)")
    installed_artifacts = ROOT / "share" / "dmesh" / "flash"
    parser.add_argument("--artifact-root", type=Path,
                        default=installed_artifacts if installed_artifacts.is_dir() else None,
                        help="CPU-qualified flash directory, such as a dmesh Nix package's share/dmesh/flash")
    parser.add_argument("--probe-timeout", type=float, default=0,
                        help="retry the managed direct probe for this many seconds; use with an external JTAG reset")
    parser.add_argument("--boot-target", type=int, choices=(1, 2),
                        help="with target=nvs: set Stage2 stg2:boot_target (1=Main, 2=Recovery)")
    parser.add_argument("--clear-boot-target", action="store_true",
                        help="with target=nvs: remove Stage2 boot target override")
    parser.add_argument("--nvs-source", type=Path,
                        help="with target=nvs: explicit preserved NVS source image")
    parser.add_argument("--sta-profile", type=Path,
                        help="with target=nvs: private infra-sta.toml input; credentials are never printed")
    parser.add_argument("--sta-ssid",
                        help="with target=nvs: select an SSID from --sta-profile")
    parser.add_argument("--sta-server-ll",
                        help="with target=nvs: Recovery server IPv6 link-local address without an interface scope")
    parser.add_argument("--sta-server-port", type=int, default=3336,
                        help="with target=nvs: Recovery server UDP port for --sta-profile")
    parser.add_argument("--mode", choices=("active", "sleepy", "sleepy-soft"),
                        help="with target=nvs: set dmesh:mode for next boot (sleepy-soft keeps the radio awake for transition tests)")
    parser.add_argument("--clear-sta-profile", action="store_true",
                        help="with target=nvs: remove only persisted STA selector/credential keys")
    parser.add_argument("--clear-pairing", action="store_true",
                        help="with target=nvs: remove sec:key and ESP NimBLE bond data over physical USB")
    parser.add_argument("--device-catalog", type=Path,
                        default=os.environ.get("DMESH_DEVICE_CATALOG", DEFAULT_DEVICE_CATALOG),
                        help="shared device/E2E catalog; defaults to the checked-in test catalog")
    parser.add_argument("--provision-security", action="store_true",
                        help="with target=nvs: explicitly install the selected catalog secret and control key")
    args = parser.parse_args()
    if args.artifact_root is not None and args.target not in ("all", "stage", "recovery", "main"):
        parser.error("--artifact-root supports all, stage, recovery, and main")
    if args.device_catalog is not None:
        args.device_catalog = Path(args.device_catalog)
    try:
        args.transport = deployment_transport(args.target, args.transport)
    except ValueError as error:
        parser.error(str(error))
    # A static board address is NVS input only. Resolve it from the same
    # catalog that supplies the selected board's USB/JTAG identity.
    if args.board_ip is None and args.target == "nvs":
        args.board_ip = board_ip_from_catalog(args.device_catalog, args.role)

    if args.transport == "action":
        action_flash(args.role)
        return 0
    if args.transport == "jtag":
        if args.check or args.role.startswith("/dev/") or args.target not in ("recovery", "main"):
            parser.error("--transport jtag is restricted to a mapped C6 <main|recovery> target")
        _, pairs = artifacts(DirectDevice("esp32c6"), args.target, args.module)
        # This authority accepts exactly one checked app partition; retain the
        # partition-table offsets here so JTAG cannot overwrite Stage2 or NVS.
        expected_offset = {"recovery": "0x10000", "main": "0x110000"}[args.target]
        if len(pairs) != 1 or pairs[0][0] != expected_offset:
            raise RuntimeError(f"unexpected {args.role} {args.target} JTAG artifact: {pairs}")
        print(f"{args.role}: JTAG {args.target} write {pairs[0][1]}", flush=True)
        jtag_write_partition(args.role, pairs[0][1], expected_offset, args.device_catalog)
        print(f"{args.role}: JTAG verified {args.target} and reset", flush=True)
        return 0
    if args.boot_target is not None and args.clear_boot_target:
        parser.error("--boot-target and --clear-boot-target are mutually exclusive")
    if args.clear_pairing and args.target != "nvs":
        parser.error("--clear-pairing requires target=nvs")
    if args.provision_security and args.target != "nvs":
        parser.error("--provision-security requires target=nvs")
    if args.clear_pairing and args.provision_security:
        parser.error("--clear-pairing cannot be combined with --provision-security")
    if args.clear_pairing and (args.boot_target is not None or args.clear_boot_target or args.mode is not None
                               or args.clear_sta_profile or args.sta_profile is not None):
        parser.error("--clear-pairing cannot be combined with other NVS changes")
    if args.target == "nvs" and args.boot_target is None and not args.clear_boot_target and args.mode is None and not args.clear_sta_profile and not args.clear_pairing and args.sta_profile is None and not args.provision_security:
        parser.error("target=nvs requires a Stage2 override, mode, --sta-profile, --clear-pairing, or --provision-security")
    if args.sta_ssid is not None and args.sta_profile is None:
        parser.error("--sta-ssid requires --sta-profile")
    if args.sta_server_ll is not None and args.sta_profile is None:
        parser.error("--sta-server-ll requires --sta-profile")
    physical = direct_serial_port(args.role, args.device_catalog)
    if args.check:
        device = probe_direct_until(physical, args.flash_baud, args.probe_timeout)
        if device is None:
            return 1
        chip = "esp32c6" if device.is_c6 else "esp32s3" if device.is_s3 else "esp32"
        print(f"{args.role}: direct USB probe ok chip={chip} flash_size={device.flash_size_mb}MB port={physical}", flush=True)
        reset_direct(physical, chip, args.flash_baud)
        return 0
    # A local Main/module write must not race the raw NAN owner.  Keep this
    # transport-specific: Recovery/stage targets may already be running in a
    # non-Main boot partition, while future FSK/NAN object transports must not
    # be disabled merely because the module name is `flash`.
    provisioning_started = time.monotonic()
    print(f"{args.role}: direct USB provisioning on {physical}", flush=True)
    preflash_sta_off(args.role, args.target, physical)
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
                physical, chip, args.role, args.boot_target, args.clear_boot_target,
                args.mode, args.clear_sta_profile, args.clear_pairing, args.server, args.board_ip, args.server_port, args.flash_baud,
                args.nvs_source, args.sta_profile, args.sta_ssid, args.sta_server_ll,
                args.sta_server_port, args.device_catalog if args.provision_security else None,
            )
            pairs = [("0x9000", image)]
        else:
            chip, pairs = artifacts(device, args.target, args.module, args.artifact_root)
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
