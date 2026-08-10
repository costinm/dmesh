# Building DMesh

This repository owns device-specific mesh code: `lmesh`, `dmesh-store`,
`mesh-tun`, and `fw/esp32`. It consumes upstream `mesh` for common telemetry
and protocol support, and `ssh-mesh` for SSH, HTTPS, SFTP, and forwarding.

## Local build environment

The checked-in build scripts source `env.sh` before invoking Cargo, Nix,
Android, or firmware tools. It keeps all mutable state under `target/`: Cargo,
Rustup, Gradle, Nix profiles, Android SDK/NDK, ESP-IDF, and the Rust ESP
toolchain. It does not use a host home directory or host-installed build
tools. Source `env.sh` manually only when using other repo tools.

```sh
cd "$(git rev-parse --show-toplevel)"
. ./env.sh

# For one-off commands from a sandboxed runner that does not inherit shell
# initialization:
./scripts/with-env.sh rg --version
```

## Linux MUSL binaries

Install the repo-local Nix profile, then build every DMesh binary for static
MUSL:

```sh
scripts/build.sh deps
scripts/build.sh musl
```

Run the lmesh unit tests through the repository wrapper:

```sh
scripts/build.sh lmesh-test
scripts/build.sh lmesh-check
scripts/build.sh object-store-test
```

These host-only checks source `env.sh`, select the repo-local Rust toolchain,
and keep Cargo state under `target/`. Do not run standalone Cargo commands for
the DMesh or object-store checks. The `mesh-cli` artifact is built from the
sibling `ssh-mesh` checkout by `scripts/build.sh musl`; that build sources
ssh-mesh's own `env.sh` and writes only to its own `target/`.

Run the host-side Recovery/DRS2 protocol checks with:

```sh
scripts/build.sh recovery-test
```

This is the single supported host test entry point for the Recovery transport:
it checks framing, signatures, CPU-specific image selection, partition-table
handling, the unsigned bootstrap transfer, block/DONE sequencing, and the
per-device archive using a localhost TCP fake device. It does not open UART,
reset a board, or flash hardware.

The profile is `target/nix/profile`; `lmesh`, `mesh-tun`, and `dmeshtui` are
written to `target/x86_64-unknown-linux-musl/release/`. The generic `mesh` CLI
is built only by the sibling ssh-mesh workspace, at
`$DMESH_SSH_MESH_DIR/target/x86_64-unknown-linux-musl/release/mesh`. After
sourcing `env.sh`, that is the only `mesh` selected through PATH and
placed on `PATH`; `MESH_TOOLS` defaults to lmesh's
generated command catalog. The default `MESH_SERVICE_DIR` selects the installed
mesh-init service definitions, so `mesh lmesh esp serial.command ...` resolves
lmesh locally; use `$DMESH_LMESH_CONTROL_ENDPOINT` or another explicit
UDS/TCP endpoint for an isolated or different service. `mesh` itself remains
service-independent, and callers can override `MESH_TOOLS` or
`MESH_SERVICE_DIR`.
Android JNI/UI crates remain Android build inputs and are not included in the
Linux MUSL set.
`scripts/build.sh check` runs the workspace Cargo check using the same
local ssh-mesh override when that checkout is present. The dependency step also
installs the stable Rust toolchain and MUSL target into `target/rustup`.

## Android

Install the Android SDK, NDK, JDK, Rust/NDK helpers, and other host tools into
the same repo-local profile, then build the Android apps:

```sh
scripts/build-android.sh deps
scripts/build-android.sh build debug
```

Android SDK/NDK contents are installed under `target/android-sdk`; generated
native libraries and APKs remain under `target/`.

## ESP32 firmware

Install ESP32 host tools into their dedicated profile and ESP-IDF/Rust ESP
toolchains under `target/`:

```sh
scripts/esp32-deps.sh
scripts/build-fw.sh all
```

ESP-IDF and Rust ESP state live under `target/esp32-6.0`; its Nix host profile
is `target/nix/esp32-profile`. See [fw/esp32/BUILD.md](fw/esp32/BUILD.md) for
build details and [fw/esp32/rust/docs/flashing.md](fw/esp32/rust/docs/flashing.md)
for current provisioning and remote-flash instructions.

`scripts/build-fw.sh` builds the Rust Main images. Pass `e5`/`esp32` for a
classic ESP32 or `recovery-s3`/`esp32s3` for the common 4 MiB Main image. Build
the second-stage bootloader and Recovery with `scripts/build-recovery-fleet.sh
all`. Main artifacts are under `target/flash/`, and bootloader/Recovery
artifacts are under `target/recovery-fleet/`. Local Main and module development
flashing uses the common managed-forward-safe tool:

```sh
scripts/flash-device.py <board> main
scripts/flash-device.py <board> module --module lora
```

It temporarily releases only the selected forward, uses esptool's verified
write, and restores the forward. The legacy Wi-Fi/Recovery path remains
available for later performance comparison while `mod_flash` and the Rust/lmesh
flash protocol are reworked. See
`fw/esp32/rust/docs/flashing.md` for commands and log locations.

The reusable managed UART/recovery test surface is the lmesh CLI:

```sh
source ./env.sh
mesh lmesh usb.serial.forward.list
mesh lmesh esp.serial.command port=lora4 command=status timeout_sec=8
mesh lmesh usb.serial.reset port=lora4
```

All operations use the lmesh control socket and never open UART devices
directly. Routine Main and module flashing uses `scripts/flash-device.py`.
The normal command performs a read-only preflight automatically before any
reset, handoff, or NVS write. `--check <board>` is available when only the
preflight is wanted; it checks the saved board configuration, managed forward, server,
and CPU-specific image artifacts.
The same helper includes bounded generic `command` and `handshake` calls,
device discovery,
forward `list`, `forward-start`, and `forward-stop`, plus the explicit `dtr`
hardware-test operation. `dtr` is never used by normal flashing or forward
startup; all of these operations go through the lmesh control socket.
Managed reset changes RTS only, checks that DTR is released, and verifies that
the forward executed the pulse. If DTR was deliberately asserted by a prior
hardware test, release it explicitly before retrying reset.

The persistent server is supervised by `mesh-init` from
`docs/lab/recovery-tcp-server.toml`. Install that definition in the active
mesh-init service directory; it runs `fw/recovery/tools/flash-server.py` in the
foreground and restarts it automatically.

For the lab host's Recovery network, configure the lmesh mesh-init service
with `LMESH_AP_AUTOSTART=1`, `LMESH_AP_IFACE=wlan0`,
`LMESH_AP_ADDRESS=10.78.0.1/16`, and `LMESH_AP_NETWORK=10.78.0.0/16`.
lmesh then owns the address, route, and open MAC-derived
`Direct-XXXXXXXX-Dmesh-local` AP on every restart. Do not run a separate
hostapd. `fw/recovery/tools/recovery-bootstrap-ap.toml` remains a route-only
fallback for hosts that have not yet deployed the lmesh settings.

The server's default command is intentionally parameter-free:

```sh
fw/recovery/tools/start-server.sh start
```

It listens on `10.78.0.1:3336` and uses Main as the compatibility default.
New Main clients identify the requested resource in the DRS2 HELLO, so the
same listener can serve CPU-specific Main, Recovery, stage2, data, and named
`hello`/`lora` modules. Recovery itself always requests Main. Server logs are
in `target/recovery-server/all-3336.log`; per-device state is in
`target/flash-devices/<mac-without-colons>/`.
