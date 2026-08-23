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
scripts/build.sh transport-test
scripts/build.sh object-store-test
python3 -m unittest scripts.test_recovery_udp scripts.test_flash_device
```

These are the supported host gates for the Recovery transport, object
verification, and flasher orchestration. They do not open UART, reset a board,
or flash hardware. Host success is required before a firmware build or device
test, but it is not proof that a device update completed.

## Interactive transport test sessions

Use one shared `tmux` session named `dmesh` for live firmware and bearer
testing. It keeps the build, direct UART diagnostic output, and individual test
commands visible and attachable from another terminal. Test scripts may require
`tmux` for this reason; do not replace these long-running checks with
backgrounded shell jobs. A device owns at most one `DEVICE.uart` window, which
prevents competing watchers or CLIs from opening the same serial port.

```sh
cd "$(git rev-parse --show-toplevel)"
session=dmesh
tmux new-session -d -s "$session" -n build
tmux send-keys -t "$session":build 'source ./env.sh && scripts/build-fw.sh e6' Enter

# Naming convention: build, DEVICE.uart, DEVICE.udp, and matrix.DESCRIPTION.
# DEVICE.uart is interactive: it renders UART diagnostics and accepts commands
# on stdin (status, services, log-watch 8, metrics, events, control,
# iperf 65536, quit) without a second serial owner.
tmux new-window -t "$session" -n e6.uart
tmux send-keys -t "$session":e6.uart \
  'source ./env.sh && target/debug/dmesh-cli /dev/serial/by-id/<e6-serial> --watch --interactive --timeout-secs 300' Enter

# Run stream requests and throughput checks in separate windows. Substitute
# a serial path or udp://<device-ip>:3339; both use the same stream services.
tmux new-window -t "$session" -n e6.udp
tmux send-keys -t "$session":e6.udp \
  'source ./env.sh && target/debug/dmesh-cli udp://10.78.0.101:3339 --service status' Enter
tmux new-window -t "$session" -n e7.udp
tmux send-keys -t "$session":e7.udp \
  'source ./env.sh && target/debug/dmesh-cli udp://10.78.0.102:3339 --log-watch' Enter

tmux attach -t "$session"
```

From any other terminal, observe the same live session with `tmux attach -t
dmesh`, inject a stream command into the sole e6 UART owner, or inspect a pane
without attaching:

```sh
tmux list-windows -t dmesh
tmux send-keys -t dmesh:e6.uart 'status' Enter
tmux send-keys -t dmesh:e6.uart 'log-watch 8' Enter
tmux capture-pane -pt dmesh:e6.uart -S -120
```

Detach with `Ctrl-b d`; this leaves tests running. Stop a bounded lab session
only when its evidence has been captured: `tmux kill-session -t dmesh`. Use the
window naming convention rather than another session, so UART ownership and
captured logs stay attributable to one device.

The profile is `target/nix/profile`; `lmesh`, `mesh-tun`, and `dmeshtui` are
written to `target/x86_64-unknown-linux-musl/release/`. The generic `mesh` CLI
is built only by the sibling ssh-mesh workspace, at
`$DMESH_SSH_MESH_DIR/target/x86_64-unknown-linux-musl/release/mesh`. After
sourcing `env.sh`, that is the only `mesh` selected through PATH and
placed on `PATH`; `MESH_TOOLS` defaults to lmesh's
generated command catalog. The default `MESH_SERVICE_DIR` selects the installed
mesh-init service definitions. The `lmesh-uart` forwarding service is retired;
use `dmesh-cli` for a physical serial interface. `mesh` itself remains
service-independent, and callers can override `MESH_TOOLS` or
`MESH_SERVICE_DIR`.

### Managed Linux radio services

The privileged stable AP/radio service is `lmesh-wifi` on `wlan0`. `lmesh` is
the separate development/test service and normally uses `wlan1`; do not mix
their interfaces or UDP test endpoints. After sourcing `env.sh`, use the
ssh-mesh `mesh` client for operational RPC rather than invoking a service
binary directly:

```sh
# Read-only state useful before and after a firmware bearer test.
mesh lmesh-wifi wifi.ap.stations iface=wlan0
mesh lmesh-wifi wifi.rawnan.status iface=wlan0
mesh lmesh wifi.ap.stations iface=wlan1
```

Both are supervised by `mesh-init`. On this host its control socket is
`/run/mesh/mesh-init/mesh.sock`; the checkout environment can select another
run directory, so set it explicitly for supervisor calls:

```sh
export MESH_INIT_SOCK=/run/mesh/mesh-init/mesh.sock
mesh-init status lmesh-wifi
mesh-init status lmesh
```

Do not use `systemctl`, signal a service PID, or spawn an unsupervised
replacement. For a deliberately requested AP/reassociation test, perform a
controlled stop and start through the supervisor. `stop` is intentional and
does not automatically restart the service, so always issue the matching
`start` and capture station/recovery evidence:

```sh
mesh-init stop lmesh-wifi
mesh-init start lmesh-wifi
```

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
build details and
[notes/plans/main-recovery-transport-reuse.md](notes/plans/main-recovery-transport-reuse.md)
for the current transport/flashing migration.

The build scripts expose side-effect-free help and state their defaults:

```sh
scripts/build-fw.sh --help
scripts/build-stage2.sh --help
```

`scripts/build-fw.sh` builds Rust Main images; no argument means `all`. Pass
`e5`/`esp32`, `esp32s3`, or `e6`/`esp32c6` for one CPU family.
The C Stage2 builder also defaults to `all`. Main artifacts are under
`target/flash/` and Stage2 under `target/stage2/`.

Rust Recovery is frozen and low priority. `scripts/build-recovery-rust.sh`
fails deliberately; do not use it in current build or deployment workflows.
For a compile/size check only, set `DMESH_ALLOW_RECOVERY_BUILD=1`; this does
not make Recovery a supported deployment lane.

Current development and provisioning use the direct USB/esptool implementation
inside `flash-device.py`. Its target defaults to `main`:

```sh
scripts/flash-device.py <board>
scripts/flash-device.py <board> main
scripts/flash-device.py <board> module --module lora
scripts/flash-device.py <board> stage
scripts/flash-device.py <board> recovery  # emergency rollback only
```

Legacy UART byte forwarding is retired. Explicit USB provisioning opens only
the requested physical port for esptool's verified write; it neither starts
nor restores a service-owned serial forward. This is the current development
path for Main, Stage2, modules, and NVS. Wi-Fi Recovery is the
intended production Main-update path, but it is not the default flashing
transport in this checkout.

Raw UDP6 and raw ESP-NOW/action are current QUIC-lite bearers shared by Main
and Recovery. They use `dmesh-fw-transport` hardware glue and portable framing
from host-tested crates; they are not socket emulation or ESP-IDF ESP-NOW.
`lmesh-wifi` owns the privileged host AP/radio side. See
[notes/2026-08-18-c6-raw-udp6-espnow-results.md](notes/2026-08-18-c6-raw-udp6-espnow-results.md)
for exact C6 commands, rates, sizes, and known limitations.

All routine commands, logs, and object transfers use `dmesh-server` services
on QUIC-lite streams over an available L2 bearer. UART is one such L2 bearer;
it has no special command or logging role. Routine flashing uses
`scripts/flash-device.py`.
`--check <board>` probes only the selected direct USB port and reports its
chip. It does not contact a mesh service or open a runtime transport.

The persistent UDP object bearer is owned by the mesh-init-supervised
`lmesh-wifi` service; the flasher does not start or replace it.

### Shared Main/Recovery transport

The old C Recovery and `dmesh_flash_tcp` paths are retired. Main and Recovery
use the shared Rust transport, object verification, command/log services, and
flash sinks. UART, raw IPv6 UDP, and raw ESP-NOW/action are adapters for that
one stack. Both firmware images default to raw UDP6 plus ESP-NOW; there is no
DMesh lwIP socket-transport option. ESP-IDF may still link lwIP as an SDK
dependency.

Any reusable function without ESP-IDF or FreeRTOS dependencies belongs in a
host crate with tests. Main-only differences are application handlers,
sleepy-device hooks, and beacon synchronization/power policy. Treat other
Main/Recovery behavioral differences as bugs.

For the lab host's Recovery network, install the separate
`crates/lmesh-wifi/examples/mesh-init/lmesh-wifi.toml` mesh-init service and set its
`LMESH_INTERFACES` value to the AP interface, for example `wlan0`.
`lmesh-wifi` owns the open MAC-derived `Direct-XXXXXXXX-Dmesh-local` AP and the
shared raw-NAN monitor on `wlan0` at startup. Do not run a separate hostapd or
WPA/NAN control daemon. Use `mesh lmesh-wifi wifi.rawnan.status` and
`mesh lmesh-wifi wifi.rawnan.ping` for bounded host tests.

The frequently rebuilt experimental `lmesh` service is separate: its
`LMESH_INTERFACES` should be `wlan1`, and it starts the same raw-NAN monitor on
that interface. Restart it with `scripts/build.sh lmesh-restart`; restart the
stable AP service with `scripts/build.sh lmesh-wifi-restart`.
