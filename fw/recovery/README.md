# DMesh Recovery

*This is in process of replacement with a Rust recovery using the same code as Main,
i.e. QUIC-lite over multiple datagram transports instead of TCP *

The normative Recovery UART, event, and manifest-extension contract is
[API.md](API.md). This README is operational/build guidance only.

The main idea is to use the 'control plane' pattern for flash updates. Instead of
using signed images we sign blocks that fit in a low-end device RAM and can be
verified independently. The 'control plane' sends first a signed list of blocks SHAs,
followed by each block - device verifies the EC-256 signature based on the provisioned root key and verifies and writes each block.

The protocol can read and write any region of the flash - the device is not trusted
but the control plane signature is. Initial implementation lacks some elements (version and anti-rollback, etc) and the main use is to flash remote devices over wifi, but it'll eventually converge with the generic mesh control plane protocol. 
 
Recovery is the minimal C ESP-IDF application that updates Main when selected
by the custom second-stage bootloader. It owns open-STA Wi-Fi, one TCP
connection, DRS2 parsing, optional P-256 verification, flash writes, request
clearing, and reboot. It contains no product update policy.

The shared flash transport is owned by
`fw/recovery/transport/dmesh_flash_tcp/`. Main imports that platform-only C
source through its native CMake component; Recovery has no dependency on the
mesh application. This is intentional so the Recovery/stage2 tree can move to
a separate repository later. Main's default import path is in-tree, and can be
overridden for a split checkout with `DMESH_RECOVERY_TRANSPORT_DIR`.

The transport is a signed object-store control plane, not just a firmware
flasher. Its negotiated target identifies the signed object being installed;
today those objects include Main, boot/recovery images, and named modules, and
the same protocol is intended to carry signed configuration snapshots and
larger data objects. Main remains responsible for deciding when an object is
safe to apply (including quiescing a module before erasing its mapped region).

The object identity, replace/append/resume commit policies, replay rules, and
the DRS2 extension boundary are defined in
[`OBJECT_STORE.md`](OBJECT_STORE.md). Keep this document as the operational
flashing guide; use that document when adding configuration or data objects.

An object is addressed by a stable type/name/version tuple, with a declared
length and SHA-256 digest. The manifest signature authenticates that tuple,
the digest, and the ordered block list; blocks are transport chunks, not
independent authority. Configuration and data objects use the same verified
write path as images, but their commit policy is selected by Main (for example
atomic replacement for a settings snapshot or append/resume for a data
object). Receivers must reject an invalid signature, digest mismatch,
unsupported type, or stale version before exposing an object to a module.

```text
Main command -> stage2 -> Recovery -> flash-server.py -> Main partition
                                      |
                                      +-> reboot -> stage2 -> Main
```

## Normal operation

`fw/recovery/tools/flash-server.py` is the long-running host resource service.
With no arguments it serves CPU-specific blobs from `target/flash` on
`10.78.0.1:3336` and keeps accepting connections. New Main clients identify
the requested resource in HELLO, so one listener can serve Main, Recovery,
stage2, and named modules; older clients use Main as the default. The
mesh-init definition is
`docs/lab/recovery-tcp-server.toml`.

For a systemd host, the on-demand units are next to the tools:
`fw/recovery/tools/flash-server.socket` and `flash-server.service`. Start the
socket explicitly with `systemctl start flash-server.socket`; neither
unit is boot-enabled. The socket listens on TCP port 3336 and activates the
server only when a Recovery connection arrives.

The lab host AP and route can be bootstrapped with
`fw/recovery/tools/bootstrap-ap-route.sh`. The preferred deployment installs
`docs/lab/lmesh-wifi.toml` and sets `LMESH_INTERFACES=wlan0` (or the host's
owned AP interface). `lmesh-wifi` owns the open AP on every service start.
With no environment overrides it uses
its MAC-derived `Direct-XXXXXXXX-Dmesh-local` SSID, which Recovery can find.
The corresponding mesh-init definition is
`fw/recovery/tools/recovery-bootstrap-ap.toml`; install it only on the host
that owns the AP interface. The script does not run hostapd itself, so lmesh
remains the AP owner. Optional overrides are `DMESH_RECOVERY_AP_IFACE`,
`DMESH_RECOVERY_HOST_IP`, `DMESH_RECOVERY_NETWORK`, and
`DMESH_RECOVERY_AP_SSID`.

The checked-in lab service has no private signing key configured. It serves the
current unkeyed fleet; keyed devices will fail closed until that service is
given the corresponding `--signing-key` configuration.

Start an update through Main with only the logical board role:

```sh
scripts/flash-device.py e5 main
```

The script reads `target/flash-devices/network.json`. The saved SSID is written
to the Recovery request so normal updates do not scan. If no SSID is saved,
Recovery falls back to scanning for an open `Direct-*-Dmesh` AP. Server and
port default to `10.78.0.1:3336`; local IP defaults to
`10.78.<MAC[4]>.<MAC[5]>`.

The control command currently travels through managed lmesh. The image data is
Wi-Fi/TCP only. This is a deployment requirement: remote devices may no longer
have a USB connection, so Main -> Recovery and Recovery -> Main upgrades must
remain Wi-Fi-only. Do not stop lmesh forwarding during the transfer; it is
useful for serial evidence. USB provisioning is only first provisioning or P0 repair
of stage-2/Recovery, never a fallback for a failed remote Main update.

## Managed UART and Recovery test commands

All UART, reset, and stage2 tests use the same lmesh control socket. The
Python tools never open `/dev/tty*` themselves and use saved defaults from
`target/flash-devices/network.json`:

Starting or restarting a lmesh forward never pulses RTS and never enters the
bootloader. Linux may assert DTR/RTS while opening a CP210x tty; lmesh
normalizes both together to the released/normal state so a transient line
combination cannot select reset or ROM bootloader. Only an explicit managed
reset pulses RTS, and DTR remains reserved for separately requested hardware
tests.

To send a normal firmware command or read status, use the mesh CLI. It keeps
sleepy devices on the NAN active-window path:

```sh
source ./env.sh
mesh lmesh-uart esp.serial.command port=lora4 command=status
```

When `timeout_sec` is omitted, lmesh uses a 3-second response budget after
the command is sent. Sleepy targets are reached automatically across two NAN
wake windows with an 8-second rendezvous budget, for a default maximum of
about 11 seconds. `active_ms` is not needed for ordinary commands.

The flash helpers do not open a UART or use DTR.  Use the mesh CLI for an
individual status/reset diagnostic, and use `scripts/flash-device.py` for a
complete Main update.  The complete update performs the status preflight,
writes the Recovery request, explicitly reboots through the managed forward,
verifies the resulting Main image transfer on the server, and waits for the
rebooted Main image to answer a fresh status request.  It therefore does not
require a separate reboot, stage2, or reflash command.

`reset` requires a lower post-reset Main uptime; an lmesh ACK alone is not
reset evidence. `stage2` requires the framed CBOR boot identity and sends the
selector immediately through the managed forward. `recovery-sta` is separate
so a failed Recovery handoff can be diagnosed without another reset. Use
`scripts/flash-device.py` for a complete local update and verification, and
post-reboot Main status.
The normal command runs the same read-only preflight automatically before any
reset or Recovery handoff; use `--check` when only that preflight is wanted.
Status uses the managed `port=` path by default, which queues
sleepy-node commands until a UART heartbeat; pass `--direct` only when the
board is known to be awake. `--direct` marks only that client connection for
immediate delivery; it does not change the forward's default sleepy-node
policy. For a sleepy board where only the reset request
should be issued, use `reset --no-verify`; otherwise give `reset` a timeout
long enough to span its UART heartbeat.

If a bounded status/command timeout occurs, the tool prints the forward's
drop, reset, queue, and wake counters. A running forward with zero client
drops and increasing wake counters indicates a sleepy-window miss; it does
not justify an immediate reset or USB flash.

The reset implementation changes RTS only. It first checks that DTR is
released, waits for the managed forward to report an executed pulse, and
leaves the forward alive if the pulse is rejected. `reset --no-verify` skips
the Main status preflight but still verifies that lmesh executed the pulse.
Use the explicit `dtr --release` hardware test only when a bridge line was
previously asserted; DTR is otherwise not touched by flashing or reset.

The same helper exposes the remaining managed UART operations used in lab
work: `command`, `handshake`, `list`, `devices`, `forward-start`, `forward-stop`, and
`boot`. Normal forward lifecycle remains owned by mesh-init; use the manual
start/stop commands only for a deliberate lab override. `dtr` is an explicit
hardware experiment and may reset or strap a board; it is never part of status,
flashing, forward startup, or Recovery. No operation in this script opens a
UART device directly.

Named modules use the same negotiated server through the Python verifier:

```sh
scripts/flash-device.py lora4 module --module lora
```

The module command now targets the Rust lmesh object/DRS2 server at
`10.78.0.1:3337` by default. Main image updates still use the legacy Python
compatibility server on port 3336 during the migration. Use `--gateway` and
`--port` to select another endpoint deliberately.

It waits for a completed `target=module` record. The server selects the
CPU-specific artifact: `target/modules/xtensa-esp32s3-espidf` for S3 and
`target/modules/xtensa-esp32-espidf` for classic ESP32. Do not hand-copy a
module between those ISA directories.

Module updates are hot updates. Main asks the loader to stop the module task
before Recovery erases the mapped data region, but Main itself is not rebooted.
After a successful transfer, the next explicit `module op=run` refreshes the
DMOD header and maps the new image. A reboot is only needed if Main or the
managed transport is independently unhealthy.

The managed flashing reliability can be exercised periodically without
executing the module. The default canary uses the hardware module on sleepy
`lora4`; each cycle records the pre-flash mode, first/fallback path, transfer
SHA, block count, and latency in an append-only JSONL file:

```sh
source ./env.sh
python3 fw/recovery/tools/flash-reliability-test.py \
  --role lora4 --module hw --count 3 --interval-sec 60
```

This is a transport/recovery test only. It must remain part of the normal
flash validation process, and feature work should not replace or bypass its
managed lmesh/NAN path.

Before an authorized canary or fleet update, run the read-only Main-flash
preflight:

```sh
mesh lmesh-uart usb.serial.forward.list
```

It verifies the saved board entry, managed forward, server listener, and both
CPU-specific Main artifacts, including their sizes and SHA-256 values. It does
not reset or send a firmware command.

The Python tools use the managed direct lmesh forward by default and load the
saved SSID and board address from `target/flash-devices/network.json`. NAN
gateway routing is experimental/WIP and is not used by normal flashing.

Recovery must never update `recovery_app` while executing from that partition.
The transport rejects that target in the Recovery build before any manifest or
erase operation. Main, executing from `main`, is the only updater for
Recovery and stage-2; Recovery updates Main and other non-self targets.

## Build and measured size

Run the offline flash-helper regression before changing the host protocol or
handoff logic:

```sh
python3 -m unittest fw/recovery/tools/test_flash_tools.py
```

It covers the important late-success case where Recovery creates a failed
intermediate TCP record before a later retry succeeds. Runtime verification
still requires the managed lmesh forward and the server-side per-device
transfer record.

```sh
scripts/build-recovery-fleet.sh all
```

Both chip builds use the same 4 MiB partition table from
[`../boot/partitions.csv`](../boot/partitions.csv). The final 256 KiB, labelled
`data`, is reserved for shared future use and is ignored by the current Main
image. Larger physical flash is intentionally outside the Recovery layout.

| chip | Recovery binary | `0xd0000` partition free |
|---|---:|---:|
| ESP32 | 634,176 bytes | 217,792 bytes |
| ESP32-S3 | 634,032 bytes | 217,936 bytes |

Artifacts are written under `target/recovery-fleet/<chip>/` and published under
`target/flash/<chip>-<flash-size>/` for the shared server. The Rust Recovery
prototype remains for comparison; the active image is C because ESP-IDF's
Wi-Fi/vendor libraries dominate both builds and C is smaller.

## Protocol summary

DRS2 is a device-first, length-prefixed protocol over TCP. The device sends its
chip, flash size, MAC, partition role, and trust-key fingerprint. The host reads
the partition table, selects a matching image, and negotiates one of:

- one authenticated manifest followed by the complete block stream.

Blocks are 4 KiB. The manifest contains the expected truncated SHA-256 for
each block and is the first frame after HELLO. Recovery hashes only incoming
TCP block payloads against that manifest, then reads each written block back
and compares the bytes with the received payload; it does not pre-hash the
target or send a hash list. P-256 authenticates the
manifest when a trust/signing key is present, with TOFU allowed for an unkeyed
device. TCP flow control paces the stream and there are no per-block ACKs. The
host emits a small `FLOW_PULSE` frame after every four blocks; Recovery and
Main consume it without replying, so it is only a packetization diagnostic and
does not add another acknowledgement protocol. Recovery also emits a small
`PROGRESS` frame after every 64 accepted blocks. The host drains these frames
while waiting for the terminal `DONE`; its payload is three network-order
`u32` values containing the accepted-block count, device elapsed milliseconds
since session start, and cumulative device block-processing milliseconds. The
third value covers SHA validation and, for a real flash, erase/write/readback
work; it does not include time waiting for TCP input. The host does not wait
for an individual progress frame or use it for pacing. This sparse return diagnostic keeps the flash path independent
of the diagnostic socket direction; the host-side `FLOW_PULSE` still marks
every four-block group.

The manifest flags byte has bit 0 `DRY_RUN`. The device-side recovery/Main command sets `dry_run=true`; Recovery then receives and
validates every block and the complete bitmap but performs no erase, write, or
flash readback. This provides a transport/hash baseline without changing the
device image. The server has no dry-run mode of its own and stays running for
later connections. The direct Recovery form is `cmd:STA <server:port>
<local-ip> <ssid> dryrun`; the Main form adds `dry_run=true` to the recovery
command that starts the protocol.

The trust key is the 65-byte uncompressed P-256 point in NVS key
`recovery/trust_key`. No provisioned fleet key means no authenticated-update
claim should be made yet.

## Supported targets

The shared worker knows Main, Recovery, stage2/bootloader, partition table, NVS,
and data targets. Intended use is Recovery -> Main and Main -> Recovery.
Remote stage2 replacement is high risk because there is only one ROM-loaded
copy and no power-loss rollback.

Important current gap: the C worker does not yet bind a session to the target
authorized by its caller; the manifest can select any supported target. Fix
target pinning before treating authenticated DRS2 as a production boundary.

## Completion and retries

Recovery switches the RTC selector to Main only after the device reports a
successful DRS2 session. Transport settings are runtime-only. Failures keep
the RTC selector on Recovery. Wi-Fi association retries in 30-second windows,
and TCP connection retries for 30 seconds per attempt.

The direct manifest path requires exactly one block for every manifest entry
before accepting `DONE`; duplicate and out-of-range block indexes are errors.

## Logs and evidence

- per-device state: `target/flash-devices/<mac>/`
- saved network defaults: `target/flash-devices/network.json`
- flash service logs: `target/recovery-server/`
- managed serial capture: `$HOME/logs/<device>.log`
- USB provisioning/emergency incidents: `target/evidence/flash/`

Each per-device directory includes HELLO/device metadata, the observed
partition table, flash session JSON, image hashes, last observed Recovery IP,
and captured NVS when provisioning tools fetched it.

## Current recommendation

Keep this architecture and keep Recovery small. Before production use:

1. pin the allowed flash target in the device API;
2. add a protected provisioned latch and provision P-256 keys;
3. test power loss and malformed sessions on real boards.

The detailed rationale, wire behavior, security caveats, measurements, and
long-term alternatives are in [DESIGN.md](DESIGN.md).
