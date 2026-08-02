# DMesh Recovery

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

```text
Main command -> stage2 -> Recovery -> flash-server.py -> Main partition
                                      |
                                      +-> reboot -> stage2 -> Main
```

The design is sound and the Wi-Fi path has repeatedly updated ESP32 and
ESP32-S3 boards. Current deployment is still bootstrap-grade: fleet devices do
not yet have trust keys and the default server uses unsigned-fast for unkeyed
devices. See [DESIGN.md](DESIGN.md) for the exact security properties and the
priority hardening list.

## Normal operation

`fw/recovery/tools/flash-server.py` is the long-running host service. With no arguments
it serves chip-specific Main images from `target/flash` on
`10.78.0.1:3336` and keeps accepting connections. The mesh-init definition is
`docs/lab/recovery-tcp-server.toml`.

For a systemd host, the on-demand units are next to the tools:
`fw/recovery/tools/flash-server.socket` and `flash-server.service`. Start the
socket explicitly with `systemctl start flash-server.socket`; neither
unit is boot-enabled. The socket listens on TCP port 3336 and activates the
server only when a Recovery connection arrives.

The checked-in lab service has no private signing key configured. It serves the
current unkeyed fleet; keyed devices will fail closed until that service is
given the corresponding `--signing-key` configuration.

Start an update through Main with only the logical board role:

```sh
fw/recovery/tools/flash-main-command.py e5
```

The script reads `target/flash-devices/network.json`. The saved SSID is written
to the Recovery request so normal updates do not scan. If no SSID is saved,
Recovery falls back to scanning for an open `Direct-*-Dmesh` AP. Server and
port default to `10.78.0.1:3336`; local IP defaults to
`10.78.<MAC[4]>.<MAC[5]>`.

The control command currently travels through managed lmesh. The image data is
Wi-Fi/TCP only. Do not stop lmesh forwarding during the Wi-Fi transfer; it is
useful for serial evidence. USB/esptool is for first provisioning or emergency
repair, not routine Main updates.

## Build and measured size

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

- compatibility manifest plus missing-block bitmap;
- signed sparse changed-block manifest;
- explicit unsigned-fast full transfer for an unkeyed device.

Blocks are 4 KiB. New builds stream blocks without per-block ACK round trips
and finish with one `DONE`. Verified modes authenticate a P-256-signed manifest,
check received blocks, read back writes, and verify the full image SHA-256.
Unsigned-fast deliberately skips those checks and must remain a bootstrap path.

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

Recovery clears only the one-shot request marker after the device reports a
successful DRS2 session. Transport settings remain in NVS for later updates.
Failures leave the marker set. Wi-Fi association retries in 30-second windows,
and TCP connection retries for 30 seconds per attempt.

Unsigned-fast currently needs an additional received-block bitmap: an early
`DONE` can otherwise mark a partial unkeyed transfer successful. This is a
known high-priority reliability fix.

## Logs and evidence

- per-device state: `target/flash-devices/<mac>/`
- saved network defaults: `target/flash-devices/network.json`
- flash service logs: `target/recovery-server/`
- managed serial capture: `target/lmesh-radio-build/log/serial.log`
- USB provisioning/emergency incidents: `target/evidence/flash/`

Each per-device directory includes HELLO/device metadata, the observed
partition table, flash session JSON, image hashes, last observed Recovery IP,
and captured NVS when provisioning tools fetched it.

## Current recommendation

Keep this architecture and keep Recovery small. Before production use:

1. pin the allowed flash target in the device API;
2. make unsigned-fast completion strict;
3. add a protected provisioned latch and provision P-256 keys;
4. increase per-block authenticated digests and add protocol capability/version
   negotiation;
5. test power loss and malformed sessions on real boards.

The detailed rationale, wire behavior, security caveats, measurements, and
long-term alternatives are in [DESIGN.md](DESIGN.md).
