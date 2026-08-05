# DMesh Recovery and flash design

Stage2 is a minimal boot supervisor. Recovery is the smallest image including
ESP-IDF Wi-Fi, TCP, NVS, and flash APIs. Main is reusing the same flash protocol and the code as a library to flash recovery, stage2, modules. 

## Status

Most of the testing and development is with the unsigned blobs - it is faster.

The signed images are in progress - basic P-256 and block verification are implemented but not the image version and anti-rollback, tools to generate/sign
images offline - or extensive testing on the crypto side.

## Component boundary

```text
Main
  - decides whether and when to update
  - writes the Recovery request
  - may use the shared worker to flash anything but itself.

stage2
  - selects Recovery or Main - based on reboot count, UART in dev.

Recovery
  - loads transport settings and trust key from NVS
  - joins an open (no password) Wi-Fi as a station
  - connects to the host flash server by IP:port
  - receives and applies (signed) blobs
  - reboots

host flash server
  - identifies chip/flash/MAC from HELLO
  - reads and validates the device partition table
  - selects the matching artifact below target/flash
  - signs or explicitly bootstraps the manifest
  - records per-device evidence
```

The shared implementation is owned here at
`fw/recovery/transport/dmesh_flash_tcp/`. It is compiled directly into
Recovery and imported by Main's native CMake component. The transport includes
only ESP-IDF/lwIP/mbedTLS/NVS interfaces; it does not include or link against
the mesh application. This keeps `fw/recovery` movable to another repository.
Main's CMake integration defaults to the in-tree path and accepts
`DMESH_RECOVERY_TRANSPORT_DIR` when the transport is supplied by a separate
checkout or vendored dependency.

The library connects to the open AP, starts an TCP outbound connection;
the signed manifest supplies the actual blocks.

There is no HTTP, HTTPS, MQTT, BLE, filesystem, compression, OTA-data state,
or package manager in Recovery.

## Normal update flow

The long-running host process is `fw/recovery/tools/flash-server.py`. With no arguments it serves CPU-selected resources from `target/flash`, listens on
`10.78.0.1:3336`, keeps accepting devices, and enables unsigned-fast only for
devices reporting no trust key. 

Clients put the requested target in the extended HELLO, allowing one server to serve Main, Recovery, stage2, and named modules. A missing selector falls back to
 Main for compatibility.

The artifact layout is `target/flash/<cpu>/`, for example
`target/flash/esp32/main-app.bin`, `recovery.bin`, and `bootloader.bin`.
Named module lookup first checks the matching CPU directory and then the
older shared `target/modules/<rust-target>/` layout. The selector extension is
reserved for future signed configuration/resource blobs without requiring
another TCP listener.

That lab service does not currently provide a signing key. Once a device trust
key is provisioned, the service must be configured with the corresponding
private signing key or the device will correctly reject its manifests.

The normal control action is:

```sh
fw/recovery/tools/flash-main-command.py <lmesh-role>
```

Network defaults live in `target/flash-devices/network.json`. A saved SSID is
put into the NVS request, avoiding a scan on every update. An absent SSID is a
fallback that makes Recovery scan for the first open `Direct-*-Dmesh` network.
The server defaults to `10.78.0.1`, the port to `3336`, and an absent local
address to `10.78.<MAC[4]>.<MAC[5]>` with a `/16` mask. 

Recovery is intentionally open-STA only, to keep image small and avoid connecting
to 'real' networks or seeing passwords. The device and the flash server are both
completely untrusted. There is no point to use wireless encryption for an image
that is not encrypted and can be extracted from the device.

The security is based on signing the image manifest, including the list of block
SHA. We do not sign the entire image because the device can't load it all in
memory - and we may support incremental updates where only modified blocks are 
sent.

Human-facing flash tools use the managed direct lmesh forward by default and
load the saved SSID, netmask, and board address from
`target/flash-devices/network.json`. The Main control-plane request carries
the netmask through to its static STA setup; this matters for the lab's
`10.78.0.0/16` network when a device address is in another third-octet
subnet, such as `10.78.84.60`. NAN-gateway routing is experimental/WIP and is not used for routine flashing.

Recovery retries association in 30-second windows with a short delay between
windows. It remains in Recovery while the AP is absent. After association, the
flash worker retries the numeric IPv4 server for 30 seconds at 200 ms intervals.
Hostnames, DHCP policy, AP mode, and IPv6 are not part of the minimal path.

## Flash framing

TCP carries raw length-prefixed frames:

```text
u32 magic  = 0x44525332 ("DRS2")
u16 type
u16 payload_length
u8  payload[payload_length]
```

Integers are network byte order. TCP supplies ordering, retransmission, and
flow control; DRS2 supplies message boundaries. No PPP framing is used on TCP.
The maximum frame payload is 65,535 bytes and the current flash block is 4,096
bytes.

The device speaks first:

```text
device -> HELLO
host   -> READ_PARTITION_TABLE
device -> PARTITION_TABLE
... mode-specific negotiation and blocks ...
host   -> DONE
device -> DONE or ERROR
```

HELLO reports chip model/revision, MAC, CPU/crystal frequency, flash size,
DRAM/PSRAM totals, device role/partition, trust-key presence, and the SHA-256
fingerprint of the exact 65-byte uncompressed SEC1 P-256 public key.

New clients append an 18-byte HELLO extension: the target id and an optional
ASCII resource name. The server uses it to select the requested blob for that
connection. Recovery always sends `main`; Main may request `recovery`,
`stage2`, `partition`, `data`, or `module` plus a name such as `hello` or
`lora`. Old 69/71-byte HELLO messages remain valid and use the server's Main
default. The extension is intentionally the resource-selection point for
future signed configuration blobs; they do not require a second listener.

Supported targets are raw stage2/boot, raw partition table, Recovery, NVS,
data, and Main. `READ_BLOCK`/`BLOCK_DATA` are reserved diagnostic frames.
Unknown or malformed frames fail the session.

## Transfer modes

### Compatibility manifest

```text
HASH_QUERY  -> HASH_LIST
MANIFEST    -> MISSING bitmap
BLOCK ...
HASH_QUERY  -> HASH_LIST
DONE        -> DONE
```

The manifest contains target, offset, 4 KiB geometry, image size, partition
table SHA-256, full image SHA-256, trust-key fingerprint, and one 32-bit
truncated SHA-256 per block. Its P-256 signature covers all those fields and
hashes. Recovery reports missing blocks, verifies each received block before
erase/write, reads it back, and verifies the final full-image SHA-256.

New peers set a manifest flag that suppresses per-block ACKs. The host streams
all selected blocks, TCP flow control limits outstanding data, and one final
`DONE` completes the transfer. `--per-block-acks` remains available for older
Recovery images.

### Sparse manifest extension

```text
HASH_QUERY       -> HASH_LIST
SPARSE_MANIFEST  -> MANIFEST_READY
BLOCK ...
HASH_QUERY       -> HASH_LIST
DONE             -> DONE
```

The signed manifest carries only changed offsets, lengths, and truncated
hashes. Once the complete manifest is authenticated, Recovery pre-erases the
listed sectors, accepts only listed blocks, verifies each block before writing,
reads it back, and performs the full-image check. A power loss after pre-erase
can leave Main incomplete, but the persistent request brings the next boot
back to Recovery.

### Unsigned-fast bootstrap extension

```text
FAST_UNSIGNED -> FAST_READY
BLOCK ...
DONE          -> DONE
```

This mode is accepted only when no trust key is present. It sends every block
and skips initial hashes, per-block hashes/readback, and final SHA verification.
It is a speed-oriented development/factory path, not an authenticated update.

Current weakness: the receiver does not track that every expected block was
received exactly once before accepting `DONE`. A buggy or hostile host
can therefore cause a partial image to be treated as success and clear the
request. The device will need to check the SHA of each block it has against the
manifest before considering the upgrade complete.

Also missing/WIP is a protection against reboot selecting an incomplete main.

## Authentication and trust

The trust root is NVS blob `recovery/trust_key`, exactly 65 bytes, beginning
with SEC1 uncompressed-point byte `0x04`. Malformed key data fails closed.

For keyed devices:

- HELLO reports the key fingerprint;
- the host manifest fingerprint must match;
- P-256 ECDSA over SHA-256 is mandatory;
- blocks must match the authenticated digest list;
- the final image must match the authenticated full SHA-256.

For unkeyed devices, compatibility and sparse manifests with an all-zero key
fingerprint are also accepted unsigned; unsigned-fast is not the only unsigned
form. This is deliberate bootstrap behavior in the current code.

The 32-bit per-block hashes are not a sufficient independent security level.
The signed full-image SHA-256 prevents a modified complete image from being
accepted, but a hostile transport can feasibly search for a block with the same
32-bit prefix, cause destructive writes, and force the final check to fail.
That is an availability attack rather than a successful authenticated install.
Use at least 128-bit block digests in the next protocol version.

There is no anti-rollback counter or freshness token. An attacker able to
serve an older correctly signed manifest can replay it. Rollback resistance
is required, but still WIP, will be added after the rest of the protocol works.

The protections are for distributing updates over untrusted flash servers and Wifi,
not for physical access. 

It is technically possible to blow the JTAG fuses and encrypt the 2stage, and
have 2stage check the signature of the main and recovery. That can protect the 
device from modifications to some extent, but would not make it a trusted device,
it's just a modem and controller.

## Target permissions and self-update

The intended matrix is:

| Running image | Allowed routine target |
|---|---|
| Recovery | Main only |
| Main | Recovery; optionally data/NVS |
| factory/emergency flow | stage2 and partition table over UART/esptool |

Main correctly rejects `target=main` at its Rust command surface. The current
client now sends the requested target in the extended HELLO, and the host
selects the matching CPU-specific blob before sending a manifest. The device
still validates the manifest target and partition range; a future hardening
step should advertise and enforce an allowed-target mask before erase.

Updating Recovery from Main is reasonable because Main remains bootable if the
Recovery write fails. Updating stage2 is qualitatively different: ROM has one
fixed bootloader location and there is no rollback copy. A power failure during
that write can require physical UART flashing. Keep remote stage2 updates rare,
signed, power-qualified, readback-verified, and operationally separate from
routine Main updates.

## Request and completion semantics

Main writes request marker version/magic plus SSID, password, server, local IP,
port, URL placeholder, and flags into namespace `recovery`, commits, and
reboots. Stage2 reads only the marker. Recovery loads transport values.

On success Recovery:

1. receives device-side `DONE` from the shared worker;
2. clears `request_magic`, `request_version`, and `flags` but retains transport
   defaults;
3. writes RTC `RECOVERY_OK`;
4. reboots.

Any network, framing, signature, range, erase, write, readback, or final-digest
failure leaves the request marker intact. No NVS write occurs per block.

## Size and performance

Current minimal release artifacts:

| chip | Recovery binary | partition | free |
|---|---:|---:|---:|
| ESP32 | 634,176 (`0x9ad40`) | `0xd0000` | 217,792 bytes |
| ESP32-S3 | 634,032 (`0x9acb0`) | `0xd0000` | 217,936 bytes |

The majority of the footprint is ESP-IDF Wi-Fi, PHY, TCP/IP, and WPA-related
vendor libraries even though the configured network is open. HTTP, TLS, AP
mode, filesystem, and CBOR are absent. Reimplementing the application in Rust
does not remove those vendor libraries; C remains the smaller active Recovery.

Observed full Main rewrites are generally about 22-29 seconds for roughly
1.6 MB with unsigned-fast/no-per-block-ACK operation. The earlier verified
sparse full rewrite on E5 took 35.446 seconds; the earlier unsigned-fast test
took 29.327 seconds. Sparse transfer is valuable when blocks actually match,
not when every build changes most blocks.

## Host state and evidence

The server chooses artifacts from `target/flash/<chip>-<flash-size>/` and
archives state under `target/flash-devices/<mac>/`:

- `device.json` and raw HELLO;
- partition table and optional captured NVS;
- `flashes/*.json` and `flash-history.jsonl`;
- current image and block hashes;
- last observed Recovery IP.

The selected artifact is snapshotted before negotiation; the server checks its
inode, size, and modification time before and after reading, retrying briefly
if a build is replacing it. Its full SHA-256 is written into the flash session
record before the first block is sent. A concurrent build therefore cannot
silently change the bytes of an in-progress transfer or make its evidence
ambiguous.

The saved network defaults are in `target/flash-devices/network.json`. Server
logs are under `target/recovery-server/` when the wrapper is used; managed UART
logs are under `target/lmesh-radio-build/log/`.

## High-value improvements

In priority order:

1. Enforce an exact allowed target in the device worker before any erase.
2. Require complete, non-duplicate block receipt in unsigned-fast before
   accepting `DONE`; retain a cheap final readback/hash if practical.
3. Add a protected provisioned latch so trust-key absence fails closed after
   factory provisioning.
4. Introduce DRS2 version/capability/target negotiation. This enables one
   long-running port without guessing the intended target and avoids behavior
   flags hidden in reserved bytes.
5. Expand authenticated block hashes from 32 bits to at least 128 bits and
   track received indices in every mode.
6. Add socket receive/send timeouts and explicit protocol error codes so a
   stalled host cannot pin Recovery indefinitely and logs identify the failed
   invariant.
7. Add optional signed generation/anti-rollback enforcement where products
   require it.
8. Validate image chip/header/entry metadata before final success. This does
   not replace signatures; it catches selecting a validly signed wrong artifact.
9. Make key rotation atomic and separately authorized; do not expose arbitrary
   NVS replacement as the trust-key update mechanism.
10. Add device-side protocol tests for malformed lengths, duplicate/out-of-order
    blocks, early DONE, target mismatch, power loss at each erase/write stage,
    bad partition-table digest, bad key, replay, and reconnect.

## Long-term options

- Store a compact digest index in the final sector of each updatable partition.
  The device can return it immediately, the host can send a signed replacement,
  changed blocks follow, and the new index commits last. This can also support
  bounded stage2 verification. The current layouts do not reserve this sector.
- Add A/B Recovery on flash-rich boards if remote Recovery upgrades become
  common. Keep one Recovery slot on 4 MB devices unless field data justifies the
  space cost.
- Use ESP secure boot and flash encryption for a production chain of trust.
  DRS2 authenticates update input but cannot protect an unsigned stage2 already
  replaced in flash.
- Consider an immutable boot shim only if remote stage2 upgrades are truly
  required. Otherwise manual/provisioning-only stage2 updates are simpler and
  safer.
- Keep DRS2 focused on bounded flash/diagnostic operations. Reusing framing is
  useful; turning Recovery into a general remote command server would expand
  the permanent attack surface and violate the component boundary.
- ESP8266 support remains deferred and requires a separate size/layout/SDK
  evaluation rather than conditional compilation of this ESP32 design.

## Verdict

This is not a bad idea; it is a good architecture with an intentionally small
policy surface and a proven Wi-Fi data path. The bad version of this idea would
put Wi-Fi and update policy into stage2, rely on OTA selection state, or permit
the shared worker to write arbitrary targets. Keep the split, harden the three
critical invariants above, provision trust roots, and resist growing Recovery
into a second product firmware.
