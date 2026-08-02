# Recovery implementation plan

## Current status

The active implementation is the shared C DRS2 TCP path. It builds for E5
classic ESP32 and ESP32-S3, verifies P-256 manifests when a trust key exists,
supports explicitly unsigned provisioning when it does not, and performs
device-first sparse 4096-byte updates. The Rust prototype is retained under
[`../recovery-rust`](../recovery-rust) for comparison, but is not used.

The previous C image was 786,864 bytes on classic ESP32 and 783,504 bytes on
ESP32-S3. The new minimal profile is open-STA only; AP fallback, TCP-server
mode, password handling, HTTP, and DNS are excluded. If the SSID is omitted,
the profile performs one bounded scan for an open `Direct-...-Dmesh` AP. An
unconfigured request uses host `10.78.0.1`, port `3336` for classic ESP32 or
`3337` for ESP32-S3, and local `10.78.<MAC[4]>.<MAC[5]>`. Measured Recovery
the current classic ESP32 image is 632,336 bytes (`0x9a610`) within the
`0xd0000` app slot; the previously measured S3 image is 631,024 bytes. The E5
layout and USB stage2/Recovery provisioning have been exercised on hardware.

## Phase 1: shared ABI and host tests

- Define the bootloader-readable NVS request keys and version constants.
- Define the C callback interfaces for streams, keys, partitions, logging, and
  reboot state.
- Implement canonical record encoding/decoding and ECDSA P-256 test vectors.
- Add host tests for malformed records, invalid signatures, offset overflow,
  gaps, repeated sectors, and failed writes.

## Phase 2: second-stage bootloader

- Fork the ESP-IDF bootloader project into `fw/boot`.
- Add E5 GPIO configuration and three-second hold detection.
- Add NVS request reads through `nvs_bootloader_read()`.
- Add RTC-retained six-attempt state and Main healthy-start acknowledgement.
- Select and load Recovery or Main through the ESP-IDF bootloader loader.
- Build without `otadata` and without application networking components.

## Phase 3: Recovery application

- Create the minimal ESP-IDF application under `fw/recovery/app`.
- Add network-role selection: open STA with configured SSID, or a bounded
  `Direct-...-Dmesh` scan when SSID is absent.
- Add fixed unconfigured bootstrap defaults: host `10.78.0.1`, per-CPU TCP
  ports, and a MAC-derived `10.78.<MAC[4]>.<MAC[5]>` local address.
- Implement the minimal framed TCP stream first; measure an optional HTTP
  adapter separately and retain it only if its code/RAM cost is justified.
- Link the shared core and provide ESP-IDF flash/NVS/reboot adapters.
- Implement serial logs for every boot, request, record, write, and failure
  transition.
- Build a signed Main update stream and verify it against host test vectors.
- Add the `bootstrap` test feature:
  - enter only when the trust-key entry is positively absent;
  - select STA/AP from SSID presence;
  - select TCP client/server from remote server presence;
  - accept a length-delimited unsigned test image for an explicit partition;
  - stop after one image, timeout, or failure;
  - make the feature removable from production builds.
- Add tests proving missing-key bootstrap succeeds and present-key bootstrap is
  rejected.

Bootstrap bring-up is implemented and tested on E5 and the attached classic
fleet. The open AP remains fixed to channel 6 so it matches lmesh's existing
`wifi.sta.join_open` helper. Recovery waits for STA association, retries the
outbound TCP connection for 30 seconds, and handles short TCP reads with an
explicit receive-all loop. The P-256 manifest path is implemented and covered
by host protocol tests; signed hardware verification remains a separate test.

## Phase 4: Main integration

- Add the shared core to Main's build without adding Recovery's Wi-Fi app.
- Add request creation and Main healthy-start acknowledgement.
- Add an optional Main-controlled Recovery image update path.
- Keep Main's product behavior separate from the shared updater.

## Phase 5: size and E5 validation

- Build optimized bootloader and Recovery images.
- Record map/component sizes and finalize the partition CSV.
- Verify no LoRa profile or unrelated mesh component is linked.
- Perform build-only and host tests first.
- Flash E5 only after the layout and recovery failure tests are reviewed. Done.

E5 validation evidence (2026-08-01): custom bootloader 28,192 bytes,
Recovery 632,336 bytes, Main 1,633,760 bytes, and the partition table all
build successfully. Recovery is `0xd0000` bytes at `0x10000`; Main is
`0x2e0000` bytes at `0xe0000`.

Using the Recovery UART `STA` command, an open STA association on the lmesh
host AP, static addresses host `10.78.0.1` / E5 `10.78.0.200`, and TCP port
3336, Recovery received and flashed the full Main image. The host observed a
Recovery hello with role/partition `2/2`, validated the partition table, sent
all 399 blocks, and independently verified all 399 post-write truncated
SHA-256 values before the final device image SHA check. Recovery rebooted and
the second-stage bootloader selected Main; the Main boot log was captured over
the managed UART forward. This is the first complete E5 Main-over-Recovery
proof using the current 4096-byte DRS2 protocol.

This evidence is bootstrap-only. It does not establish signed-record
verification. The minimal profile now uses the infrastructure AP and a
numeric host address.

S3 fleet evidence (2026-08-01): lora4 accepted the 22,400-byte second-stage
bootloader and the 783,504-byte Recovery image over Main/TCP, along with the S3 Main
image. Recovery accepted the saved STA request for `10.78.0.204`, transferred
the image, cleared the request, and Main returned live status through lmesh
(`xtal_mhz=40`). The bootloader NVS parser was changed from
`strtoul()` to a bounded decimal/hex parser after the S3 ROM fault was found.

The health counters are second-stage state in RTC retained RAM. The
bootloader reads the update request from NVS but does not write or commit NVS
for routine boot attempts. A successful Main or Recovery health event clears
the corresponding counters in RTC RAM. If both six-attempt budgets are
exhausted, the bootloader logs `uart_flash_required` and halts; the lmesh
serial log is the evidence source for that emergency path.

Fleet completion evidence (2026-08-01): after the lora1 emergency recovery,
the active `target/` artifact path was corrected. E5 passed Recovery, stage2,
partition-table, and sanitized NVS raw-TCP targets. lora1, lora2, and lora3
passed current Main, stage2, and Recovery raw-TCP updates. lora4 passed S3
stage2, Recovery, and `dmesh_store` data updates. All boards returned live
Main status through managed lmesh; no routine USB flashing was used after the
lora1 emergency repair.

## Future: differential flash and shared framing

The current protocol intentionally sends a complete raw image after the CBOR
command starts a session. Future work should reserve the final flash sector of
each target partition for a block-hash sector and make the TCP exchange
device-first:

1. the device sends its current hash sector;
2. the host sends a signed replacement hash sector;
3. the host sends only blocks absent from, or different from, the device's
   current hash set;
4. after all writes verify, the device commits the replacement hash sector.

The hash sector should identify the block size, image length, digest algorithm,
truncation length, and generation. Evaluate truncated SHA-256 first; a Merkle
tree is not the intended starting point. The final sector is part of the
partition contract and therefore must be excluded from the image payload and
from the usable image-size calculation. The update must leave the old hash
sector usable until all changed blocks have been written, so an interrupted
transfer remains diagnosable and does not require a routine NVS write.

The same compact hash table should be usable by the second-stage bootloader to
verify Recovery and Main before handoff. Separately evaluate whether the
second-stage bootloader can implement a bounded version of the differential
protocol without pulling normal networking or policy into the bootloader.

Also evaluate PPP framing for the second-stage, Recovery, and Main control/data
channels. Compare its size, RAM, escaping, packet-boundary, and diagnostic
benefits with the working `DRS2` raw TCP stream. This is a consistency study,
not a prerequisite for the current bootstrap or remote Main-flash path.

## Non-urgent TODO: host-AP IPv6 zero-config transport

For parallel provisioning, allow the host to start an open AP named
`DMESH_<base32 host MAC>`. Recovery should scan for the `DMESH_` prefix,
connect to the host, derive the host's deterministic link-local IPv6 address
from the MAC encoded in the SSID, and use fixed Recovery/control TCP ports.
The host must explicitly assign that link-local address; no SLAAC or DHCP is
required. A signed image makes AP/SSID spoofing unable to install unauthorized
firmware; spoofing can still cause denial of service. The unsigned no-key
bootstrap path remains provisioning-only.
