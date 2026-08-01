# Recovery implementation plan

## Current status

The active E5 implementation is the C Recovery bootstrap path. It has been
built and exercised for an unsigned TCP image transfer and boot handoff. It
does not yet verify signatures or authenticated records. The Rust prototype is
retained under [`../recovery-rust`](../recovery-rust) for comparison, but is
not used.

The current C image is 786,864 bytes on classic ESP32 and 783,504 bytes on
ESP32-S3. Both fit the 0xd0000 Recovery partition. AP-only and STA-only
variants have not been built; the current tested configuration is STA-capable
with the open AP fallback.

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
- Add network-role selection: STA when SSID is present, otherwise AP.
- Add transport-role selection: TCP client when a remote server address is
  present, otherwise TCP server.
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
fleet. The open AP remains fixed
to channel 6 so it matches lmesh's existing `wifi.sta.join_open` helper; the
signed record path is still pending. Recovery waits for STA association and
handles short TCP reads with an explicit receive-all loop. No signature
verification has been tested or claimed yet.

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
- Flash E5 only after the layout and recovery failure tests are reviewed.

E5 validation evidence (2026-08-01): custom bootloader 27,808 bytes,
Recovery 786,864 bytes, Main 1,615,760 bytes in the current build, and the
partition table all build successfully. Recovery is `0xd0000` bytes at
`0x10000`; Main is `0x2e0000` bytes at `0xe0000`.

Using the Recovery UART `STA` command, an open STA association on the lmesh host AP, static
addresses host `10.78.0.1` / E5 `10.78.0.200`, and TCP port 3336, Recovery
received and flashed the full Main image. The host measured 10.381 seconds
(1.150 Mbit/s including flash writes). Recovery rebooted and the corrected
second-stage bootloader selected Main; Main returned `uptime_ms=22445`, heap
telemetry, and `lora_rx=0 lora_tx=0`. The original NVS was restored and read
back with matching SHA-256
`d04172aaef332b66fbb798234e66b9c90acc87d7b55ba6e8be9225009802c9ab`.

This evidence is bootstrap-only. It does not establish signed-record
verification, and it does not include an AP-only versus STA-only size
comparison.

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
benefits with the working `DRS1` raw TCP stream. This is a consistency study,
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
