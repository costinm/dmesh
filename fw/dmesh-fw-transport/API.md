# dmesh-fw-transport API

`dmesh-fw-transport` is the no-std ESP firmware integration layer shared by
Recovery and Main. It may contain ESP-IDF/FreeRTOS adapters, UART tasks,
sockets, NVS, flash workers, and ESP SHA callbacks when those are genuinely
shared by the firmware binaries. RTC boot-target/reboot policy remains a
Recovery-shell concern.

`recovery-rust` has no reusable implementation modules and Main must never
depend on it. Both binaries depend directly on this crate, `quic-lite`, and
`dmesh-server` at the appropriate layer.

Code that can be host-tested without firmware ownership belongs in
`quic-lite` (transport mechanics) or `dmesh-server` (CBOR schema, services,
object records). Every Rust source file in this crate repeats that boundary.

## Transport profile and NVS

`TransportProfile` is the fixed-capacity, allocation-free STA and transport
profile. Both binaries persist it under NVS namespace `dmesh` with these keys:

| Field | NVS key |
| --- | --- |
| STA SSID | `ssid` |
| transport peer | `server` |
| static IPv4 address | `ip` |
| gateway | `gw` |
| mask | `mask` |
| UDP transport port | `port` |

`TransportSettings` adapts these operations to a platform NVS handle.
`load_profile` and `persist_profile` own bounded parsing and serialization;
they never initialize flash/NVS, start STA, or commit an RTC boot target.
Main's settings service must expose these same keys directly. Historical
`recovery.*` aliases are not a transport configuration surface.

## Command schema

The canonical CBOR decoder is `dmesh-server::recovery`. Firmware calls
`apply_recovery_packet` to apply the decoded record to `TransportProfile`.
The result tells the binary whether a profile changed and whether Recovery may
perform its *post-successful-Main-image* handoff. Applying a command itself
does not reboot, flash, open a bearer, or mutate RTC.

Direct CBOR records and QUIC-lite stream requests must reach the same handler
registry. UART is only an L2 adapter and must not parse service commands.

### Direct-CBOR exception plane

Direct CBOR bypasses stream ordering, flow credit, congestion control, path
selection, authentication, and normal service accounting. It is therefore an
exception plane with a deliberately small allow-list, not a lower-latency
command API.

| Direct record | Why it may bypass QUIC-lite | Direction/limits |
| --- | --- | --- |
| Stage2 boot selection/status | Stage2 runs before the transport runtime exists | UART only; small CBOR request/response |
| Initial STA profile/bootstrap request | Needed only to create the first usable IP/QUIC-lite path | UART only; bounded profile; no bulk data |
| Boot identity and fatal bootstrap failure | Lets an attached operator diagnose failure before a connection exists | device-to-host only; one bounded record per event |
| Explicit recovery escape/reboot request | Last-resort repair when no usable transport can be established | UART only; authenticated in the future security layer |

Ordinary configuration, command responses, object/flash requests, status,
metrics, iperf, and all ordinary logs are prohibited from direct CBOR. They
use registered QUIC-lite streams. A high-priority stream is the answer for a
latency-sensitive command or response; it must not open a bypass.

The current direct-CBOR parser is transitional and is broader than this list.
Before removing Main's legacy dispatcher, enforce this allow-list at direct
ingress and count/reject every other direct record. Normal log streaming is
also deferred; until then boot/fatal records above are the only direct log
exceptions.

## Main command migration

Main's historical `commands` and `transports` modules are not a stable wire
surface. Keep an operation only by registering a tag and name in
`dmesh-server::services::StreamRegistry` and implementing the operation behind
that handler. Do not wrap its old CBOR request/response parser in a new UART
path.

| Existing Main area | Shared handler destination |
| --- | --- |
| Recovery/flash profile, GET/object, iperf | existing `recovery` and `object` services |
| status, metrics, events, logs | existing `status`, `metrics`, `events`, `log-watch` services |
| Wi-Fi STA/session control | `control` handler plus firmware STA adapter |
| NAN, LoRa/FSK, ESP-NOW, battery, hardware/modules | Main-contributed handlers with stable numeric tags and names |
| ad-hoc test, text console, old framed command maps | remove; do not migrate as compatibility handlers |

The action-frame server is already attached to `StreamRegistry`. The next
conversion attaches marked UART and direct CBOR to that same registry, then
removes the legacy `transports` dispatch functions and their callers.

### Main relay connection storage

Main distinguishes a passive association from an active QUIC-lite connection.
A passive record holds only peer identity, DCID, and recency; it never
allocates stream, ACK, retransmission, or handler state. Main retains up to
256 such records. An active connection owns the mux and handler state and is
admitted only while internal byte-addressable heap remains above its reserve.

| Target | Active connection ceiling | Rationale |
| --- | ---: | --- |
| classic ESP32 without PSRAM | 3 | Two gateway/data peers plus one control-plane peer; preserve DRAM for Wi-Fi, modules, and normal firmware operation. |
| ESP32-S3 and ESP32-C6 | 16 | Relay target; passive peers remain remembered beyond this active set. |

The normal relay profile retains one retransmittable packet per active peer.
Bulk transfer profiles are separately admitted: they must not reserve a large
window for every peer merely because the relay has observed its NAN/action
association. This is an explicit resource boundary, not a UART or ESP-NOW
special case.

## Lifecycle ownership

- Recovery owns only successful Main-image completion: clear/arm the Stage2
  handoff as required, select Main, and restart.
- Main writes requested module, Stage2, and Recovery targets without reboot or
  RTC changes. A distinct control handler may arm an RTC/Stage2 transition to
  Recovery.
- Both use the same profile and tested STA adapter. Infrastructure Main starts
  STA from the profile; battery Main starts with NAN/LoRA/FSK discovery and
  activates STA for an active session with explicit idle timeout/exit policy.

## Deferred stream records

Log-watch and similar lossy framed streams remain a future milestone. The
eventual contract is one application record per QUIC STREAM frame, bounded
queues, and drop-on-congestion based on queue age/priority. This crate does
not implement that behavior yet.
