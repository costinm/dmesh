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

`TransportProfile` is the fixed-capacity, allocation-free runtime STA
preference. The registered firmware `nvs` handler owns persistent settings;
the only value read directly before that handler can run is `dmesh:ssid`.

| Field | NVS key |
| --- | --- |
| STA SSID | `ssid` |

Raw UDP6 derives its link-local source address from the STA MAC and its peer
from received packets/the associated AP BSSID. It does not use an NVS IPv4
address, gateway, mask, server, or UDP port.

Unsolicited events default to the stable `lmesh-wifi` UDP destination port
3336. This runtime default is not persisted and is distinct from the fixed
raw UDP6 bearer port (3339); a registered event handler may select a different
destination. Service requests, including iperf, carry their own port.

Use `nvs get ssid` and `nvs set ssid <value>` for this preference. The same
handler owns other validated DMesh NVS values. Historical `recovery.*` aliases
are not a transport configuration surface.

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
| Initial STA profile/bootstrap request | Needed only to select the first raw UDP6 association | UART only; bounded SSID preference; no bulk data |
| Boot identity and fatal bootstrap failure | Lets an attached operator diagnose failure before a connection exists | device-to-host only; one bounded record per event |
| Explicit recovery escape/reboot request | Last-resort repair when no usable transport can be established | UART only; authenticated in the future security layer |

Ordinary configuration, command responses, object/flash requests, status,
metrics, and all ordinary logs are prohibited from direct CBOR. They
use registered QUIC-lite streams. A high-priority stream is the answer for a
latency-sensitive command or response; it must not open a bypass.

The current direct-CBOR parser is transitional and is broader than this list.
Before removing Main's legacy dispatcher, enforce this allow-list at direct
ingress and count/reject every other direct record. Normal log streaming is
also deferred; until then boot/fatal records above are the only direct log
exceptions.

### Live STA egress and raw-rate controls

The direct Recovery command `recovery sta_driver_tx=true|false` changes the
next raw-UDP6 STA response without a reboot or a Wi-Fi re-association.
`false` selects explicit raw 802.11 injection; `true` selects the ESP-IDF
associated Ethernet handoff (`esp_wifi_internal_tx`). The control is volatile
and is reset to `false` at boot. It exists to compare driver queue/rate
behavior while preserving the same NDP, UDP6 parser, QUIC-lite connection,
and packet-pool path; it is not a production network preference.

`recovery raw_tx_rate=<0|6|9|12|18|24|36|48|54>` is a raw-injection
diagnostic, not evidence that a PHY change took effect. It invokes ESP-IDF's
fixed-rate API without a reboot or reassociation, but on the current C6 test a
post-association request for 6 Mbit/s was accepted while both host evidence
and raw-TX completion status still showed the 1-Mbit/s default. Inspect the
completion rate and host capture; never treat command acceptance as an applied
rate. `0` leaves ESP-IDF's documented 1-Mbit/s raw-frame default in effect;
it is not driver rate control.

Every direct Recovery command patches only the named live fields. For example,
changing `sta_driver_tx` preserves the configured NAN/NOW opt-in, ACK cadence,
rate, and path policy. `radio.snapshot` reports the active `sta_driver_tx`
selection alongside the existing raw TX rate and counters.

`recovery bssid_check_disabled=true|false` selects the private STA receive
filter used by raw UDP6 and action experiments. `true` is the historical
default/bypass. Changing it performs one logged STA stop/start and
re-association (about one second on e6), rather than claiming that the private
filter can be safely reversed while frames are live. It does not reboot the
device or rebuild firmware. `radio.snapshot` key `78` reports the applied
setting; validate each choice with NDP plus a completed UDP6 request.

## Main command migration

Main's historical `commands` and `transports` modules are not a stable wire
surface. Keep an operation only by registering a tag and name in
`dmesh-server::services::StreamRegistry` and implementing the operation behind
that handler. Do not wrap its old CBOR request/response parser in a new UART
path.

| Existing Main area | Shared handler destination |
| --- | --- |
| Recovery/flash profile and GET/object | existing `recovery` and `object` services |
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
