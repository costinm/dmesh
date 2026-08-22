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

## Radio setup

The implementation keeps a fixed-capacity, allocation-free cache while it
starts Wi-Fi. It is not a public "profile" or a third transport choice. The
public choice is one `transport.start`: `mode=Sta` associates, and `mode=Nan`
does not. Its SSID is ephemeral, supplied only by an accepted start command,
and discarded when the radio setup is replaced or the device reboots. Firmware
has no SSID NVS read/write path, and ESP-IDF Wi-Fi NVS support is disabled.

Raw UDP6 derives its link-local source address from the STA MAC and its peer
from received packets/the associated AP BSSID. It does not use an NVS IPv4
address, gateway, mask, server, or UDP port.

### Shared packet bound

UART, raw UDP6, and the current NOW/vendor-action bearer use one common
transport datagram maximum: **1100 bytes** (`quic_lite::DEFAULT_MAX_DATAGRAM_SIZE`).
All firmware buffers and the host raw-action client derive from that bound.
Current control/IPERF callers must request at most 1100 bytes; there is no
per-bearer MTU negotiation yet. This prevents a host action client from
emitting a final packet that the e6 action ingress cannot complete.

The DMesh NOW/vendor-action bearer always transmits with 802.11 MAC ACK
disabled, for both broadcast and unicast Address-1. QUIC-lite acknowledgements
and retransmission provide delivery semantics; a monitor or AP-coexistence
peer must not be required to acknowledge a management action at the MAC layer.
`mac_ack` remains a radio-lab diagnostic override only and defaults to false.

Unsolicited events default to the stable `lmesh-wifi` UDP destination port
3336. This runtime default is not persisted and is distinct from the fixed
raw UDP6 bearer port (3339); a registered event handler may select a different
destination. Service requests, including iperf, carry their own port.

After the boot AP+NOW radio is live, firmware also broadcasts the same bounded
CBOR boot status and boot-identity records over NOW that it first emits on
UART. This is discovery evidence, not a replacement for a correlated
QUIC-lite request/response.

Firmware additionally emits a bounded tagged-CBOR `announce` record at boot
on UART and NOW, then refreshes it approximately every 15 minutes while NOW is
active. Once associated, it also sends the same bytes on UDP6 multicast
`ff02::5227` / port `5227`; this is separate from the raw QUIC-lite port
`3339`. The raw receiver validates that multicast destination and checksum,
then retains the last ten announce IDs with their source IPv6/MAC address and
last-seen time. Its fields are device MAC identity, uptime seconds, current
associated or unassociated transport mode, and a small golden-counter summary.
The same cache receives NOW action, active NAN Service Info, and UART announce
records before any bearer-specific QUIC-lite/control dispatch. A
connectionless observation has its MAC (or an unspecified UART peer) but no
IPv6 source address. Thus boot and periodic records are treated identically
whether UDP6 multicast, NOW, or NAN SD delivered them; only provenance differs.
A host records received NAN Service Info announcements as
`wifi.rawnan.discovery`.

When NAN DW capture is enabled, firmware also keeps that same current CBOR
announce as its active Publish Service Info. It is emitted only after the
Wi-Fi owner has opened a confirmed discovery window, once after boot/update
and then on the approximately 15-minute announce cadence. `nan_dw_interval=0`
therefore keeps the descriptor pending rather than creating continuous
promiscuous RX or an out-of-window NAN action. The publish state is replaced
atomically with each boot/periodic record; it never retains an ESP-IDF frame
or a second NAN-only discovery schema.

`announce.observed` (component 6, method 3) is the corresponding local
diagnostic handler. It takes an empty map and returns a bounded typed list of
device id, source MAC/IPv6, uptime, mode, counters, kind, and monotonic
last-seen time. ESP32 returns at most ten copied entries; it never exposes a
Wi-Fi driver buffer. E2E callers should query it only after a flashed device
has been running for at least 20 seconds.

`followups.observed` (component 6, method 4) is the corresponding local
receipt handler for directed DMesh NAN Follow-ups. It takes an empty map and
returns up to ten copied entries with source/target, message type, sequence,
payload length/hash, and monotonic last-seen time. Payload bytes remain in the
fixed Wi-Fi-owner cache, so this response is bounded by the common 1100-byte
MTU and never exposes a driver buffer.

The existing `wifi.raw.send` handler is also the explicit NAN Follow-up test
sender: provide a complete DMesh NAN Follow-up action frame at channel 6. The
firmware recognizes control `0x12` and routes it to the DW owner. It is
accepted only while the selected NAN discovery window is open and its BSSID
matches the selected cluster; outside-DW or generic raw-action transmission is
rejected. This preserves the rule that no follow-up is emitted by an
always-on action lane.

An active NAN SDF Service Info payload is a bounded direct CBOR record, not
text metadata. Publish SSI is carried directly in the Service Descriptor;
active-Subscribe SSI is carried in its SDEA. The Wi-Fi capture callback
extracts and copies either form to the shared ingress pool, releases the
hardware buffer, and the common worker applies a `transport.start` with
exactly the UART control parser. The normal radio-mode replacement loop
performs any later Wi-Fi transition; no NAN callback starts, stops, or
reconfigures the radio. An accepted active Subscribe receives one directed
DMesh NAN Follow-up containing the correlated CBOR response, using the
already-open discovery window and the current STA/AP action lane. An accepted
Publish SI retains the NOW broadcast response path. Rejected payloads are
reported only as bounded diagnostics.
ESP32 records are intentionally unsigned discovery metadata. A record that
does include a public key must include a valid signature before a receiver
treats that key as an identity; Android will use the same optional form when
its platform key adapter is wired to this record.

`nvs get ssid` and `nvs set ssid` are not transport commands. Historical
`recovery.*` aliases are not a transport configuration surface.

## Main STA mode: current behavior and planned rendezvous

This section distinguishes implemented behavior from the intended production
policy. A successful association or a callback registration is not proof of
STA+NAN+NOW delivery; each coexistence combination needs its own radio and
end-to-end test.

### Current Main behavior

Neither `mode=infra` nor `mode=sleepy` starts STA from NVS at boot. A UART
`transport.start` record starts the shared STA/raw UDP6 bearer from its
ephemeral SSID; future NAN Service Info uses exactly the same command. The
initial session deadline is 3 seconds for sleepy mode. A tracked DMesh
stream keeps it live; after the final tracked stream completes, Main applies a
200-ms command grace and then stops STA. Ordinary UDP/action packets which do
not create a tracked stream do not extend the session.

The current NAN wake message is not yet a transport command: it does not carry
or validate SSID, BSSID, a distinct IPv6 endpoint, RSSI-selected channel or
rate, or other association parameters. The future packet is an **active
subscribe** NAN service descriptor whose **Service Info** bytes are a bounded
CBOR command. It is decoded by the same command handler as UART; it
must not introduce a parallel SD-info schema or use a NAN follow-up.
`request_ephemeral_nan_session` exists to consume the resulting validated,
memory-only radio setup later, but no current NAN ingress applies that command.
Discovery data must never write device Wi-Fi NVS.

The physical choice is `control.transport.start {mode: Sta}` (associate with an
infrastructure AP) or `{mode: Nan}` (do not associate). `now`,
`nan_dw_interval`, and `ap` are independent settings on either mode. Default
`now=0` adds the private non-promiscuous action callback; NAN DW
capture is independently scheduled. The mode uses the shared ingress/pool
and poll handlers; it is neither the default nor an unassociated
NAN+NOW-at-boot implementation.

### STA-related controls

`transport.start` carries one complete volatile radio setup. Its `ssid` is
an ephemeral STA target, never an NVS write; tests obtain it from the managed
AP owner and send it over UART, while future NAN Service Info carries the same
CBOR command. A started setup is immutable for its radio epoch. To change a
field, issue another start: `wifi_esp` stops the previous STA/NOW/raw ingress
cleanly, then creates the replacement epoch. There is no live mode mutation.

| Control | Default | Effect and transition cost |
| --- | --- | --- |
| `transport.start.ssid`, `sta_bssid`, `sta_channel` | unset | Ephemeral association target, queried from the managed AP owner by Rust e2e and sent over UART. `sta_bssid` and `sta_channel` select the intended AP without an application-owned discovery scan; all three values stay in RAM and never change NVS. A future optional IPv6 field is only needed when the peer is not the BSSID-derived link-local endpoint. |
| Main `mode=infra` | n/a | Keeps the infrastructure policy active but does not associate from NVS. |
| Main `mode=sleepy` | n/a | Keeps STA off until UART or future NAN Service Info; uses the bounded session lifecycle. |
| `control.transport.start {mode: Sta, ssid: ...}` | n/a | Required ephemeral STA target and full associated STA/raw-UDP6 setup. It replaces the boot setup. |
| boot default / `control.transport.start {mode: Nan}` | n/a | Unassociated NOW setup. At boot it starts once as open APSTA on channel 6; an explicit later Nan start deliberately replaces the current setup. |
| `now` | `0` | Private action callback: `0` default/on, `1` explicit on, `2` explicit off. A future `udp6` setting will be independent. |
| `nan_dw_interval` | `0` | NAN promiscuous capture cadence in 512 ms DWs: `0` off, `1` each DW, `8` four seconds, `16` eight seconds. Requires NOW enabled (`now != 2`). |
| `ap` | `1` at boot | Local AP: `0` off, `1` on. The default unassociated start configures APSTA before its one Wi-Fi start, so the AP holds channel 6. STA+AP is not part of this first test path. |
| `espnow_capture` | `false` | Legacy volatile setting; do not use it to select staged Main coexistence. |
| `sta_driver_tx` | `true` | ESP-IDF associated Ethernet TX for raw UDP6 egress. Set `false` only for the raw-802.11-injection diagnostic A/B; it takes effect on the next replacement start. |
| `raw_tx_rate` | `0` | Request raw injection PHY rate; live diagnostic and driver/capture verification required. |
| `sta_raw_rx_enabled` | `true` | Select raw UDP6 RX callback, or ESP-IDF esp-netif/lwIP RX when false. |
| `sta_bssid_check_disabled` | `true` | **Accept other BSSIDs** in the private raw RX path. Keep this historical bypass enabled by default; set `false` only for standard STA BSSID-filter A/B. It applies on the next replacement start. |
| `sta_ampdu_enabled` | `true` | A-MPDU policy; changing it recreates the STA driver and reassociates. |
| `sta_11b_rates_disabled` | `true` | Pre-start legacy-rate policy; changing it recreates the STA driver and reassociates. |
| `tx_burst_packets`, `ack_frequency`, `ack_delay_ms` | start defaults | Raw-bearer pacing/ACK controls. A future active-subscribe Service Info CBOR command uses the same fields and validation as UART. |
| `path_policy` | `0` | QUIC-lite/action path-selection policy; it does not select a Wi-Fi radio mode. |
| `timeout_ms` | `300000` | Decoded start setting, but it does not replace Main's fixed 3-second sleepy-session deadline or its 200-ms stream grace today. |

### Directed-association timing gate

The public ESP-IDF STA API accepts SSID, BSSID, and channel, but does not
publish a direct-auth/no-scan operation. The driver may use its internal
no-scan branch only after it already holds a matching BSSID/channel candidate;
firmware must not call that private implementation. The supported
`transport.start` path therefore remains the one under test.

`firmware_e6_bssid_directed_sta_association` obtains the active AP identity
from its supervised owner, starts e6 from the default unassociated NAN+NOW
state, and measures only `esp_wifi_connect()` through the STA CONNECTED event.
It defaults to a 500-ms bound and restores NAN+NOW before a failing assertion.
Run it against the 500-TU lab AP without changing host radio state:

```sh
DMESH_E2E_E6=/dev/ttyACM0 \
DMESH_E2E_AP_SERVICE=lmesh DMESH_E2E_AP_IFACE=wlan1 \
cargo test -p dmesh-cli --test firmware_e2e \
  firmware_e6_bssid_directed_sta_association -- --ignored --nocapture
```

`DMESH_E2E_BSSID_CONNECT_MAX_MS` can relax the diagnostic threshold while
investigating a driver/AP regression; it must not be used to claim that a
500-TU AP has a beacon-independent association path.

### Target production policy (not implemented)

Powered, non-sleepy devices should boot unassociated in NAN+NOW-only mode.
Sleepy devices should boot in sparse NAN mode with a four-second cadence. A
NAN+NOW exchange followed by an active-subscribe NAN service descriptor whose
Service Info carries CBOR (or the same command over UART) will select either
STA or STA+NAN+NOW. Extend that one shared command schema, rather than
defining an SD-info encoding, with SSID or BSSID, optional IPv6 when it differs
from the derived link-local peer, and association parameters selected or
adjusted from NAN SD RSSI/policy.

The common production rendezvous must be operable from `dmesh-cli` and covered
by Rust end-to-end tests before the default changes. It must send the request
in the next selected DW, retry in DW0 and DW8 when the first NOW/nearest-DW
attempt receives no response, and make the resulting mode observable. While
STA is live, UDP must be able to request a mode change. If `dmesh-server` has
no active streams, the device should apply a short post-request timeout and
return to NAN or NAN+NOW. None of that NAN-CBOR ingress, retry, CLI, e2e, or
UDP-driven mode-revert pieces is implemented by the controls above.

### Coexistence regression gates

The hardware matrix should load a pair/device configuration, query the managed
host AP name, select each device's tagged transport mode, and apply the same
UDP6/NOW/NAN service checks to device and host peers. Report delivered bytes,
device-side elapsed/goodput, action counters, association/channel, and live
promiscuous state; a successful callback registration or UART command response
is not a no-regression result.

## Control schema

The canonical CBOR decoders are `dmesh-server::control` for settings/physical
transport lifecycle and `dmesh-server::connection` for bearer-neutral
QUIC-lite association policy. Firmware calls `apply_control_record` only as an adapter from an ingress record to the shared
typed request. `transport.*` starts, stops, or configures a physical bearer;
`connection.configure` updates QUIC-lite association defaults without starting
or selecting a radio. Applying a control request itself does not reboot, flash,
open a connection, or mutate RTC.

Direct CBOR records and QUIC-lite stream requests must reach the same handler
registry. UART is only an L2 adapter and must not parse service commands.

### Direct-CBOR exception plane

Direct CBOR bypasses stream ordering, flow credit, congestion control, and
normal stream accounting. It is the common bounded-message representation for
request/response, loss-tolerant events, and discovery/follow-up bearers;
authorization and forwarding remain ingress-adapter policy. Operations that
need ordered bulk transfer, backpressure, or reliable completion use a
QUIC-lite stream with the same handler schema.

| Direct record | Why it may bypass QUIC-lite | Direction/limits |
| --- | --- | --- |
| Stage2 boot selection/status | Stage2 runs before the transport runtime exists | UART only; small CBOR request/response |
| Initial STA bootstrap request | Needed only to select the first raw UDP6 association | UART only; bounded SSID preference; no bulk data |
| Boot identity and fatal bootstrap failure | Lets an attached operator diagnose failure before a connection exists | device-to-host only; one bounded record per event |
| Explicit recovery escape/reboot request | Last-resort repair when no usable transport can be established | UART only; authenticated in the future security layer |

Ordinary bounded configuration, command responses, status, metrics, and
low-rate events may use direct CBOR or a registered QUIC-lite stream. Object
and flash transfer, bulk logs, and operations requiring reliable ordered
completion use a QUIC-lite stream. A direct record never creates a private
transport queue or reserves a bulk buffer.

Recovery's control, radio-lab, and raw-frame-injection direct ingress accepts
only common tagged component envelopes and rejects the retired Recovery map.
Raw injection is `radio.tx` in component `4`; its frame bytes remain borrowed
until the ESP adapter submits them and it is not a control decoder.
Normal log streaming is also deferred; until then boot/fatal records above are
the only direct log exceptions.

### STA egress, raw-rate, and BSSID controls

`transport.start` carries `sta_driver_tx`, `raw_tx_rate`, and
`sta_bssid_check_disabled` together with the STA target and NOW policy. They
apply only while `wifi_esp` creates that epoch. `sta_driver_tx=true` selects
the ESP-IDF associated Ethernet handoff (`esp_wifi_internal_tx`); `false`
selects explicit raw 802.11 injection for diagnostic A/B work.

`raw_tx_rate=<0|6|9|12|18|24|36|48|54>` remains a raw-injection diagnostic,
not proof that the PHY rate took effect. Inspect the completion rate and host
capture; `0` leaves ESP-IDF's documented 1-Mbit/s raw-frame default in effect.

`sta_bssid_check_disabled=true` is the default accept-other-BSSID policy for
the private raw receive path. Set it to `false` only for standard STA BSSID
filtering A/B. Any of these changes requires another full `transport.start`;
`wifi_esp` stops the old epoch before reassociating and `radio.snapshot` key
`78` reports the applied BSSID policy. Validate either choice with NDP and a
completed UDP6 request.

## Main command migration

Main's historical `commands` and `transports` modules are not a stable wire
surface. Keep an operation only by registering a tag and name in
`dmesh-server::services::StreamRegistry` and implementing the operation behind
that handler. Do not wrap its old CBOR request/response parser in a new UART
path.

| Existing Main area | Shared handler destination |
| --- | --- |
| Recovery/flash bootstrap and GET/object | existing `recovery` and `object` services |
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

The normal relay setup retains one retransmittable packet per active peer.
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
- Both use the same start settings and tested STA adapter. Infrastructure Main
  starts STA from `transport.start`; battery Main starts with NAN/LoRA/FSK discovery and
  activates STA for an active session with explicit idle timeout/exit policy.

## Deferred stream records

Log-watch and similar lossy framed streams remain a future milestone. The
eventual contract is one application record per QUIC STREAM frame, bounded
queues, and drop-on-congestion based on queue age/priority. This crate does
not implement that behavior yet.
