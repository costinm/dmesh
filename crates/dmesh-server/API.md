# dmesh-server CBOR handler API

`dmesh-server` owns bearer-neutral CBOR records and handler schemas.  It has
no ESP-IDF, FreeRTOS, socket, UART, or Wi-Fi-driver dependency.  Firmware,
`dmesh-cli`, and privileged host radio adapters use the same typed decoder.

## Common tagged envelope

New APIs use one root CBOR map.  Component and method are keys `1` and `2`;
request id, parameters, fields, result, and error use keys `3` through `7`.
Key `9` (`to`) is routing metadata: if present the receiving mesh adapter
forwards the original record to that destination instead of executing it
locally.  A device that has no forwarding adapter rejects such a record rather
than allowing a legacy decoder to ignore `to` and execute it locally.

Key `10` (`data`) is an optional CBOR byte string outside the typed
parameter/field maps. It is for opaque binary payloads such as an object
chunk: the bounded decoder exposes a borrow of the ingress record, so a relay
or ESP adapter need not base64 encode or copy the payload merely to inspect
the destination. The sender retains ownership of its bytes until the record
has been accepted by the selected bearer; an actual relay makes at most its
normal bounded packet-pool copy.

`{0: method, 6: payload}` was the retired Recovery/Main command map. It is
not decoded by the common service or firmware-control path; new callers must
use the envelope above.

## Core settings and radio lifecycle

Component `1` is the common device-control component. Its requests and
responses are ordinary tagged records: they may use a direct message when the
result fits, or a QUIC-lite stream when ordering/reliability or a larger result
is needed. A NAN SD/follow-up, raw action, LoRa/FSK message, UART record, and
UDP6 direct datagram therefore carry identical bytes. None gets a private
firmware command grammar.

| Method | Name | Fields | Result / adapter responsibility |
| ---: | --- | --- | --- |
| 1 | `settings.get` | `1:key` text | Return the current value, or a typed not-found error. |
| 2 | `settings.set` | `1:key`, `2:value` text | Validate and persist a deployment setting through its adapter. SSID is not a setting: STA receives it only in `transport.start`. |
| 3 | `settings.list` | none | Return bounded known settings and current values. |
| 4 | `transport.start` | `1:kind` enum plus the complete volatile radio profile | Stop any previous radio epoch cleanly, then start one explicit bearer personality. |
| 5 | `transport.stop` | `1:kind` enum | Stop the selected bearer. |

`transport.start.kind` is `1=sta`, `5=uart`, or `6=nan`. Values `2`, `3`, and
`4` are retired and rejected. A start record holds one immutable, volatile
radio profile: `2:ssid` (STA target), `5:raw_tx_rate`, `6:sta_driver_tx`,
`7:sta_bssid_check_disabled`, `8:sta_ampdu_enabled`, `9:sta_11b_rates_disabled`,
`10:sta_raw_rx_enabled`, `13:espnow_capture`, `14:nan_dw_interval`, `15:now`,
`16:ap`, and optional `17:sta_passphrase` (8..63 bytes, volatile WPA2
credential). Omitted fields use the current profile defaults only while this
new epoch is constructed; they cannot be patched afterward. A later start is
the only way to replace a selected radio setup. `ssid` is session data, not an
NVS write, so UART and future NAN Service Info use identical CBOR. Replaying
the same complete start (as an active NAN Publish/Subscribe may do in several
discovery windows) is an acknowledgement-only no-op: it must not stop Wi-Fi,
reset NOW, or begin another association. A different complete profile is the
only start that replaces the current epoch.

`now=0` is the default/on spelling, `now=1` is explicit on, and `now=2` is
explicit off for the raw-UDP6 baseline. The initial ESP adapter currently
implements STA; it rejects unassociated NAN and UART lifecycle requests until
those Wi-Fi owners exist. It does not define method IDs or decode CBOR itself.

Settings have no firmware-only namespace. Each deployment may expose a
bounded store (ESP NVS, host configuration, or a test in-memory store) through
the same handler. A setting implementation owns validation and persistence;
the `dmesh-server` schema owns the wire request, result, and error shape.

`transport.*` ends at the physical-bearer boundary. It starts/stops/configures
radios, UART, and future LoRa/FSK paths; it never creates a QUIC-lite
association, stream, RPC, or forward.

## Privileged A-to-B forwarder probes

`probe::ProbeRequest` and `probe::ProbeResponse` are the common host/Android
control-plane contract for deciding whether two nodes can form a mesh-chain
link. A probe is not sent to an ESP as a new handler. Instead, the signed
control plane applies the existing `transport.start` records to endpoint A and
endpoint B, sends the normal NAN SD/follow-up, NOW, and UDP6 low-level checks,
then returns one structured response.

The request contains each endpoint's implementation (`Host`, `Android`, or
`ESP`), identity, and full desired mode
(`transport_kind`, `now`, `nan_dw_interval`, and `ap`), optional directed STA
`bssid`, requested bearer checks (`test_nan`, `test_now`, `test_udp6`), short
and sustained byte counts, and `measure_mode_switch`. It supports a
NAN+NOW-only ESP pair (`udp6=false`) and an Android path (`now=false,
udp6=true`) without minting distinct APIs.

The response records per-endpoint mode replacement/BSSID-association timing,
whether a requested colocated AP stayed active,
and per-bearer attempt/success, packet loss, latency, bytes, elapsed time, and
RSSI. Unknown metrics are omitted rather than represented as zero. The
controller uses the recommendation and raw measurements to select a forwarder,
rate/profile, discovery-window cadence, and operational timeout.

## QUIC-lite connection primitives

Component `3` owns bearer-neutral QUIC-lite connection primitives. Its first
method is `1=connection.configure`, whose fields are ACK frequency/delay, TX
burst, path policy, and timeout. The portable value type is
`quic_lite::connection::ConnectionPolicy`; its manager owns connection IDs,
stream allocation, RPC, forwarding, credits, and memory grants. Future
`connection.open`, `stream.open`, `rpc`, and `forward` operations belong to
this component, not to `transport.*` or any radio component.

A physical transport only makes one or more paths available to that manager.
Hosts can exercise the connection surface over in-memory or loopback bearers.
On the current raw firmware bearer, a changed policy retires the active raw
association so the next QUIC-lite OPEN receives one coherent profile. It does
not restart STA, change channel, or reconfigure radio callbacks. Path policy
and timeout remain connection-manager settings and are not radio controls.

## Signed objects and flash

`signed_object` is the host/Android service for image retrieval. Its GET body
is `{0:name?,1:cpu,2:target}` and its ordered response is manifest, blob, and
done records. `ObjectServer` is its host implementation; the transport is
responsible only for an authenticated ordered stream.

`flash` is the device-handler contract, not an ESP transport feature. Its body extends
the same object identity with optional `address` and `transport` plus
`dry_run`: `{0:name?,1:cpu,2:target,3:address?,4:transport,5:dry_run}`.
An implementation fetches from `signed_object` and feeds the response to `SignedObjectReceiver`.
That receiver performs shared record framing, manifest/signature/block
validation, and calls an injected sink. Firmware injects the erase/write
partition sink; host tests inject `FileImageSink`.

The device retains the `flash` request stream while it opens the separate
`signed_object` GET on the selected authenticated path. It sends the command
response only after the sink is complete and durable; the request handler does
not wait or block a bearer task.

The sink must be nonblocking on the receive path. It returns stream credit
only after accepted bounded storage is available; failure aborts the transfer. No
transport, UART, or radio adapter may create a private unbounded queue for
flash records.

## Radio laboratory handlers

The radio laboratory is a set of handlers, not a text console or a one-off
experiment protocol. It uses component `4` of the common tagged envelope.
Direct PPP, action, and QUIC hardware-service requests carry the same
`{1:4,2:method,5:fields}` bytes; responses carry their snapshot at key `6`.
Directed records are rejected before a local radio adapter executes them. The
bearer adapter may add authentication/stream policy, but it must not parse or
rewrite handler fields.

| Method | Name | Purpose |
| ---: | --- | --- |
| 71 | `radio.tx` | Submit one bounded raw 802.11 frame through the selected radio adapter. |
| 72 | `radio.control` | Apply an explicit partial radio-state update, then return the applied snapshot. |
| 73 | `radio.snapshot` | Return one counter/state snapshot without changing radio state. |
| 74 | `radio.reset_counters` | Advance the metric epoch, reset lab counters, and return the reset snapshot. |
| 75 | `radio.check` | Start a bounded raw action-bearer `SERVICE_ECHO` check, then return the current snapshot. |

`radio.control` fields are optional: omitted means unchanged.  They are
command-scoped and must never modify NVS or influence a subsequent reboot.

`radio.check` uses canonical CBOR body `{0:5,17:peer-mac,18:nonce,19:timeout-ms}`.
The service framing and check response live in `dmesh-server`; host and ESP
adapters only provide packet-at-a-time action I/O.  The same method is valid
over raw PPP and the registered hardware stream service.

| Field | CBOR key | Type | Meaning |
| --- | ---: | --- | --- |
| `channel` | 2 | `u8` 1..13 | channel retained for disconnected/raw operation |
| `interface` | 3 | enum | `auto`, `sta`, `ap`, `nan` |
| `rate` | 5 | enum | `auto`, `6`, `9`, `12`, `18`, `24`, `36`, `48`, `54` Mbps |
| `disable_11b` | 6 | bool | raw-TX PHY policy |
| `sta_state` | 7 | enum | `reconnect` or `disconnect_hold` |
| `comparator_bssid` | 8 | MAC | exact Address-3 comparator value |
| `comparator_enabled` | 9 | bool | enable/disable comparator; enable requires a BSSID in the same request |
| `promiscuous` | 10 | bool | explicit raw monitor state |
| `dw_policy` | 11 | enum | `normal`, `disabled`, `manual` |
| `rx_filter` | 12 | enum | `management`, `management_data` |
| `ap_mode` | 13 | enum | `disabled` or ephemeral open APSTA owner |
| `ap_beacon_tu` | 14 | `u16` | AP beacon interval, 100..60000 TU; supplied with `ap_mode=open` |
| `raw_sta_mode` | 15 | enum | `main_style`: Main's idempotent idle-STA start, unassociated and prom off |
| `mac_ack` | 16 | bool | request driver MAC ACK for raw action TX; disabled by default so QUIC-lite owns loss recovery |
| `action_destination_broadcast` | 20 | bool | send NOW-like action Address-1 as broadcast; an explicit non-promiscuous ROC/filter experiment |
| `roc_listen_ms` | 25 | `u16` | request one 10..1000 ms same-channel ESP-IDF remain-on-channel action listener; rejected when the driver cannot accept the requested ROC mode |

`ap_mode=open` starts a channel-selected open APSTA radio owner with a
deterministic `DIRECT-XXXXXX-dmesh` SSID derived from the AP MAC. It creates
no `esp_netif`, DHCP server, or lwIP data plane and never changes NVS. This is
shared by Recovery and Main specifically to test NOW/NAN action reception when
unassociated or associated with an ESP AP.

Raw 802.11 injection is `radio.tx` (method `71`) in the same component. Its
fields are `1:frame` bytes, `2:channel`, `3:interface`, `4:system_sequence`,
`5:rate`, and `6:disable_11b`. The shared decoder borrows the frame from the
ingress record and the ESP/host adapter decides how to submit it; it does not
allocate a socket buffer or create a bearer-local queue.

The applied snapshot includes metric epoch, station association state, channel,
bounded ROC listener request/failure/frame counters and its NOW/NAN/other-action classifications,
non-promiscuous vendor-IE beacon/NAN-beacon/other-IE counters,
live promiscuous state, DW state, comparator BSSID/armed/errors, requested and
applied TX interface/rate, TX attempts/driver outcomes, receive dispatcher and
parser outcomes, self-echoes, drops, and NAN classification counters.  The
host takes a snapshot before and after each batch and computes deltas.  The
firmware must not periodically emit snapshots while a lab case is executing.
When the adapter exposes them, the snapshot also contains the actual STA and
AP MACs.  E2E callers must use the selected interface's reported MAC as the
raw-action peer identity; they must not infer an AP MAC from a STA MAC.
It also returns the raw service client's delivered bytes and device-monotonic
elapsed microseconds. A caller may derive goodput from those two fields; its
own completion latency remains a separately reported host-observation metric.

## Raw-bearer service check

`RawCheckClient` is a bounded liveness check for the raw bearer. It
opens a normal raw QUIC-lite association and requests `SERVICE_ECHO` with an
eight-byte caller nonce. The standard status response proves OPEN, stream
request, response, and ACK/credit delivery without allocating a bulk sender
or reserving a response buffer. Bearer adapters report their own RSSI and
driver-counter sample next to the status result: those radio-specific values
do not belong in this portable service response.

The machine-readable schema is
[`schemas/radio-lab.schema.json`](schemas/radio-lab.schema.json).  The
`dmesh-cli` firmware schema catalog imports its method/field tags and types so
the same records can be emitted with `--command` in direct PPP mode or sent as
a QUIC hardware-service body.
