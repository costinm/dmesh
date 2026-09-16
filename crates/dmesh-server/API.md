# dmesh-server CBOR handler API

`dmesh-server` owns bearer-neutral CBOR records and handler schemas.  It has
no ESP-IDF, FreeRTOS, socket, UART, or Wi-Fi-driver dependency.  Firmware,
`dmesh-cli`, and privileged host radio adapters use the same typed decoder.

Platform integrations are adapters, not command owners. Android and Linux may
report bounded network and power observations, then implement common control
requests with explicit capability results. Framework-specific callbacks,
permissions, and handles do not appear in this schema or in public method
names; they stay behind the adapter that supplies those facts.

## Device-list observations

`discovery.nodes` is the bounded, cross-platform discovery inventory. Its
device identity, decoded announce metadata, bearer name, and receiver-side
observation fields are presentation-safe. A radio adapter's native peer handle
is only an opaque correlation fact: Android `PeerHandle` values, Linux MAC
addresses, and firmware MAC addresses are not interchangeable identities and
must not be rendered as a user-facing device name.

Each observation supplies `available_fields` and `unavailable_fields` bitsets:
`1=peer correlation`, `2=BSSID`, `4=channel`, `8=RSSI`, and `16=payload
fingerprint`. `peer correlation` says that the local adapter has a native
return path; its value is deliberately absent from the presentation list
because Android `PeerHandle`, Linux MAC, and ESP MAC are incomparable. An
unavailable fact is a platform limit, not zero or a failed discovery. UI
surfaces render it as unavailable and keep adapter-specific diagnostics in
their native status snapshot rather than adding platform-only device-list
columns. All adapters report packet counters (`packets`, active Publish,
active Subscribe, and Follow-up), last packet kind, timestamps, and bounded
payload length/hash with the same meaning. `channel`, when available, is the
receiver's channel at capture time: it determines whether NOW/NAN can be
expected to work between the observed radios, but does not claim that a peer
is permanently configured for that channel. When two STA/AP devices share an
IP network, UDP6 is the normal data path regardless of whether channel-bound
NAN/NOW discovery is also available.

```mesh-api
id = "discovery.nodes"
component = "discovery"
method = "nodes"
component-index = 6
method-index = 9
ui-visibility = "default"
summary = "Return the bounded cross-bearer observed-device inventory"
```

## Local NAN status and transport metrics

Component `7` reports local runtime health. It never duplicates the peer
inventory above and it never exposes Linux interface/process controls.
Unavailable platform facts and counters are omitted. Metrics are split by the
runtime that owns the counter so an ESP and a host can report the same facts
without an ambiguous aggregate `wifi.raw.metrics` response.

`telemetry.nan_status` fields are `1:active`, `2:cluster_id` bytes, `3:sync_id` bytes,
`4:publishing`, and `5:publish_pending`. Metric responses are bounded maps
whose stable numeric key identifies a counter within that method. Per-peer
signal/rate/retry observations continue to use `raw_wifi::WifiLinkMetrics`.

```mesh-api
id = "telemetry.nan_status"
component = "telemetry"
method = "nan_status"
component-index = 7
method-index = 1
ui-visibility = "default"
summary = "Return local NAN attach, cluster, synchronization, and publish state"
```

```mesh-api
id = "telemetry.now_metrics"
component = "telemetry"
method = "now_metrics"
component-index = 7
method-index = 2
summary = "Return local ESP-NOW submission, receive, admission, dispatch, drop, and error counters"
```

```mesh-api
id = "telemetry.nan_metrics"
component = "telemetry"
method = "nan_metrics"
component-index = 7
method-index = 3
summary = "Return local NAN beacon, SDF, Service Info, Follow-up, dispatch, drop, and error counters"
```

```mesh-api
id = "telemetry.udp6_metrics"
component = "telemetry"
method = "udp6_metrics"
component-index = 7
method-index = 4
summary = "Return local raw IPv6 validation, UDP delivery, NDP, transmit, and failure counters"
```

```mesh-api
id = "telemetry.wifi_link_metrics"
component = "telemetry"
method = "wifi_link_metrics"
component-index = 7
method-index = 5
summary = "Return common optional per-peer Wi-Fi link observations"
```

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
| 1 | `settings.get` | `1:key` text | Return one non-secret current value, or a typed not-found error. `sec:*` values are write-only. |
| 2 | `settings.set` | `1:key`, `2:value` text | Validate and persist a deployment setting through its adapter. `sec:*` is accepted for first-use provisioning but is never echoed. |
| 3 | `settings.list` | none | Return bounded known settings and current non-secret values; present `sec:*` keys are reported as `<redacted>`. |
| 4 | `transport.set` | `1:kind` enum plus the complete volatile radio profile | Replace the complete radio profile; an all-off profile replaces stop. |

```mesh-api
id = "transport.set"
component = "transport"
method = "set"
component-index = 1
method-index = 4
ui-visibility = "default"
summary = "Replace a node's complete volatile physical transport profile"
[request]
fields = [
  { name = "kind", index = 1, type = "u8", required = true },
  { name = "ssid", index = 2, type = "string" },
  { name = "bssid", index = 3, type = "string" },
  { name = "channel", index = 4, type = "u8" },
  { name = "nan_dw_interval", index = 14, type = "u8" },
  { name = "now", index = 15, type = "u8" },
  { name = "ap", index = 16, type = "u8" },
  { name = "passphrase", index = 17, type = "string" },
  { name = "ndp", index = 19, type = "u8" },
  { name = "open", index = 24, type = "bool" },
]
```

`transport.set.kind` is `1=sta`, `5=uart`, or `6=nan`. Values `2`, `3`, and
`4` are retired and rejected. A set record holds one immutable, volatile
radio profile: `2:ssid` (STA target), `5:raw_tx_rate`, `6:sta_driver_tx`,
`7:sta_bssid_check_disabled`, `8:sta_ampdu_enabled`, `9:sta_11b_rates_disabled`,
`10:sta_raw_rx_enabled`, `13:espnow_capture`, `14:nan_dw_interval`, `15:now`,
`16:ap`, optional `17:sta_passphrase` (8..63 bytes, volatile WPA2 override;
absent selects the fixed DMesh WPA2 key),
credential). Omitted fields use the current profile defaults only while this
new epoch is constructed; they cannot be patched afterward. A later set is
the only way to replace a selected radio setup. `ssid` is session data, not an
NVS write, so UART and future NAN Service Info use identical CBOR. Replaying
the same complete set (as an active NAN Publish/Subscribe may do in several
discovery windows) is an acknowledgement-only no-op: it must not stop Wi-Fi,
reset NOW, or begin another association. A different complete profile is the
only set that replaces the current epoch.

A provisioned NVS STA profile is applied at boot through this same complete
`transport.set(kind=sta)` path, with its configured NOW/NAN extension. If
association fails, the adapter keeps that STA profile as the desired next
epoch while it returns to NOW+NAN; it makes one new STA attempt immediately
before the next periodic advertisement. The same fallback/retry rule applies
to a later volatile `transport.set(kind=sta)`.
`19:ndp` is the common NAN Data
Path policy (`0` off, `1` on). Android implements it today; adapters without
NDP retain the requested profile and report unsupported capability rather than
interpreting it as a different bearer.

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
control plane applies the existing `transport.set` records to endpoint A and
endpoint B, sends the normal NAN SD/follow-up, NOW, and UDP6 low-level checks,
then returns one structured response.

The request contains each endpoint's implementation (`Host`, `Android`, or
`ESP`), identity, and full desired mode
(`transport_kind`, `now`, `nan_dw_interval`, `ndp`, and `ap`), optional directed STA
`bssid`, requested bearer checks (`test_nan`, `test_nan_data`, `test_now`, `test_udp6`), short
and sustained byte counts, and `measure_mode_switch`. `test_scan` requests a
bounded passive AP observation; `test_soft_ap` measures Android/host local
SoftAP creation. It supports a
NAN+NOW-only ESP pair (`udp6=false`) and an Android path (`now=false,
udp6=true`) without minting distinct APIs.

The response records per-endpoint mode replacement/BSSID-association timing,
whether a requested colocated AP stayed active, per-endpoint SoftAP outcomes,
and source/target scan counts (all APs, channel-6 APs, DMesh
candidates, and the last DMesh RSSI),
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

## Direct messages and DCID forwarding setup

A direct message carries the DMesh custom-version QUIC long header with empty
DCID/SCID fields and a four-byte packet number, followed directly by one
tagged-CBOR record. Its version-specific packet type distinguishes it from
connection setup; it does not carry a QUIC frame, create endpoint
state, consume stream credit, ACK, retransmit, or use flow control. Direct
messages are appropriate for idempotent desired-state commands and small
responses; a record with key `3` (`id`) requests a correlated response on a
separately routed direct message. Connection setup uses the Initial-shaped long
header and its official source/destination CID fields.

Component `5` configures independent one-way forwarding rules. It is accepted
through the stream handler surface; the first portable
implementation supplies the codec and a bounded unified DCID registry, while
platform adapters still own next-hop resolution and egress.

| Method | Name | Fields |
| ---: | --- | --- |
| 1 | `relay.apply` | `1:allocation`, `6:revision`, `7:present`; when present, optional `2:proposed_dcid` plus `3:next_hop`, `4:outbound_dcid`, `5:position` |
| 2 | `relay.pair` | one forward rule plus `11..16` reverse allocation/DCID/next-hop/outbound/position/revision fields |
| 3 | `relay.list` | empty request; returns active mappings, capacity, and active QUIC association snapshots |
| 4 | `relay.rm` | `21:dcid`, `22:revision`; removes the paired entries for that local DCID |

`next_hop` is a device-local opaque route handle. It is neither an overlay
identity nor source-path metadata and it is never put in a forwarded packet.
The initial portable NOW handle is `transport_id << 56 | mac48`, with the
reserved byte at bits 48--55 equal to zero. Main validates that representation
and binds it to a directed `EspNowPeer` while handling `relay.apply`; invalid,
zero, broadcast, and unsupported bearer handles fail closed. UDP6 uses a
transport-tagged controller token because a link-local IPv6 address and UDP
port do not fit in this compact value. During `relay.pair`, Main binds that
token to the complete request-ingress tuple. The two rules are transactionally
reconciled locally but remain independent directional DCID entries.
The relay accepts a proposed local DCID or later returns a locally allocated
one. `outbound_dcid=0` means the final next hop receives a direct message;
nonzero values select another relay rule or a QUIC endpoint. A forward and its
return path remain separate setup records. Repeating an equal allocation with
the same request `id` is an idempotent retry: it returns the current result and
does not consume another rule slot; a different target for the same local DCID
is rejected.

`relay.list` is read-only and is served on a normal QUIC stream. Its result is
`{1: active, 2: capacity, 3: rules, 4: connections, 5: last_close_monotonic}`.
`last_close_monotonic` is `0` until a peer has completed a QUIC CLOSE and is
retained after that association is released. Each rule contains its
local DCID, outbound DCID, current revision, resolved device-local next-hop,
and (when an association is active) field `5`, that endpoint's receive CID.
The compact CBOR next-hop value is typed as `{1: transport_id, 2:
address_bytes, 3: udp_port?}`: NOW carries its MAC and UDP6 carries its real
IPv6 address and port. The opaque UDP6 token is never returned; the HTTP
control plane renders the typed result as, for example, `udp://[fe80::...]:3339`.

Each `connections` entry is association state from `quic-lite`, not a
per-bearer cache: `{1: receive_cid, 2: peer_cid, 3: streams, 4: active_path?,
5: valid_paths, 6: last_close_monotonic?, 7: packet_stats}`. `streams` has
locally initiated (`1`) and peer initiated (`2`) directions, each `{1: active,
2: total}`. A valid packet received on a new UART, UDP, or NOW path changes
only `active_path`; the CIDs and stream totals remain on the same association.

`relay.rm` is an authenticated stream operation. Its revision guards the
named local mapping (the forward mapping can legitimately have a newer
revision after relay-open updates its outbound DCID). If that mapping is still
current, the relay removes it, its paired reverse mapping, relay-open metadata,
and any no-longer-used local route binding. Missing DCIDs return `false`; a
stale revision is rejected.

### Relay-open CID ownership

`relay.pair` is the only bootstrap exception to otherwise opaque DCID
forwarding. It does **not** make the relay a QUIC endpoint: the client and
server still each choose their own receive CID. It gives the relay two local
aliases, one for each direction, and binds the reverse bearer route to the
client's stable UDP tuple.

```
 client (CID C)                 relay (aliases F, R)                  server (CID S)
 ──────────────                 ────────────────────                  ──────────────
 relay.pair(F?, R?, client=C) ───────────────────────────────────────►
                         ◄──── observed pair(F, R); F/R may differ from F?/R?

 OPEN: outer DCID=F, body client_receive_cid=C ───────────────────────►
                         relay-open: outer DCID -> 0; body CID C -> R ─► OPEN
                                                                    ◄── ACK: DCID=R, server CID=S
                         reverse rule: DCID R -> C ────────────────────► ACK: DCID=C, server CID=S

 later client packet: outer DCID=F ─► forward rule: F -> S ───────────►
 later server packet: outer DCID=R ◄─ reverse rule: R -> C ◄───────────
```

The client must first generate its own nonzero receive CID `C`, request a
pair, and use the **observed** forward alias `F` returned by the relay—not its
proposal—for relay-open. The relay changes the plaintext bootstrap OPEN once:
it substitutes `R` for `C` in `client_receive_cid` and forwards the outer
packet with DCID zero. The server consequently sends its OPEN_ACK to `R`; the
normal reverse rule rewrites that outer DCID to `C` before delivery to the
client. After ACK, the server's independently chosen CID `S` is installed as
the forward rule's outbound DCID. All subsequent packets are opaque DCID
rewrites. A client retry uses the same `C` and UDP source port; the desired
state response makes the relay aliases stable unless a collision caused a
different observed pair.

The aliases are intentionally hop-local.  They are not a single circuit label
that every relay can correlate.  In the forward direction, each relay replaces
the alias by the one meaningful to its next hop; only the final relay replaces
its last-hop alias by the server-selected receive CID `S`.  The reverse path is
independent and ends at the client-selected receive CID `C`:

```text
 client       relay A          relay B          egress          server
   ── F0 ──► [F0 -> F1] ──► [F1 -> F2] ──► [F2 -> S] ───────► CID S

 client       relay A          relay B          ingress         server
 CID C ◄──── [R1 -> C] ◄──── [R2 -> R1] ◄──── [R3 -> R2] ◄──── R3
```

Thus the first relay knows only `F0` and `F1`, a middle relay knows only its two
adjacent aliases, and the last relay alone learns `S`.  With independently
allocated reverse aliases, a foreign middle relay cannot learn either endpoint
CID or the complete circuit from forwarding state.  This is the required
privacy property when the mesh owner controls the first and last relays but
intermediate relays are untrusted.

Circuit construction belongs to `dmesh-server`, above individual L2 adapters
and outside the QUIC endpoint. It selects an adjacent next hop and returns the
local alias for that leg. UDP6, UART, NOW, FSK, and BLE-CoC adapters only
deliver bounded packets to that adjacent peer and apply the installed
alias-to-alias forwarding rule.

AEAD does not prevent this translation.  The sending endpoint protects the
packet using the header that the receiving endpoint will see: in the forward
direction that header contains `S`.  After packet protection, the first-hop
adapter substitutes `F0`; relays translate only that fixed-width field; and the
egress restores `S` before the server removes header protection or verifies
AEAD.  The ciphertext and every other authenticated header byte remain
unchanged, so both endpoints authenticate the same canonical header even
though intermediate links carried hop-local aliases.  The reverse direction
works identically with `C` as its canonical destination CID.

This encoding also preserves the privacy property: no plaintext copy of the
canonical packet or final CID accompanies the alias.  A simple outer alias in
front of an otherwise visible QUIC packet would expose `S` to every relay and
is therefore not an acceptable replacement.  Long-header support still needs
separate design and tests for its explicit CID lengths, exposed source CID,
Initial-key derivation, and bootstrap sequencing; it does not require changing
the established short-header alias model.

`relay::install_symmetric_chain` is the CP-side handler for the initial
`[source, relay..., destination]` form. Each `ChainNode` supplies the transport
used to reach that node and either a six-byte MAC (`NOW`) or an IPv6 link-local
address (`UDP6`). The adapter resolves that description at the relay being
configured, exchanges the direct setup request, and must verify its matching
response ID before advancing. It creates forward and return labels over the
same relay sequence; the transports may differ by direction because each
next-hop description is resolved locally.

## Signed objects and flash

`signed_object` identifies an immutable image with
`{0:name?,1:cpu,2:target}`. The host-side `ObjectServer` resolves that identity
to one object body. On the wire the object-data stream is exactly one complete
canonical CBOR manifest followed immediately by `image_size` raw binary bytes
and QUIC FIN. There is no per-block CBOR or private manifest/blob/done framing.

`flash` is the device-handler contract, not an ESP transport feature. Its body extends
the same object identity with optional `address` and `transport` plus
`dry_run`: `{0:name?,1:cpu,2:target,3:address?,4:transport,5:dry_run}`.
The host sends that body and the device feeds ordinary ordered stream bytes to
`SignedObjectReceiver`. The CBOR decoder reports the exact manifest boundary;
the receiver validates the signed manifest before admitting body data, derives
block indexes and lengths from it, verifies the body incrementally, and calls
an injected sink. Firmware injects the erase/write partition sink; host tests
inject `FileImageSink`. Invalid manifest, length, proof, digest, or sink state
is an application rejection and terminates the stream/operation.

The host owns object selection and opens one QUIC-lite association containing
the `flash` command stream and the ordered object-data stream. The device sends
the correlated command response only after the sink is complete and durable;
the request handler does not wait or block a bearer task.

Only one association may own a mutable object sink at a time. The shared
`ExclusiveTransfer` state admits and constructs that operation atomically from
the application's point of view, without allocating for a contender. A request
from another association receives the correlated application error
`flash already in progress`; it cannot replace, release, or feed the incumbent
operation. Only completion, rejection, owner close, or the bounded application
idle timeout releases it. Multicast Recovery announcements are discovery and
never imply automatic transfer ownership.

The sink must be nonblocking on the receive path. It returns stream credit
only after accepted bounded storage is available; failure aborts the transfer. No
transport, UART, or radio adapter may create a private unbounded queue for
flash records.

Firmware derives its bounded storage-slot count from current available memory
with `bounded_storage_slots`, then fallibly allocates those slots and advertises
only the byte capacity actually obtained. The slot count is application sink
configuration that host tests can inject; it is never a QUIC packet or bearer
credit constant. Receiver storage is allocated before the platform sink factory
runs, so allocation failure cannot leave a flash worker or file handle behind.

Stream consumers enter through `prepare_inbound_stream` and
`consume_inbound_stream`. The latter gives the application an ordered reader;
each `read()` copies only the bytes the handler has accepted into its bounded
parser or storage buffer, then the dispatcher publishes the corresponding
reclaimed window. The handler neither observes QUIC chunks nor chooses a
window. Exclusive mutable sinks use `consume_exclusive_inbound_stream`, which
adds only association ownership and application-progress timeout refresh; both
ordinary receive and asynchronous storage-ready turns use that same helper.
An application-consumer failure removes and returns the failed operation with
its request ID, allowing the handler to send one correlated error and admit a
later request immediately; a transport publication error retains it because
already-consumed application state must not be discarded.
Raw chunk extraction and QUIC receive-window mutation are private to the shared
transport module, so firmware flash, host file storage, and future upload probes
cannot grow separate ACK, credit, or operation-liveness loops.

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

`radio.control` fields are optional: omitted means unchanged.  They are
command-scoped and must never modify NVS or influence a subsequent reboot.

Reachability checks are not radio laboratory operations. `check` sends a
directed `announce.discovery` request and expects the normal signed announce;
throughput uses the bearer-neutral `probe` QUIC stream. There is no
`radio.check`, raw-bearer echo, or Wi-Fi-specific probe handler.

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
| `ap_mode` | 13 | enum | `disabled` or ephemeral fixed-WPA2 APSTA owner |
| `ap_beacon_tu` | 14 | `u16` | AP beacon interval, 100..60000 TU; supplied with `ap_mode=open` |
| `raw_sta_mode` | 15 | enum | `main_style`: Main's idempotent idle-STA start, unassociated and prom off |
| `mac_ack` | 16 | bool | request driver MAC ACK for raw action TX; disabled by default so QUIC-lite owns loss recovery |
| `action_destination_broadcast` | 20 | bool | send NOW-like action Address-1 as broadcast; an explicit non-promiscuous ROC/filter experiment |
| `roc_listen_ms` | 25 | `u16` | request one 10..1000 ms same-channel ESP-IDF remain-on-channel action listener; rejected when the driver cannot accept the requested ROC mode |

`ap_mode=open` retains its legacy method name but starts a channel-selected
WPA2 APSTA radio owner with Android's fixed `DIRECT-dmesh` SSID and
`untrusted-open-mode` PSK. It creates
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
It also returns the QUIC probe client's delivered bytes and device-monotonic
elapsed microseconds. A caller may derive goodput from those two fields; its
own completion latency remains a separately reported host-observation metric.

## Reachability and probe services

Reachability is bearer-independent. The operator-facing `check` operation
sends a directed `announce.discovery` request and expects the peer's signed
announce; there is no `wifi.raw.check` or raw-bearer echo operation.
Throughput and loss measurements use the normal QUIC `probe` stream service.
Radio snapshots remain separate observations and do not initiate a connection.

The machine-readable schema is
[`schemas/radio-lab.schema.json`](schemas/radio-lab.schema.json).  The
`dmesh-cli` firmware schema catalog imports its method/field tags and types so
the same records are sent through the normal QUIC hardware-service stream.
