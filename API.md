# DMesh API

This is the sole human-readable DMesh service contract. Requests and responses use
tagged CBOR with the numeric component, method, and field tags shown below.
`lmesh` is the Linux service name; its daemon integrates the Linux radio handlers
with the shared DMesh handlers. HTTP endpoints accept and return JSON, translating
at the boundary to the same tagged records. Android platform plumbing may still
use JSON internally. The installed command catalog is
[`crates/lmesh/resources/tools.json`](crates/lmesh/resources/tools.json).

Examples use a catalogued device name and the managed Linux service:

```sh
dmesh-cli DEVICE telemetry.nan_status
dmesh-cli DEVICE transport.set --mode=6 --nan_dw_interval=1 --now=1
dmesh-cli DEVICE transport.set --1=6 --14=1 --15=1
```

`DEVICE` is a node name (or FQDN, or VIP6) found in the node records (`DMESH_NODES_DIR`; `dmesh-cli devices sync` records the nodes it can see). Use `--field=value` or the numeric
`--tag=value` form for declared request fields. The corresponding HTTP JSON
endpoint uses the method name and field names from this document; see
[`crates/dmesh-cli/README.md`](crates/dmesh-cli/README.md) for transport,
flash, reset, logs, and NAN wake examples.

Each method carries a **Platforms:** marker listing the platforms that
register a CBOR handler for it: `A` = Android (`crates/dmesh-android`),
`L` = Linux (`lmesh`), `E` = Embedded (`fw/main`). Every handler is
registered through the one `dmesh_server::registry` (component and method
numbers plus names); a platform registers only methods it implements. A
method that is absent, or would only be a stub, is not registered, is not
marked, and is not listed by `services`; a request for it receives the shared
numeric "unsupported or invalid stream request" error. A platform that lists
a method in a catalog or schema without registering a handler is not marked.
Response fields are optional unless a table has a `Required` column marking
them `yes`; required fields must be present even when their value is zero.

Every method is a handler on a bidirectional stream: a header, then an optional
raw body, with FIN after the body. How a stream is laid out and dispatched is
defined once for all mesh APIs in the ssh-mesh
[Handler streams](https://github.com/costinm/ssh-mesh/blob/main/crates/mesh-api/PROTOCOLS.md#handler-streams-header-and-body)
contract; this document defines only the methods, their header fields, and,
where a method has one, what its body contains.

<!-- dmesh-api:portable -->

# `discovery` API (6)

## 9. `nodes` — Return the retained cross-bearer observed-device inventory

**Platforms:** A L E

**UI:** default

### Response

The binary QUIC response contains a result map whose field `1` is an array of
observer-local device rows. HTTP returns the same information as
`{"devices":[...]}`. A stable `device_id` is the merge key; `peer` is an
optional bearer-local correlation address and is never a device identity.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `device_id` | `bytes` | Stable signed identity hint; empty for a provisional observation. |
| 2 | `peer` | `bytes[6]` | Optional observer-local radio address; all-zero means unavailable. |
| 3 | `bssid` | `bytes[6]` | Optional receiver-side BSSID. |
| 4 | `available_fields` | `u32` | Observation capability bitset: peer=1, BSSID=2, channel=4, RSSI=8, payload fingerprint=16. |
| 5 | `first_seen_ms` | `u32` | Observer-local first receipt time; zero or max means unavailable. |
| 6 | `last_seen_ms` | `u32` | Observer-local last receipt time; zero or max means unavailable. |
| 7 | `packets` | `u32` | Total admitted discovery packets. |
| 8 | `active_publish_rx` | `u32` | Active Publish receipts. |
| 9 | `active_subscribe_rx` | `u32` | Active Subscribe receipts. |
| 10 | `followup_rx` | `u32` | Follow-up receipts. |
| 11 | `last_kind` | `u8` | Last discovery packet kind. |
| 12 | `last_payload_len` | `u16` | Payload length metadata; payload is not retained here. |
| 13 | `last_payload_hash` | `u32` | Non-secret payload fingerprint. |
| 14 | `unavailable_fields` | `u32` | Explicit complement of `available_fields`. |
| 15 | `channel` | `u8` | Optional receiver-side capture channel. |
| 16 | `bearer` | `string` | Bearer of this row's observation: `udp_multicast`, `nan`, `now`, `ble`. A device seen on several bearers has one row per bearer, all with the same `device_id`. |
| 17 | `rssi_dbm` | `i16` | Last signal strength of this observation, when the bearer reports one. |
| 18 | `name` | `string` | Device name from its announce. |
| 19 | `vip6` | `bytes` | The device's 16-byte virtual IPv6 address. |
| 20 | `device_class` | `u8` | Announced device class (ESP=1, host=2, Android=3, ...). |
| 21 | `probe_capabilities` | `u16` | Announced probe capability set. |
| 22 | `authenticated` | `bool` | The announce carried a public key whose signature verified. |
| 23 | `uptime_secs` | `u32` | Producer-relative uptime from its announce. |
| 24 | `udp_endpoint` | `string` | Where the device accepts QUIC over UDP (advertised address and port, with this receiver's interface scope); absent when it has no UDP path, such as a device seen only over NAN or BLE. |
| 25 | `network_name` | `string` | Shared network label from its announce. |

Fields 1 to 15 are the compact form every platform sends. Fields 16 and up come from
the announce, so a platform that has it (Android, Linux) includes them and a device
that only has an identifier (firmware) omits them; an absent field is unknown, not
empty.

### Device record

Linux, Android and the CLI persist one device record (`dmesh_server::device_record::DeviceRecord`,
one TOML file per device, keyed by the low 64 bits of its VIP6, or by its MAC while the identity is
unknown) holding the long- and medium-lived facts about a device: optional `name`, `domain`,
`device_type`, radio `mac`, signed `public_key`, `vip6`, static addresses, wake capability, `trust`
(`first-seen`, `paired`, `verified`) and transport `endpoints`. A record may also hold a `secret`
and the control-plane `root_public_key`, whether or not this controller paired the device; where
secrets are stored may change with the security work. A record with a secret is a mode-0600 file in
a mode-0700 directory, the secret is redacted from debug output, and it is never returned by
`discovery.nodes` or an HTTP/UI handler. Live endpoints, last-seen, RTT and sleep state are not
stored. Pairing and discovery observations are producers of this record, merged without replacing a
secret or lowering trust; there is no alternate device schema.

The advertised `vip6` is always the complete 16-byte ULA. RFC 4193 allocates
`fc00::/7`: the following `L` bit selects centrally assigned (`0`) or locally
assigned (`1`, conventionally `fd00::/8`) space. For locally provisioned DMesh
devices, the next 40-bit Global ID is derived from the provisioned owner root
CA, the following 16-bit subnet ID is initially zero, and the low 64 bits are
the device identity hint. An all-zero 40-bit owner ID marks an unconfigured
device; receivers must not infer common ownership from the fixed ULA bits.

## 10. `active` — Run one discovery pass on every available local bearer

**Platforms:** A L E

The handler fans out locally to all currently owned discovery adapters (for
example UDP multicast, NAN, BLE, or UART). It is not a path-selection hint for
QUIC and does not queue application traffic behind a busy bearer. Each adapter
only reports observations it actually received; callers subsequently read the
merged `discovery.nodes` inventory.

Discovery is one principle on every medium: the same signed request (the
`announce.discovery` record), answered by the same signed announce, whether it
travels as a UDP datagram, a NAN service-discovery frame (service info) or a NOW
action. The record is the payload; the medium only changes the envelope. A node
that owns a WLAN (Linux with a configured interface, the firmware) answers a request
that arrives on NOW. Android answers on NAN only.

A request is sent immediately, as a multicast would be, and also in the next
discovery windows, including DW0 and DW8 (a sleepy peer listens only then), on both
NOW and NAN. `to` selects one peer: a `udp://` endpoint, or on Linux a MAC address
(the request is addressed to that peer on NOW and on NAN, with the same repeats), whose
reply is awaited. A `nan.wakeup` is a NAN service-discovery request too and is sent the
same way, on NAN and on NOW, so a Linux host and firmware that sync on NOW fake-beacons
(no Android device running NAN) can wake each other. A directed check of a path (does a QUIC association
work over this bearer) is a different thing: it is `probe`.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 40 | `medium` | `string` | Preferred radio medium, if known. |
| 41 | `to` | `string` | Optional target device identity. |


# `telemetry` API (7)

## 1. `nan_status` — Return local NAN attach, cluster, synchronization, and publish state

**Platforms:** A L E

**UI:** default

Every field is optional: an absent field means the platform cannot observe it, never
`false` or zero. The same record on Android, Linux and the firmware.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `active` | `bool` | The local NAN adapter or runtime is attached and operational. |
| 2 | `cluster_id` | `bytes` | Current cluster identifier, normally the six-byte cluster BSSID. |
| 3 | `sync_id` | `bytes` | Current synchronization-master identifier, when the stack exposes it. |
| 4 | `publishing` | `bool` | The periodic DMesh announce publish is active. |
| 5 | `publish_pending` | `bool` | A publish was requested but is not active yet. |

## 2. `now` — Return local ESP-NOW submission, receive, admission, dispatch, drop, and error counters

**Platforms:** L E

Counters are `u64`, monotonic since boot, and an unavailable value is omitted, never sent as zero. The tag of each field is also the metric id used on the wire by every platform.

### Response

Linux reports the three it can derive from the monitor events it retains: `rx_dispatched` (frames dispatched), `rx_accepted` (action frames seen) and `rx_rejected` (dispatch errors). The counts cover only the retained history.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `tx_attempted` | `u64` | Calls made to the serialized ESP-NOW action sender. |
| 2 | `tx_accepted` | `u64` | NOW requests accepted by ESP-IDF. This is local submission evidence, not evidence that a peer received the frame. |
| 3 | `tx_failed` | `u64` | NOW sender calls rejected before ESP-IDF accepted the frame. |
| 4 | `rx_dispatched` | `u64` | Rx dispatched. |
| 5 | `rx_accepted` | `u64` | Rx accepted. |
| 6 | `rx_rejected` | `u64` | Rx rejected. |
| 7 | `rx_self_echo` | `u64` | Rx self echo. |
| 8 | `rx_dropped` | `u64` | Rx dropped. |
| 9 | `registered_actions` | `u64` | Registered actions. |
| 10 | `registered_drops` | `u64` | Registered drops. |
| 11 | `last_roc_body_prefix` | `u64` | First four bytes of the last ROC action body, in network byte order. This is framing evidence, not application payload retention. |
| 12 | `last_roc_body_len` | `u64` | Bounded byte length of the last ROC action body. |
| 13 | `rx_invalid_drops` | `u64` | Rx invalid drops. |
| 14 | `rx_busy_drops` | `u64` | Rx busy drops. |
| 15 | `rx_shared_ingress_drops` | `u64` | Rx shared ingress drops. |
| 16 | `last_registered_body_prefix` | `u64` | Last registered body prefix. |
| 17 | `last_registered_body_len` | `u64` | Last registered body len. |
| 18 | `tx_busy` | `u64` | NOW submit calls refused for temporary ESP-IDF memory pressure. |

## 3. `nan` — Return local NAN beacon, SDF, Service Info, Follow-up, dispatch, drop, and error counters

**Platforms:** L E

Counters are `u64`, monotonic since boot, and an unavailable value is omitted, never sent as zero. The tag of each field is also the metric id used on the wire by every platform. Fields with a `_us` suffix are gauges (a duration or time), not counters.

### Response

Linux reports `beacons`, the raw-NAN monitor's beacon count, and no other field.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `beacons` | `u64` | Beacons. |
| 2 | `sdfs` | `u64` | Sdfs. |
| 3 | `followups_rx` | `u64` | Followups rx. |
| 4 | `followups_queued` | `u64` | Followups queued. |
| 5 | `followups_sent` | `u64` | Followups sent. |
| 6 | `followups_dropped` | `u64` | Followups dropped. |
| 7 | `service_info_matched` | `u64` | Service info matched. |
| 8 | `service_info_enqueued` | `u64` | Service info enqueued. |
| 9 | `service_info_dropped` | `u64` | Service info dropped. |
| 10 | `service_info_dispatched` | `u64` | Service info dispatched. |
| 11 | `active_publish_attempted` | `u64` | Active publish attempted. |
| 12 | `active_publish_sent` | `u64` | Active publish sent. |
| 13 | `active_publish_dropped` | `u64` | Active publish dropped. |
| 14 | `active_discovery_queued` | `u64` | Common `discovery.active` requests admitted by the Main owner. |
| 15 | `active_discovery_sent` | `u64` | Active-discovery Subscribe SDFs accepted by the Wi-Fi action submitter. |
| 16 | `active_discovery_dropped` | `u64` | Active-discovery Subscribe SDF driver submission failures. |
| 17 | `dw8_radio_stop_us` | `u64` | Time spent stopping STA/AP/NAN/NOW before the most recent DW8 sleep. |
| 18 | `dw8_radio_resume_us` | `u64` | Time from timer wake to restored NAN/NOW receive ownership. |
| 19 | `dw8_awake_us` | `u64` | Total awake time from a DW8 timer wake to the following sleep entry. |
| 20 | `last_sdf_after_beacon_us` | `u64` | Last received NAN SDF relative to the selected cluster beacon. |
| 21 | `last_sdf_frame_bytes` | `u64` | Byte length of the last raw SDF admitted by promiscuous ingress. |
| 22 | `last_sdf_source_le` | `u64` | Last raw SDF source MAC packed little-endian into the low 48 bits. |
| 23 | `small_sdf_max_bytes` | `u64` | Largest raw SDF at or below 128 bytes observed since boot. |
| 24 | `small_sdf_max_source_le` | `u64` | Source of the frame which established `SMALL_SDF_MAX_BYTES`. |
| 25 | `pending_sdf_queued` | `u64` | SDF semantic intents accepted since boot. |
| 26 | `pending_sdf_rejected` | `u64` | SDF intent requests rejected because all bounded slots were occupied. |
| 27 | `pending_sdf_tx_attempted` | `u64` | DW-gated public-action submissions attempted for all SDF intents. |
| 28 | `pending_sdf_tx_accepted` | `u64` | SDF submissions accepted by the Wi-Fi action driver. |
| 29 | `pending_sdf_completed` | `u64` | Intents whose requested bounded transmission count was consumed. |
| 30 | `pending_sdf_count` | `u64` | Current number of independently retained SDF intents. |
| 31 | `light_sleep_attempts` | `u64` | Explicit timer-light-sleep attempts made by Main's DW policy. |
| 32 | `light_sleep_entries` | `u64` | Successful `esp_light_sleep_start` entries, rather than requested sleep. |
| 33 | `light_sleep_skipped` | `u64` | Rejected timer/light-sleep calls; this must not be treated as a wake. |
| 34 | `last_sleep_requested_us` | `u64` | Most recent requested timer duration for an explicit DW sleep. |
| 35 | `last_sleep_duration_us` | `u64` | Measured duration inside the most recent light-sleep call. |
| 36 | `first_frame_after_wake_us` | `u64` | First management frame observed after the most recent explicit wake. Zero means no frame arrived before the next sleep boundary. |
| 37 | `first_beacon_after_wake_us` | `u64` | First NAN beacon observed after the most recent explicit wake. Zero means the selected beacon was missed in that window. |

## 4. `udp6` — Return local raw IPv6 validation, UDP delivery, NDP, transmit, and failure counters

**Platforms:** L E

Counters are `u64`, monotonic since boot, and an unavailable value is omitted, never sent as zero. The tag of each field is also the metric id used on the wire by every platform.

### Response

Linux reports `rx_invalid` only: discovery datagrams that failed validation.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `rx_frames` | `u64` | Rx frames. |
| 2 | `rx_queue_drops` | `u64` | Rx queue drops. |
| 3 | `rx_invalid` | `u64` | Rx invalid. |
| 4 | `udp_delivered` | `u64` | Udp delivered. |
| 5 | `ndp_advertisements` | `u64` | Ndp advertisements. |
| 6 | `tx_failures` | `u64` | Tx failures. |
| 7 | `raw_tx_completions` | `u64` | Raw tx completions. |
| 8 | `raw_tx_completion_failures` | `u64` | Raw tx completion failures. |

## 5. `wifi_link` — Return common optional per-peer Wi-Fi link observations

**Platforms:** L E

Optional fields distinguish unavailable driver telemetry from a measured zero. A device describes its one peer in the top-level fields; a host with several peers sends a `links` array of such rows and no top-level peer fields.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `schema_version` | `u8` | Record schema version. |
| 2 | `interface_index` | `u32` | Interface index. |
| 3 | `peer_mac` | `bytes` | Peer MAC address. |
| 4 | `rx_bytes` | `u64` | Bytes received from the peer. |
| 5 | `tx_bytes` | `u64` | Bytes sent to the peer. |
| 6 | `rx_packets` | `u64` | Packets received. |
| 7 | `tx_packets` | `u64` | Packets sent. |
| 8 | `mac_tx_retries` | `u64` | Driver MAC transmit retries. |
| 9 | `mac_tx_failed` | `u64` | Driver MAC transmit failures. |
| 10 | `rx_dropped` | `u64` | Received frames dropped. |
| 11 | `rx_airtime_us` | `u64` | Receive airtime. |
| 12 | `tx_airtime_us` | `u64` | Transmit airtime. |
| 13 | `signal_dbm` | `i8` | Last signal strength. |
| 14 | `signal_avg_dbm` | `i8` | Average signal strength. |
| 15 | `ack_signal_dbm` | `i8` | Last ACK signal strength. |
| 16 | `ack_signal_avg_dbm` | `i8` | Average ACK signal strength. |
| 17 | `rx_bitrate_kbit_s` | `u64` | Receive bitrate. |
| 18 | `tx_bitrate_kbit_s` | `u64` | Transmit bitrate. |
| 19 | `expected_throughput_kbit_s` | `u64` | Driver-expected throughput. |
| 20 | `bearer_rx_frames` | `u64` | Raw bearer frames received. |
| 21 | `bearer_rx_drops` | `u64` | Raw bearer receive drops. |
| 22 | `bearer_rx_invalid` | `u64` | Raw bearer invalid frames. |
| 23 | `bearer_udp_delivered` | `u64` | UDP datagrams delivered from this bearer. |
| 24 | `bearer_ndp_advertisements` | `u64` | Neighbor advertisements sent. |
| 25 | `bearer_tx_failures` | `u64` | Raw bearer transmit failures. |
| 26 | `raw_tx_completion_failures` | `u64` | Raw injection MAC completion failures. |
| 27 | `links` | `WifiLink[]` | One row per peer, each with the fields above, for a host that tracks several peers (a Linux AP's stations). A device reports its one peer in the top-level fields instead. |

One `links` row has fields 1 to 26 above, with the same tags and meanings.

`WifiLink` fields:

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `schema_version` | `u8` | Record schema version. |
| 2 | `interface_index` | `u32` | Interface index. |
| 3 | `peer_mac` | `bytes` | Peer MAC address. |
| 4 | `rx_bytes` | `u64` | Bytes received from the peer. |
| 5 | `tx_bytes` | `u64` | Bytes sent to the peer. |
| 6 | `rx_packets` | `u64` | Packets received. |
| 7 | `tx_packets` | `u64` | Packets sent. |
| 8 | `mac_tx_retries` | `u64` | Driver MAC transmit retries. |
| 9 | `mac_tx_failed` | `u64` | Driver MAC transmit failures. |
| 10 | `rx_dropped` | `u64` | Received frames dropped. |
| 11 | `rx_airtime_us` | `u64` | Receive airtime. |
| 12 | `tx_airtime_us` | `u64` | Transmit airtime. |
| 13 | `signal_dbm` | `i8` | Last signal strength. |
| 14 | `signal_avg_dbm` | `i8` | Average signal strength. |
| 15 | `ack_signal_dbm` | `i8` | Last ACK signal strength. |
| 16 | `ack_signal_avg_dbm` | `i8` | Average ACK signal strength. |
| 17 | `rx_bitrate_kbit_s` | `u64` | Receive bitrate. |
| 18 | `tx_bitrate_kbit_s` | `u64` | Transmit bitrate. |
| 19 | `expected_throughput_kbit_s` | `u64` | Driver-expected throughput. |
| 20 | `bearer_rx_frames` | `u64` | Raw bearer frames received. |
| 21 | `bearer_rx_drops` | `u64` | Raw bearer receive drops. |
| 22 | `bearer_rx_invalid` | `u64` | Raw bearer invalid frames. |
| 23 | `bearer_udp_delivered` | `u64` | UDP datagrams delivered from this bearer. |
| 24 | `bearer_ndp_advertisements` | `u64` | Neighbor advertisements sent. |
| 25 | `bearer_tx_failures` | `u64` | Raw bearer transmit failures. |
| 26 | `raw_tx_completion_failures` | `u64` | Raw injection MAC completion failures. |

## 6. `battery` — Return the latest portable battery and power snapshot

**Platforms:** A

`BatteryState` is the shared optional state for Android, ESP32, and Linux.
Android currently produces it; the other adapters may leave fields absent
until they implement an observer. Unknown values are omitted, not replaced
with zero or false. Durations are measured in milliseconds by the reporting
adapter; `idle_ms` and `charging_ms` describe the current interval, while
`total_idle_ms` accumulates since that adapter started.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `battery_percent` | `u8` | Charge level from 0 to 100. |
| 2 | `charging` | `bool` | Power source is charging the battery. |
| 3 | `power_save` | `bool` | Platform power-saving mode is active. |
| 4 | `idle` | `bool` | Platform idle or sleep mode is active. |
| 5 | `idle_ms` | `u64` | Elapsed time in the current idle interval. |
| 6 | `total_idle_ms` | `u64` | Accumulated idle time since observer start. |
| 7 | `charging_ms` | `u64` | Elapsed time in the current charging interval. |

## 7. `quic` — Return aggregate QUIC counters for live associations

**Platforms:** A L E

**Rust CBOR:** generated

These are QUIC-core counters summed over associations with an active QUIC
endpoint on the node. They reset when an association is removed or the node
restarts. Packet ACKs and retransmission counters describe transport
processing; they do not prove that an application consumed or committed stream
data. Bearer submission and receive/drop metrics remain in the bearer-specific
telemetry methods. Like the sibling telemetry handlers, this returns a
documented QUIC-specific counter set rather than a general process-metrics
dump.

### Response

| Tag | Field | Type | Required | Description |
|---:|---|---|---|---|
| 1 | `live_associations` | `u64` | yes | Associations currently included in this snapshot. |
| 2 | `received_packets` | `u64` | yes | Valid QUIC packets received. |
| 3 | `sent_packets` | `u64` | yes | QUIC packets emitted. |
| 4 | `received_stream_packets` | `u64` | yes | Received packets containing stream data. |
| 5 | `received_control_packets` | `u64` | yes | Received packets containing only control frames. |
| 6 | `sent_stream_packets` | `u64` | yes | Emitted stream packets, including retransmissions. |
| 7 | `sent_control_packets` | `u64` | yes | Emitted ACK and control packets. |
| 8 | `duplicate_packets` | `u64` | yes | Duplicate received packets. |
| 9 | `out_of_order_packets` | `u64` | yes | Out-of-order received packets. |
| 10 | `inferred_missing_packets` | `u64` | yes | Missing packet numbers inferred from receive progress. |
| 11 | `retransmitted_packets` | `u64` | yes | Packets sent again after initial transmission. |
| 12 | `loss_events` | `u64` | yes | Loss-detection events. |
| 13 | `submission_failures` | `u64` | yes | Bearer submission failures reported to QUIC. |

## 8. `quic_associations` — Return QUIC transport state for each live association

**Platforms:** A L

Target platforms: A L E; registered on A and L from the node's per-association
state (a client association counts once it is established). The first-path bearer
and peer come from the node; `streams_local_active` and `streams_peer_active` are
not filled yet.

One row per live association; the same counters as `quic`, per association,
plus send-credit state. Round-trip time and congestion window are not listed
because `quic-lite` does not expose them yet.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `associations` | `QuicAssociation[]` | One row per live association. |

`QuicAssociation` fields:

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `association` | `u64` | Association id, local to this node. |
| 2 | `bearer` | `string` | Bearer name the association uses (`udp`, `now`, `nan`, `uart`, `ble`, `usb`). |
| 3 | `peer` | `string` | Bearer-local peer address, as `discovery.nodes` reports it. |
| 4 | `received_packets` | `u64` | Valid packets received. |
| 5 | `sent_packets` | `u64` | Packets emitted. |
| 6 | `retransmitted_packets` | `u64` | Packets sent again. |
| 7 | `loss_events` | `u64` | Loss-detection events. |
| 8 | `submission_failures` | `u64` | Bearer submission failures. |
| 9 | `bytes_in_flight` | `u64` | Stream bytes awaiting peer ACKs. |
| 10 | `peer_max_data` | `u64` | Peer-advertised connection send credit. |
| 11 | `peer_sent_data` | `u64` | New stream bytes charged against that credit. |
| 12 | `largest_acked_by_peer` | `u32` | Largest packet number the peer acknowledged. |
| 13 | `streams_local_active` | `u64` | Locally opened streams without a FIN. |
| 14 | `streams_peer_active` | `u64` | Peer-opened streams without a FIN. |

## 9. `bearers` — Return common counters for each bearer

**Platforms:** A L E

Target platforms: A L E. E reports a row for `now` and `udp6` (the bearers that keep
these counters); A and L report a row for every bearer registered on the QUIC node,
from the node's own per-bearer counters. Fields a bearer does not count are omitted
(`rx_rejected` is not kept by the node).

One row per bearer the node runs. These are the bearer's own submission and
receive facts; QUIC's view of the same traffic is in `quic`. Bearer-specific
detail stays in that bearer's method (`ble.status`, `now`, `nan`, `udp6`).

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `bearers` | `BearerCounters[]` | One row per bearer. |

`BearerCounters` fields:

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | `udp`, `now`, `nan`, `uart`, `ble`, `usb`. |
| 2 | `state` | `u8` | Down=0, up=1. |
| 3 | `tx_submitted` | `u64` | Packets handed to the bearer. |
| 4 | `tx_accepted` | `u64` | Packets the radio or driver accepted. |
| 5 | `tx_failed` | `u64` | Submissions that failed. |
| 6 | `tx_busy` | `u64` | Submissions refused as temporarily busy. |
| 7 | `rx_packets` | `u64` | Packets accepted from the bearer. |
| 8 | `rx_rejected` | `u64` | Packets that failed validation. |
| 9 | `rx_dropped` | `u64` | Packets dropped for lack of a packet slot or queue room. |
| 10 | `queue_depth` | `u32` | Packets currently queued on the bearer. |

## 10. `memory` — Return packet pool, worker stack, and memory metrics

**Platforms:** A L E

Target platforms: A L E, with fields omitted where the platform has no such
value (a host process has no worker stacks; a device has no process RSS).
Registered on A, L and E (Android and Linux report `process_rss_bytes` only); replaces
`memory.snapshot` (103/1), which no platform registers any more.

### Response

Tags start at 1; the older snapshot method used 0-based tags.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `packet_slots` | `u32` | Packet pool capacity. |
| 2 | `packet_slots_available` | `u32` | Packet slots currently free. |
| 3 | `packet_drops` | `u32` | Packets dropped for lack of a slot. |
| 4 | `worker_stack_bytes` | `u32` | Worker stack size. |
| 5 | `worker_running` | `bool` | Worker is running. |
| 6 | `worker_starts` | `u32` | Worker starts. |
| 7 | `worker_create_failures` | `u32` | Worker creation failures. |
| 8 | `worker_stack_min_free_words` | `u32` | Smallest free worker stack seen, in words. |
| 9 | `free_internal_bytes` | `u32` | Free internal heap. |
| 10 | `min_free_internal_bytes` | `u32` | Smallest free internal heap since boot. |
| 11 | `largest_internal_block_bytes` | `u32` | Largest free internal heap block. |
| 12 | `process_rss_bytes` | `u64` | Resident set size of the process (Linux, Android). |

## 11. `power` — Return CPU frequency, power-management, and sleep counters

**Platforms:** E

Target platforms: A E (L when it has an observer). Registered on E; replaces
`power.snapshot` (102/1), which no platform registers any more. Battery state
stays in `battery`.

### Response

Tags start at 1; the older snapshot method used 0-based tags.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `cpu_mhz` | `u32` | Current CPU frequency. |
| 2 | `min_mhz` | `u32` | Power-management minimum frequency. |
| 3 | `max_mhz` | `u32` | Power-management maximum frequency. |
| 4 | `automatic_light_sleep` | `bool` | Automatic light sleep is enabled. |
| 5 | `configured` | `bool` | Power management is configured. |
| 6 | `light_sleep_attempts` | `u32` | Light-sleep attempts. |
| 7 | `light_sleep_entries` | `u32` | Light-sleep entries. |
| 8 | `light_sleep_skipped` | `u32` | Skipped light sleeps. |
| 9 | `last_sleep_requested_us` | `u32` | Last requested sleep duration. |
| 10 | `last_sleep_duration_us` | `u32` | Last measured sleep duration. |

## 12. `runtime` — Return radio lifecycle generations and sleep state

**Platforms:** E

Target platforms: A L E. Registered on E; replaces `runtime.snapshot` (101/1),
which no platform registers any more (Android's and Linux's only reported the
service name, version and uptime, which `status` and `firmware.identity` carry).

### Response

Tags start at 1; the older snapshot method used 0-based tags.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `desired_mode` | `u32` | Desired radio mode. |
| 2 | `desired_generation` | `u32` | Desired-state generation. |
| 3 | `request_id` | `u32` | Request that produced the desired state. |
| 4 | `sleepy` | `bool` | Sleepy operation is selected. |
| 5 | `radio_lifecycle` | `u32` | Radio lifecycle state. |
| 6 | `applied_generation` | `u32` | Generation the radios have applied. |
| 7 | `power_lifecycle` | `u32` | Power lifecycle state. |
| 8 | `sleep_blockers` | `u32` | Bitset of reasons sleep is blocked. |
| 9 | `last_error` | `u32` | Last lifecycle error code. |
| 10 | `stale_completion_count` | `u32` | Completions ignored as stale. |
| 11 | `queue_overflow_count` | `u32` | Lifecycle queue overflows. |
| 12 | `wake_cause` | `u32` | Last wake cause. |
| 13 | `last_stale_reason` | `u32` | Reason the last stale completion was rejected. |

## 13. `device` — Return software version and hardware capacity

**Platforms:** A L E

**Rust CBOR:** generated

Static platform information, independent of radio state. Main and Recovery
register the same handler. Values unavailable on a platform are omitted, not
reported as zero. `total_ram_bytes` is physical RAM, not currently free heap;
`flash_bytes` is physical flash capacity on ESP and is omitted on hosts where
there is no equivalent single flash device. Discovery supplies node identity,
CPU class and Main/Recovery role for flashing; this telemetry is not a flash
protocol prerequisite.

### Response

| Tag | Field | Type | Required | Description |
|---:|---|---|---|---|
| 1 | `version` | `string` | yes | Running application version. |
| 2 | `cpu_type` | `string` | yes | CPU family or host architecture. |
| 3 | `total_ram_bytes` | `u64` | no | Physical RAM capacity when known. |
| 4 | `flash_bytes` | `u64` | no | Physical flash capacity when applicable. |
| 5 | `role` | `string` | yes | main, recovery, linux, or android. |

# `transport` API (1)

## 4. `set` — Replace a node's complete volatile physical transport profile

**Platforms:** A L E

**UI:** default

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `mode` | `u8` | Selected physical transport: STA=1, UART=5, NAN=6. |
| 2 | `ssid` | `string` | STA target. |
| 3 | `bssid` | `string` | Optional directed STA BSSID. |
| 4 | `channel` | `u8` | Selected channel. |
| 5 | `raw_tx_rate` | `u8` | Raw injection diagnostic rate. |
| 6 | `sta_driver_tx` | `bool` | Use the associated ESP driver TX path. |
| 7 | `sta_bssid_check_disabled` | `bool` | Disable BSSID filtering in raw RX. |
| 8 | `sta_ampdu_enabled` | `bool` | Enable STA A-MPDU. |
| 9 | `sta_11b_rates_disabled` | `bool` | Disable legacy 802.11b rates. |
| 10 | `sta_raw_rx_enabled` | `bool` | Enable the raw UDP6 receive adapter. |
| 13 | `espnow_capture` | `bool` | Legacy diagnostic capture setting. |
| 14 | `nan_dw_interval` | `u8` | NAN discovery-window interval. |
| 15 | `now` | `u8` | ESP-NOW policy. |
| 16 | `ap` | `u8` | AP policy. |
| 17 | `passphrase` | `string` | Volatile WPA2 override. |
| 18 | `uart` | `u8` | UART speed or off selector. |
| 19 | `ndp` | `u8` | NAN Data Path policy. |
| 24 | `open` | `bool` | Open-mode policy. |
| 25 | `wake_target` | `string` | MAC address allowed to apply NAN wake. |
| 26 | `ble` | `u8` | BLE policy. |
| 27 | `iface` | `string` | Linux-owned interface; omitted on devices. |

# `companion` API (209)

Pairing makes an unpaired ESP32 a companion of one Linux or Android controller.
Every pairing attempt first sends `nan.pair_wakeup` through a nearby observer,
even when the provisioning exchange will use USB or BLE. A sleepy
unpaired device may then open a time-limited pairing window. A device that already
has `sec:key` ignores this invitation.
`kind` selects the bearer used for this operation: `uart` (USB or serial) or
`ble`. Companions use only these two. `id` is its adapter-local identifier, a
serial path or a BLE address. The host verifies the signed device identity,
generates a new shared secret, writes it to the device, and durably stores the
secret with the device MAC and public key in the device's record (a private file).
The signed `device_id` is stable across bearers.

Bearers add no cryptography of their own. The shared secret is what QUIC-lite
uses to authenticate and encrypt once it is on the device. Over the wired UART
(trusted physical access) the host may set or replace the secret, even on a
device that has one and with no pairing window: that host could reflash the
device anyway, so a later pair simply overrides the secret (future eFuse policy
may restrict this). Pairing leaves the UART attached to the node and in use; a
port that is already attached, for example at startup, is reused. Over BLE the
channel is a plain, unencrypted L2CAP CoC (no BLE pairing or bond, so no prompt on any
platform), and the device refuses when it already has a secret or its pairing window is
closed; only a wired unpair or pair resets it. The shared secret, installed once over that
channel, is what authenticates and encrypts everything after. Once paired, the same ownership works over any available
transport.
Firmware never returns the raw secret over control.

Linux stores one pairing result per signed device VIP6 in
`DMESH_PAIRED_DEVICES_DIR` (default `/home/system/etc/lmesh/paired`). The
directory is mode 0700 and each JSON result is mode 0600. Android uses the
same layout under its app-private `files/ssh-mesh/paired` directory. A result is
created from signed discovery, the device's NVS name (or the name set during
pairing), the installed control-plane root public key, and the newly generated secret. Its filename is the final eight
VIP6 bytes as 16 lowercase hexadecimal digits plus `.json`;
the old catalog inventory is not pairing authority. The secret must not appear in normal
discovery, logs, HTTP responses, or command history.

BLE advertisements use a distinct DMesh pairing service while unpaired. Once
paired they use the operational service and may include a short owner hint,
such as the last four bytes of the owner's VIP, to help a controller match its
private inventory. The hint is public metadata, not authorization; signed
identity and shared-secret proof remain required.

## 1. `pair` — Provision an unpaired companion

**Platforms:** A L

`vip6` is optional. The device is identified by its bearer (the serial port or
BLE address) and by its signed discovery reply, whose VIP6 the owned record is
keyed on. When `vip6` is given it must match that reply, and the host refuses a
device that proves a different identity. UART and BLE use the same exchange over an ordinary QUIC
association on the host's running node (BLE over a plain CoC): discover, `provision.install`, then
save the device record. A device that refuses leaves no host record. A
re-pair over the wire replaces the earlier record. `id` is the serial path or
BLE address (from scan results); `psm` defaults to 128. A UART port stays attached
afterwards; a port already attached (`LMESH_UART`) is reused.

Pairing reads the device name from NVS through signed discovery. Optional
`name` replaces it, or supplies an initial name, and must be written to NVS
before the local pairing result is committed.
Pairing also installs a control-plane root public key into `dmesh:cp` NVS.
By default this is the controller's own public key. If a root CA is configured,
the controller uses that CA's public key; `root_public_key_b64` can select an
explicit compressed P-256 public key for this pairing. The selected root key
is saved in the private pairing result and is not a shared secret.
A successful pair response means the device accepted the new secret and the
host saved the matching identity and secret durably. Android's native
Bluetooth API owns permission and connecting.

```sh
mesh lmesh companion.pair --kind=uart --id=/dev/ttyUSB0
mesh lmesh companion.pair --kind=ble --id=AA:BB:CC:DD:EE:FF --psm=128
mesh lmesh companion.unpair --kind=uart --id=/dev/ttyUSB0
```

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `kind` | `string` | Provisioning bearer: `uart` or `ble`. |
| 2 | `id` | `string` | Adapter-local identifier from discovery. |
| 3 | `vip6` | `string` | Optional signed VIP the device must prove; default: whatever it proves. |
| 4 | `baud` | `u32` | Optional UART physical baud rate. |
| 5 | `psm` | `u16` | Optional BLE CoC PSM; default 128. |
| 6 | `name` | `string` | Optional new device name, persisted in NVS during pairing. |
| 7 | `root_public_key_b64` | `string` | Optional base64 compressed P-256 control-plane root public key (33 bytes). |

## 2. `unpair` — Reset a companion to unpaired state

**Platforms:** A L

`kind` names the bearer carrying this operation; it does not identify the
bearer on which pairing happened. Unpair removes the shared secret, the
control-plane root and every BLE bond (stored peer keys) on the ESP32 and removes
its device record on Linux or Android. A UART stays attached. Afterwards the ESP32 behaves like
an unpaired device. Over BLE, unpair requires proof of the current
shared secret and must reject devices owned by another controller. UART alone
may unlock a device without that proof, including one paired to someone else.
Physical UART access already permits Linux to flash the ESP32; future eFuse
policy may restrict that ability. The UART exception must never apply to a
request that arrives over BLE, even if its `kind` field says `uart`.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `kind` | `string` | Bearer carrying the unpair request. |
| 2 | `id` | `string` | Target identifier on that bearer. |

# `provision` API (210)

This device-side internal API is used after the targeted NAN pairing wake.
It accepts direct UART/USB, which may replace an existing secret, and an
BLE CoC (plain, unencrypted), which is accepted only for a device with no secret and an
open pairing window. It rejects Wi-Fi, NAN, and relayed requests. The device commits name and root first,
then the secret last. The caller verifies the correlated result and durably
saves the signed identity, name, root and secret before reporting completion.
Credential bytes are never logged.

## 1. `install` — Commit an unpaired device's companion credentials

**Platforms:** E

**Visibility:** private

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | Name to persist in NVS. |
| 2 | `root_public_key` | `bytes` | Compressed P-256 control-plane root, 33 bytes. |
| 3 | `secret` | `bytes` | Newly generated shared secret, 32 bytes. |

## 2. `unpair` — Forget the companion credentials and BLE bonds

**Platforms:** E

**Visibility:** private

Wired UART/USB only; a radio bearer is refused whatever the request claims.
The device erases the shared secret, the control-plane root and every BLE bond,
so it behaves as unpaired again, and answers `true` only when all of that
succeeded. No proof of the current secret is needed: physical access already
permits reflashing the device. The request has no fields.

# `log` API (208)

## 1. `record` — One-way diagnostic message from a companion bearer

**Platforms:** none

**Visibility:** private

This tagged message has no request ID or response. A host UART adapter wraps
unframed boot and crash text in this message after receiving it; normal QUIC
frames remain unchanged. `log.watch` is the interface that reads retained records.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `text` | `string` | One size-limited UTF-8 log line. |
| 2 | `source` | `string` | Observer-local bearer path or name. |
| 3 | `timestamp_ms` | `u64` | Observer receipt time. |

## 2. `watch` — Read retained log and event records, optionally streaming them with periodic metric snapshots

**Platforms:** A L E

Target platforms: A L E; registered on E, which keeps the last 32 ESP-IDF log
lines (`E (1234) tag: text` becomes level, source `tag` and text), and on L,
which serves its `tracing` history (`mesh::local_trace`): warnings, errors and
events whose `event_type` is watched or retained, with `target` as `source`
and `event_type` as `kind`, and on A, which serves the same history plus NAN
follow-ups and events (`nan.followup`, `nan.event`) and BLE scan results
(`ble.scan_result`). Replaces `log-watch` (9/5) and `events` (9/4), which no
platform registers any more. An event is a record whose `kind` is set; a plain
log line has none.

Every node keeps one retained history of recent records. `watch` returns
records with `seq` greater than `since_seq`, oldest first, and a `cursor` to
pass as the next `since_seq`. `dropped` counts records that left the history
before they were read.

With `stream` set, the response header is the same, and the response body then
continues as a sequence of CBOR records, each one a `LogRecord` map as below,
until the request's `timeout` ends (60 s when absent, at most one hour) or the
caller closes the stream. No length
or count is declared; each record is a self-delimiting CBOR item.

Periodic snapshots use the same record: for each name in `snapshots` (a
telemetry method such as `telemetry.quic`), every `interval_ms` the node emits
a `LogRecord` whose `kind` is that method name and whose `fields` is exactly the
response that method returns. A snapshot is not retained, so its `seq` is 0. A snapshot of a method the node does not
register is skipped, and a `log` record with `source` `log.watch` says so once.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `since_seq` | `u64` | Return records after this sequence number. |
| 2 | `limit` | `u32` | Most records in the response (poll mode). |
| 3 | `level` | `u8` | Least severe level to return (error=1, warn=2, info=3, debug=4, trace=5). |
| 4 | `source` | `string` | Only records from this source or one below it (`bearer` matches `bearer.ble`). |
| 5 | `kind` | `string` | Only events whose kind starts with this prefix. |
| 6 | `stream` | `bool` | Keep the stream open and send new records as they arrive. |
| 7 | `snapshots` | `string[]` | Telemetry method names to snapshot periodically. |
| 8 | `interval_ms` | `u32` | Snapshot period; default 1000 and at least 100. |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `records` | `LogRecord[]` | Records (poll mode; empty when streaming). |
| 2 | `cursor` | `u64` | `seq` of the last record returned or sent so far. |
| 3 | `dropped` | `u64` | Records lost from the history since `since_seq`. |

`LogRecord` fields:

| Tag | Field | Type | Required | Description |
|---:|---|---|---|---|
| 1 | `seq` | `u64` | yes | Sequence number, increasing by one per record on this node. |
| 2 | `time_ms` | `u64` | yes | Milliseconds since the node started; no wall clock is assumed. |
| 3 | `level` | `u8` | yes | error=1, warn=2, info=3, debug=4, trace=5. |
| 4 | `source` | `string` | yes | Producing module, dotted (`quic`, `nan`, `bearer.ble`). |
| 5 | `kind` | `string` | no | Event type, or a telemetry method name for a snapshot; absent for a plain log line. |
| 6 | `text` | `string` | yes | Message; a device may shorten it to fit its slot. |
| 7 | `fields` | `cbor` | no | One CBOR map of structured values of an event, or a snapshot's response. |

# `probe` API (8)

`probe` is a core test and diagnostic tool, and a production control-plane tool
for comparing paths, so every platform registers it and any node can be probed
from any other: Android to Android, Android to Linux, ESP32 to either, and every
other combination. Two methods are involved, on two different nodes:

- `probe.start` is a request to a node (the one addressed by `to`, or the node
  that receives it) to run a probe against `peer`. It has no body in either
  direction; its response header is the outcome.
- `probe.handler` is the handler on the node that is probed (the `peer`). It is
  an ordinary registered method with the usual CBOR header in front, and its
  response body streams the probe payload. More probe handlers (sink, echo,
  error injection, chat-like exchanges, delays) will be added beside it as tests
  need them, each its own method.

`quic-lite` itself has no CBOR and no registry: its probe workload
(`quic_lite::probe`) is wrapped by these handlers, and its own tests attach it
directly.

## 1. `start` — Ask a node to run a probe against a peer

**Platforms:** A L E

**UI:** advanced

The envelope's destination `to` (a request field named `to`, tag 15 in this
catalog) selects the node that runs the probe as the QUIC client; it is not part
of the request's `fields` map. `peer` names the probed node: `espnow://MAC`,
`udp://HOST:PORT`, `usb://`, `ble://`, or `mesh://VIP`, which is resolved through
discovery to the current address and path. Bearer names select explicit
transports. Query options may be added to the URI later; comma-separated
multipath destinations are not accepted until multipath is implemented. Wakeup
of a sleepy peer is a separate transport/discovery policy and is not part of
this request.

Tags 3 to 5 are reserved (`pace_us`, `burst_packets`, `burst_delay_us`); a
decoder rejects them.

**Request body:** none

**Response body:** none

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `bytes` | `u64` | Payload length to move. |
| 2 | `packet_size` | `u16` | Packet size the payload is built from. |
| 6 | `ack_frequency` | `u8` | Packets per acknowledgment. |
| 7 | `ack_delay_ms` | `u8` | Acknowledgment delay. |
| 8 | `low_priority_bytes` | `u32` | Bytes on a low-priority stream. |
| 9 | `high_priority_bytes` | `u32` | Bytes on a high-priority stream. |
| 10 | `parallel_streams` | `u8` | Concurrent streams. |
| 11 | `initial_consume_delay_ms` | `u32` | Delay before the first read. |
| 12 | `consume_delay_ms` | `u32` | Delay between reads. |
| 13 | `peer` | `string` | The probed node (destination URI). |
| 15 | `to` | `string` | Node that runs the probe (envelope destination). |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `status` | `string` | `ok` or `error`. |
| 2 | `peer` | `string` | The probed node. |
| 3 | `requested_bytes` | `u64` | Requested payload length. |
| 4 | `received_bytes` | `u64` | Validated payload bytes received. |
| 5 | `elapsed_us` | `u64` | Elapsed time. |

## 2. `handler` — Answer a probe with a header and then the probe payload

**Platforms:** A L E

**UI:** advanced

**Request body:** none

**Response body:** the probe payload, `bytes` octets long.

Packet `k` of the payload starts with `k` as a big-endian `u32`, and every other
byte is its stream offset modulo 256, so a caller can validate it however the
transport chunks it. A request the node does not support (a `peer`, more than one
stream, priority streams, ACK tuning, more than the probe limit) is answered with
an error header and no body. The generator and the validator are
`quic_lite::probe::ProbePayload`.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `bytes` | `u64` | Payload length to send. |
| 2 | `packet_size` | `u16` | Packet size the payload is built from. |
| 6 | `ack_frequency` | `u8` | Packets per acknowledgment. |
| 7 | `ack_delay_ms` | `u8` | Acknowledgment delay. |
| 8 | `low_priority_bytes` | `u32` | Bytes on a low-priority stream. |
| 9 | `high_priority_bytes` | `u32` | Bytes on a high-priority stream. |
| 10 | `parallel_streams` | `u8` | Concurrent streams. |
| 11 | `initial_consume_delay_ms` | `u32` | Delay before the first read. |
| 12 | `consume_delay_ms` | `u32` | Delay between reads. |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `bytes` | `u64` | Length of the payload that follows. |
| 2 | `packet_size` | `u64` | Packet size the payload is built from. |

<!-- dmesh-api:end -->

<!-- dmesh-api:settings -->

Device settings requests use component `1`. `settings.set` writes the named
setting; use `settings.get` to verify its value.

```sh
dmesh-cli DEVICE settings.get --key=name
dmesh-cli DEVICE settings.set --1=name --2=demo
```

# `settings` API (1)

## 1. `get` — Read one setting

**Platforms:** A L E

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `key` | `string` | Setting name. |

## 2. `set` — Write one setting

**Platforms:** A L E

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `key` | `string` | Setting name. |
| 2 | `value` | `string` | Setting value. |

## 3. `list` — List setting keys

**Platforms:** A L E

<!-- dmesh-api:end -->

<!-- dmesh-api:nan -->

A reachable observer can request a targeted wake; a successful response means
the observer accepted it. Query the target again to confirm it is awake.

```sh
dmesh-cli OBSERVER nan.wakeup --to=aa:bb:cc:dd:ee:ff
dmesh-cli DEVICE telemetry.nan_status
```

# `nan` API (6)

## 11. `wakeup` — Direct a NAN wake request to one observed device

**Platforms:** A L E

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `to` | `string` | Target radio MAC address. |

## 12. `pair_wakeup` — Invite only an unpaired device into a time-limited pairing window

**Platforms:** L E

An observer sends this targeted NAN request before pairing over any bearer.
The device accepts it only while `sec:key` is empty; a paired device ignores
it. The observer response means the wake was queued, not that the device
entered pairing mode or that pairing completed.

```sh
dmesh-cli OBSERVER nan.pair_wakeup --to=aa:bb:cc:dd:ee:ff
```

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `to` | `string` | Target radio MAC address from discovery. |

<!-- dmesh-api:end -->

<!-- Linux-only methods (`lmesh.*`, `link.steer`, `object.nan.dry_run`, `wifi.interface.*`,
`wifi.ap.*`, `wifi.sta.*`) are implemented only by the experimental `lmesh-wifi`
crate and are documented in [`crates/lmesh-wifi/API.md`](crates/lmesh-wifi/API.md). -->

<!-- dmesh-api:android -->

# `ble` API (201)

Android BLE adapter operations. The service uses tagged CBOR; the Android framework remains behind the Rust backend.

## 1. `status` — Report local BLE adapter and bearer state

**Platforms:** A

**UI:** default

## 2. `scan` — Start a time-limited BLE scan

**Platforms:** A

**UI:** default

## 3. `scan_stop` — Stop the BLE scan

**Platforms:** A

**UI:** default

## 4. `scan_results` — List retained BLE scan results

**Platforms:** A

**UI:** default

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `limit` | `u64` | Maximum result count, capped at 64. |

## 5. `scan_clear` — Clear retained BLE scan results

**Platforms:** A

**UI:** default

## 6. `connect` — Connect to a BLE device over L2CAP CoC

**Platforms:** A

**Visibility:** private

Platform adapter operation used by `companion.pair`. Public clients use the
companion API so the same method applies to BLE, UART, and Wi-Fi.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `address` | `string` | Scanned device address. |
| 2 | `psm` | `u16` | L2CAP PSM; defaults to 128. |

## 7. `disconnect` — Disconnect the local BLE bearer

**Platforms:** A

**Visibility:** private

# `radio` API (202)

## 1. `history` — Read retained local radio event history

**Platforms:** A

**UI:** default

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `limit` | `u64` | Maximum event count, capped at 256. |
| 2 | `since_ms` | `u64` | Earliest event timestamp. |
| 3 | `keys` | `string` | Event key selector. |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `events` | `cbor[]` | Retained NAN receipt events, newest first; each one CBOR map. |
| 2 | `followups` | `cbor[]` | Retained NAN follow-up receipts, newest first; each one CBOR map. |
| 3 | `ble_scan_results` | `cbor` | Matching retained BLE scan results (`results`, `count`), one CBOR map. |
| 4 | `count` | `u64` | Total rows across the three lists. |

# `usb` API (204)

## 1. `status` — Report local USB adapter state

**Platforms:** A

**UI:** default

## 2. `devices` — List USB devices visible to the host

**Platforms:** A

**UI:** default

## 3. `open` — Open and attach a USB serial device

**Platforms:** A

**UI:** default

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `vendor_id` | `u16` | USB vendor ID. |
| 2 | `product_id` | `u16` | USB product ID. |
| 3 | `auto` | `bool` | Select an available matching device. |

## 4. `close` — Close the active USB bearer

**Platforms:** A

**UI:** default

## 5. `discover` — Read the attached device's signed identity

**Platforms:** A

Sends a tagged discovery request over the open USB QUIC bearer. The response
must carry a valid device signature. This is a read-only identity check and
does not pair or claim the device.

**UI:** default

# `wifi` API (205)

## 1. `status` — Report local Wi-Fi controller and NAN state

**Platforms:** A

**UI:** default

## 2. `scan` — Request a time-limited platform Wi-Fi scan

**Platforms:** A

**UI:** default

# `status` API (203)

## 1. `text` — Return the Rust-generated local status table

**Platforms:** A

**UI:** default

Human-readable service state, IP addresses and direct-neighbor counts for the
status shell. It is a local-only method: the table names local addresses, so a
network peer is declined.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `status_text` | `string` | Line-oriented status table. |

<!-- dmesh-api:end -->

## Additional device methods

These are active tagged-CBOR methods whose implementations live in the device
or shared service handlers. Their wire names are retained for existing clients.
The component and method columns are the numeric CBOR tags.

| Component | Method | Wire name | Purpose | Platforms |
|---:|---:|---|---|---|
| 101 | 2 | `runtime.reset` | Reset the runtime diagnostics counters. | E |
| 10 | 2 | `object.flash` | CLI name of `POST /flash` (wire: `http.post`, path `/flash`): transfer a firmware image into a selected durable slot. | E |
| 1000 | 3 | `module.stop` | Request module shutdown with a deadline before flash work. | E |
| 1000 | 1 | `module.status` | Refresh and read the installed module header and loader result. | E |
| 1000 | 2 | `module.init` | Initialize the installed module loader. | E |
| 11 | 1 | `boot.recovery` | Request a Main to Recovery handoff. | E |
| 104 | 80 | `ble.start` | Start the BLE companion radio. | E |
| 104 | 81 | `ble.stop` | Stop the BLE companion radio. | E |
| 104 | 82 | `ble.scan` | Start a time-limited BLE scan. | A E |
| 104 | 83 | `ble.status` | Read BLE adapter and link state. | A E |
| 104 | 84 | `ble.scan_stop` | Stop an active BLE scan. | A E |
| 104 | 85 | `ble.connect` | Connect to a selected BLE peer. | A E |
| 104 | 86 | `ble.coc.send` | Send one payload as one BLE L2CAP CoC SDU. | E |
| 9 | 1 | `status` | Read compact device health and application state. | A L E |
| 9 | 2 | `services` | List registered service handlers. | A L E |
| 4 | 71 | `radio.tx` | Submit one size-limited raw radio frame for diagnostics. | L E |
| 4 | 72 | `radio.control` | Adjust volatile radio diagnostic controls. | L E |
| 4 | 73 | `radio.snapshot` | Read radio state and counters. | L E |
| 4 | 77 | `wifi.scan` | Scan or read retained Wi-Fi results. | E |
| 4 | 74 | `radio.reset_counters` | Reset radio diagnostics counters. | L E |

Platform registration notes:

- Only implemented methods are registered. Android and Linux do not register
  `boot.recovery`, `module.*`, `runtime.reset`, `object.flash` or
  `ble.start/stop/coc.send`: they depend on the ESP Stage2/Recovery/module
  layout or its radio lifecycle, so a request receives the numeric error.
- `object.flash` (`POST /flash`): registered by Main and Recovery firmware at the key
  `[http (2002), post (2), 10]`. Android and Linux do not register the device flash
  operation. The request header and the raw image body share one QUIC stream.
- Stubs are not registered. Android answers `status`, `services`,
  `telemetry.nan_status`, `battery`, `quic`, `quic_associations`, `bearers`, `memory`
  and `log.watch`; Linux
  answers `status`, `services`, the typed `telemetry.*` methods it has counters
  for, `bearers`, `quic_associations` and `log.watch`. Neither has a source for
  `power` or `runtime`, and Linux has none for `battery` or the BLE methods
  other than the startup CoC bearer, so those are absent. The old `metrics`,
  `events`, `log-watch` and the three `*.snapshot` methods are registered
  nowhere. The firmware registers `status` and `services` from
  component 9 only (its logs are `log.watch`, its snapshots are
  `telemetry.memory`, `power`, `runtime` and `bearers`), and has no
  `telemetry.battery` source.
- Internal Android service methods (`ble` 201, `radio` 202, `usb` 204,
  `wifi` 205, `companion` 209, `transport.set`) are registered local-only:
  reachable from the local control surface and HTTP gateway, declined for a
  network peer.
- `log.record` (208/1): one-way message produced only by the Linux UART
  adapter; no platform registers a handler. It is intended to become a QUIC
  datagram with its own registration.
- `nan.pair_wakeup` (6/12): not registered on Android; the invitation is
  sent by the Linux controller.
- `companion.pair`/`companion.unpair` (209): the device-side counterpart is
  `provision.install` (210), registered only in the firmware.
- `probe.start` (8/1) and `probe.handler` (8/2) are ordinary registered
  handlers on every platform that can run them; see the `probe` API above. The
  firmware and Linux run `probe.start` as a client (ESP-NOW, UDP6/UDP); Android
  runs it over its UDP, USB and BLE bearers.
- The firmware module components (1000-1003) are compiled when the
  `modules` feature is enabled (the Main default); Recovery omits them.
- Android additionally registers a named `status.text` service on the HTTP
  gateway surface; it is not a numeric device method.
- The ssh-mesh common methods `mesh` (2000) and `trace` (2001) have reserved
  numbers outside every service's range. Linux registers them in this registry
  and dispatches them by number as CBOR (`mesh.lifecycle` and
  `trace.set_level` are local-only); a gateway that addresses them by text name
  is translated to the number at the edge. Android serves them only on the
  HTTP gateway.
- `status.text` (203/1) and `radio.history` (202/1) are written against the
  typed structs generated from this document (`crates/dmesh-server/src/platform_api.rs`)
  and encode their results with the tags above. Other Android platform methods
  still return JSON-shaped results in tagged CBOR until their response tables
  are added here.

The request fields below are optional unless the handler description says otherwise.
An empty request uses an empty CBOR map. Response fields are handler-specific and
are described by the method purpose above.

### `status` response fields

| Field | Type | Description |
|---|---|---|
| `status` | `string` | `ok` for a successful status response. |
| `role` | `string` | `main` for the running Main firmware. |
| `uptime_secs` | `u64` | Main uptime in seconds. |
| `sta_enabled` | `bool` | Whether the persisted profile enables infrastructure STA. |
| `sta_associated` | `bool` | Whether STA is currently associated to an access point. |
| `sta_bssid` | `string` | Associated AP BSSID, or `unavailable` when not associated. |
| `sta_ipv4` | `string` | Current STA IPv4 address, or `unavailable` until DHCP assigns one. |

### `object.flash` request fields

`object.flash` is the CLI name of `POST /flash`. On the wire it is the generic REST request of the
tagged-CBOR envelope (component `2002` `http`, method `2` `post`, `params` the path `[10]` or
`["flash"]`, `fields` the headers below, see ssh-mesh `mesh-api/PROTOCOLS.md`, "HTTP component"). A
command built by the CLI carries the same headers as its fields; the sender adds `content-length`
(header `1`) and posts it.

| Tag | Field | Type | Values |
|---:|---|---|---|
| 64 | `name` | `text` | — |
| 65 | `cpu` | `u8` | — |
| 66 | `target` | `u8` | — |
| 67 | `address` | `u32` | — |
| 68 | `transport` | `u8` | — |
| 69 | `dry_run` | `bool` | — |

Header keys may be spelled by number or by name; a name and its number together are a duplicate.
`name` optionally selects the object; `cpu` and nonzero `target` identify its platform image.
`address` is an optional platform-specific destination, `transport=0` means use the active
connection's default path, and `dry_run=false` is the normal write mode. Omitted `transport` and
`dry_run` have those same defaults. `content-length` is the number of image bytes that follow, and a
request without it (or with a length larger than the destination) is refused. Unknown, duplicate, or
malformed headers are rejected before the firmware sink can erase anything.

**Request body:** the image: raw bytes that follow the request header on the same stream; FIN follows
the last image byte. There is no manifest, block table, digest or signature (the transport carries
integrity; see `notes/design/object-transfer-integrity.md`), and the device chooses its own block
size. A body shorter or longer than `content-length` is rejected.

**Response body:** none. The response header carries `fields {0: status}` and, for success, the
result text `flash complete`; a refusal carries `error` with status `400` (invalid target), `413`
(image larger than the destination or no length), `501` (unavailable) or `503` (a flash is already in
progress).

The firmware registers the flash handler at the dispatch key `[http, post, 10]` (component, method,
path: the longest registered prefix of a request's key wins, there is no second router). The handler
is chosen as soon as the header is complete and may refuse before any body byte arrives; it then
streams the body incrementally into the sink. The association and stream that carried the
request own the entire operation, and a stream with no progress for 15 seconds is abandoned and
releases the writer.

The response is returned on that same stream only after the body ends and the sink has made the
image durable. Handler acceptance, stream ACKs, and byte counts are not proof of durable completion or
successful reboot. The response has no body and ends with FIN, like every header-only handler
response. Recovery schedules its Stage2 handoff only after durable completion and finishing this
ordinary response direction; Main leaves the written slot for the normal boot/update path.
`dry_run=true` validates through the sink's dry-run behavior and does not signal durable flash
completion.

### `ble.scan` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 2 | `duration_ms` | `u32` | — |

### `ble.status` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 1 | `ready` | `bool` | — |
| 2 | `advertising` | `bool` | — |
| 3 | `connected` | `bool` | — |
| 4 | `coc_connected` | `bool` | — |
| 5 | `generation` | `u32` | — |
| 6 | `handle` | `u16` | — |
| 7 | `coc_rx` | `u32` | — |
| 8 | `coc_rx_rejected` | `u32` | — |
| 9 | `scanning` | `bool` | — |
| 10 | `scan_reports` | `u32` | — |
| 11 | `scan_matches` | `u32` | — |
| 12 | `last_scan_addr` | `mac` | — |
| 13 | `last_scan_addr_type` | `u8` | — |
| 14 | `last_scan_rssi` | `i32` | — |
| 15 | `bonded` | `bool` | — |
| 16 | `coc_tx_pending` | `bool` | — |
| 17 | `local_addr` | `hex` | — |
| 18 | `local_addr_type` | `u8` | — |
| 19 | `ingress_enqueued` | `u32` | — |
| 20 | `ingress_accepted` | `u32` | — |
| 21 | `ingress_rejected` | `u32` | — |
| 22 | `egress_attempts` | `u32` | — |
| 23 | `egress_sent` | `u32` | — |
| 24 | `egress_send_errors` | `u32` | — |
| 25 | `egress_blocked_disconnected` | `u32` | — |
| 26 | `egress_blocked_pending` | `u32` | — |

### `ble.connect` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 2 | `addr` | `hex` | — |
| 3 | `addr_type` | `u8` | — |
| 4 | `psm` | `u16` | — |

### `ble.coc.send` request fields

The payload is the complete CoC SDU. It has no bearer-local length prefix.

| Tag | Field | Type | Values |
|---:|---|---|---|
| 2 | `data` | `hex` | — |

### `radio.tx` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 1 | `frame` | `hex` | — |
| 2 | `channel` | `u8` | — |
| 3 | `interface` | `enum` | auto=0, sta=1, ap=2, nan=3 |
| 4 | `system_sequence` | `bool` | — |
| 5 | `rate` | `enum` | auto=0, 6=6, 9=9, 12=12, 18=18, 24=24, 36=36, 48=48, 54=54 |
| 6 | `disable_11b` | `bool` | — |

### `radio.control` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 2 | `channel` | `u8` | — |
| 3 | `interface` | `enum` | auto=0, sta=1, ap=2, nan=3 |
| 5 | `rate` | `enum` | auto=0, 6=6, 9=9, 12=12, 18=18, 24=24, 36=36, 48=48, 54=54 |
| 6 | `disable_11b` | `bool` | — |
| 7 | `sta_state` | `enum` | reconnect=0, disconnect_hold=1 |
| 8 | `comparator_bssid` | `mac` | — |
| 9 | `comparator_enabled` | `bool` | — |
| 10 | `promiscuous` | `bool` | — |
| 11 | `dw_policy` | `enum` | normal=0, disabled=1, manual=2 |
| 12 | `rx_filter` | `enum` | management=0, management_data=1 |
| 13 | `ap_mode` | `enum` | disabled=0, open=1 |
| 14 | `ap_beacon_tu` | `u16` | — |
| 15 | `raw_sta_mode` | `enum` | main_style=1 |
| 16 | `mac_ack` | `bool` | — |
| 20 | `action_destination_broadcast` | `bool` | — |
| 21 | `applied_channel` | `u8` | — |
| 22 | `sta_associated` | `bool` | — |
| 23 | `applied_promiscuous` | `bool` | — |
| 24 | `dw_capturing` | `bool` | — |
| 25 | `applied_comparator_bssid` | `mac` | — |
| 26 | `comparator_armed` | `bool` | — |
| 27 | `comparator_errors` | `u32` | — |
| 28 | `applied_tx_interface` | `enum` | — |
| 29 | `applied_tx_rate` | `enum` | — |
| 30 | `ap_active` | `bool` | — |
| 40 | `tx_attempted` | `u32` | — |
| 41 | `tx_driver_accepted` | `u32` | — |
| 42 | `tx_driver_failed` | `u32` | — |
| 43 | `rx_driver_dispatch` | `u32` | — |
| 44 | `rx_parser_accepted` | `u32` | — |
| 45 | `rx_parser_rejected` | `u32` | — |
| 46 | `rx_self_echo` | `u32` | — |
| 47 | `rx_dropped` | `u32` | — |
| 48 | `nan_beacons` | `u32` | — |
| 49 | `nan_sdfs` | `u32` | — |
| 50 | `nan_followups` | `u32` | — |

### `radio.snapshot` response fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 20 | `epoch` | `u32` | — |
| 21 | `applied_channel` | `u8` | — |
| 22 | `sta_associated` | `bool` | — |
| 128 | `sta_enabled` | `bool` | Infrastructure STA requested by the active profile. |
| 129 | `sta_bssid` | `mac` | Associated AP BSSID; absent when not associated or unavailable. |
| 130 | `sta_ipv4` | `bytes` | Four IPv4 octets in network order; absent without a lease. |
| 131 | `sta_connections` | `u32` | Cumulative SDK connected callbacks since boot; wraps at u32 maximum. |
| 132 | `sta_disconnections` | `u32` | Cumulative SDK disconnected callbacks since boot, including intentional releases. |
| 133 | `sta_last_event_disconnect_reason` | `u8` | Most recent SDK disconnect reason, including local STA_LEAVING (36); zero before any callback. |
| 134 | `sta_diagnostic_log_drops` | `u32` | Structured STA records rejected by encoding/UART egress since boot. Missing logs do not imply missing events. |
| 135 | `sta_scan_rssi_threshold_dbm` | `i8` | Live SDK fast-scan RSSI threshold; SDK documents nonnegative values as default -127 dBm. |
| 136 | `sta_scan_authmode_threshold` | `u8` | Live SDK minimum auth-mode enum; not the AP's advertised auth mode. |
| 137 | `sta_config_channel` | `u8` | SDK association channel hint; zero means no preference, not the current radio channel. |
| 138 | `sta_config_bssid` | `mac` | SDK-configured BSSID; binding only when tag 139 is true, not proof of association. |
| 139 | `sta_config_bssid_set` | `bool` | Whether the SDK pins the configured BSSID. |
| 140 | `sta_scan_method` | `u8` | SDK scan-method enum. |
| 141 | `sta_pmf_capable` | `bool` | SDK configured PMF capability. |
| 142 | `sta_pmf_required` | `bool` | SDK requires PMF. |
| 143 | `sta_sae_pwe_method` | `u8` | SDK SAE password-element method enum. |
| 144 | `sta_config_ssid` | `bytes` | Raw 32-byte SDK SSID array, including trailing NULs; no credential material. |
| 23 | `applied_promiscuous` | `bool` | — |
| 24 | `dw_capturing` | `bool` | — |
| 25 | `applied_comparator_bssid` | `mac` | — |
| 26 | `comparator_armed` | `bool` | — |
| 27 | `comparator_errors` | `u32` | — |
| 28 | `applied_tx_interface` | `enum` | — |
| 29 | `applied_tx_rate` | `enum` | — |
| 30 | `ap_active` | `bool` | — |
| 31 | `mac_ack` | `bool` | — |
| 40 | `tx_attempted` | `u32` | — |
| 41 | `tx_driver_accepted` | `u32` | — |
| 42 | `tx_driver_failed` | `u32` | — |
| 43 | `rx_driver_dispatch` | `u32` | — |
| 44 | `rx_parser_accepted` | `u32` | — |
| 45 | `rx_parser_rejected` | `u32` | — |
| 46 | `rx_self_echo` | `u32` | — |
| 47 | `rx_dropped` | `u32` | — |
| 48 | `nan_beacons` | `u32` | — |
| 49 | `nan_sdfs` | `u32` | — |
| 50 | `nan_followups` | `u32` | — |
| 51 | `tx_duration_us_total` | `u32` | — |
| 52 | `tx_duration_us_max` | `u32` | — |
| 53 | `tx_duration_le_250us` | `u32` | — |
| 54 | `tx_duration_le_750us` | `u32` | — |
| 55 | `tx_duration_le_2ms` | `u32` | — |
| 56 | `tx_duration_gt_2ms` | `u32` | — |

### `wifi.scan` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 6 | `configured_sta_auth_mode` | `u8` | — |
| 7 | `configured_sta_ssid` | `text` | — |
| 30 | `fresh` | `bool` | — |
| 31 | `last_results` | `bool` | — |
| 40 | `iface` | `text` | — |
| 41 | `ssid` | `text` | — |
| 42 | `channel` | `u8` | — |
| 43 | `passive` | `bool` | — |


### `radio.reset_counters` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 20 | `epoch` | `u32` | — |
| 21 | `applied_channel` | `u8` | — |
| 22 | `sta_associated` | `bool` | — |
| 23 | `applied_promiscuous` | `bool` | — |
| 24 | `dw_capturing` | `bool` | — |
| 25 | `applied_comparator_bssid` | `mac` | — |
| 26 | `comparator_armed` | `bool` | — |
| 27 | `comparator_errors` | `u32` | — |
| 28 | `applied_tx_interface` | `enum` | — |
| 29 | `applied_tx_rate` | `enum` | — |
| 30 | `ap_active` | `bool` | — |
| 40 | `tx_attempted` | `u32` | — |
| 41 | `tx_driver_accepted` | `u32` | — |
| 42 | `tx_driver_failed` | `u32` | — |
| 43 | `rx_driver_dispatch` | `u32` | — |
| 44 | `rx_parser_accepted` | `u32` | — |
| 45 | `rx_parser_rejected` | `u32` | — |
| 46 | `rx_self_echo` | `u32` | — |
| 47 | `rx_dropped` | `u32` | — |
| 48 | `nan_beacons` | `u32` | — |
| 49 | `nan_sdfs` | `u32` | — |
| 50 | `nan_followups` | `u32` | — |


## Firmware module payload contracts

The following module service payloads use the tagged envelope above. Their
inner CBOR tuples and C callback ABI are specific to the optional ESP modules.

**Platforms:** E (compiled only with the firmware `modules` feature; Android
and Linux answer component 1000 with the "device-only" error.)

### Module loader

`fw/modules` supplies optional flash-module handlers for any application that
links the ESP module loader. The handler transport is a normal QUIC-lite
stream or a direct bearer record; the stream payload begins with one complete
tagged-CBOR envelope. There is no stream service byte.

The common envelope fields are defined by `dmesh-server::tagged` (see
`PROTOCOLS.md` in ssh-mesh for all keys, including `8: timeout` in milliseconds):

```text
{ 1: component, 2: method, 3: request_id?, 8: timeout_ms?, 10: binary_payload? }
```

Responses preserve `component`, `method`, and `request_id`, and put the result
in field `6` as `{1: ok, 2: loader_result_abs}`.

## Components

| Component | Handler | Method | Meaning |
|---:|---|---:|---|
| 1000 | module | 1 | Refresh and return loader header/status. |
| 1000 | module | 2 | Initialize the native module loader. |
| 1000 | module | 3 | Request a loader stop with a deadline before flash work. |
| 1001 | hello | 4 | Start module service tag 46. |
| 1002 | lora | 4 | Configure and start/command module service tag 43. |
| 1003 | hardware | 4 | Start module service tag 45. |

For `RUN` (method 4), field `10` is passed unchanged as the size-limited module
payload. The loader derives flash placement from its service tag and validates
the DMOD header; callers never supply a flash offset.

For component `1002` only, field `4` is the required one-item CBOR array
`[operation]`. Supported operations are `probe`, `probe127`, `probe126`,
`rx`, `tx`, `stop`, `reconfigure`, `fsk`, and `stats`. Field `10` is the
opaque `tx`/`fsk` packet, never a command string. Optional field `5` is a
numeric configuration map. Its IDs follow `dmesh_lora_config_v1` after the
ABI header: `1..14` are chip/frequency/bandwidth/SF/SPI/sync/power and the
seven board pins; `15..24` are board-power and SX126x settings; `25..30` are
coding rate, preamble, CRC, CAD mode, CAD interval, and CAD RX duration. An
omitted map uses the established SX127x TLORA profile (913.125 MHz, 250 kHz,
SF10, CR5, sync word 0x2b). This makes legacy LoRa boards usable without
reintroducing the retired text-command dispatcher; SX1262 boards must provide
their wiring/configuration map.

## Ownership and limits

`dmesh-server` owns a fixed 16-entry, no-allocation component registry. Each
component has a separate function registration, and a component may serve any
number of concurrent QUIC streams. The bearer only owns stream ordering and
flow control; it does not interpret a module ID.

This first extraction includes the loader control/start path. Module-originated
settings reads/writes, emitted events, and nested service calls currently fail
with loader ABI result `-2`; they are intentionally not routed through the
deleted Main string-command dispatcher. They will be connected to the common
`dmesh-server` settings/event/direct-record handlers in the next migration.

## Frozen Recovery build option

Recovery is currently frozen and its build entry point is deliberately
disabled. Do not use the historical commands below; Main is the active
firmware lane. They are retained only as migration notes:

The last C6 measurement (2026-08-21) produced 911,360 bytes without modules
and 949,136 bytes with modules: +37,776 bytes. The one-MiB recovery partition
therefore retains 99,440 bytes of headroom with module support.

### Hardware module

Status: experimental V3. Service tag `45`, slot `2`, one 64-KiB slot.

`hw.dmod` is a replaceable, `no_std` peripheral service. Main supplies the
host ABI; the module owns peripheral policy and emits compact telemetry. Main
does not need to understand the event payloads.

The C ABI declaration is [dmesh_hw_abi.h](../modules/include/dmesh_hw_abi.h).
The numeric module ABI below is part of this root contract.
Names are documentation only; firmware requests and events use integer tuples.

#### Module request

The module entry payload is a definite-length CBOR array of unsigned integers.
The first item is `operation`; the remaining items depend on that operation.
No text keys or text values are required.

The array is the body of QUIC-lite stream service tag `45`. The immediate
stream response is CBOR `[0]` when the fixed-capacity Main-owned module queue accepts
the request; execution and samples are asynchronous module events. `[0]` is
not a completed-operation result.

##### Operation IDs

| ID | Name | Purpose |
|---:|---|---|
| 1 | `battery` | Read the configured battery ADC and emit one event |
| 2 | `adc_probe` | Sample one or more ADC pins |
| 3 | `button` | Run the GPIO button interrupt task |

##### Battery request

```text
[1, pin, ref_mv, divider_x100, min_mv, max_mv,
   control_pin, control_level, enabled]
```

All fields after `1` are optional and default to the corresponding settings:

| Position | Field | Default |
|---:|---|---:|
| 1 | ADC GPIO | `battery.pin`, 35 |
| 2 | ADC reference in mV | `battery.ref_mv`, 3300 |
| 3 | Battery divider ×100 | `battery.divider_x100`, or `battery.divider` parsed as decimal |
| 4 | Empty voltage in mV | `battery.min_mv`, 3300 |
| 5 | Full voltage in mV | `battery.max_mv`, 4200 |
| 6 | ADC control GPIO | `battery.ctrl`, -1 disabled |
| 7 | Control active level | `battery.ctl_lvl`, 1 |
| 8 | Enabled | 1 |

When a control GPIO is present, the module configures it as an output, sets
the active level, waits 10 ms, samples, then sets the inactive level.

##### ADC probe request

```text
[2, sample_count, interval_ms, ref_mv, pin0, pin1, ...]
```

`sample_count=0` means continuous until the module task is stopped. The count
is bounded by the host/task lifetime; `interval_ms` is clamped to 0..60000.
The loader permits independent service tasks to run concurrently. The radio
service (tag 43) and hardware service (tag 45) have separate runtime state;
flash preparation stops all active services before erasing their slots.
If no pins are supplied, the default list is `[34, 35, 36, 39]`.

##### Button request

```text
[3, gpio, enabled]
```

Defaults are `button.gpio=0` and `enabled=1`. The module registers both-edge
interrupts, classifies releases as short, long (at least 2500 ms), or double
(within 500 ms), and exits when the host stop callback is asserted.

#### Event ABI

Events use the common module event callback with `value_type=5`:

```text
ModuleEvent(event_id, value_type=5, flags, cbor_tuple)
```

The payload is a CBOR tuple of unsigned integers. `value_type=5` means Main
must forward the bytes unchanged; it must not format or reinterpret fields.
Module callback payloads are limited to 1024 bytes until stream-response
segmentation is implemented. Main exposes them unchanged through service tag
`events` as CBOR `[next_sequence, [[sequence, event_id, value_type, flags,
payload], ...]]`; clients poll with the ASCII request `since=<sequence>`.

##### Event IDs and tuples

| ID | Name | Tuple |
|---:|---|---|
| 110 | `adc.sample` | `[pin, raw, adc_mv, 0, 255, ref_mv, unit, channel]` |
| 111 | `battery.sample` | `[pin, raw, adc_mv, battery_mv, level, ref_mv, unit, channel]` |
| 101 | `button.short` | `[pin, held_ms, 0]` |
| 102 | `button.long` | `[pin, held_ms, 0]` |
| 103 | `button.double` | `[pin, held_ms, 0]` |

For `adc.sample`, battery voltage is zero and level is `255` (unknown).
`level=255` is reserved for unknown; otherwise battery level is 0..100.
`unit` is 1-based (`1=ADC1`); `channel` is the ESP ADC channel number.

#### Host ABI

The host table provides generic GPIO, ADC, I2C, SPI, RGB LED, IRQ, event
wait, stop, sleep, and monotonic-time callbacks. `adc_read` is the original
raw/mV operation. `adc_read_ex` is additive and returns ADC unit/channel
metadata. Modules must check `size` before using additive fields.

Callbacks return zero on success or an ESP error/result code. The host owns
SDK objects and synchronization; modules must not link ESP-IDF or block on
unbounded operations.

#### Ownership and storage

- Main owns the ABI implementation and command/service dispatch. The
  device-facing identity is the numeric service tag; names are controller and
  schema data only.
- `hw.dmod` owns battery, ADC probe, button, and peripheral policy.
- Recovery owns only the flash transport and named module-slot writing.
- LoRa and hardware modules use fixed 64-KiB-aligned slots: physical offset is
  `(service_tag - 43) * 0x10000`.
- Event IDs 1..127 are reserved for core hardware events; 128..255 are
  available for future peripheral modules.
- Operation IDs 1..63 are reserved for this module; 64..255 are future work.

### LoRa module

`mod_lora` owns the module-local radio ABI. Main owns loading, placement,
power, GPIO/SPI host primitives, and forwarding; this document owns radio
configuration, packet semantics, and module event tuples.

The module event tuple is `[event_id, value_type, flags, value]`. Current IDs
are `1=rx_started`, `2=rx_stopped`, `3=tx_done`, `4=reconfigured`,
`5=stats`, and `6=tx_error`. RX/TX operations are asynchronous; completion and
errors are events, not blocking command responses.

LoRa and FSK wire payloads are opaque to Main. Chip-specific IRQ, FIFO, BUSY,
reset, and continuous-RX behavior remain module-owned.

The QUIC-lite service tag is `43`. Main acknowledges an accepted stream
request with CBOR `[0]`, then invokes the module from its serialized owner
loop. RX/TX completion remains an asynchronous module event; bearer tasks do
not wait for radio work.
