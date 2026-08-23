# lmesh-wifi API

`lmesh-wifi` is the host Wi-Fi/netd ownership crate used by the full `lmesh`
service and the isolated `lmesh-wifi` service. Linux Wi-Fi, AP/STA, and raw-NAN
operations are implemented in this crate.

## Ownership

`LMESH_INTERFACES` is a comma-separated allowlist of Wi-Fi interfaces owned by
the process. Names are trimmed, sorted, and deduplicated. An empty value owns
no interfaces. AP, STA, and NAN operations must reject interfaces outside this
set.

Example:

```text
LMESH_INTERFACES=wlan0,wlan1
```

## Capabilities

The crate provides the common ownership and authorization layer for:

- direct nl80211 open-AP operations and station inspection;
- STA join/status/address test operations;
- raw-NAN diagnostics and sleepy-device wake/control traffic;
- NAN object-store bearer primitives already exposed by lmesh.

The shared DM v1 NAN/BLE wire format and raw frame state machine live in
[`dmesh-rawnan/API.md`](../rawnan/API.md). This crate owns only the Linux
interface operations and their AP/STA/raw-NAN orchestration.

Legacy UART forwarding is retired. The UART L2 implementation is owned only by
`dmesh-cli`, including its E2E harness; `lmesh-wifi` does not open, proxy,
enumerate, or select a board serial device. Host service requests use the
CBOR mesh/UDP/NAN paths instead.

Experimental BLE HCI operations are owned by `lmesh` and are intentionally
outside this stable library.

The full AP command names remain `wifi.ap.*`. Host raw-NAN operations are
`wifi.rawnan.*` and use the shared `dmesh-rawnan` state machine. Frame
transmission is selectable: `monitor`/`monitor_active` inject through a
monitor VIF, while `onchannel`, `onchannel_noack`, and `roc` use
`NL80211_CMD_FRAME` on the owned base interface. The Wi-Fi-only binary exposes
the service socket selected by mesh-init, normally
`/run/mesh/lmesh-wifi/mesh.sock`.

## Common announce identity

UDP multicast, NAN Service Info, NOW forwarding, and the local
`wifi.discovery.observe` ingress all update one bounded discovered-device
registry. An ESP32 announce may be unsigned (no public key and no signature).
A host or Android announce that includes a public key is admitted only when
its P-256 signature verifies over the canonical tagged-CBOR record and its
device ID matches the key digest. Invalid key-bearing records are dropped
before they reach the registry or its change-only JSONL log. This keeps
transport provenance separate from identity validation.

## Reviewed tagged-CBOR methods

The Wi-Fi methods below are the reviewed tagged-CBOR surface. They use
component index 5. The raw listener/check methods are deliberately bounded
diagnostics: they may create or remove a raw monitor child, but never retune,
start, stop, or reconfigure the owned AP. Other radio/AP state changes remain
in the legacy JSON-RPC gateway until their fields and side effects receive the
same wire review.

The corresponding request structs in [`src/api.rs`](src/api.rs) are a
dependency-free source for a review draft. This does not replace this file:
stable numeric IDs remain reviewed here before catalog generation.

```sh
cd ../rust/ssh-mesh
cargo run -p mesh-api-gen -- --rust /ws/dmesh/crates/lmesh-wifi/src/api.rs \
  --out-api /tmp/lmesh-wifi-api-from-rust.md
```

```mesh-api
id = "wifi.ap.status"
component = "wifi"
method = "ap.status"
component-index = 5
method-index = 1
summary = "Return owned open-AP status"
[request]
fields = [{ name = "iface", index = 1, type = "string" }]
```

```mesh-api
id = "wifi.sta.status"
component = "wifi"
method = "sta.status"
component-index = 5
method-index = 2
summary = "Return owned station status"
[request]
fields = [{ name = "iface", index = 1, type = "string" }]
```

```mesh-api
id = "wifi.rawnan.status"
component = "wifi"
method = "rawnan.status"
component-index = 5
method-index = 3
summary = "Return raw-NAN status, the bounded one-hour cross-bearer discovered-device inventory, and NAN follow-ups. New/dropped devices append JSONL records to LMESH_DISCOVERY_LOG or LMESH_WIFI_DISCOVERY_LOG (default /run/mesh/lmesh-wifi/discovery.jsonl); routine refreshes do not log."
[request]
fields = [{ name = "iface", index = 1, type = "string" }]
```

```mesh-api
id = "wifi.rawnan.active_publish"
component = "wifi"
method = "rawnan.active_publish"
component-index = 5
method-index = 15
summary = "Replace the local active NAN Publish Service Info. An enabled descriptor is emitted once in the next confirmed discovery window and then at the bounded refresh cadence; this request never transmits immediately or changes interface state. service_info_hex is the bounded CBOR Service Info payload."
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "enabled", index = 2, type = "bool" },
  { name = "service_info_hex", index = 3, type = "string", optional = true },
]
```

```mesh-api
id = "wifi.probe.plan"
component = "wifi"
method = "probe.plan"
component-index = 5
method-index = 16
summary = "Resolve a discovery-selected comprehensive pair probe and return the live ESP/Android/Host fleet without changing the control-plane radio"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "source_id", index = 2, type = "string", required = true },
  { name = "target_id", index = 3, type = "string", required = true },
  { name = "short_bytes", index = 4, type = "u32" },
  { name = "long_bytes", index = 5, type = "u32" },
]
```

```mesh-api
id = "wifi.interface.status"
component = "wifi"
method = "interface.status"
component-index = 5
method-index = 4
summary = "Return owned interface status"
[request]
fields = [{ name = "iface", index = 1, type = "string" }]
```

```mesh-api
id = "wifi.ap.stations"
component = "wifi"
method = "ap.stations"
component-index = 5
method-index = 5
summary = "Return associated station metrics for an AP interface"
[request]
fields = [{ name = "iface", index = 1, type = "string" }]
```

```mesh-api
id = "wifi.raw.metrics"
component = "wifi"
method = "raw.metrics"
component-index = 5
method-index = 6
summary = "Return bounded raw action receive and dispatch counters"
[request]
fields = [{ name = "iface", index = 1, type = "string" }]
```

```mesh-api
id = "wifi.raw.stop"
component = "wifi"
method = "raw.stop"
component-index = 5
method-index = 7
summary = "Stop the raw action listener"
[request]
fields = [{ name = "iface", index = 1, type = "string" }]
```

```mesh-api
id = "wifi.raw.listen"
component = "wifi"
method = "raw.listen"
component-index = 5
method-index = 8
summary = "Start or renew a bounded raw action listener"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "channel", index = 2, type = "u8" },
  { name = "listen_sec", index = 3, type = "u64" },
  { name = "rx_variant", index = 4, type = "string" },
]
```

```mesh-api
id = "wifi.raw.check"
component = "wifi"
method = "raw.check"
component-index = 5
method-index = 9
summary = "Run one raw action liveness check"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "channel", index = 2, type = "u8" },
  { name = "destination", index = 3, type = "string", required = true },
  { name = "nonce", index = 4, type = "u64" },
  { name = "timeout_ms", index = 5, type = "u64" },
  { name = "tx_rate_mbps", index = 6, type = "u8" },
  { name = "tx_variant", index = 7, type = "string" },
  { name = "rx_variant", index = 8, type = "string" },
  { name = "expected_peer", index = 9, type = "string" },
]
```

```mesh-api
id = "wifi.raw.iperf"
component = "wifi"
method = "raw.iperf"
component-index = 5
method-index = 10
summary = "Run raw action QUIC-lite IPERF"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "channel", index = 2, type = "u8" },
  { name = "destination", index = 3, type = "string", required = true },
  { name = "bytes", index = 4, type = "u64" },
  { name = "packet_size", index = 5, type = "u16" },
  { name = "timeout_ms", index = 6, type = "u64" },
  { name = "tx_rate_mbps", index = 7, type = "u8" },
  { name = "tx_variant", index = 8, type = "string" },
  { name = "rx_variant", index = 9, type = "string" },
  { name = "expected_peer", index = 10, type = "string" },
]
```

```mesh-api
id = "wifi.raw.send"
component = "wifi"
method = "raw.send"
component-index = 5
method-index = 11
summary = "Send one raw Wi-Fi validation frame"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "channel", index = 2, type = "u8" },
  { name = "tx_variant", index = 3, type = "string" },
  { name = "tx_rate_mbps", index = 4, type = "u8" },
  { name = "frame_hex", index = 5, type = "string" },
]
```

```mesh-api
id = "wifi.rawnan.ping"
component = "wifi"
method = "rawnan.ping"
component-index = 5
method-index = 12
summary = "Send a bounded NAN discovery probe"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "channel", index = 2, type = "u8" },
  { name = "destination", index = 3, type = "string" },
  { name = "bssid", index = 4, type = "string" },
  { name = "payload", index = 5, type = "string" },
  { name = "wait_ms", index = 6, type = "u64" },
]
```

```mesh-api
id = "wifi.rawnan.listen"
component = "wifi"
method = "rawnan.listen"
component-index = 5
method-index = 14
summary = "Start or renew a bounded raw-NAN listener"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "channel", index = 2, type = "u8" },
  { name = "listen_sec", index = 3, type = "u64" },
]
```

At startup the service prepares the service-owned monitor fixture and keeps
the receive loop active. A raw-NAN-specific subscription such as
`dmesh.event.wifi.rawnan.rx`, `.beacon`, or `.discovery` only consumes that
existing loop; test requests never create, stop, retune, or administratively
change an interface. `wifi.rawnan.status` reports whether that monitor is
active, whether a NAN cluster BSSID has been learned, and a newest-first
bounded receipt list for DMesh NAN Follow-ups. Its `discovered_devices`
inventory is keyed by device identity and retains the latest observation for
every bearer: `nan` states whether this host actually observed NAN from the
device, `active_transport` projects the advertised transport mode, and
`observations` preserves the peer/timestamp per source. A UDP6-only Android
record therefore remains visible even when `nan.observed=false`. Each receipt retains
peer/BSSID, DMesh message type and sequence, and the bounded payload for E2E
attribution.

The inventory is bearer-neutral: raw NAN receives enter it directly, while
the sibling `lmesh` service forwards its already validated multicast announce
records over the local supervised socket as `wifi.discovery.observe`. That
local-only ingress accepts the canonical CBOR announce, cannot change radio
state, and uses the same one-hour expiry and change-only log. Standalone
`lmesh-wifi` defaults to `/run/mesh/lmesh-wifi/discovery.jsonl`; embedded
`lmesh` uses `/run/mesh/lmesh/discovery.jsonl` to avoid duplicate service
records. Set `LMESH_DISCOVERY_LOG` (or the compatibility
`LMESH_WIFI_DISCOVERY_LOG`) only when one explicit durable aggregate log is
intended.

The permanent active monitor is retained for NOW transmission. At startup the
service also registers management beacons through nl80211 and feeds either RX
lane into the same NAN synchronization state. This is needed on adapters that
deliver SDF actions to an active monitor but suppress beacon RX there; the
registration does not start, stop, or retune an interface.

`mesh.send radio=nan destination=<peer-mac> payload=<text>` and
`mesh.tagged.forward destination=<peer-mac>` are the explicit Follow-up test
senders. They construct a NAN Follow-up SDF, rather than a generic vendor
action, and return `NAN follow-up outside discovery window` unless the
selected cluster beacon opened the current DW. They reuse the service-owned
permanent monitor; neither command starts, stops, nor reconfigures a host
interface.

The host experiment commands are available on the service socket:

## Object-store UDP bearer

The Wi-Fi service starts the feature-gated host QUIC/UDP adapter from
`dmesh-server`. It can also be started on the existing service socket
without restarting `lmesh-wifi`:

```text
mesh lmesh-wifi wifi.object.udp.start bind=0.0.0.0 port=3336 root=/ws/dmesh/target/flash
```

The bearer is also started automatically by `lmesh-wifi` at port 3336. The
explicit command is idempotent and remains useful for selecting another
artifact root.

The server routes datagrams by opaque DCID to a transport connection, then
dispatches its registered `dmesh-server` stream services. This includes binary
CBOR GET/manifest/blob transfer and the deterministic `iperf` stream handler;
clients can therefore request IPERF over the same managed UDP bearer that owns
the WLAN interface and its capabilities. UDP is only the datagram bearer;
`quic-lite` itself has no socket, CBOR, or UDP code. No TCP object-store
compatibility listener remains.

## ESP-NOW/action validation

`dmesh-cli` is the standalone UART/STA test client and UDP server. It is also
the only host process allowed to open a board UART. `lmesh-wifi` owns only the
WLAN capabilities needed to validate raw ESP-NOW/vendor-action frames; it does
not proxy an IPERF or service request through a serial device.

NAN remains discovery/bootstrap only. The extended ESP-NOW/DMesh vendor-action
frame is the planned QUIC-lite data bearer and will carry the same
`dmesh-server` object/control/log services as UDP and UART. Raw-action
injection/history commands below are diagnostics, not object or flashing
completion evidence; the production action flash operation is added only with
the host action adapter and the shared Main/Recovery receiver.

```text
wifi.interface.status iface=wlan1
wifi.interface.up iface=wlan1
wifi.interface.channel iface=wlan1 channel=6
wifi.raw.stop iface=wlan1
wifi.raw.send iface=wlan1 destination=<mac> bssid=<cluster> payload=hex:...
# `monitor` is the default host NOW/NAN injector; `action` remains an
# explicit nl80211 management-frame experiment and requires association.
wifi.raw.send iface=wlan1 tx_variant=action destination=<mac> bssid=<cluster> payload=hex:...
wifi.raw.send iface=wlan1 tx_variant=nan_data_raw llc=hex:... destination=<mac> bssid=<cluster> payload=hex:...
wifi.raw.send iface=wlan1 channel=6 tx_variant=monitor frame_hex=<80211-header-and-body-hex>
wifi.raw.send iface=wlan1 channel=6 tx_variant=af_packet frame_hex=<ethernet-frame-hex>
messages.history keys=wifi.raw.tx,wifi.raw.rx limit=40
```

### Historical AP+NAN setup reference

```sh
source ./env.sh
mesh lmesh wifi.ap.start_open iface=wlan1 ssid=dmesh-lmesh6 beacon_interval_tu=500
mesh lmesh-wifi wifi.ap.status iface=wlan0
mesh lmesh-wifi wifi.rawnan.status iface=wlan0
```

The optional `beacon_interval_tu` is clamped to 10--1000 TU and defaults to
100; larger values reduce beacon contention during raw-action measurements.
The AP command owns only `wlan1`; `lmesh-wifi` continues to own `wlan0`.
The former UART command steps are intentionally omitted: transport tests use
the registered QUIC-lite services over a discovered L2 path. `sync_beacon` is
an explicit debugging transmission, not production NAN master-election
behavior. See [`debugging.md`](debugging.md) for captures.

### Persistent socket and event polling

The Unix socket accepts multiple newline-delimited requests on one connection:

```sh
socat - UNIX-CONNECT:/run/mesh/lmesh-wifi/mesh.sock
{"method":"wifi.rawnan.status","iface":"wlan0"}
{"method":"messages.history","keys":"wifi.ap.mgmt,wifi.rawnan.rx","limit":40}
```

Use `/run/mesh/lmesh/mesh.sock` for `wlan1`. The textual `mesh` command is
convenient for polling the structured event history:

```sh
while sleep 1; do
  mesh lmesh-wifi messages.history keys=wifi.ap.mgmt,wifi.rawnan.rx limit=40
done
```

For live pub/sub, keep the socket open and subscribe by `target`:

```sh
timeout 2s socat - UNIX-CONNECT:/run/mesh/lmesh-wifi/mesh.sock
{"method":"subscribe","targets":["dmesh.event.wifi"]}

# Text-oriented mesh client (9-second default timeout, overridden here).
timeout 2s mesh --timeout-sec 2 lmesh-wifi subscribe targets=dmesh.event.wifi
```

The server sends an acknowledgement, buffered matching records, and then live
records until the connection closes. The same envelope is used for traces,
discovery, beacons, action frames, and data events; semantic IDs and schemas
remain an L7 concern. Use `/run/mesh/lmesh/mesh.sock` for the experimental
`lmesh` service, or:

```sh
timeout 2s socat - UNIX-CONNECT:/run/mesh/lmesh/mesh.sock
{"method":"subscribe","targets":["dmesh.event.wifi"]}
timeout 2s mesh --timeout-sec 2 lmesh subscribe targets=dmesh.event.wifi
```

The `mesh` client defaults to a 9-second response/stream timeout; pass
`--timeout-sec N` to change it. The shell `timeout` bounds the whole sampling
command as well.

`wifi.raw.send` records the selected bearer, interface-up result, addresses,
LLC marker, payload length, and kernel error/result in `wifi.raw.tx` history.
The `messages.history` method is exposed by both the full `lmesh` service and
the standalone `lmesh-wifi` service.

## Host counterpart of the firmware radio laboratory

`wlan1` is the host-side sender/receiver for the Recovery-first raw-frame
matrix; it avoids reflashing a second ESP merely to change a frame shape or
rate.  Use the existing explicit operations as the host counterpart of the
firmware `radio.control` handler:

```text
wifi.interface.channel iface=wlan1 channel=6
wifi.rate.profile iface=wlan1 profile=auto disable_80211b=false
wifi.raw.listen iface=wlan1 channel=6 rx_variant=nl80211 listen_sec=60
wifi.raw.send iface=wlan1 channel=6 tx_variant=action destination=ff:ff:ff:ff:ff:ff bssid=<cluster> payload=hex:...
wifi.raw.send iface=wlan1 channel=6 tx_variant=monitor tx_rate_mbps=54 frame_hex=<80211-frame>
wifi.raw.iperf iface=wlan1 channel=6 destination=<esp-mac> bytes=16384 packet_size=1100 tx_variant=monitor rx_variant=monitor tx_rate_mbps=54 timeout_ms=20000
wifi.raw.stop iface=wlan1
messages.history keys=wifi.raw.tx,wifi.raw.rx,wifi.rawnan.rx limit=40
```

`wifi.raw.iperf` is a host raw-action client using the same bearer-neutral
`dmesh_server::raw_iperf::RawIperfClient` as firmware. All current bearers
share the 1100-byte maximum transport packet; `packet_size`,
`tx_rate_mbps` (6, 9, 12, 18, 24, 36, 48, or 54), and `timeout_ms` are explicit
runtime parameters. `tx_variant=monitor` is the default and historically
proven AF_PACKET/radiotap injection path; `tx_variant=nl80211` is retained as
an explicit management-frame driver experiment. `rx_variant` is independently
selectable and defaults to monitor. Its result reports the chosen values and
counts each received action once.


The operations deliberately share frame builders, `dmesh-rawnan` parsing, and
event history with `lmesh-wifi`; no ESP-specific socket facade is emulated.
Linux has no equivalent of the ESP private Address-3 hardware comparator or
its NAN interface.  Consequently, a host result must label monitor capture as
monitor capture and must not claim a non-promiscuous comparator result.  The
before/after history samples are the host metric boundary, while the ESP
`radio.snapshot` counters are the device metric boundary.

For arbitrary injection, `frame_hex` bypasses the structured DMesh builders:
`monitor`/`monitor_active` takes an 802.11 management or data frame without
radiotap and adds the required radiotap header; both use the already-prepared
NAN+NOW monitor and do not change radio state. `action` submits the same
802.11 header through `NL80211_CMD_FRAME`/`send_mgmt_frame` (driver support is
adapter-specific); `af_packet` writes a complete
Ethernet frame directly to `wlan1`. The latter exercises the normal AP/STA
data path and is not an 802.11-header injection API.

AP startup is a service policy. `LMESH_AP_ADDRESS` optionally selects the
static IPv4 address/prefix applied to the owned open AP; the current service
default is `10.78.0.1/16`. `lmesh-wifi` uses the normal 100-TU interval
(`LMESH_AP_BEACON_INTERVAL_TU=100`). `lmesh` defaults its independently owned
`wlan1` lab AP to 500 TU; setting `LMESH_AP_AUTOSTART=0` restores the AP-off
NAN+NOW experiment. The AP defaults to HT20 so STA, NAN, and NOW can share a
single 20 MHz channel. Set
`LMESH_AP_HT40=true`, or pass
`ht40=true` to `wifi.ap.start_open`, only for a dedicated AP experiment.

`wifi.interface.channel` is an explicit nl80211 channel pin for the owned
interface (currently 2.4 GHz channels 1-13). It brings only that interface up
and does not reconfigure `wlan0` or restart `lmesh-wifi`. To create a carrier
that holds channel 6, use the existing explicit `wifi.ap.start_open iface=wlan1`
command; stop it with `wifi.ap.stop iface=wlan1` before returning to an
unassociated raw-NAN experiment. Ad-hoc and P2P modes remain driver-specific
and are not enabled implicitly by this command.

> TODO(host AP-off NAN+NOW): make the permanent `wlan1mon` fixture retain its
> requested channel while `wlan1` is unassociated, then validate NAN/NOW
> receive without an AP carrier. On the current mt7921u setup, a successful
> `wifi.interface.channel` call is not sufficient to keep an unassociated
> managed-plus-monitor radio tuned; the explicit wlan1 AP is the temporary
> lab anchor only, never an automated-test setup step.
>
> `lmesh` preserves `channel`, `ht40`, and `beacon_interval_tu` when it
> forwards this explicit lab/startup operation. They are not E2E test setup.

For an operator-only scan-path diagnostic, use a passive, single-channel
scan. It does not bring an interface up, start or stop an AP, or create/delete
a monitor VIF; it only asks cfg80211 to dwell on channel 6 and returns the BSS
cache result. It is not permitted in automated tests and cannot replace a
received NAN sync beacon as a DW clock.

```text
wifi.scan iface=wlan1 channel=6 passive=true
```

To replace the AP with an unassociated 802.11 OCB carrier on channel 6, use:

```text
wifi.ap.stop iface=wlan1
wifi.ocb.start iface=wlan1 freq=2437 bandwidth=10MHz
```

OCB means “outside context of a BSS”: there is no SSID, association, WPA, or
AP station table. It is supported only when the driver and regulatory domain
advertise OCB on the requested frequency. This changes only `wlan1` and
disconnects any station using its AP.

`wifi.raw.stop` removes only lmesh's `wlan1mon` monitor VIF, allowing the
interface to be retuned or changed to AP/IBSS/P2P without affecting `wlan0`.

When `wlan1` is an AP, its single nl80211 AP-SME receive loop registers and
handles normal AP management frames together with NAN public actions and the
DMesh/ESP-NOW vendor-action marker (`7f 18 fe 34`). A monitor VIF is not needed
for that AP-main receive path. All action frames pass through one classifier,
which records the source/destination/BSSID, signal, NAN classification, and
the DMesh vendor payload when present. This adapter cannot register beacon
frames through the AP-SME socket (`Registration to specific type not
supported`); beacon capture therefore requires an existing monitor/capture
interface. The AP remains fully functional when that optional registration is
rejected.

For repeatable captures, use `scripts/capture-rawnan.sh`. Set
`DMESH_CAPTURE_IFACE`, `DMESH_SSID`, `DMESH_NAN_BSSID`, `DMESH_SRC`, and
`DMESH_DST` as needed, then run `show`, `tcpdump`, or `tshark`.

For fixed-rate NAN experiments, use `wifi.rate.profile` on an owned interface:

```text
wifi.rate.profile iface=wlan0 profile=12 disable_80211b=true
wifi.rate.profile iface=wlan0 profile=24 disable_80211b=true
wifi.rate.profile iface=wlan0 profile=ht3
wifi.rate.profile iface=wlan0 profile=ht3-24
wifi.rate.profile iface=wlan0 profile=auto
```

Inspect or request the owned interface's power-save policy through the same
service (rather than an out-of-band `iw` command). Drivers can reject this in
AP mode; the result preserves the exact nl80211 error for diagnosis:

```text
wifi.power_save iface=wlan0 enabled=false
wifi.power_save iface=wlan0 enabled=true
```

The 12/24 profiles restrict legacy 2.4 GHz rates and remove 802.11b/CCK
rates. `ht2`, `ht3`, and `ht4` are exact HT-MCS diagnostics: they omit legacy
data fallback so station status can prove the selected MCS. `ht3-24` is the
association-safe version: MCS3 plus only a 24 Mbps OFDM fallback. They are
intended for bounded throughput trials, not as a startup default. `auto`
restores driver-selected rates. The service sends the nested
`NL80211_ATTR_TX_RATES` request directly, so no `iw` executable or inherited
child-process capability is required; kernel errno/extack text is returned on
failure. Restore it after each trial. The Linux single-frame matrix is
`scripts/test-nan-fixed-rates.sh` and defaults to 12 and 24 Mbps.

Service startup defaults to the standard driver/automatic policy
(`LMESH_WIFI_RATE_PROFILE=auto`) for ordinary Wi-Fi traffic. NAN
synchronization/discovery beacons are forced to 6 Mbps, and NAN public
action/SDF frames use the mandatory OFDM family. For targeted close-peer
traffic, add `tx_rate_mbps=12|24|48|54` to a monitor-based `wifi.raw.send`;
this is encoded in the monitor radiotap RATE field and does not change the
interface-wide NAN policy. The nl80211 action-frame path rejects a per-frame
rate attribute, so it reports that kernel error rather than silently falling
back.

To recover one stale client without interrupting the AP, use:

```text
wifi.ap.station.remove iface=wlan0 mac=84:0d:8e:07:42:c4
wifi.ap.station.remove_all iface=wlan0
```

These issue nl80211 station deletion requests. The AP remains running and
other clients are not intentionally disconnected.

## Library surface

- `InterfaceSet::parse` and `InterfaceSet::from_environment` load ownership.
- `InterfaceSet::require` rejects unowned interfaces.
- `WifiNetd::authorize` applies the ownership policy to `Operation::Ap`,
  `Operation::Sta`, and `Operation::Nan`.

The protocol text/JSON/CBOR conversion and schema loading are provided by
`ssh-mesh/crates/mesh`, not duplicated here.
