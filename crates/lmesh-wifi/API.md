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

Legacy UART forwarding is retired. `lmesh-uart` remains a reusable serial L2
library, but has no device command, log, or flash socket. A future
`lmesh-wifi` device manager may own a board's direct serial and STA adapters
together; it contributes both to the same peer/path record, whose DCID maps to
one QUIC-lite connection. It may therefore probe, select, or use serial and
UDP concurrently without making an application command bearer-specific.

Experimental BLE HCI operations are owned by `lmesh` and are intentionally
outside this stable library.

The full AP command names remain `wifi.ap.*`. Host raw-NAN operations are
`wifi.rawnan.*` and use the shared `dmesh-rawnan` state machine. Frame
transmission is selectable: `monitor`/`monitor_active` inject through a
monitor VIF, while `onchannel`, `onchannel_noack`, and `roc` use
`NL80211_CMD_FRAME` on the owned base interface. The Wi-Fi-only binary exposes
the service socket selected by mesh-init, normally
`/run/mesh/lmesh-wifi/mesh.sock`.

At startup the service starts the open AP, but does not create a raw-NAN
monitor. A monitor is acquired only while a live raw-NAN-specific subscription
such as `dmesh.event.wifi.rawnan.rx`, `.beacon`, or `.discovery` is connected;
a broad `dmesh.event.wifi` subscription does not start it. The monitor is
released when the last such subscriber disconnects. Explicit
`wifi.rawnan.listen` and `wifi.rawnan.ping` requests may still acquire it for a
bounded diagnostic. `wifi.rawnan.status` reports
whether that monitor is active and whether a NAN cluster BSSID has been
learned.

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

## Gateway IPERF client

`transport.client.iperf` starts the same `lmesh-uart` client implementation
used by the standalone `dmesh-iperf` binary. It is a gateway operation, not a
second raw-radio benchmark:

```text
mesh lmesh-wifi transport.client.iperf iface=wlan0 \
  serial=/dev/serial/by-id/<device> bootstrap=10.78.0.1:0 \
  backend=10.78.0.1:3339 bytes=2097152 bearer=spill
```

The current host gateway slice requires a direct serial L2 plus an IP backend.
`bearer` accepts `uart`, `udp`, `aggregate`/`fastest`, or `spill`; the same
policy values will select ESP-NOW and LoRa/FSK paths once those adapters enter
the shared connection owner. The request returns once the bounded client task
starts; its terminal report is emitted by the shared client, not inferred from
that start acknowledgement.

`transport.client.service` uses the same client implementation for direct
UDP/IP service requests, including a bounded `log-watch` poll:

```text
mesh lmesh-wifi transport.client.service iface=wlan0 \
  target=udp://10.78.0.42:3339 service=log-watch log_records=16
```

It records completion in service history. `log-watch` is presently a bounded
poll; a persistent framed subscription is planned and will use this same
connection/path owner.

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
wifi.raw.send iface=wlan1 tx_variant=onchannel_noack destination=<mac> bssid=<cluster> payload=hex:...
wifi.raw.send iface=wlan1 tx_variant=action destination=<mac> bssid=<cluster> payload=hex:...
wifi.raw.send iface=wlan1 tx_variant=nan_data_raw llc=hex:... destination=<mac> bssid=<cluster> payload=hex:...
wifi.raw.send iface=wlan1 channel=6 tx_variant=monitor frame_hex=<80211-header-and-body-hex>
wifi.raw.send iface=wlan1 channel=6 tx_variant=af_packet frame_hex=<ethernet-frame-hex>
messages.history keys=wifi.raw.tx,wifi.raw.rx limit=40
```

### Historical AP+NAN setup reference

```sh
source ./env.sh
mesh lmesh wifi.ap.start_open iface=wlan1 ssid=dmesh-lmesh6
mesh lmesh-wifi wifi.ap.status iface=wlan0
mesh lmesh-wifi wifi.rawnan.status iface=wlan0
```

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

For arbitrary injection, `frame_hex` bypasses the structured DMesh builders:
`monitor`/`monitor_active` takes an 802.11 management or data frame without
radiotap and adds the required radiotap header; `af_packet` writes a complete
Ethernet frame directly to `wlan1`. The latter exercises the normal AP/STA
data path and is not an 802.11-header injection API. `monitor_active` may take
the parent interface down, so use `monitor` while an AP must remain active.

AP startup is a service policy. `LMESH_AP_ADDRESS` optionally selects the
static IPv4 address/prefix applied to the owned open AP; the current service
default is `10.78.0.1/16`.

`wifi.interface.channel` is an explicit nl80211 channel pin for the owned
interface (currently 2.4 GHz channels 1-13). It brings only that interface up
and does not reconfigure `wlan0` or restart `lmesh-wifi`. To create a carrier
that holds channel 6, use the existing explicit `wifi.ap.start_open iface=wlan1`
command; stop it with `wifi.ap.stop iface=wlan1` before returning to an
unassociated raw-NAN experiment. Ad-hoc and P2P modes remain driver-specific
and are not enabled implicitly by this command.

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
