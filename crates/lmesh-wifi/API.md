# lmesh-wifi API

`lmesh-wifi` is the host Wi-Fi/netd ownership crate used by the full `lmesh`
service and the isolated `lmesh-wifi` service. Linux Wi-Fi, AP/STA, and host
NAN operations are implemented in this crate.

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
- legacy WPA-supplicant NAN publish, subscribe, follow-up, and event operations
  (compatibility only; not started by either service);
- raw-NAN diagnostics and sleepy-device wake/control traffic;
- NAN object-store bearer primitives already exposed by lmesh.

The shared DM v1 NAN/BLE wire format and raw frame state machine live in
[`dmesh-rawnan/API.md`](../rawnan/API.md). This crate owns only the Linux
interface operations and their AP/STA/NAN orchestration.

UART forwarding is implemented by the independent `lmesh-uart` service. This
crate owns no UART service lifecycle or control socket.

The full AP command names remain `wifi.ap.*`. Host raw-NAN operations are
`wifi.rawnan.*` and use the shared `dmesh-rawnan` state machine. Frame
transmission is selectable: `monitor`/`monitor_active` inject through a
monitor VIF, while `onchannel`, `onchannel_noack`, and `roc` use
`NL80211_CMD_FRAME` on the owned base interface. Neither path requires
`wpa_supplicant`. The older
`wifi.nan.*` commands are WPA-supplicant compatibility operations and are not
the AP/raw-NAN startup path. The Wi-Fi-only binary exposes the service socket selected by mesh-init, normally
`/run/mesh/lmesh-wifi/mesh.sock`.

At startup the service starts the open AP and an all-day raw-NAN monitor on
each owned default interface. `wifi.rawnan.status` reports whether that
monitor is active and whether a NAN cluster BSSID has been learned. Use
`wifi.rawnan.ping` for the bounded raw-frame smoke test.

The host experiment commands are available on the service socket:

Native Linux NAN is exposed as a long-lived debug service on the same socket.
It may replace the selected interface mode while the experiment is running;
events remain available through `messages.history`:

The compatibility `wpa_supplicant` binary is reproducibly built from the DMesh
flake (the package was recovered from the historical ssh-mesh flake):

```sh
nix build .#wpa-supplicant-nan
./result/bin/wpa_supplicant \
  -g /run/mesh/wpa-supplicant/global \
  -G plugdev \
  -c /ws/rust/ssh-mesh/crates/mesh-init/examples/wpa-supplicant-nan.conf \
  -dd
```

```text
wifi.nan.native.start iface=wlan0 service_name=dmesh subscribe=false
wifi.nan.native.status iface=wlan0
messages.history keys=wifi.nan.native.event,wifi.nan.native.error limit=40
wifi.nan.native.stop iface=wlan0

# wpa_supplicant-compatible userspace USD over nl80211 (no monitor VIF)
wifi.nan.usd.start iface=wlan0 service_name=dmesh subscribe=false
messages.history keys=wifi.nan.usd.tx,wifi.nan.usd.rx,wifi.nan.usd.error limit=40
wifi.nan.native.stop iface=wlan0
```

The `wifi.nan.usd.start` service reproduces wpa_supplicant's userspace
`CONFIG_NAN_USD` path: it registers the NAN SDF public action alongside the
DMesh/ESP-NOW vendor action, requests ROC, injects complete SDF action frames,
and keeps the nl80211 event reader alive. The older `wifi.nan.native.start`
command remains the kernel `NL80211_CMD_*_NAN` experiment.

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

### Minimal AP+NAN test

```sh
source ./env.sh
mesh lmesh wifi.ap.start_open iface=wlan1 ssid=dmesh-lmesh6
mesh lmesh-wifi wifi.ap.status iface=wlan0
mesh lmesh-wifi wifi.rawnan.status iface=wlan0
mesh lmesh-uart esp.serial.command port=e6 \
  command='wifi mode=sta ssid=Direct-CAB879CC-Dmesh-local psk= channel=6 timeout=10000' \
  timeout_sec=20
mesh lmesh-uart esp.serial.command port=e6 \
  command='nan sync_beacon=count=1 interval_ms=100' timeout_sec=15
mesh lmesh-uart esp.serial.command port=e6 \
  command='nan publish=count=1 sync=true' timeout_sec=15
```

The AP command owns only `wlan1`; `lmesh-wifi` continues to own `wlan0`.
`sync_beacon` is an explicit debugging transmission. It is not enabled as a
production NAN master-election behavior. See
[`debugging.md`](debugging.md) for the complete command set and captures.

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
