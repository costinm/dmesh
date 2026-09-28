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
mesh lmesh wifi.interface.list
mesh lmesh wifi.mgmt.capture --iface=wlan0 --channel=6 --capture_ms=200
```

`DEVICE` is a device-catalog target. Use `--field=value` or the numeric
`--tag=value` form for declared request fields. The corresponding HTTP JSON
endpoint uses the method name and field names from this document; see
[`crates/dmesh-cli/README.md`](crates/dmesh-cli/README.md) for transport,
flash, reset, logs, and NAN wake examples.

<!-- dmesh-api:portable -->

# `discovery` API (6)

## 9. `nodes` — Return the retained cross-bearer observed-device inventory

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

### Controller-owned device record

Linux and Android persist one private `OwnedDevice` pairing result per signed
`device_id`; each record contains optional `name`, radio `mac`,
signed `public_key`, `vip6`, transport `endpoints`, and controller/device `secret`. The secret is
stored only in the mode-0600 private device file, is redacted from debug
output, and is never returned by `discovery.nodes` or an HTTP/UI handler.
Android BLE pairing is one producer of this record; it is not an alternate
device schema.

The advertised `vip6` is always the complete 16-byte ULA. RFC 4193 allocates
`fc00::/7`: the following `L` bit selects centrally assigned (`0`) or locally
assigned (`1`, conventionally `fd00::/8`) space. For locally provisioned DMesh
devices, the next 40-bit Global ID is derived from the provisioned owner root
CA, the following 16-bit subnet ID is initially zero, and the low 64 bits are
the device identity hint. An all-zero 40-bit owner ID marks an unconfigured
device; receivers must not infer common ownership from the fixed ULA bits.

## 10. `active` — Run one discovery pass on every available local bearer

The handler fans out locally to all currently owned discovery adapters (for
example UDP multicast, NAN, BLE, or UART). It is not a path-selection hint for
QUIC and does not queue application traffic behind a busy bearer. Each adapter
only reports observations it actually received; callers subsequently read the
merged `discovery.nodes` inventory.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 40 | `medium` | `string` | Preferred radio medium, if known. |
| 41 | `to` | `string` | Optional target device identity. |


# `telemetry` API (7)

## 1. `nan_status` — Return local NAN attach, cluster, synchronization, and publish state

**UI:** default

## 2. `now_metrics` — Return local ESP-NOW submission, receive, admission, dispatch, drop, and error counters

## 3. `nan_metrics` — Return local NAN beacon, SDF, Service Info, Follow-up, dispatch, drop, and error counters

## 4. `udp6_metrics` — Return local raw IPv6 validation, UDP delivery, NDP, transmit, and failure counters

## 5. `wifi_link_metrics` — Return common optional per-peer Wi-Fi link observations

## 6. `battery` — Return the latest portable battery and power snapshot

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

# `transport` API (1)

## 4. `set` — Replace a node's complete volatile physical transport profile

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

# `connection` API (3)

## 1. `configure` — Replace volatile QUIC-lite association defaults

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 2 | `ack_frequency` | `u8` | Packets per acknowledgment. |
| 3 | `ack_delay_ms` | `u8` | Acknowledgment delay. |
| 4 | `tx_burst_packets` | `u8` | Transmit burst ceiling. |
| 11 | `path_policy` | `u8` | Path selection policy. |
| 12 | `timeout_ms` | `u32` | Association timeout. |

# `companion` API (209)

Pairing makes an unpaired ESP32 a companion of one Linux or Android controller.
Every pairing attempt first sends `nan.pair_wakeup` through a nearby observer,
even when the provisioning exchange will use USB, BLE, or Wi-Fi. A sleepy
unpaired device may then open a time-limited pairing window. A device that already
has `sec:key` ignores this invitation.
`kind` selects the bearer used for this operation. Initial provisioning is
currently limited to direct UART/USB and encrypted BLE CoC. It does
not bind ownership to that bearer or disable the other transports. `id` is
its adapter-local identifier, such as a serial path, BLE address, or signed
Wi-Fi discovery identity. The host verifies the signed device identity,
generates a new shared secret, writes it to the device, and durably stores the
secret with the device MAC and public key in its private owned-device file.
The signed `device_id` is stable across bearers. A Bluetooth bond alone does
not grant access to privileged handlers; the shared secret does. Once paired,
the same ownership works over any available transport. A second pair attempt
must reject the device until an authorized unpair resets it. Firmware never
returns the raw secret over control.

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

For UART, `vip6` must match a signed discovery check; physical access is the
trust boundary, as with esp-tool, so no link encryption is required. BLE uses
an address from scan results and provisions the secret only after bonding and
an encrypted CoC connection; `psm` defaults to 128. Wi-Fi pairing is deferred.
Pairing reads the device name from NVS through signed discovery. Optional
`name` replaces it, or supplies an initial name, and must be written to NVS
before the local pairing result is committed.
Pairing also installs a control-plane root public key into `dmesh:cp` NVS.
By default this is the controller's own public key. If a root CA is configured,
the controller uses that CA's public key; `root_public_key_b64` can select an
explicit compressed P-256 public key for this pairing. The selected root key
is saved in the private pairing result and is not a shared secret.
Android's native
Bluetooth API owns permission and bonding. A successful pair response means
the device accepted the new secret and the host saved the matching identity
and secret durably; starting an asynchronous bond is not completion.

```sh
mesh lmesh companion.pair --kind=uart --id=/dev/ttyUSB0 --vip6=fd00::1234
mesh lmesh companion.pair --kind=ble --id=AA:BB:CC:DD:EE:FF --psm=128
mesh lmesh companion.unpair --kind=wifi --id=fd00::1234
mesh lmesh companion.unpair --kind=uart --id=/dev/ttyUSB0
```

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `kind` | `string` | Provisioning bearer: `uart` or `ble`. |
| 2 | `id` | `string` | Adapter-local identifier from discovery. |
| 3 | `vip6` | `string` | Signed discovered VIP, required for UART. |
| 4 | `baud` | `u32` | Optional UART physical baud rate. |
| 5 | `psm` | `u16` | Optional BLE CoC PSM; default 128. |
| 6 | `name` | `string` | Optional new device name, persisted in NVS during pairing. |
| 7 | `root_public_key_b64` | `string` | Optional base64 compressed P-256 control-plane root public key (33 bytes). |

## 2. `unpair` — Reset a companion to unpaired state

`kind` names the bearer carrying this operation; it does not identify the
bearer on which pairing happened. Unpair removes its shared secret and
BLE pairing data on the ESP32, removes its owned-device entry and BLE bond on
Linux or Android, and releases its bearer. Afterwards the ESP32 behaves like
an unpaired device. Over Wi-Fi or BLE, unpair requires proof of the current
shared secret and must reject devices owned by another controller. UART alone
may unlock a device without that proof, including one paired to someone else.
Physical UART access already permits Linux to flash the ESP32; future eFuse
policy may restrict that ability. The UART exception must never apply to a
request that arrives over Wi-Fi or BLE, even if its `kind` field says `uart`.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `kind` | `string` | Bearer carrying the unpair request. |
| 2 | `id` | `string` | Target identifier on that bearer. |

# `provision` API (210)

This device-side internal API is used after the targeted NAN pairing wake.
It accepts direct UART/USB or an encrypted BLE CoC, and rejects Wi-Fi, NAN,
unencrypted CoC, and relayed requests. The device commits name and root first,
then the secret last. The caller verifies the correlated result and durably
saves the signed identity, name, root and secret before reporting completion.
Credential bytes are never logged.

## 1. `install` — Commit an unpaired device's companion credentials

**Visibility:** private

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | Name to persist in NVS. |
| 2 | `root_public_key` | `bytes` | Compressed P-256 control-plane root, 33 bytes. |
| 3 | `secret` | `bytes` | Newly generated shared secret, 32 bytes. |

# `log` API (208)

## 1. `record` — One-way diagnostic message from a companion bearer

**Visibility:** private

This tagged message has no request ID or response. A host UART adapter wraps
unframed boot and crash text in this message after receiving it; normal QUIC
frames remain unchanged. `log-watch` remains the device pull interface.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `text` | `string` | One size-limited UTF-8 log line. |
| 2 | `source` | `string` | Observer-local bearer path or name. |
| 3 | `timestamp_ms` | `u64` | Observer receipt time. |

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

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `key` | `string` | Setting name. |

## 2. `set` — Write one setting

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `key` | `string` | Setting name. |
| 2 | `value` | `string` | Setting value. |

## 3. `list` — List setting keys

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

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `to` | `string` | Target radio MAC address. |

## 12. `pair_wakeup` — Invite only an unpaired device into a time-limited pairing window

An observer sends this targeted NAN request before pairing over any bearer.
The device accepts it only while `sec:key` is empty; an owned device ignores
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

<!-- dmesh-api:linux -->

These methods run on the managed `lmesh` daemon and may change `wlan0` state.
The request tables give the numeric field tags used on its CBOR socket.

```sh
mesh lmesh wifi.interface.list
mesh lmesh telemetry.nan_status
mesh lmesh wifi.scan --iface=wlan0 --last_results=true
mesh lmesh wifi.mgmt.capture --iface=wlan0 --channel=6 --capture_ms=200
```

# `lmesh` API (4)

## 30. `probe` — Run a time-limited QUIC probe through the selected Linux radio path

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `to` | `string` | to parameter. |
| 2 | `bytes` | `u64` | bytes parameter. |
| 3 | `packet_size` | `u16` | packet size parameter. |
| 4 | `parallel_streams` | `u8` | parallel streams parameter. |
| 5 | `initial_consume_delay_ms` | `u32` | initial consume delay ms parameter. |
| 6 | `consume_delay_ms` | `u32` | consume delay ms parameter. |
| 7 | `timeout_ms` | `u64` | timeout ms parameter. |

## 8. `send` — Send a payload through the selected mesh radio

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `radio` | `string` | radio parameter. |
| 2 | `destination` | `string` | destination parameter. |
| 3 | `payload` | `string` | payload parameter. |

## 10. `messages.history` — Read retained local message history

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `keys` | `string` | keys parameter. |
| 2 | `limit` | `u64` | limit parameter. |


# `link` API (221)

## 30. `steer` — link.steer on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `node` | `string` | node parameter. |
| 2 | `radio` | `string` | radio parameter. |
| 3 | `reason` | `string` | reason parameter. |

# `object` API (224)

## 30. `nan.dry_run` — object.nan.dry_run on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `image_size` | `u64` | image size parameter. |
| 2 | `mtu` | `u64` | mtu parameter. |

# `wifi` API (5)

## 30. `interface.list` — wifi.interface.list on the local Linux mesh daemon

**UI:** advanced

## 31. `interface.up` — wifi.interface.up on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |

## 32. `interface.channel` — wifi.interface.channel on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `channel` | `u8` | channel parameter. |

## 33. `ocb.start` — wifi.ocb.start on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `freq` | `u32` | freq parameter. |
| 3 | `bandwidth` | `string` | bandwidth parameter. |

## 34. `rate.profile` — wifi.rate.profile on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `profile` | `string` | profile parameter. |
| 3 | `disable_80211b` | `bool` | disable 80211b parameter. |

## 35. `data.listen` — wifi.data.listen on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `listen_sec` | `u64` | listen sec parameter. |

## 36. `data.send` — wifi.data.send on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `destination` | `string` | destination parameter. |
| 3 | `payload` | `string` | payload parameter. |

## 37. `ap.start_open` — wifi.ap.start_open on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `ssid` | `string` | ssid parameter. |
| 3 | `channel` | `u8` | channel parameter. |
| 4 | `ht40` | `bool` | ht40 parameter. |
| 5 | `beacon_interval_tu` | `u16` | beacon interval tu parameter. |

## 38. `ap.stop` — wifi.ap.stop on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |

## 39. `ap.station.add` — wifi.ap.station.add on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `mac` | `string` | mac parameter. |
| 3 | `aid` | `u16` | aid parameter. |

## 40. `sta.join_open` — wifi.sta.join_open on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `ssid` | `string` | ssid parameter. |

## 41. `sta.configure_ipv4` — wifi.sta.configure_ipv4 on the local Linux mesh daemon

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `address` | `string` | address parameter. |
| 3 | `prefix` | `u8` | prefix parameter. |

## 13. `mgmt.capture` — Capture Wi-Fi management frames on an owned monitor interface

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `channel` | `u8` | channel parameter. |
| 3 | `capture_ms` | `u64` | capture ms parameter. |
| 4 | `max_frames` | `u64` | max frames parameter. |
| 5 | `active` | `bool` | active parameter. |

<!-- dmesh-api:end -->

<!-- dmesh-api:android -->

# `ble` API (201)

Android BLE adapter operations. The service uses tagged CBOR; the Android framework remains behind the Rust backend.

## 1. `status` — Report local BLE adapter and bearer state

**UI:** default

## 2. `scan` — Start a time-limited BLE scan

**UI:** default

## 3. `scan_stop` — Stop the BLE scan

**UI:** default

## 4. `scan_results` — List retained BLE scan results

**UI:** default

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `limit` | `u64` | Maximum result count, capped at 64. |

## 5. `scan_clear` — Clear retained BLE scan results

**UI:** default

## 6. `connect` — Connect to a BLE device over L2CAP CoC

**Visibility:** private

Platform adapter operation used by `companion.pair`. Public clients use the
companion API so the same method applies to BLE, UART, and Wi-Fi.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `address` | `string` | Scanned device address. |
| 2 | `psm` | `u16` | L2CAP PSM; defaults to 128. |

## 7. `disconnect` — Disconnect the local BLE bearer

**Visibility:** private

# `radio` API (202)

## 1. `history` — Read retained local radio event history

**UI:** default

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `limit` | `u64` | Maximum event count, capped at 256. |
| 2 | `since_ms` | `u64` | Earliest event timestamp. |
| 3 | `keys` | `string` | Event key selector. |

# `usb` API (204)

## 1. `status` — Report local USB adapter state

**UI:** default

## 2. `devices` — List USB devices visible to the host

**UI:** default

## 3. `open` — Open and attach a USB serial device

**UI:** default

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `vendor_id` | `u16` | USB vendor ID. |
| 2 | `product_id` | `u16` | USB product ID. |
| 3 | `auto` | `bool` | Select an available matching device. |

## 4. `close` — Close the active USB bearer

**UI:** default

## 5. `discover` — Read the attached device's signed identity

Sends a tagged discovery request over the open USB QUIC bearer. The response
must carry a valid device signature. This is a read-only identity check and
does not pair or claim the device.

**UI:** default

# `wifi` API (205)

## 1. `status` — Report local Wi-Fi controller and NAN state

**UI:** default

## 2. `scan` — Request a time-limited platform Wi-Fi scan

**UI:** default

<!-- dmesh-api:end -->

## Additional device methods

These are active tagged-CBOR methods whose implementations live in the device
or shared service handlers. Their wire names are retained for existing clients.
The component and method columns are the numeric CBOR tags.

| Component | Method | Wire name | Purpose |
|---:|---:|---|---|
| 5 | 3 | `relay.list` | List active relay allocations and peer links. |
| 101 | 1 | `runtime.snapshot` | Read desired and applied radio lifecycle generations, sleep state, and counters. |
| 101 | 2 | `runtime.reset` | Reset the runtime diagnostics counters. |
| 102 | 1 | `power.snapshot` | Read CPU frequency, power management, and sleep counters. |
| 103 | 1 | `memory.snapshot` | Read packet pool, worker stack, and internal memory metrics. |
| 8 | 1 | `probe` | Run a time-limited QUIC-lite transfer and report throughput. |
| 10 | 2 | `object.flash` | Transfer a verified firmware object into a selected durable slot. |
| 1000 | 3 | `module.stop` | Request module shutdown with a deadline before flash work. |
| 11 | 1 | `boot.recovery` | Request a Main to Recovery handoff. |
| 12 | 1 | `firmware.identity` | Read the booted firmware identity after a handoff or update. |
| 104 | 80 | `ble.start` | Start the BLE companion radio. |
| 104 | 81 | `ble.stop` | Stop the BLE companion radio. |
| 104 | 82 | `ble.scan` | Start a time-limited BLE scan. |
| 104 | 83 | `ble.status` | Read BLE adapter and link state. |
| 104 | 84 | `ble.scan_stop` | Stop an active BLE scan. |
| 104 | 85 | `ble.connect` | Connect to a selected BLE peer. |
| 104 | 86 | `ble.coc.send` | Send one payload as one BLE L2CAP CoC SDU. |
| 9 | 1 | `status` | Read compact device health and application state. |
| 9 | 2 | `services` | List registered service handlers. |
| 9 | 3 | `metrics` | Read general transport and service counters. |
| 9 | 4 | `events` | Read retained event history. |
| 9 | 5 | `log-watch` | Read retained structured log records. |
| 4 | 71 | `radio.tx` | Submit one size-limited raw radio frame for diagnostics. |
| 4 | 72 | `radio.control` | Adjust volatile radio diagnostic controls. |
| 4 | 73 | `radio.snapshot` | Read radio state and counters. |
| 4 | 77 | `wifi.scan` | Scan or read retained Wi-Fi results. |
| 4 | 74 | `radio.reset_counters` | Reset radio diagnostics counters. |

The request fields below are optional unless the handler description says otherwise.
An empty request uses an empty CBOR map. Response fields are handler-specific and
are described by the method purpose above.

### `runtime.snapshot` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 0 | `desired_mode` | `u32` | — |
| 1 | `desired_generation` | `u32` | — |
| 2 | `request_id` | `u32` | — |
| 3 | `sleepy` | `bool` | — |
| 4 | `radio_lifecycle` | `u32` | — |
| 5 | `applied_generation` | `u32` | — |
| 6 | `power_lifecycle` | `u32` | — |
| 7 | `sleep_blockers` | `u32` | — |
| 8 | `last_error` | `u32` | — |
| 9 | `stale_completion_count` | `u32` | — |
| 10 | `queue_overflow_count` | `u32` | — |
| 11 | `wake_cause` | `u32` | — |
| 12 | `cpu_mhz` | `u32` | — |
| 13 | `pm_min_mhz` | `u32` | — |
| 14 | `pm_max_mhz` | `u32` | — |
| 15 | `pm_automatic_light_sleep` | `bool` | — |
| 16 | `pm_configured` | `bool` | — |
| 17 | `light_sleep_attempts` | `u32` | — |
| 18 | `light_sleep_entries` | `u32` | — |
| 19 | `light_sleep_skipped` | `u32` | — |
| 20 | `last_sleep_requested_us` | `u32` | — |
| 21 | `last_sleep_duration_us` | `u32` | — |

### `power.snapshot` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 0 | `cpu_mhz` | `u32` | — |
| 1 | `min_mhz` | `u32` | — |
| 2 | `max_mhz` | `u32` | — |
| 3 | `automatic_light_sleep` | `bool` | — |
| 4 | `configured` | `bool` | — |
| 5 | `light_sleep_attempts` | `u32` | — |
| 6 | `light_sleep_entries` | `u32` | — |
| 7 | `light_sleep_skipped` | `u32` | — |
| 8 | `last_sleep_requested_us` | `u32` | — |
| 9 | `last_sleep_duration_us` | `u32` | — |

### `memory.snapshot` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 0 | `packet_slots` | `u32` | — |
| 1 | `packet_slots_available` | `u32` | — |
| 2 | `packet_drops` | `u32` | — |
| 3 | `worker_stack_bytes` | `u32` | — |
| 4 | `worker_running` | `bool` | — |
| 5 | `worker_starts` | `u32` | — |
| 6 | `worker_create_failures` | `u32` | — |
| 7 | `worker_stack_min_free_words` | `u32` | — |
| 8 | `free_internal_bytes` | `u32` | — |
| 9 | `min_free_internal_bytes` | `u32` | — |
| 10 | `largest_internal_block_bytes` | `u32` | — |

### `probe` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 1 | `bytes` | `u64` | — |
| 2 | `packet_size` | `u16` | — |
| 3 | `pace_us` | `u32` | — |
| 4 | `burst_packets` | `u8` | — |
| 5 | `burst_delay_us` | `u32` | — |
| 6 | `ack_frequency` | `u8` | — |
| 7 | `ack_delay_ms` | `u8` | — |
| 8 | `low_priority_bytes` | `u32` | — |
| 9 | `high_priority_bytes` | `u32` | — |
| 10 | `parallel_streams` | `u8` | — |
| 11 | `initial_consume_delay_ms` | `u32` | — |
| 12 | `consume_delay_ms` | `u32` | — |

### `object.flash` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 0 | `name` | `text` | — |
| 1 | `cpu` | `u8` | — |
| 2 | `target` | `u8` | — |
| 3 | `address` | `u32` | — |
| 4 | `transport` | `u8` | — |
| 5 | `dry_run` | `bool` | — |

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

### `events` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 1 | `since` | `u64` | — |

### `log-watch` request fields

| Tag | Field | Type | Values |
|---:|---|---|---|
| 1 | `since` | `u64` | — |
| 2 | `records` | `u8` | — |

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

### `radio.snapshot` request fields

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

### Module loader

`fw/modules` supplies optional flash-module handlers for any application that
links the ESP module loader. The handler transport is a normal QUIC-lite
stream or a direct bearer record; the stream payload begins with one complete
tagged-CBOR envelope. There is no stream service byte.

The common envelope fields are defined by `dmesh-server::tagged`:

```text
{ 1: component, 2: method, 3: request_id?, 10: binary_payload? }
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
