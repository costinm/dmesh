# lmesh-wifi API (internal, experimental)

These methods exist only in the `lmesh-wifi` crate: the experimental Linux Wi-Fi
radio library that `lmesh` currently links. They are **not part of the DMesh
common API** (`../../API.md`): Android and the firmware do not implement them, and
`lmesh` will stop registering them when it no longer depends on `lmesh-wifi`
(it will use `crates/rawnan` for NAN and NOW, `crates/lmesh-wpa` for the station and
P2P AP, and `dmesh-server` for UDP discovery). The crate is intended to move to its
own repository for Wi-Fi radio experiments.

Numbers and field tags are fixed so the generated catalog and typed requests
(`src/mesh_core_api.rs`) stay stable. The same generator reads this file for the
`linux` group (`scripts/dmesh_api.py linux`).

Platform markers here use `L` for `lmesh` linking `lmesh-wifi`; none of these
methods run on Android (`A`) or the firmware (`E`).

<!-- dmesh-api:linux -->

These methods run on the managed `lmesh` daemon and may change `wlan0` state.
The request tables give the numeric field tags used on its CBOR socket.

```sh
mesh lmesh wifi.interface.list
```

# `lmesh` API (4)

## 8. `send` — Send a payload through the selected mesh radio

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `radio` | `string` | radio parameter. |
| 2 | `destination` | `string` | destination parameter. |
| 3 | `payload` | `string` | payload parameter. |

## 10. `messages.history` — Read retained local message history

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `keys` | `string` | keys parameter. |
| 2 | `limit` | `u64` | limit parameter. |


# `link` API (221)

## 30. `steer` — link.steer on the local Linux mesh daemon

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `node` | `string` | node parameter. |
| 2 | `radio` | `string` | radio parameter. |
| 3 | `reason` | `string` | reason parameter. |

# `object` API (224)

## 30. `nan.dry_run` — object.nan.dry_run on the local Linux mesh daemon

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `image_size` | `u64` | image size parameter. |
| 2 | `mtu` | `u64` | mtu parameter. |

# `wifi` API (5)

## 30. `interface.list` — wifi.interface.list on the local Linux mesh daemon

**Platforms:** L

**UI:** advanced

## 31. `interface.up` — wifi.interface.up on the local Linux mesh daemon

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |

## 32. `interface.channel` — wifi.interface.channel on the local Linux mesh daemon

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `channel` | `u8` | channel parameter. |

## 37. `ap.start_open` — wifi.ap.start_open on the local Linux mesh daemon

**Platforms:** L

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

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |

## 40. `sta.join_open` — wifi.sta.join_open on the local Linux mesh daemon

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `ssid` | `string` | ssid parameter. |

## 41. `sta.configure_ipv4` — wifi.sta.configure_ipv4 on the local Linux mesh daemon

**Platforms:** L

**UI:** advanced

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `iface` | `string` | iface parameter. |
| 2 | `address` | `string` | address parameter. |
| 3 | `prefix` | `u8` | prefix parameter. |
<!-- dmesh-api:end -->
