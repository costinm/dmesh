# lmesh API

`lmesh` exposes local mesh discovery control as newline-delimited JSON over a Unix
domain socket. Under mesh-init it uses systemd-style socket activation and takes
the activated listener fd. When started standalone without activation, it binds
`./lmesh/mesh.sock` by default.

Use the generic `mesh` client for normal device commands, for example
`mesh lmesh esp.serial.command port=lora1 command=status`. The local endpoint
resolves to the UDS forward `/run/mesh/lmesh/lora1.sock`; the optional RFC2217
TCP listener is diagnostic/remote-serial transport only and is never a
flashing path. FQDN-shaped endpoints may instead resolve to a remote host,
container, VM, SSH forward, or sandbox, so callers must not assume local
`/dev` or `/run` paths are visible.

Serial forwards also reserve two newline commands locally in lmesh:
`mesh lora1.lmesh dtr [milliseconds]` and `mesh lora1.lmesh rst` are local
CP210x diagnostics, not normal firmware commands. The normal path is binary
CBOR over lmesh; use `esp.active` through a powered gateway to wake a sleepy
node over raw-NAN. A physical GPIO0/PRG press remains the last-resort local
recovery path and opens a two-second console/active window. Bare
`mesh lora1.lmesh` opens the bidirectional debug stream.

The complete low-level ESP command ABI is kept alongside this product API in
[`ESP_FIRMWARE_API.md`](ESP_FIRMWARE_API.md). Its command IDs are the source of
truth for firmware CBOR dispatch; `resources/tools.json` remains the curated
host-facing subset, not a firmware command inventory.

The same methods can be called using flat JSONL or JSON-RPC 2.0. One request is sent per
line and one response is returned per line.

## API specification blocks

This document is the source of truth for lmesh's public API. Every public method
will carry a nearby `mesh-api` TOML block containing its component/method IDs,
field tags, visibility, and optional positional slots. `mesh` extracts those
blocks to generate `resources/tools.json` and the schema-optional gateway
dictionary. Private firmware commands use the same blocks in
`ESP_FIRMWARE_API.md` but are omitted from the MCP catalog.

## Compact CBOR transports

CBOR is the compact transport form of the same API. A CBOR record has a compact
envelope map and a nested `payload` map: there is no JSON-RPC `jsonrpc`, `params`,
or `result` envelope. Only the compact
one-byte key range `0..15` is reserved: `0=method`, `1=id`, `2=from`, `3=to`,
`4=status`, `5=error`, `6=payload`, `7=type`, `8=seq`, `9=ts_ms`, `10=name`,
`11=flags`, `12=count`, `13=total`, `14=more`, and `15=code`. The remaining
one-byte keys `16..23` are available to a service for its hottest local fields.
Method-local keys begin at 32 (a two-byte CBOR unsigned integer); common
segmentation uses nested-payload fields `32=segment_id`, `33=segment_offset`, `34=segment_total`,
`35=segment_hash`, `36=segment_index`, `37=segment_count`. Unknown names remain
CBOR text keys.

TTY/USB and other byte streams wrap a record as `u32-be length | 00 cb 00 00 |
CBOR`; the length includes the four type bytes. Indefinite-length CBOR maps allow
streaming generation, so a gateway need not pre-serialize payload just to learn its
encoded length. LoRa, NAN, BLE, raw Wi-Fi, and
UDP use the CBOR bytes directly because their outer transport carries length.
Large host records are segmented using the common segment fields. ESP adapters
forward records up to the firmware's 4,000-byte UART record limit and paginate
or emit multiple complete response records for larger results.

Flat request:

```json
{"method":"nodes"}
```

JSON-RPC request:

```json
{"jsonrpc":"2.0","method":"nodes","id":1}
```

Flat success responses use the mesh response shape:

```json
{"success":true,"data":...}
```

JSON-RPC success responses put the payload in `result`; errors use either the mesh
`success:false,error` shape or JSON-RPC `error`, depending on the request format.

## Environment

| Variable | Default | Description |
| --- | --- | --- |
| `LMESH_ANNOUNCE_INTERVAL_SECS` | `60` | Positive integer interval, in seconds, between automatic multicast announcements sent by the lmesh server. Invalid or zero values fall back to `60`. |
| `LMESH_CONFIG_FILE` | `/home/system/etc/lmesh/lmesh.toml` | Optional override for isolated or non-system deployments. The normal service does not need this variable. |
| `LMESH_CONTROL_SOCKET` | `./lmesh/mesh.sock` | Standalone fallback UDS path used only when no activation listener is provided. Relative paths resolve against the working directory. |
| `LMESH_DEVICE_ID` | derived | Optional 6-byte hex DMesh radio device id, for example `001122334455` or `00:11:22:33:44:55`. |
| `LMESH_SERIAL_DEVICES` | unset | Comma-separated ESP serial radio devices, for example `/dev/ttyUSB0,/dev/ttyUSB1`. Devices default to 460800 baud and are listed as `esp-serial-*` adapters. |
| `LMESH_WIFI_IFACE` | `wlan1` | Default Wi-Fi interface used by the NAN/WPA control methods. |
| `LMESH_WPA_CTRL_DIR` | `/run/mesh/wpa-supplicant-nan` | WPA control socket directory used by NAN methods. |
| `LMESH_NAN_AUTOSTART` | `1` | Starts default NAN publish/subscribe at service startup only when the configured WPA control socket exists. |
| `LMESH_AP_AUTOSTART` | `1` | Starts the basic open channel-6 AP after NAN startup when it has a separate Wi-Fi phy. Set `0` to disable it. |
| `LMESH_AP_IFACE` | `wlan0` | Interface used by the startup AP. It must differ from `LMESH_WIFI_IFACE` and use a separate phy. |

When `etc/lmesh/lmesh.toml` exists under the lmesh working directory, `lmesh`
also reads additional radio adapters and managed serial forwards.
`LMESH_CONFIG_FILE` can point to the same TOML format explicitly and takes
precedence.

```toml
[[radios]]
id = "lab-esp0"
kind = "esp-serial"
medium = "serial"
path = "/dev/ttyUSB0"
network = "lab"
baud = 460800

[[radios]]
id = "remote-a"
kind = "remote-uds"
medium = "remote"
path = "/tmp/ssh-forwarded/lmesh.sock"

[[serial_forwards]]
port = "USB0"
baud = 460800
tcp_port = 3330
tcp_mode = "rfc2217"
dtr = false
multi = true
```

Set `serial_log_path` at the top level to capture every managed serial forward
in one append-only logfmt file. Records contain `ts_ms`, `board`,
`dir=rx|tx`, escaped `text`, and exact `hex` bytes, so `rg 'Guru Meditation'
target/lmesh-radio-build/log/serial.log` finds firmware failures while the
interleaved host timestamps correlate commands, DW activity, and board output.
`usb.serial.forward.list` reports the configured path plus `log_records` and
`log_write_errors`. Direct USB flashing releases the managed forward first, so
flash traffic never enters this log; `log_suppressed_records` and
`log_suppressed_bytes` report other intentionally excluded traffic.
Set `log = false` on a `serial_forwards` entry to exclude a noisy source such
as a power meter while keeping its UDS/TCP forward active.
Set `raw = true` only for a non-firmware serial source such as a power meter;
it forwards bytes verbatim instead of decoding the ESP UART PPP/CBOR codec.

Known adapter kinds are `host-mcast`, `host-ble`, `host-nan`, `esp-serial`,
`remote-uds`, `android-ble`, and `android-nan`. A `remote-uds` adapter is an
SSH-forwarded or otherwise proxied lmesh JSONL socket on another machine; it can
front its own Linux radios, Android JNI radios, or ESP boards connected to that
remote host. Android kinds are contract placeholders for platform adapters.
Configured `serial_forwards` are started at lmesh process startup and are
resolved by role name. Set `port = "lora1"` (or `power1`, `s3-1`, etc.) and
provide a stable `/dev/serial/by-id/...` `path`; numeric USB/ACM names remain
only a compatibility fallback. The runtime sockets are under
`/run/mesh/lmesh/<role>.sock`.
visible through `usb.serial.forward.list`; use their UDS sockets for console
and test access. Direct physical USB-UART is required for flashing.
For the local lab service, copy `crates/lmesh/examples/lab-forwards.toml` to
`/home/system/etc/lmesh/lmesh.toml` (or the checked local target copy); the
mesh-init example uses the standard path instead of a per-process environment
variable.

## Lightweight MCP Methods

All lmesh JSONL connections also support the shared mesh MCP-compatible methods:

The `tools/list` command catalog is the hand-maintained
`resources/tools.json`. Keep it in sync with this document when the public
command surface changes; do not generate it from Rust code.

The production API is transport-neutral. Clients should normally call `send`,
`ping`, `radios.list`, `links.list`, `neighbors`, `messages.history`, and the
stable Wi-Fi/BLE/NAN methods. Adapter-specific `esp.*` methods are diagnostics
and direct firmware controls; they are useful for tests and bring-up but should
not become the product contract when an equivalent high-level method exists.

| Method | Result |
| --- | --- |
| `initialize` | Protocol version, server info, and `tools`/`resources` capabilities. |
| `tools/list` | Contents of `tools.json` from `MESH_RES_DIR`, otherwise `/home/lmesh/etc/resources` overlaying `/opt/lmesh/resources`. |
| `tools/call` | Calls the native lmesh method named by `name`, with `arguments` mapped to normal method params. |
| `resources/list` | File resources from the same resource lookup plus registered resources. |
| `resources/read` | Reads a listed `file://` resource when it is under the resolved resource directories. |

## Methods

| Method | Params | Result |
| --- | --- | --- |
| `nodes` | none | Array of currently discovered nodes. Alias: `list_nodes`. |
| `get_node` | `public_key: string` | One discovered node, or an error when not found. |
| `announce` | `metadata: object<string,string> \| null` | Sends a multicast announcement for the local node and returns success. |
| `status` | none | Reports process capabilities, HCI raw-socket probe, and optional WPA control status through the control UDS. |
| `radios.list` | none | Lists configured host, serial, remote UDS, and future Android radio adapters. |
| `neighbors` | `seen_within_sec: integer = 21600` | Returns the normalized neighbor table from recent radio messages. |
| `links.list` | `seen_within_sec: integer = 21600` | Returns lmesh link observations derived from recent radio messages, including radio, RSSI/SNR, quality, and selected path. |
| `ping` / `disc` | `radio: string = "all"`, `wait_ms: integer = 900`, `nonce: string \| null` | Discovers peers over `all`, `nan`, `lora`, `ble`, `serial`, or `sta`. The default Wi-Fi path is NAN publish/subscribe through wpa_supplicant, aligned with Android `lib-lm3`. |
| `send` | `radio: string = "best"`, `destination: mac \| null`, `payload: string` | Sends a mesh payload over the selected radio. `best` currently selects NAN follow-up using the Android-compatible DMesh NAN v1 payload. `lora` uses a configured ESP serial adapter when available; Linux host radios, Android JNI adapters, and SSH-forwarded `remote-uds` lmesh instances should all fit behind this same method. |
| `link.steer` | `node: string \| null`, `radio: string = "best"`, `reason: string = "manual"` | Records a high-level steering hint for a peer. Future encrypted control-plane forwarding should use this shape. |
| `discovery.ping` | `medium: string = "all"` | Compatibility wrapper for `ping`, mapping `medium=wifi` to `radio=wifiraw`. |
| `messages.history` | `keys: string = "messages,net,wifi,BLE,N"`, `limit: integer = 40` | Returns recent radio method results recorded by this process. |
| `usb.serial.list` | `handshake: bool = false` | Lists visible `/dev/ttyUSB*`, `/dev/ttyACM*`, and `/dev/serial/by-id/*` serial devices, including configured lmesh radio adapters and active forwards. With `handshake=true`, probes each device with the DMesh profile. |
| `usb.serial.handshake` | `port: string = "USB0"`, `profile: string = "generic"`, `timeout_sec: number = 1.5` | Runs a one-shot handshake without holding the device open. `port` is a logical token such as `USB0`, `USB1`, or `ACM0`; lmesh derives `/dev/ttyUSB0`, `/dev/ttyUSB1`, or `/dev/ttyACM0`. `profile=generic` sends `help`; `profile=dmesh`/`esp` sends firmware status probes; `profile=cmd:<text>` sends a custom command. Returns raw text and parsed mesh messages. |
| `usb.serial.reset` | `port: string = "USB0"`, `mode: "run"\|"bootloader" = "run"` | Pulses ESP USB serial modem lines into running firmware or ROM download mode. If a lmesh forward is active, reset is queued on that forward's owned serial FD. Release the forward and use direct USB-UART sparse flashing; restore the forward after flash. |
| `usb.serial.forward.start` / `usb.serial.connect` | `port: string = "USB0"`, `baud: integer = 460800`, `tcp_port: integer \| null`, `tcp_mode: "auto"\|"framed"\|"rfc2217" = "auto"`, `handshake: bool = false`, `multi: bool = false` | Starts a generic UDS forward for a USB serial device. lmesh derives the device path and socket from `port`, e.g. `USB0` -> `/dev/ttyUSB0` and `/run/mesh/lmesh/USB0.sock`; configured role names use their stable `/dev/serial/by-id` path and `/run/mesh/lmesh/<role>.sock`. The socket is `0770` and group `dialout`. With `tcp_port`, lmesh also exposes the same forward on `127.0.0.1:<tcp_port>` for diagnostics or remote serial access, never firmware flashing. Connections are passive: they do not pulse DTR or send a wake probe. Serial output is broadcast to all connected UDS and TCP clients with bounded backpressure queues. Newline records `dtr [milliseconds]` (default 120 ms, maximum 10000 ms) and `rst` are explicit local lmesh controls and are not sent to firmware. By default, only the first connected client can send input; `multi=true` allows every client to send. UDS clients use the mesh stream envelope; lmesh translates it to the physical UART `0x7e | escaped-CBOR | 0x7e` codec. RFC2217 mode interprets Telnet/RFC2217 controls and forwards escaped binary data. |
| `usb.serial.forward.stop` / `usb.serial.disconnect` | `port: string = "USB0"` | Stops a managed serial forward and removes its socket. |
| `usb.serial.forward.list` | none | Lists active managed serial forwards. Each forward includes live atomic `stats`: client accepts/drops, bytes in each direction, UART/client `WouldBlock` counts, queue high-water marks, and poll ready/timeout counts. Use it during an RFC2217 transfer to identify whether the UART, TCP client, or bounded queues are limiting progress. |
| `wifi.raw.listen` | `iface: string = LMESH_WIFI_IFACE`, `ctrl_dir: string = LMESH_WPA_CTRL_DIR`, `channel: integer = 6`, `listen_sec: integer = 60`, `rx_variant: string = "nl80211"` | Listens for the custom raw vendor-action bulk transport during NAN-synchronized active windows. |
| `wifi.raw.send` | `iface: string = LMESH_WIFI_IFACE`, `ctrl_dir: string = LMESH_WPA_CTRL_DIR`, `channel: integer = 6`, `listen_sec: integer = 60`, `destination: mac \| rx:mac \| raw:mac`, `source: mac \| null`, `tx_variant: string = "standard"`, `tx_duration_ms: integer \| null`, `payload: string` | Sends custom raw vendor-action bulk traffic. It is unassociated and uses the stable DMesh marker rather than the ESP-NOW API. |
| `wifi.raw.ping` | `iface: string = LMESH_WIFI_IFACE`, `ctrl_dir: string = LMESH_WPA_CTRL_DIR`, `channel: integer = 6`, `listen_sec: integer = 60`, `wait_ms: integer = 900`, `nonce: string \| null` | Sends a small custom raw-action probe. |
| `wifi.data.listen` | `iface: string = LMESH_WIFI_IFACE`, `listen_sec: integer = 60` | Opens an AF_PACKET listener on the normal AP/STA netdev, requests packet multicast membership for the real MAC, raw receive MAC, and shared multicast MAC, and records matching DMesh Ethernet frames as `wifi.data.rx`. This tests efficient kernel/driver data-path delivery, not monitor visibility. Requires `CAP_NET_RAW`. |
| `wifi.data.send` | `iface: string = LMESH_WIFI_IFACE`, `destination: mac \| rx:mac \| raw:mac \| null`, `payload: string` | Sends a DMesh Ethernet frame with experimental EtherType `0x88b5` on the normal AP/STA netdev path. Defaults to the shared DMesh multicast MAC. Requires `CAP_NET_RAW`. |
| `wifi.mgmt.capture` | `iface: string = LMESH_WIFI_IFACE`, `channel: integer = 6`, `capture_ms: integer = 4000`, `max_frames: integer = 32`, `active: bool = false` | Captures beacon and probe-response frames through an AF_PACKET monitor interface and returns raw frame hex plus parsed SSID/channel/rate/capability IE summaries. Requires `CAP_NET_RAW`; `active=true` recreates the monitor interface with active monitor flags. |
| `wifi.ap.start_open` | `iface: string = LMESH_WIFI_IFACE`, `ssid: string \| null` | Starts a password-less open AP on channel 6 through direct nl80211. When `ssid` is omitted, lmesh uses `Direct-XXXXXXXX-Dmesh-local`, with `XXXXXXXX` from the last 4 MAC bytes. Exact defaults and future tuning knobs are recorded in `WIFI.md`. The response includes `template_lengths`, `steps`, `profiles`, and `selected_profile` so driver rejections can be compared across AP template variants. While the AP is alive, lmesh records AP SME auth/assoc/probe/deauth frames as `wifi.ap.mgmt`, including raw frame hex and `rx_signal_dbm` when available. |
| `wifi.ap.stop` | `iface: string = LMESH_WIFI_IFACE` | Stops AP operation through direct nl80211. |
| `wifi.ap.status` | `iface: string = LMESH_WIFI_IFACE` | Returns default AP SSID/channel/BSSID information and station metrics where available. |
| `wifi.ap.stations` | `iface: string = LMESH_WIFI_IFACE` | Dumps associated station metrics through nl80211, including MAC, RSSI/signal, inactive time, packet/byte counters, retries, failures, and connected time when exposed by the driver. Station observations feed `links.list` as `radio=sta`. |
| `wifi.ap.station.add` | `iface: string = LMESH_WIFI_IFACE`, `mac: mac`, `aid: integer = 1` | Experimental: calls `NL80211_CMD_NEW_STATION` with a discovered MAC, minimal open-AP station attributes, and authorized/authenticated/associated station flags, without a normal auth/assoc exchange. This is for evaluating whether a driver can accept synthetic station entries discovered over raw Wi-Fi/LoRA/BLE and deliver their data frames on the normal AP netdev. |
| `wifi.scan` | `iface: string = LMESH_WIFI_IFACE`, `ssid: string \| null` | Scans for nearby Wi-Fi BSS entries through the lmesh radio process and returns parsed BSSID, SSID, signal, frequency/channel, capability, and auth hints. `ssid` optionally limits active scan probes to one SSID. |
| `wifi.sta.join_open` | `iface: string = LMESH_WIFI_IFACE`, `ssid: string` | Joins a password-less open AP on channel 6 through direct nl80211. |
| `wifi.sta.status` | `iface: string = LMESH_WIFI_IFACE` | Dumps station-mode AP peer metrics through nl80211 and reports `associated=true` when the interface has a current AP peer. Peer observations feed `links.list` as `radio=sta`. |
| `ble.scan` | `dev_id: integer = 0`, `reason: string = "jsonl"`, `scan_ms: integer = 1500` | Runs a bounded passive LE scan through raw Linux HCI sockets, parses DMesh 16-bit and operational 128-bit service-data announcements, records `BLE.rx` events, and returns `reports` plus parsed `dmesh` entries with `mode`, `event`, RSSI, address, and duplicate status. Requires `CAP_NET_RAW`. |
| `ble.adv` | `dev_id: integer = 0`, `on: bool = true`, `payload: string = "lmesh"` | Enables or disables BLE advertising with DMesh service UUID `0xFD5D` and current DMesh service-data layout. Requires `CAP_NET_RAW`. |
| `esp.serial.command` | `adapter: string \| null`, `port: string \| null`, `command: string`, `timeout_sec: number = 1.5` | Debug/test method: accepts a local text command, translates it to framed CBOR, and returns normalized binary firmware records. Prefer high-level methods for product flows. |
| `esp.active` | `adapter: string \| null`, `port: string \| null`, `gateway: string \| null`, `target: mac-or-last4 \| null`, `active: bool = true`, `active_ms: integer \| null` | Put an ESP into runtime-only powered/transfer radio mode. Direct `active=true` (`active`) stays on until `active=false` (`idle`) or reset; `active_ms` requests a bounded 1,000..300,000 ms session. Each `active` also enables the target's normal bounded UART debug/modem window, while the radio override remains active until `idle` or reset. With `gateway=lora1` and `target=<last4-or-MAC>`, lmesh sends addressed compact-CBOR `active`/`idle` via lora1's raw-NAN queue; this is the normal sleepy-node control path. Gateway delivery does not support `active_ms` yet. |
| `esp.status` | `adapter: string \| null`, `port: string \| null`, `extended: bool = false` | Diagnostic wrapper for firmware `status` or `xstatus`. `status` is the compact golden-signal line; `xstatus` is verbose debug telemetry. |
| `esp.power.profile` | `adapter: string \| null`, `port: string \| null`, `profile: "dfs"\|"perf"\|"low"\|"auto"\|null`, `save: bool = false` | Diagnostic wrapper for `power status=true` or `power profile=...`. The intended saved infra profile is `auto`. |
| `esp.lora.status` | `adapter: string \| null`, `port: string \| null` | Diagnostic wrapper for `lora status=true` on an ESP adapter. Product status should flow into `radios.list`, `links.list`, and `messages.history`. |
| `esp.wifi.raw_status` | `adapter: string \| null`, `port: string \| null` | Diagnostic wrapper for raw Wi-Fi counters on an ESP adapter. |
| `esp.sleep.status` | `adapter: string \| null`, `port: string \| null` | Diagnostic wrapper for ESP power/sleep state. |
| `esp.telemetry.stats` | `adapter: string \| null`, `port: string \| null`, `reset: bool = false` | Diagnostic wrapper for ESP telemetry counters. |
| `esp.serial.command` AP sync settings | Use `nvs op=set nan.sync_source=auto|nan_only|ap_only`, `nan.ap_owner=true|false`, and optional `nan.ap_loss_ms`, `nan.ap_recovery_ms`, `nan.ap_recovery_listen_ms`, `nan.ap_slot_tu`, `nan.ap_beacon_tu`; inspect source selection with `mode status=true` and `nan stats=true`. Firmware rationale and the AP-sync E2E scenario are in [`fw/esp32/rust/docs/wifi.md`](../../fw/esp32/rust/docs/wifi.md). |
| `esp.stability.start` | `source: string = "lora1"`, `expected: comma-list \| null`, `interval_sec: integer = 120`, `wait_sec: integer = 12`, `cycles: integer \| null`, `host_nan: bool = false` | Starts a background discovery/ping runner through the already-managed powered `source` UDS forward. Each cycle sends `mode ping=true` on the source LoRa, raw action, and raw-NAN paths. `host_nan=true` additionally enables the experimental direct host NAN/USD probe; it is not the normal sleepy-ESP control path because WPA does not expose a target Discovery Window scheduler. |
| `esp.stability.status` | none | Returns the running state, configured source/targets, host-NAN setting, completed-cycle count, and the last cycle's source and host-NAN observations. |
| `esp.stability.stop` | none | Requests a running stability loop stop; the current serial observation window ends before the worker exits. |
| `esp.battery.adc_probe` | `adapter: string \| null`, `port: string \| null`, `adc1_pins: string = "32,33,34,35,36,39"`, `count: integer = 3` | Low-level hardware probe for ESP ADC battery wiring. |
| `wifi.nan.start` | `iface: string = LMESH_WIFI_IFACE`, `ctrl_dir: string = LMESH_WPA_CTRL_DIR` | Brings the interface up, attaches it to wpa_supplicant, and verifies WPA 2.11 NAN/USD support with `GET_CAPABILITY nan`. NAN/USD begins when lmesh publishes or subscribes; it has no separate `NAN_START` control command. |
| `wifi.nan.default` | `iface`, `ctrl_dir`, `service_name: string = "dmesh"`, `ttl: integer = 3600` | Starts host DMesh NAN: publish with both solicited and unsolicited transmissions plus active subscribe on service `dmesh`, using `radio_protocol::build_nan_service_info("android", device_id, wake_count)`. lmesh calls this at startup unless `LMESH_NAN_AUTOSTART=0`, and logs NAN follow-up events unless `LMESH_NAN_EVENT_LOG=0`. |
| `wifi.nan.status` | `iface`, `ctrl_dir`, `events_ms: integer = 100` | Returns `STATUS`, `DRIVER_FLAGS`, `DRIVER_FLAGS2`, `GET_CAPABILITY nan`, and recently received NAN events. |
| `wifi.nan.events` | `iface`, `ctrl_dir`, `wait_ms: integer = 250`, `max_events: integer = 64` | Attaches to the wpa_supplicant control socket and returns parsed `NAN-DISCOVERY-RESULT`, `NAN-REPLIED`, `NAN-RECEIVE`, transmit status, and related events. DMesh NAN v1 SSI/follow-up payloads are decoded when present. |
| `wifi.nan.publish` / `wifi.nan.adv` | `iface`, `ctrl_dir`, `service_name: string = "dmesh"`, `ssi_hex: hex \| null`, `ttl: integer = 3600`, `freq: integer = 2437`, `srv_proto_type: integer = 0` | Sends `NAN_PUBLISH` with wpa_supplicant's default solicited and unsolicited transmissions, so the host both advertises and responds. When `ssi_hex` is omitted, lmesh uses Android-compatible DMesh NAN service info. |
| `wifi.nan.subscribe` / `wifi.nan.sub` | `iface`, `ctrl_dir`, `service_name: string = "dmesh"`, `ssi_hex: hex \| null`, `ttl: integer = 3600`, `freq: integer = 2437`, `active: bool = true`, `srv_proto_type: integer = 0` | Sends active `NAN_SUBSCRIBE` aligned with Android `lib-lm3`. |
| `wifi.nan.transmit` | `iface`, `ctrl_dir`, `handle: integer`, `address: mac`, `req_instance_id: integer \| null`, `ssi_hex: hex \| null`, `payload: string \| null`, `cookie: integer \| null` | Sends one NAN follow-up. If `payload` is used, lmesh sends UTF-8 bytes directly; high-level `send radio=nan` wraps payloads with `build_nan_followup("command_text", ...)`. |
| `wifi.nan.ping` | `iface`, `ctrl_dir`, `peer: hex device id`, `payload: string = "ping"` | Compatibility helper that builds a DMesh NAN follow-up and sends `NAN_TRANSMIT`. |
| `wifi.nan.size_probe` | `iface`, `ctrl_dir`, `sizes: comma-list = "64,128,192,224,230,255,384,512,1024"`, `mode: "publish"\|"transmit" = "publish"` | Probes what SSI/follow-up sizes wpa_supplicant accepts at the control/API layer. Over-the-air DW success still needs peer observation. |

Node results contain:

| Field | Type | Description |
| --- | --- | --- |
| `public_key` | `string` | Base64url-encoded P-256 public key. |
| `address` | `string` | Last observed `IP:port` for the peer. |
| `metadata` | `object<string,string>` | Optional metadata from the peer announcement. |

## Discovery Storage

Discovered peers are persisted under:

```text
./lmesh/nodes/<sha256(public_key)>.json
```

Each file stores `public_key`, latest `address`, and up to 16 `announces`. Each
announcement entry is an array:

```json
[timestamp_millis, public_key, "ip:port", {"public_key":"...","metadata":{}}]
```

## Structured Traces

Push-style discovery events are emitted through normal `tracing` output and mesh local
trace handling. Consumers should subscribe through the common mesh trace path; there is
no lmesh-specific subscribe method.

Relevant structured events:

| Level | Message | Fields | Meaning |
| --- | --- | --- | --- |
| `debug` | `service_started` | `public_key` | Server startup; identifies the local announcement key. |
| `debug` | `mcast_v4` | `multicast_ip`, `multicast_port` | IPv4 multicast receive path is active. |
| `debug` | `mcast_v6` | `multicast_ip`, `multicast_port` | IPv6 multicast receive path is active. |
| `debug` | `mcast_none` | none | Neither multicast socket could be opened. |
| `info` | `node_seen` | `public_key`, `address`, `metadata` | A new peer was discovered. |
| `info` | `node_updated` | `public_key`, `address`, `metadata` | An existing peer announced again or changed address/metadata. |
| `warn` | `persist_fail` | `public_key`, `address`, `error` | Discovery worked, but the node JSON file could not be updated. |
| `debug` | `bad_request` | `error` | A malformed JSONL/JSON-RPC request was received. |

The multicast wire announcement is JSON:

```json
{"public_key":"base64url-spki","metadata":{"key":"value"}}
```

## Radio Wire Protocol

`mesh::message` owns shared text/JSON/JSON-RPC parsing and normalized
`MeshMessage` records. It parses mesh text records such as
`kind key=value flag payload=hex:...`, firmware reply/log lines such as
`stats ...`, `messages ...`, `ev=...`, and `event type=...`, and WPA control
responses through a WPA adapter parser. WPA remains text-like but does not use
mesh `key=value` command syntax: requests are plain ASCII commands such as
`STATUS` or `NAN_PUBLISH ...`, responses are plain text such as `OK`, `FAIL`,
or key/value-ish status lines, and asynchronous events look like
`<3>CTRL-EVENT-...`.

`lmesh::radio_protocol` owns the DMesh BLE/NAN `DM` v1 frame format. It is a
library API. Linux BLE/NAN JSONL methods use it for frame encoding while keeping
platform-specific raw HCI sockets and `wpa_supplicant` control outside the
protocol module.

JNI or local adapter boundaries should stay message-oriented: text method/args
for routing and metadata, raw bytes for payload frames, and an FD slot where
needed. CBOR is the intended future structured binary format when JSON/text is
too verbose; protobuf is not planned for this path. Evaluate `minicbor` first on
ESP firmware and host Rust together, comparing firmware build size, allocation
behavior, ESP-IDF/no-std compatibility, and round-trip parity. Text remains the
mandatory debug and UDS-test baseline until CBOR passes that evaluation.

Public helpers:

| Helper | Purpose |
| --- | --- |
| `DMESH_BLE_SERVICE_UUID16` | DMesh BLE service UUID16, `0xFD5D`. |
| `build_ble_service_data` / `parse_ble_service_data` | BLE service-data wake and payload-hint frames. |
| `build_nan_service_info` / `parse_nan_service_info` | WiFi Aware/NAN service-specific info frames. |
| `build_nan_followup` / `parse_nan_followup` | WiFi Aware/NAN follow-up message frames. |

The active low-power Wi-Fi control plane is raw NAN, not ESP-NOW-like action
frames. Sleeping ESP32-S3 nodes manually parse and generate the required NAN
beacon, discovery-window, service-discovery, and follow-up subset; they do not
act as master and may deep sleep between discovery windows. Powered Linux and
Android nodes use their official NAN implementations for interoperability and
cluster/master duties. Android `lib-lm3` uses service name `dmesh`, solicited
publish, active subscribe, and the DMesh NAN v1 service-info/follow-up format
exposed by this crate. lmesh host defaults also keep unsolicited publish
enabled. Legacy ESP-NOW-like raw Wi-Fi methods remain diagnostics only. See
`../../notes/ai/lmesh-radio-handoff.md` for the current architecture and test
handoff.

## Real-Hardware Radio Setup

Install repo-local helpers into the normal development profile:

```bash
nix profile add .#radio-deps --profile target/nix/profile
```

Run preflight before live tests:

```bash
lmesh-radio-preflight
```

The preflight reports Wi-Fi interfaces/phys, driver-visible NAN markers from
`iw phy`, current process capabilities, and WPA control socket status.

Recommended development permission path:

1. Let `mesh-init` start `wpa-supplicant-nan` as `build` with ambient
   `CAP_NET_ADMIN` and `CAP_NET_RAW`. Its WPA config should contain:

   ```text
   ctrl_interface=DIR=/run/mesh/wpa-supplicant-nan GROUP=plugdev
   ```

2. Run `lmesh` as `build` under a `mesh-init` service with ambient and bounding
   capabilities containing `CAP_NET_ADMIN` and `CAP_NET_RAW`. The example
   configs assume mesh-init starts with `PATH` containing `lmesh` and
   `wpa_supplicant`; persistent logs and state belong under `HOME`,
   `MESH_HOME`, or a test directory such as `target/`, not `/run`.

mesh-init creates `/run/mesh/<service>/`, sets ownership from the service
`User`/`Group`, and leaves the directory world-traversable/writable. The UDS
server performs its own peer-credential identity checks; the directory
permission is only for socket creation and connection reachability.

For production, use the same layout with a dedicated `net` user instead of
`build`.

Fallback for direct local testing:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep target/debug/lmesh
sudo setcap cap_net_admin,cap_net_raw+ep target/release/lmesh
getcap target/debug/lmesh target/release/lmesh
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/$(pidof lmesh)/status
```

For the attached lab adapters, start with `wlan1` / MediaTek `mt76x2u` because
that is the interface expected to show NAN TX/RX frame sections in `iw phy`;
verify `wlan0` / Atheros `ath9k_htc` separately.
