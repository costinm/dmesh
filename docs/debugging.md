
# Debugging

Most difficult part is waking up doze/idle mode - most popular commands:

## Repo-local tooling

Keep DMesh builds self-contained under `target/`. The build helper
uses the repo-local Cargo and Gradle homes and the Nix profile in
`target/nix/profile`; manual commands should use the same environment:

```sh
cd "$(git rev-parse --show-toplevel)"
./scripts/build-android.sh deps
. target/nix/profile/bin/dmesh-setenv
export RUSTUP_HOME="$PWD/target/rustup"
export CARGO_HOME="$PWD/target/.cargo"
export GRADLE_USER_HOME="$PWD/target/.gradle"
```

Build only `app-dmesh` by default:

```sh
./scripts/build-android.sh build release
```

`DMESH_SSH_MESH_DIR` optionally selects a local ssh-mesh checkout. A sibling
checkout is detected automatically; the build keeps DMesh tooling and caches
under `target/`. To test the standalone Git dependency path instead, point the
override at a missing directory:

```sh
DMESH_SSH_MESH_DIR="$PWD/no-ssh-mesh-override" \
  ./scripts/build-android.sh build release
```

### Managed service control

Use the `mesh` CLI for `mesh-init` service control. The RPC component is
`mesh-init` and the service argument is `name=value`:

```sh
mesh mesh-init mesh-init status [name=SERVICE]
mesh mesh-init mesh-init start name=SERVICE
mesh mesh-init mesh-init stop name=SERVICE
mesh mesh-init mesh-init reload
```

```sh
adb -s SERIAL install -r target/apk/release/app-dmesh-release.apk
adb -s SERIAL shell am start-foreground-service \
  -n com.github.costinm.dmesh.lm/.DMService
```

Grant runtime permissions explicitly on physical devices:

```sh
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.ACCESS_FINE_LOCATION
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.ACCESS_BACKGROUND_LOCATION
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.NEARBY_WIFI_DEVICES
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.BLUETOOTH_SCAN
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.BLUETOOTH_CONNECT
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.BLUETOOTH_ADVERTISE
```

Prefer the app's command provider and in-memory history over `logcat` for normal
lmesh debugging. `logcat` is useful as a last resort for framework WiFi Aware,
Bluetooth, permission, or crash failures, but it is too noisy for routine
message-level checks.

JNI follows the same 'structured message' style as all transports. Rust modules should be 
reached through small generic handlers, with CBOR `byte[]` payloads,
and an FD slot when needed. 

## Tcpdump

```
# Wifi Direct uses 1,6,11 for announcements / discovery - useful to stay in those
# channels even in AP/client mode
iw phy phy0 set channel 6

# Radio tap shows signal level, freq, low level Wifi frames
wireshark -i wlan0 -I -y IEEE802_11_RADIO

Filters:
wlan_mgt.ssid contains "DIRECT"

```

## Host UART and QUIC captures

The host tools can save serial sideband logs and capture opaque QUIC packets
crossing Tokio bearers. Set either or both variables on the `dmesh-cli`
invocation:

```sh
UART_TARGET=/dev/serial/by-id/DEVICE
UART_CODEC_LOG=/tmp/dmesh-uart.log \
QUIC_LITE_PCAP=/tmp/dmesh-quic.pcap \
  dmesh-cli "$UART_TARGET" status --timeout-secs 3 \
    --repeat-secs 2 --linger-secs 10
```

`UART_CODEC_LOG` appends complete unframed UART console/sideband text lines
observed by the host reader; it excludes bytes inside marked QUIC packets.
`QUIC_LITE_PCAP` creates a classic PCAP of QUIC packets crossing the Tokio
node's bearer boundary, for all bearers attached to that node—not just UART.
The Linux cooked-v2 header records ingress/egress direction and bearer ID.
For UART, capture occurs after PPP decoding on receive and before PPP framing
on send; it does not include raw serial bytes, framing errors, or non-QUIC
sideband traffic.

The UART log is appended, but each new Tokio node creates/truncates its PCAP
path. Use a fresh PCAP filename for each process when preserving earlier
captures. Capture I/O errors are reported to stderr and do not stop packet
delivery. These are host observations; use `dmesh-cli SERIAL --watch` or a
tagged `log.watch` request to collect device-side logs separately.

For a UDP firmware object upload, set `QUIC_LITE_PCAP` on the `object.flash`
process; it records that process's flash association across the UDP bearer.
Run a separate `dmesh-cli SERIAL --watch` process with `UART_CODEC_LOG` set to
capture UART sideband logs. The PCAP is a capture at the host QUIC bearer boundary, not
a record of raw UDP/IP headers or proof that the device application consumed
the captured bytes. Use a fresh capture path for each upload process.

Firmware UART diagnostics are emitted as one-line `key=value` records with a
monotonic `ts_ms`, `level`, and `event`; `dmesh-cli SERIAL --watch` prints
those device lines directly. QUIC dispatch records include the phase,
component/method tags, request ID, association handle, stream ID, and match
result. `object_flash.progress` is emitted every five seconds while a transfer
is active. It reports application-consumed body bytes and selected QUIC-core
counters; zero progress with increasing QUIC receive/ACK counters distinguishes
transport processing from application acceptance. The debug UART queue is
lossy, so use `UART_CODEC_LOG` to retain what the host actually observed.

`telemetry.quic` returns a node-wide snapshot over associations with
an active QUIC endpoint on firmware, Linux, and Android. The Rust
`quic_lite::NodeTelemetry` and
`AssociationTelemetry` snapshots expose QUIC packet, ACK, loss,
retransmission, and submission-failure counters; bearer-specific telemetry
remains the source for radio/UDP receive and transmit failures. QUIC ACKs and
retransmissions are not application-delivery or flash-commit proof. Aggregate
counters disappear when their association is removed and restart with the
node; use live `object_flash.progress` records for one upload.

Query the snapshot from any reachable DMesh node with
`dmesh-cli DEVICE telemetry.quic`. It is an empty request and returns
the required numeric counters documented in [`API.md`](../API.md).

Example: capture an object upload over UDP while passively watching UART logs
(run these in separate terminals; substitute a selected serial device and
discovered, scoped link-local endpoint):

```sh
UART_CODEC_LOG=/tmp/device-uart.log \
  dmesh-cli SERIAL status --timeout-secs 10 --linger-secs 300

QUIC_LITE_PCAP=/tmp/object-flash.pcap \
  dmesh-cli 'udp://[DEVICE_LINK_LOCAL%IFACE]:3339' object.flash \
    cpu=CPU target=TARGET dry_run=true --file IMAGE
```

The upload command reports completion only after the terminal `object.flash`
result; ACKs are not upload-completion evidence.

Firmware handler streams expire after 15 seconds without application progress.
Successful handler work records its **completion** time: a synchronous partition
erase may take longer than 15 seconds and must not make a progressing upload
look idle immediately afterward. Flash is not exempt from the idle timeout.
An `object_flash.idle_timeout` record before a terminal success means the
upload was abandoned; the destination may already be erased or partly written.

A full congestion window is retryable QUIC `Blocked`, not
`MissingEgressAddress`: the route still exists. Stream producers retain the
unchanged bytes/FIN until ACK or capacity progress. A host-driver exit reporting
`Transport(Blocked)` is not an application flash rejection; capture both
control/timer traffic and UART logs to locate the runtime path that treated
backpressure as fatal. Neither error proves a durable flash commit.

Host and Android stream applications use `AsyncRead`/`AsyncWrite`; the Tokio
node driver owns QUIC pacing, timers, credit and retryable backpressure.
Do not add window checks or QUIC retry loops to flash/probe handlers or clients.
QUIC-lite's `stream_probe` tests run identical generic byte-stream workloads
over TCP and QUIC bearers. Its `tokio_node_driver` tests also cover a slow
reader transferring more bytes than a 16 KiB receive window. These tests do
not replace a device upload and durable-commit check.

`dmesh_server::stream_client` provides common request, flash and probe
exchanges over `AsyncRead + AsyncWrite`. Flash's multipart body is assembled
there, not in a QUIC-specific client. Request/flash exchanges read responses
concurrently with writes; a TCP test checks the same flash helper and exact
header/manifest-length/manifest/content ordering. QUIC-lite separately tests
a 1 MiB transfer through delayed, reordered, lossy and `WouldBlock` links.
Path-status congestion/history pressure retains the status on the adaptive
loss clock, rather than stopping the driver or spinning an overdue timer.
Association CLOSE waits for a retained bearer packet before retiring state.

The 2026-10-02 common-stream canary uploaded a 899,568-byte Recovery image
through Main over UDP in 6.85 seconds with terminal `object.flash` success;
post-upload status and a 64 KiB probe passed. Evidence is under
`target/evidence/e8-common-stream-IJiUMKQ8/`. This did not test booting Recovery
or flashing Main from Recovery. Detailed flash UART diagnostics were missing:
the current formatter's association Debug braces include `0x7d`, which
`send_debug_text` rejects. Do not interpret their absence as no handler
admission; correlate the terminal response and packet capture.

The passive `--watch` path does not use `UART_CODEC_LOG`; redirect its output
to a file if using that mode. `status --linger-secs` uses the Tokio UART bearer
and therefore saves sideband logs through `UART_CODEC_LOG` while UDP uploads
run separately. Do not let two processes open the same serial device.

For UART QUIC diagnosis, `--repeat-secs N` keeps one host serial reader and
Tokio node open, repeats the read-only `status` or `services` request on a
fresh QUIC association after each N-second delay, and prints each response. It stops on the first
request failure, then continues collecting UART logs for `--linger-secs N`
before returning the error. Without `--repeat-secs`, `--linger-secs N` keeps
the reader alive after the one response for that many seconds. This is useful
for retaining crash or sleep-transition logs in the same `UART_CODEC_LOG`
file; it does not change the device's logging behavior.

## Remote adb

- Ssh with `LocalForward 6018 127.0.0.1:5027`
- ADB_SERVER_SOCKET=tcp:localhost:6018 adb devices

## app-dmesh SSH message bridge

`app-dmesh` starts the Rust `dmesh` SSH server on the device at port `15022`.
For local emulator testing, forward it to the host:

```sh
adb forward tcp:11522 tcp:15022
```

For a USB device or emulator that already has `app-dmesh` installed, provision a
host SSH public key into the app sandbox and verify authenticated SSH access:

```sh
DMESH_ADB_SERIAL=94AAY0LALC ./scripts/android_ssh_trust_and_verify.sh
```

The script writes the generated public key to:

```sh
/data/user/0/com.github.costinm.dmesh.lm/files/ssh-mesh/authorized_keys
```

It restarts `DMService`, forwards host `localhost:11522` to device port `15022`,
forwards host `localhost:18080` to device admin HTTP port `18480`, and checks the
SSH banner and `/_m/adm`. The `dmesh-msg:1` direct stream is binary records, so a
separate binary client smoke test owns message-routing verification.

To test CA trust instead of a single public key:

```sh
./scripts/android_ssh_trust_and_verify.sh ca
```

Generated test keys are under:

```sh
target/android-ssh/ca_ecdsa
target/android-ssh/ca_ecdsa.pub
target/android-ssh/id_ecdsa
target/android-ssh/id_ecdsa.pub
target/android-ssh/id_ecdsa-cert.pub
```

The smoke script installs the CA public key into the app sandbox as:

```sh
/data/user/0/com.github.costinm.dmesh.lm/files/ssh-mesh/authorized_cas
```

`MeshNode` loads `authorized_cas` on service startup, so restart `DMService`
after changing that file:

```sh
adb shell am force-stop com.github.costinm.dmesh.lm
adb shell am start-foreground-service \
  -n com.github.costinm.dmesh.lm/.DMService
```

`dmesh-msg:1` is a binary transport. Each record is a four-byte big-endian
length followed by one opaque message payload (currently limited to 2 KiB). SSH
does not parse CBOR or shell text; it forwards record bytes. JNI also passes
only `byte[]`. `dmeshnative` maps those bytes to/from `MeshStream` and the typed
Bundle API before an Android service sees them.

Plain SSH exec is intentionally not a message ingress. Use `dmesh-cli` for
shared controls or an explicit message client for `dmesh-msg:1`.

## app-dmesh REST admin bridge

The Android web UI uses the embedded ssh-mesh REST admin server. It listens
on the configured HTTP port and dispatches directly to the
Rust handler registry: it does not use the retired JSONL Java bridge or a
host-style `/mesh/run/mesh/...` UDS path.

### Finding the supported HTTP API

The gateway is its own discovery surface; two read-only GETs enumerate
everything a service answers (ssh-mesh `mesh_rest`):

```sh
# Every registered service: name, backend, encoding, catalog component.
curl -sS 'http://127.0.0.1:18480/_m/mesh/services'

# Every method of one service with descriptions and field tags.
# view=all includes masked and legacy methods; the default view shows
# only operator-facing entries (x-ui-visibility default or unspecified).
curl -sS 'http://127.0.0.1:18480/_m/mesh/services/wifi/tools?view=all'
```

Method and field tags are formally specified in the root `API.md`. The
installed catalogs it generates (`crates/lmesh/resources/tools.json` for
Linux `lmesh`, `crates/dmesh-server/platform/tools.json` for the shared
platform services) are checked against `API.md` in `scripts/build.sh`, so a
catalog GET and the documentation cannot drift apart silently. Over
QUIC/UART/SSH stream transports the tagged equivalent of the service list is
component 9, method 2 (`dmesh-cli DEVICE services`).

Commands then go through one of two POST routes:
`/_m/mesh/services/<svc>/records` (a tagged record; numeric tags need no
catalog) or `/_m/mesh/services/<svc>/call/<METHOD>` (named, resolved through
the service catalog). `dmesh-cli http://... SERVICE.METHOD` uses the records
route.

Registered Android HTTP services are `ble`, `companion`, `history`, `status`,
`transport`, `usb`, and `wifi`. The Linux `lmesh` admin endpoint (localhost
port 18981) registers a single `lmesh` service backed by its UDS; numeric
tagged records dispatch there without provisioning, while the named
convenience endpoints (`/tools`, `/call/<method>`, name-based records)
resolve through the shared catalog search: `/opt/lmesh/etc/schemas/`,
`$HOME/opt/lmesh/etc/schemas/`, and `$HOME/etc/schemas/`. The mesh-init
template no longer pins `MESH_TOOLS`; a host without an installed catalog can
place one under `$HOME/etc/schemas/` for its service user.

QUIC-lite on port `3336` exposes the portable discovery and telemetry
methods, including `telemetry.battery`. Framework callbacks and JNI
diagnostics are not separate HTTP commands.

If a defensive UDS fallback is ever needed on Android, JNI configures mesh paths
under the app files tree:

```text
/data/user/0/com.github.costinm.dmesh.lm/files/ssh-mesh/run/mesh
```

Do not add Android command paths that depend on host `/mesh` directories.

Manual REST smoke test:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480

curl -sS 'http://127.0.0.1:18480/_m/mesh/services'
curl -sS 'http://127.0.0.1:18480/_m/mesh/services/ble/tools'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/ble/call/ble.status' \
  -H 'content-type: application/json' \
  -d '{"id":1}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/transport/call/transport.set' \
  -H 'content-type: application/json' \
  -d '{"id":2,"wake_target":"10:BD:A3:AC:5A:20","mode":6,"ap":1,"now":1,"ble":1,"nan_dw_interval":1}'

curl -sS -o /dev/null -L -w '%{http_code} %{url_effective}\n' \
  'http://127.0.0.1:18480/_m/adm/ble.html'

curl -sS 'http://127.0.0.1:18480/_m/mesh/services/usb/tools'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/usb/call/usb.status' \
  -H 'content-type: application/json' \
  -d '{"id":1}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/usb/call/usb.devices' \
  -H 'content-type: application/json' \
  -d '{"id":2}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/usb/call/usb.open' \
  -H 'content-type: application/json' \
  -d '{"id":3,"auto":true}'
```

The same table the Android status screen shows is generated on the Rust side
and served over HTTP by the `status` service:

```sh
curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/status/call/status.text' \
  -H 'content-type: application/json' \
  -d '{"id":1}'
```

The admin landing page (`/_m/adm/`) renders the same text in its Status
section. Bearer letters are `A` Wi-Fi Aware, `B` BLE, `W` Wi-Fi UDP6,
`N` ESP-NOW, `U` USB; `P` marks paired companions (listed first) and `z`
marks devices that announced a pending sleep.

`transport.set.wake_target` is the sleepy device's STA or AP radio MAC, not
its BLE address. The firmware admits a targeted NAN wake only when the MAC
matches one of its local radio interfaces.

If `SSH_MESH_HTTP_API_KEY` is configured, add `?apikey=...` to the first URL;
the server validates it and issues the scoped `mesh_api_key` cookie for later
calls. A missing record ID is one-way submission; the observation methods are
normally called with an ID and return a correlated result.

SSH exec text and JSON Lines are not command APIs. `dmesh-msg:1` accepts a
four-byte big-endian record length followed by one size-limited opaque message record;
`dmeshnative` maps the record to/from the typed Android Bundle adapter.

## app-dmesh control with dmesh-cli

Use the shared Rust service handlers. ADB may forward the HTTP port, but it no
longer carries commands through a ContentProvider. The direct Wi-Fi address
can instead be used as a `udp://HOST:3336` target for shared QUIC-lite methods.

```sh
adb -s SERIAL forward tcp:18480 tcp:18480
dmesh-cli http://127.0.0.1:18480 transport.set --mode=6
dmesh-cli http://127.0.0.1:18480 wifi.scan
dmesh-cli http://127.0.0.1:18480 radio.history --limit=80 --keys=net,wifi,BLE
dmesh-cli udp://[ANDROID_LINK_LOCAL%IFACE]:3336 discovery.nodes
```

The retired root-only provider and its device-secret provisioning command have
no replacement. Do not send secret material through the generic HTTP gateway.

## Radio Scan Debugging

Trigger BLE and Wi-Fi through the shared HTTP services, wait a few seconds,
then pull the retained message history:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480

dmesh-cli http://127.0.0.1:18480 ble.scan
dmesh-cli http://127.0.0.1:18480 wifi.scan
dmesh-cli http://127.0.0.1:18480 transport.set --mode=6

sleep 6

dmesh-cli http://127.0.0.1:18480 ble.status
dmesh-cli http://127.0.0.1:18480 radio.history --limit=80 --keys=net,wifi,BLE
```

Expected message patterns:

- WiFi scan: `net.status` with `event=scan` and `visible=N`.
- BLE scan: `ble.status` should report `scan=true`, and `ble.scan_results`
  should list retained DMesh service-data advertisements.
- NAN: `net.NAN.Attach`, then `net.NAN.PubStart` and `net.NAN.SubStart` before
  `net.NAN.*ServiceDiscovered` messages. DMesh follow-ups appear as
  `net.NAN.FollowupRx` / `net.NAN.FollowupTx` with parsed JSON from the Rust
  protocol code. If the history shows `net.NAN.AttachError`, NAN did not reach
  publish/subscribe.

The Android side does not hold wake locks. The expected wake paths are the
foreground service while active, periodic `LMJob` update windows, and normal
WiFi Aware framework callbacks.

Companion pairing is started from the app UI's "Pair companion" action. The
UI uses the Android Companion Device Manager flow and the local BLE scanner;
it is not exposed as an ADB shell command. Use `ble.scan`, `ble.scan_results`,
and `ble.connect` over the HTTP service when a scripted BLE connection is
needed.

## Main firmware BLE tagged surface

Control the Main-owned NimBLE radio through its numeric tagged component
(`104`) over a normal `dmesh-cli` service stream:

```sh
dmesh-cli <device> ble.start
dmesh-cli <device> ble.status
dmesh-cli <device> ble.scan duration_ms=5000
dmesh-cli <device> ble.scan_stop
dmesh-cli <device> ble.connect addr=<peer_local_addr> addr_type=<peer_local_addr_type> psm=128
dmesh-cli <device> ble.coc.send data=deadbeef
dmesh-cli <device> ble.stop
```

`ble.start` begins advertising and the PSM `0x0080` CoC server. `ble.stop`
stops scan/advertising and terminates an active LE connection. `ble.connect`
initiates a central GAP connection to `addr`, then opens the requested CoC
channel. Read the peer address from its `ble.status` `local_addr` and
`local_addr_type` fields; `addr` accepts colon-separated or compact hex.
`ble.coc.send` transmits one SDU through the active CoC channel. Pairing is Just
Works with persisted bonding. Each CoC SDU is one opaque QUIC-lite packet and
enters the shared Main connection path with bearer ID `7`.

## Two Android BLE/NAN live test

Use this when two Android devices are connected over ADB and `app-dmesh` is
installed. The script starts `DMService`, starts a BLE scan through the shared
`ble` HTTP service, waits for NAN discovery, then reads
the remaining in-memory history buffer through the shared history service. It
leaves NAN running: the service, rather than test cleanup, owns the persistent
cluster.

```sh
scripts/live_android_radio_test.py \
  --device 94AAY0LALC \
  --device RFCNB05AJ7E \
  --auto-serial \
  --duration 12
```

Expected result:

- `ble_status=True` on both devices.
- `nan_status=True` on both devices.
- At least one device reports `nan_peer=True`.
- At least one device reports `nan_followup=True`.

The script saves ADB history and captured output under
`target/live-tests/android-radio-*`.

## LoRa to Android live test

Use this when two LoRa ESP32 boards are attached as serial devices and two
Android devices are connected over ADB. The intended path is:

```text
/dev/ttyUSB0 LoRa sender -> /dev/ttyUSB1 ESP32 repeater -> Android BLE/NAN receive
```

Default BLE plus raw NAN forwarding:

```sh
scripts/live_lora_android_test.py \
  --android 94AAY0LALC \
  --android RFCNB05AJ7E \
  --tx /dev/ttyUSB0 \
  --rx /dev/ttyUSB1 \
  --wait 12
```

Official WiFi Aware/NAN backend:

```sh
scripts/live_lora_android_test.py \
  --android 94AAY0LALC \
  --android RFCNB05AJ7E \
  --tx /dev/ttyUSB0 \
  --rx /dev/ttyUSB1 \
  --nan-backend official \
  --wait 14
```

Expected BLE evidence in Android history:

- `BLE.DISC proto=dmesh`
- `event=lora_rx`
- `pending`, `payload_len`, `payload_hash`, and `prefix`
- `BLE.PENDING`
- `BLE.PULL state=subscribed`
- `BLE.MSG seq=... len=...`
- `BLE.PULL state=done`

Expected firmware console evidence:

- `lora_rx`
- companion BLE advertising while data is pending
- DMesh GATT TX notification frames: `msg seq=... hash=... len=...`
- Android ACKs: `ack seq=... hash=...`
- pending queue empty and advertising stopped after ACK
- `ev=lora.fwd t=nan ...`

For the official NAN backend, discovery/match evidence is currently the main
signal to check. Firmware logs should show `nan.match`, and Android history may
show firmware service state such as `/nan/<device_id>` with
`role=firmware_publisher`. Payload follow-up over official NAN can still fail
and fall back to raw forwarding, for example `ev=lora.fwd t=nan ... ok=false`
followed by raw NAN forwarding. Android apps do not receive raw WiFi action
frames as WiFi Aware follow-up messages; BLE is the proven LoRa-to-Android
payload wake/notice path.

The serial harness uses Python `termios` directly and does not require
`pyserial`. Use `socat` for manual serial teeing if needed, or use the firmware
project's own scripts and dependency environment when driving lower-level
firmware tests.

Check Android runtime permissions granted to `app-dmesh`:

```sh
adb shell dumpsys package com.github.costinm.dmesh.lm
```

The relevant runtime permissions are `ACCESS_FINE_LOCATION`,
`ACCESS_BACKGROUND_LOCATION`, `NEARBY_WIFI_DEVICES`, `BLUETOOTH_SCAN`, and
`BLUETOOTH_CONNECT`, and `BLUETOOTH_ADVERTISE`.

For NAN attach failures that are not explained by app history or firmware
serial logs, collect the framework WiFi Aware logs:

```sh
adb shell logcat -d -v time -t 400 \
  WifiAwareService:D \
  WifiAwareNativeApi:D \
  WifiAwareNativeManager:D \
  WifiAwareStateManager:D \
  HalDevMgr:D \
  WifiNative:E \
  nan:D \
  LM-BLE:D \
  DM-SVC:D \
  AndroidRuntime:E \
  '*:S'
```

Useful failure patterns:

- `Failed to allocate new Nan iface`
- `Was not able to obtain a WifiNanIface`
- `enableAndConfigure: null interface`
- `bestIfaceCreationProposal is null, requestIface=NAN, existingIface=[name=wlan0 type=STA, name=p2p0 type=P2P]`

That last pattern means NAN is blocked below the app because the WiFi HAL cannot
allocate a NAN interface while a P2P interface exists. Stop app-owned P2P before
retrying NAN:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480
dmesh-cli http://127.0.0.1:18480 transport.set --mode=6 --ap=0
```

Inspect the current WiFi HAL interface state and WiFi Aware counters:

```sh
adb shell dumpsys wifi
adb shell dumpsys wifi aware
```

In the output, look for:

- `Dump of HalDeviceManager`
- `mInterfaceInfoCache`
- `mDebugChipsInfo`
- `mWifiAwareMetrics`
- `mAttachStatusData`
- `totalNanScanTimeMs`

On devices with limited concurrency, a healthy state before NAN attach should
show `wlan0` STA without an app-owned `p2p0` interface.

Outbound SSH client operations use the admin HTTP bridge rather than the local
ADB shell:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connect' \
  -H 'content-type: application/json' \
  -d '{"host":"127.0.0.1","port":22,"user":"dmesh","server_key":"ssh-ed25519 ..."}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connections/1/exec' \
  -H 'content-type: application/json' \
  -d '{"command":"uname -a"}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connections/1/forward/local' \
  -H 'content-type: application/json' \
  -d '{"local_port":10022,"remote_host":"127.0.0.1","remote_port":22}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connections/1/forward/remote' \
  -H 'content-type: application/json' \
  -d '{"remote_port":10080,"local_host":"127.0.0.1","local_port":8080}'
```

# Telemetry and logs

Counters, state snapshots and logs are registered handlers like any other, and
`API.md` defines each response (`telemetry` and `log` sections). A device
omits a value it does not have; it never sends zero for "unknown".

- Firmware today: `telemetry.now`, `nan`, `udp6`, `wifi_link`, `quic`,
  `memory`, `power`, `runtime`, `bearers`, and `log.watch`. Linux and Android
  still answer the older `metrics`, `events`, `log-watch` and snapshot methods
  until they migrate.
- `log.watch` polls retained records (`since_seq`, `limit`, `level`, `source`,
  `kind`) and returns a `cursor` for the next poll. With `stream=true` and a
  `timeout` the same method keeps the stream open and, with `snapshots`
  (`telemetry.quic`, ...) and `interval_ms`, interleaves each snapshot as a
  record whose `fields` are that method's response. The CLI does not decode the
  streamed body yet.
- Firmware logs are the last 32 ESP-IDF lines; a streamed `log.watch` is polled
  every 100 ms by the owner while it waits, so keep streams short.

# Handler registry

Any request may carry `timeout=MS` (envelope key 8, milliseconds): the time the
caller allows. `dmesh-cli DEVICE probe.start peer=... bytes=... timeout=60000`
lets the probe run for a minute; without it a probe runs for a size-based
default (30 s up to 300 s). A request that runs out is answered with a
`timeout` error. See ssh-mesh `crates/mesh-api/PROTOCOLS.md`.

Every platform registers its tagged-CBOR handlers in the one
`dmesh_server::registry`, by component and method number plus name, and every
ingress (QUIC streams, UART/UDP/NOW records, the Linux control socket, the
Android HTTP gateway) dispatches through it by number. Only implemented methods
are registered, so `services` lists exactly what a platform answers
(`[component, method, "name"]`) and a request for anything else receives
`unsupported or invalid stream request` with the request's component, method
and id. Stubs are not registered: Android has no `metrics`, `memory.snapshot` or
`telemetry.*_metrics`; Linux has no `telemetry.battery`, `power.snapshot`,
`memory.snapshot` or BLE scan/connect; boot, module, runtime-reset and
flash methods are firmware-only.

Android's platform methods (`ble` 201, `radio` 202, `usb` 204, `wifi` 205,
`companion`, `transport.set`) are registered local-only. The HTTP gateway
routes `/_m/mesh/services/<name>/call/<method>` to the registry as local
ingress; a QUIC peer calling the same numbers gets the unsupported error. Check
what a device registers with:

```sh
dmesh-cli DEVICE services
curl -sS -X POST 'http://127.0.0.1:18480/_m/mesh/services/ble/call/ble.status' \
  -H 'content-type: application/json' -d '{}'
```

# Permissions

In adb mode, grant the required permissions listed in
[Repo-local tooling](#repo-local-tooling). For a quick status check:

```sh
adb shell dumpsys package com.github.costinm.dmesh.lm | \
  sed -n '/runtime permissions:/,/install permissions:/p'
```

On some devices, especially Samsung builds, use `pm grant --user 0` so the
runtime grant is applied to the active user.
