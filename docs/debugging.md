
# Debugging

Most difficult part is keeping the network alive in doze/idle mode - most popular commands:

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

Use the `mesh` CLI for `mesh-init` service control:

```sh
mesh mesh-init status [SERVICE]
mesh mesh-init start SERVICE
mesh mesh-init stop SERVICE
mesh mesh-init reload
```

Do not invoke `mesh-init start`, `stop`, or `reload` directly. `mesh-init` is
the supervisor daemon; `mesh` is the operator-facing CLI.

Do not use the ESP-IDF/ESP toolchain for Android APK work. Firmware work has
its own local build context under `fw/esp32`; only rebuild or flash
firmware when that is the task.

Install the current release APK on a USB device and start the foreground
service:

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
radio debugging. `logcat` is useful as a last resort for framework WiFi Aware,
Bluetooth, permission, or crash failures, but it is too noisy for routine
message-level checks.

JNI should follow the same message style. Rust modules should be reached through
small generic command surfaces with text command/args, raw `byte[]` payloads,
and an FD slot when needed. Keep local binary payloads as bytes; reserve CBOR
for future structured binary frames rather than adding protobuf or base64.

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
length followed by one bounded (currently 2 KiB) opaque message payload. SSH
does not parse CBOR or shell text; it forwards record bytes. JNI also passes
only `byte[]`. `dmeshnative` maps those bytes to/from `MeshStream` and the typed
Bundle API before an Android service sees them.

Plain SSH exec is intentionally not a message ingress. Use the root-only
`DMeshShellProvider` for local shell text, or an explicit message client for
`dmesh-msg:1`.

## app-dmesh REST admin bridge

The Android web UI uses the embedded ssh-mesh REST admin server. It is bound
to `127.0.0.1` on the configured HTTP port and dispatches directly to the
Rust handler registry: it does not use the retired JSONL Java bridge or a
host-style `/mesh/run/mesh/...` UDS path.

The initial Android HTTP catalog is intentionally read-only:

- `radio.status_text`
- `radio.devices`
- `radio.local_networks`
- `radio.power.state`

All four take no fields or opaque payload. Framework callbacks, NAN/BLE
adapter events, probes, storage, and the legacy shell bridge are not HTTP
methods. Mutating operations are added only after they have a common
`dmesh-server` tagged schema and an Android adapter that reports its
capability/result.

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
curl -sS 'http://127.0.0.1:18480/_m/mesh/services/android/tools'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/android/call/radio.status_text' \
  -H 'content-type: application/json' \
  -d '{"id":1}'
```

If `SSH_MESH_HTTP_API_KEY` is configured, add `?apikey=...` to the first URL;
the server validates it and issues the scoped `mesh_api_key` cookie for later
calls. A missing record ID is one-way submission; the observation methods are
normally called with an ID and return a correlated result.

SSH exec text and JSON Lines are not command APIs. `dmesh-msg:1` accepts a
four-byte big-endian record length followed by one bounded opaque message record;
`dmeshnative` maps the record to/from the typed Android Bundle adapter.

## app-dmesh ADB shell commands

`app-dmesh` also exposes a local command surface through a `ContentProvider`:

```sh
content://com.github.costinm.dmesh.lm.shell
```

The provider checks `Binder.getCallingUid()` and only accepts callers with UID
`0` or `2000`, so it is intended for root or `adb shell` use.

Show the installed root CA keys:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'key show'"
```

Provision a root public key directly:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'key add ssh-ed25519 AAAA... test-root'"
```

Provision a root public key by URL:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'key add-url url=https://example.test/ca.pub'"
```

Send a local command through the same simple command grammar used for SSH
testing:

```sh
adb shell am start-foreground-service -n com.github.costinm.dmesh.lm/.DMService
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'wifi.scan reason=manual-adb'"
```

Send one bounded request to an explicitly named app service through
DirectBinder. The Java shell adapter maps `id`, `to`, and typed `i:`/`l:`/
`f:`/`d:`/boolean values into `MeshStream`/Bundle; the result contains the
correlated response Bundle. No app receives shell text or raw CBOR.

```sh
adb shell am start-foreground-service -n com.github.costinm.dmesh.lm/.DMService
adb shell 'content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method message --arg "/web/echo id=adb-shell typed=i:7 \
  to=intent:#Intent;component=com.github.costinm.dmesh.web/.WebBridgeService;end"'
```

Subscribe to live message frames for a few seconds:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'subscribe durationMs=5000 limit=64 keys=net,wifi,BLE'"
```

Pull the recent in-memory message buffer without needing to subscribe before
the event happened:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'history durationMs=1500 limit=80 keys=net,wifi,BLE'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'history durationMs=1500 limit=60 keys=net.NAN,wifi.nan,wifi.p2p,wifi.ERR'"
```

## Radio Scan Debugging

Trigger WiFi, BLE, and NAN from the shell interface, wait a few seconds, then
pull the message history:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'wifi.scan reason=manual-debug'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'ble.scan reason=manual-debug'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
   --method command --arg 'ble.unbond addr=84:0D:8E:07:41:72'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'transport.start mode=nan'"

sleep 6

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'history durationMs=1500 limit=80 keys=net,wifi,BLE'"
```

Expected message patterns:

- WiFi scan: `net.status` with `event=scan` and `visible=N`.
- BLE scan: `BLE.scan` should include `wake=pending_intent` and
  `filters=dmesh_operational,...`. DMesh firmware or phone advertisements
  appear as compact `BLE.DISC proto=dmesh` events with
  `event`, `pending`, `payload_len`, `payload_hash`, `prefix`, and `pull`.
  If a companion is stored, only that peer is pulled. External devices still
  appear as `BLE.DISC proto=meshtastic`.
  `BLE.DISC proto=meshtastic` means the Meshtastic GATT service UUID was
  advertised.
- BLE payload transfer: expected events are `BLE.PENDING`, `BLE.PULL
  state=subscribed`, `BLE.PULL state=ready_write`, `BLE.MSG`, and `BLE.PULL
  state=done`. Android stores raw payloads in one append-only app-private file.
- NAN: `net.NAN.Attach`, then `net.NAN.PubStart` and `net.NAN.SubStart` before
  `net.NAN.*ServiceDiscovered` messages. DMesh follow-ups appear as
  `net.NAN.FollowupRx` / `net.NAN.FollowupTx` with parsed JSON from the Rust
  protocol code. If the history shows `net.NAN.AttachError`, NAN did not reach
  publish/subscribe.

The Android side does not hold wake locks. The expected wake paths are the
foreground service while active, periodic `LMJob` update windows, BLE
`PendingIntent` scan delivery, and normal WiFi Aware framework callbacks.

Single-companion and stored-message commands:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'companion status durationMs=1200'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'companion pair durationMs=2500'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'companion pair addr=84:0D:8E:07:42:C6 name=DMesh durationMs=2500'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'msg ble.pair addr=84:0D:8E:07:42:C6'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'messages file durationMs=1200'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'messages list limit=40 durationMs=1200'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'messages read seq=18 preview=96 durationMs=1200'"
```

`companion pair` first claims a recently seen `BLE.DISC proto=dmesh_pairing`
advertisement and reports `pairing=recent_scan`. If no recent pairing
advertisement is cached, it opens a 60 second direct-scan pairing window and
starts BLE scanning if needed. If CDM times out but the app scan saw the ESP, use
`companion pair addr=...` to store the single companion address directly. Use
`msg ble.pair addr=...` to attempt the DMesh GATT pairing request; a `BLE.PAIR
state=connecting` followed by `BLE.PULL phase=connect state=timeout` means
Android could create a remote GATT client but the ESP did not accept or complete
the connection in the timeout window.

`messages list` returns metadata lines from
`files/radio/ble/messages.bin`. `messages read` adds a bounded hex preview of
the raw payload; it does not base64-encode the body.

## Two Android BLE/NAN live test

Use this when two Android devices are connected over ADB and `app-dmesh` is
installed. The script starts `DMService`, sends a BLE advertisement from each
device, waits for NAN discovery, sends a NAN follow-up, then reads the
in-memory history buffer through the app content provider. It leaves NAN
running: the service, rather than test cleanup, owns the persistent cluster.

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
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'wifi.con.stop reason=nan-debug'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'wifi.con.cancel reason=nan-debug'"
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

The `ssh` command maps to the Rust JNI client methods:

```sh
adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'ssh connect host=127.0.0.1 port=22 user=dmesh serverKey=ssh-ed25519:...'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'ssh exec conn=1 command=\"uname -a\"'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'ssh forward conn=1 localPort=10022 remoteHost=127.0.0.1 remotePort=22'"

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'ssh remote-forward conn=1 remotePort=10080 localHost=127.0.0.1 localPort=8080'"
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
