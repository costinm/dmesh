
# Debugging

Most difficult part is keeping the network alive in doze/idle mode - most popular commands:

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

The build helper does the full setup, including APK install, service start,
adb forwarding, temporary test CA generation, one JSONL command, and one human
command:

```sh
./scripts/build-android.sh ssh-jsonl-smoke
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
forwards host `localhost:18080` to device admin HTTP port `18480`, checks the SSH
banner, checks `/_m/adm`, and sends one authenticated SSH direct-stream command.

To test CA trust instead of a single public key:

```sh
./scripts/android_ssh_trust_and_verify.sh ca
```

Generated test keys are under:

```sh
target/ssh-jsonl-smoke/ca_ecdsa
target/ssh-jsonl-smoke/ca_ecdsa.pub
target/ssh-jsonl-smoke/id_ecdsa
target/ssh-jsonl-smoke/id_ecdsa.pub
target/ssh-jsonl-smoke/id_ecdsa-cert.pub
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

Rust owns the SSH direct stream parser. It accepts JSON Lines when the first
character is `{`, otherwise it treats the line as a human command. Java receives
generic message names plus Android routing metadata through JNI.

Manual JSONL test:

```sh
printf '%s\n' \
  '{"id":"manual-1","method":"wifi.scan","data":{"reason":"manual-ssh-jsonl"}}' |
timeout 12 ssh \
  -i target/ssh-jsonl-smoke/id_ecdsa \
  -o CertificateFile=target/ssh-jsonl-smoke/id_ecdsa-cert.pub \
  -p 11522 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ControlMaster=no \
  -o ControlPath=none \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  dmesh@127.0.0.1 \
  -W dmesh-msg:1
```

Plain SSH exec and shell are also mapped to the same Android MsgMux command
surface. These do not execute Android/Linux processes; they send commands into
`app-dmesh` and return JSON frames:

```sh
ssh -F /dev/null \
  -i target/android-ssh/id_ed25519 \
  -p 11522 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  dmesh@127.0.0.1 \
  'permission.status'

printf '%s\n' 'permission.status' 'wifi.scan reason=manual-shell' exit |
ssh -F /dev/null -T \
  -i target/android-ssh/id_ed25519 \
  -p 11522 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  dmesh@127.0.0.1
```

Use `exit` or `quit` to close the line shell from scripts.

Expected output includes an acknowledgement line:

```json
{"id":"manual-1","ok":true,"method":"wifi.scan"}
```

The SSH direct stream remains open for additional commands until the client
closes it, so `timeout` may end the command after the acknowledgement has
already been printed. Asynchronous event streaming back to the SSH client is not
currently wired.

Human command form is also accepted when the line does not start with `{`:

```sh
printf '%s\n' 'wifi scan --id manual-2 --reason manual-ssh' |
timeout 12 ssh \
  -i target/ssh-jsonl-smoke/id_ecdsa \
  -o CertificateFile=target/ssh-jsonl-smoke/id_ecdsa-cert.pub \
  -p 11522 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ControlMaster=no \
  -o ControlPath=none \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  dmesh@127.0.0.1 \
  -W dmesh-msg:1
```

Supported human forms include:

```sh
wifi.scan reason=manual
wifi.scan --reason manual
wifi.scan --reason=manual
wifi.scan --id manual-3 --reason "manual ssh"
```

The smoke test also validates cross-app direct Binder routing to `app-chat`:

```sh
app.chat.send --id chat-1 --text hello
```

Expected output includes `app.forwarded` from app-dmesh and `chat.message`
from app-chat.

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
  --method command --arg 'wifi.nan.start reason=manual-debug'"

sleep 6

adb shell "content call --uri content://com.github.costinm.dmesh.lm.shell \
  --method command --arg 'history durationMs=1500 limit=80 keys=net,wifi,BLE'"
```

Expected message patterns:

- WiFi scan: `net.status` with `event=scan` and `visible=N`.
- BLE scan: `BLE.scan`, DMesh `wifi.BLE.DISC`, external `BLE.DISC`, or `BLE.ERR.*`.
  `BLE.DISC proto=meshtastic` means the Meshtastic GATT service UUID was
  advertised; `BLE.DISC proto=nordic_uart compatible=meshcore` means Nordic
  UART Service was advertised, which is the MeshCore-compatible path.
- NAN: `net.NAN.Attach`, then `net.NAN.PubStart` and `net.NAN.SubStart` before any `net.NAN.*ServiceDiscovered` messages. If the history shows `net.NAN.AttachError`, NAN did not reach publish/subscribe.

Check Android runtime permissions granted to `app-dmesh`:

```sh
adb shell dumpsys package com.github.costinm.dmesh.lm
```

The relevant runtime permissions are `ACCESS_FINE_LOCATION`,
`ACCESS_BACKGROUND_LOCATION`, `NEARBY_WIFI_DEVICES`, `BLUETOOTH_SCAN`, and
`BLUETOOTH_CONNECT`, and `BLUETOOTH_ADVERTISE`.

For NAN attach failures, collect the framework WiFi Aware logs:

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

In adb mode, grant the required permissions:

```
adb shell pm grant com.github.costinm.dmesh.lm android.permission.NEARBY_WIFI_DEVICES

```