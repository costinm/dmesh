
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
character is `{`, otherwise it treats the line as a human command. Java only
receives the parsed URI and string key/value pairs through JNI.

Manual JSONL test:

```sh
printf '%s\n' \
  '{"id":"manual-1","uri":"/wifi/scan","data":{"reason":"manual-ssh-jsonl"}}' |
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

Expected output includes an acknowledgement line:

```json
{"id":"manual-1","ok":true,"uri":"\/wifi\/scan"}
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
wifi scan reason=manual
wifi scan --reason manual
wifi scan --reason=manual
/wifi/scan --id manual-3 --reason "manual ssh"
```

The smoke test also validates cross-app direct Binder routing to `app-chat`:

```sh
/app/com.github.costinm.dmesh.chat/.ChatService/chat/send --id chat-1 --text hello
```

Expected output includes `/app/forwarded` from app-dmesh and `/chat/message`
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
  --method command --arg 'msg /wifi/scan'"
```

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
