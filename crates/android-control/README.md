# Android control plane

This crate runs as a standalone linux app or as a JNI library in an Android app, providing device control 
over one or more android devices using ADB protocol in developer mode.

It is using the adb-client crate, with extensions to support the new pairing.

Once an Android device is paired - the control plane can set permissions and install mesh packages and
administer - just like a ssh session would do on Linux. It is not meant to be used for forwarding
ports or as a 'shell' - the ssh-mesh provides HTTP/2 and SSH forwarding and shell with lower 
permissions, running as an app. The 'developer shell' provided by this crate is the closest thing
to root ( and does allow root on userdebug devices ).

It can be used to self-manage an android device, but the intended use is to automate a fleet 
of devices, from a small linux host or a 'trusted' android device.

## Scriptable wireless ADB pairing (Android 11+)

Wireless pairing can be driven entirely from a USB-attached `adb`, without
touching the device UI. The framework pairing server is started with the
`IAdbManager` binder call `enablePairingByPairingCode` (transaction id **8**),
and the 6-digit code plus the ephemeral port are read back from `logcat`.

```sh
ADB=<path to adb>; S=<serial>

# 1. start a fresh pairing (single call - see caveat below)
$ADB -s $S shell 'service call adb 8'

# 2. read code + port from logcat
$ADB -s $S logcat -d | grep -E 'updateUIPairCode|Pairing server started'
#   I/AdbDebuggingManager: updateUIPairCode: 468970       <- code
#   I/system_server:      Pairing server started on port 44341  <- port

# 3. Wi-Fi IPv4 of the device
ip=$($ADB -s $S shell 'ip -4 addr show wlan0' | grep -oE 'inet [0-9.]+' | awk '{print $2}')

# 4. pair with the CLI (SPAKE2-25519 over TLS 1.3, stores the device guid)
android-control-cli pair "$ip" -p 44341 -c 468970
```

### Pairing a whole fleet

`scripts/pair_usb_devices.sh` lists every USB-connected device and repeats the
above for each, storing every result in the key dir (`~/.android` by default,
override with `DMESH_ADB_KEY_DIR`). It also best-effort enables the persistent
connect service and verifies a TLS shell over it.

```sh
./scripts/pair_usb_devices.sh                # all USB devices
./scripts/pair_usb_devices.sh <serial>...    # specific serials
```

### Connecting after pairing

The pairing port is ephemeral. The persistent `_adb-tls-connect` endpoint is
started by `allowWirelessDebugging` (txn **4**, needs the current BSSID):

```sh
bssid=$($ADB -s $S shell 'dumpsys wifi' | grep -oE '[0-9A-F:]{17}' | head -1)
$ADB -s $S shell "service call adb 4 i32 1 s16 '$bssid'"
android-control-cli connect --port <connect-port> "$ip"
```

`<connect-port>` is normally discovered via mDNS (`_adb-tls-connect._tcp`).
`android-control-cli mdns` browses **all** advertising devices (pairing *and*
connect by default, `--kind pairing|connect|all`) and does not stop at the first
responder; `--json` emits a machine-readable array for fleet scripting:

```sh
android-control-cli mdns --timeout-secs 8 --json
# [{"name":"adb-RFCNB05AJ7E-J75hGU._adb-tls-connect._tcp.local.",
#   "host":"192.168.3.118","port":44241,"addr":"192.168.3.118:44241", ...}, ...]
```

If mDNS is unavailable on the LAN, read the device's LISTEN sockets
(`/proc/net/tcp6`) for the new all-interface port instead.

### Root fallback for code-hidden builds (Android 14+/15)

On builds that hide the code, `pair` is impossible from a script, but a
**userdebug/rootable** device can be made to trust the host key directly,
skipping SPAKE2. This is the path `scripts/pair_usb_devices.sh` takes when the
code is not readable:

1. `adb root` (works only on userdebug/user builds; production returns
   "adbd cannot run as root").
2. Ensure `~/.android/adbkey.pub` is in `/data/misc/adb/adb_keys`. On userdebug
   this is usually already present (USB auto-authorization adds the host key);
   the script appends it if missing.
3. Enable the persistent connect service (`allowWirelessDebugging`, txn 4) with
   the current BSSID.
4. Find adbd's listener port (mDNS `_adb-tls-connect`, else `netstat -tlnp`).
5. `android-control-cli connect --port <port> <ip>` — adbd accepts the TLS
   client cert because its key is authorized, no pairing code required.

Verified on a LineageOS Android 15 Pixel 3a: `connect` + `shell` succeed over
`<ip>:40969`. The device is functionally reachable; it is not recorded with a
SPAKE2 GUID in the local store (there was no `pair`), so track it by IP/port.

### Caveats

- **Newer Android hides the code.** Android 14+ no longer writes the 6-digit
  pairing code to `logcat` (privacy). The server still starts (the port is
  logged), but the code is only delivered via a permission-protected broadcast.
  Without root (or a small receiver app) the code is not script-readable on
  those builds; stock Android 11-13 log it. See the root fallback above.
- **Do not re-trigger while a pairing is pending.** A second `service call adb 8`
  before the first completes can destroy the native pairing waiter's mutex and
  crash `system_server` (`native_pairing_wait` -> `HandleUsingDestroyedMutex`).
  Issue one clean trigger per pairing; cancel (`disablePairing`, txn 11) or let
  it finish before re-arming.
- **mDNS is the intended discovery but is environment-dependent.** This host
  uses the `mdns-sd` crate (UDP multicast to `224.0.0.251:5353`). On some
  networks only some responders are seen, so the connect port may have to be
  read from `/proc/net/tcp6` as a fallback.