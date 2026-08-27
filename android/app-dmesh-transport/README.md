# Transport helper app

This is a standalone app providing Wifi NAN, P2P, STA and BLE transport integration for app-dmesh. 

It is useful for testing the transports standalone - and may be used by app-dmesh
instead of directly integrating the transports as a library, keeping it as an internet-only app by default.

The UI is primarily focused on handling permissions, show status and allow
manual transport activation.

Install and open it once so its foreground service keeps the public callback
sequence alive:

```sh
adb install -r target/apk/debug/app-dmesh-transport-debug.apk
adb shell am start -n com.github.costinm.dmesh.transport/.ReproActivity
```

The provider accepts the same controller primitives used by DMesh. Payloads are
bounded opaque bytes represented as lower-case hexadecimal; `options` is a
comma-separated list reserved for publish/subscribe and P2P tuning.

```sh
# Configure Service Info and an active NAN discovery request.
adb shell content call --uri content://com.github.costinm.dmesh.transport.control \
  --method announce.set --extra payload_hex:s:a101a202636e616e --extra options:s:active
adb shell content call --uri content://com.github.costinm.dmesh.transport.control \
  --method discover.set --extra payload_hex:s:a101 --extra options:s:active

# Same typed transport.start projection as the Rust adapter: NAN baseline,
# then P2P GO, then return to NAN. The result includes final state and whether
# the original reply transport survived or the previous state was restored.
adb shell content call --uri content://com.github.costinm.dmesh.transport.control \
  --method transport.start --extra mode:s:nan --extra id:s:qualify-nan --extra generation:l:1
adb shell content call --uri content://com.github.costinm.dmesh.transport.control \
  --method transport.start --extra mode:s:nan --extra ap:i:1 --extra id:s:qualify-p2p --extra generation:l:2
adb shell content call --uri content://com.github.costinm.dmesh.transport.control \
  --method transport.start --extra mode:s:nan --extra id:s:qualify-nan-return --extra generation:l:3

adb shell content call --uri content://com.github.costinm.dmesh.transport.control --method status
```

Run the complete real-radio regression gate with an ephemeral AP. It verifies
NAN -> P2P GO -> NAN -> app-scoped STA -> NAN and finally repeats NAN to prove
the idempotent `UNCHANGED` result. A failed STA association is still required
to restore NAN, but makes this qualification fail with the framework result.

```sh
adb shell content call --uri content://com.github.costinm.dmesh.transport.control \
  --method qualify.transition \
  --extra ssid:s:YOUR_AP_SSID --extra passphrase:s:YOUR_WPA2_PASSWORD \
  --extra bssid_hex:s:001122334455 --extra channel:i:6

# The same gate is available as an instrumentation regression test.
adb shell am instrument -w \
  -e sta_ssid YOUR_AP_SSID -e sta_passphrase YOUR_WPA2_PASSWORD \
  -e sta_bssid_hex 001122334455 \
  com.github.costinm.dmesh.transport.test/androidx.test.runner.AndroidJUnitRunner
```

`p2p.start`, `p2p.start_advertised`, `p2p.stop`, `nan.start`, `nan.stop`,
`lohs.start`, and `lohs.stop` remain available as low-level qualification
primitives. They are intentionally all delegated to `dmesh-wifi`.

The same shell is available in-app as a terminal:

```sh
adb shell am start -n com.github.costinm.dmesh.transport/.TermActivity
```

Lines are parsed into a method plus `key=value` string extras and passed to
`ContentResolver.call` unchanged; the result bundle is appended to the
bounded output. `/use <authority>` selects a different provider shell.
Extras are string/string; numeric keys are parsed provider-side, so typed
ADB extras (`--extra ap:i:1`) and terminal strings (`ap=1`) are equivalent.
