# lmesh Wi-Fi API

`lmesh` is the Linux mesh daemon and owns the selected Wi-Fi interface, raw-NAN
monitor, BLE adapter and local control socket. It does not serve HTTP itself.
Its radio implementation currently lives in the internal `lmesh-wifi` library;
the public Wi-Fi request reference is [root API](../../API.md); adapter details
are in [the radio README](../lmesh-wifi/README.md).

## Endpoints

- **Control: Unix domain socket** `/run/mesh/lmesh/mesh.sock.cbor`. Local
  interaction (the `mesh lmesh <method>` client, `dmesh-cli`, tests) uses this
  socket. It is mode 0660 owned by the service user.
- **UDP 3339**: the DMesh QUIC-lite port shared with ESP32 and Android.
- **HTTP: not served by lmesh.** HTTP, auth and certificates belong to
  ssh-mesh. The intended design is an ssh-mesh HTTP forwarder configured to
  forward to the lmesh UDS; it is not configured yet (planned, low priority,
  see `notes/ai/2026-11-08-lmesh-wifi-validation-gaps.md`). The former 18981
  port is not listened on. On Android the HTTP and SSH servers run in-process
  in dmesh-android.

## Wi-Fi model

`transport.set` carries a declarative intent: which transports should be
enabled. There are no wifi-specific scan, P2P or arbitrary-AP methods.

- AP is on or off. The AP uses the well-known mesh SSID and PSK and is started
  through `wpa_supplicant` (Android clients require WPA). A request cannot
  choose a name or configuration.
- Station mode may name a desired SSID. The PSK is not a request field: it is
  the well-known mesh PSK or comes from a credentials file.
- Scan results and peers (Wi-Fi, BLE, serial, NAN) are meant to appear through
  the common, transport-independent `discovery.*` methods.

Some of this is the target rather than the current state; the gaps are listed
in the note above. The supervised service template is
[lmesh.toml](mesh-init/lmesh.toml). Select the host interface there.
