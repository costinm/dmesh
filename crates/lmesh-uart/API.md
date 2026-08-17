# lmesh-uart service API

`lmesh-uart` builds the host UART L2 service and library. Legacy byte forwards
are disabled for every board. The service is being converted to a QUIC-lite
UART proxy: PPP/HDLC carries bearer packets, while commands, logs, and object
transfer are `dmesh-server` services on QUIC-lite streams. The low-level
PPP/HDLC codec is documented in [`uart-codec/API.md`](../uart-codec/API.md)
and is also used by the ESP32 firmware.

The service owns the host UART backend directly and does not depend on the
Wi-Fi service crate. Firmware framing is shared through `uart-codec`.
It does not own a Wi-Fi interface or start AP/NAN itself.

Configured forwards are loaded in this order:

1. `LMESH_UART_CONFIG_FILE`, when set;
2. `$HOME/etc/lmesh-uart/lmesh.toml`, when it exists;
3. `LMESH_CONFIG_FILE`, then the legacy `/home/system/etc/lmesh/lmesh.toml`.

The default service home is `/home/lmesh-uart`; deployments and local tests
set `HOME` to an independent `target/...` home. The binary can run directly;
mesh-init is only needed when supervision and socket setup are desired. UART access still requires filesystem access to
the selected `/dev/serial/by-id` devices and membership in the relevant device
groups.

For an absolute control socket such as /run/mesh/lmesh-uart/mesh.sock, the
parent runtime directory must already be created and owned by the service
user. mesh-init does this as root; a direct unprivileged launch should use a
target-local socket path or pre-create the runtime directory.

## Endpoint and protocol

The default mesh-init endpoint is:

```text
/run/mesh/lmesh-uart/mesh.sock
```

Set `LMESH_CONTROL_SOCKET` to use another path during development. The
endpoint accepts one JSON object per line and returns one JSON object per line.
Every response has either `{"success":true,"data":...}` or
`{"success":false,"error":"..."}`.

The configured board inventory is retained for explicit provisioning and the
proxy migration, but every legacy `serial_forwards` entry is `enabled = false`.
`forward.list` must remain empty. The replacement client surface starts with a
reusable QUIC-lite IPERF session library (also used by `dmesh-iperf`): it
opens a direct serial L2 together with its IP backend and never revives
byte-forward sockets. Generic command dispatch, IP-only targets, and
long-lived `log watch` streams are the next additions to that same client API;
they are not implemented by the current IPERF wrapper.

`lmesh-wifi` will use this same session/client API as its fleet egress-gateway
handler. ESP-NOW, STA/UDP, and future LoRa/FSK are path choices owned by the
connection runtime, not distinct command or IPERF protocols.

Per-forward sockets use `/run/mesh/lmesh-uart` by default, so the service does
not collide with the main `lmesh` service's per-device sockets. The
`LMESH_SERIAL_SOCKET_DIR` override is available for isolated local tests.

UART capture is per device and is written to HOME/logs/<device>.log. Each file
is rotated to <device>.log.1 at 16 MiB. A forward with log = false has no
capture file.

## Methods

| Method | Purpose | Common arguments |
| --- | --- | --- |
| `status` | Service and UART status | — |
| `usb.serial.list` | List discovered USB serial adapters | `handshake` |
| `usb.serial.handshake` | Probe an adapter and identify its profile | `port`, `profile`, `baud`, `timeout_sec` |
| `usb.serial.boot` | Send a boot/reset command through an adapter | `port`, `command`, `reset`, `timeout_sec` |
| `usb.serial.rst` | Pulse the adapter reset/modem line | `port` |
| `usb.serial.reset` | Alias for `usb.serial.rst` | `port` |
| `usb.serial.dtr` | Set or pulse DTR | `port`, `asserted`, `pulse_ms` |
| `esp.serial.command` | Send a framed command to an ESP32 | `adapter`, `port`, `command`, `timeout_sec`, `force_direct` |

Boolean arguments are JSON booleans, ports are adapter paths, and timeouts are
in seconds unless the argument name ends in `_ms`. The service keeps the
framing and transport details below this JSONL boundary; callers should use
these methods rather than constructing PPP frames themselves.

## Ownership and lifecycle

The reusable JSON dispatcher is exported from the crate library for the main
`lmesh` service. `mesh-init` starts and supervises this service. It should provide a separate
service home and environment from the main `lmesh` process. The service does
not create its socket parent directory; service setup is responsible for
creating the configured runtime directory with suitable ownership.
