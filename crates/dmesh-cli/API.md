# UART device-session API

`dmesh-cli` owns direct serial sessions. Do not deploy or start a UART
forwarding service or control socket. Legacy byte forwards are retired.
PPP/HDLC carries
QUIC-lite bearer packets, while
commands, logs, and object transfer are `dmesh-server` stream services. The low-level
PPP/HDLC codec is documented in [`uart-codec/API.md`](../uart-codec/API.md)
and is also used by the ESP32 firmware.

The client owns an explicitly selected device interface; it is not a UART
custom-protocol daemon and does not own Wi-Fi/AP/NAN. Firmware framing is
shared through `uart-codec`. Direct boot/platform text and compact CBOR are
rendered through the same schema used by diagnostics.

## Device inventory

The shared inventory root is `/home/lmesh/etc/lmesh/devices`. Each device has
one directory and a `device.toml` file, for example
[`examples/devices/e6/device.toml`](examples/devices/e6/device.toml). The
library accepts an explicit `/dev/...` serial path, `udp://IP:PORT` / IP
literal, or a directory name such as `e6`. `LMESH_DEVICE_DIR` overrides the
root for tests and isolated deployments.

`static_ipv4`, `ipv6_link_local`, `serial_id`, and `auth_secret_ref` are
inventory fields. The secret field is a reference only: authentication and
encryption are a future end-to-end layer across every untrusted bearer.
Current UDP sessions prefer `static_ipv4`; a serial-only profile resolves to
its `/dev/serial/by-id/<serial_id>` path. IPv6 link-local is recorded now but
needs a caller-selected interface scope before it becomes a UDP path.

The `dmesh-cli` binary is a foreground shell, not a managed UART protocol
daemon. It takes the session target directly and has no default control socket
or forwarding configuration. UART access still requires filesystem access to
the selected `/dev/serial/by-id` device and membership in the relevant device
groups.

## Session socket

The replacement client surface is a reusable QUIC-lite device session (also
used by `dmesh-cli`). It opens a direct serial L2 together with its IP
backend when explicitly requested, or a direct UDP session for an IP/device
profile. It never revives byte-forward sockets. Direct records are rendered as
text or schema-labelled compact CBOR. `--command TEXT` encodes the explicitly
selected direct-CBOR diagnostic/boot record; normal operations remain service
streams. `log-watch` currently performs the bounded server poll; framed
long-lived log delivery is pending its server handler.

`--command` and `--direct-hex` are explicitly serial operations. When their
target is an inventory name with both UDP and serial addresses, `dmesh-cli`
selects `serial_id`; it never silently changes a direct diagnostic into a UDP
request. Use service-stream options for an intentional UDP operation.

`dmesh-cli <serial-or-device> --watch` is a passive UART diagnostic for
raw boot/platform text and direct-CBOR exception records. It labels marked
QUIC-lite frames as transport observations and does not attempt to render
them as logs. Firmware-generated logs use the `log-watch` service stream.

`dmesh-cli <device-or-ip> --services` opens the registered `handlers`
stream and prints the stable service list. Its response schema is CBOR
`[[tag, name], ...]`; names are discovery/debug metadata only and never
dispatch a command. Each handler owns the compact payload fields after its
numeric tag. The CLI continues to use its local firmware schema for direct
CBOR records and handler-specific CBOR responses.

`dmesh-cli udp://IP:PORT --socket PATH` owns one UDP QUIC-lite connection
and creates a mode-0600 JSONL Unix socket. Each line such as
`{"service":"status"}`, `{"service":"services"}`, or
`{"service":"log-watch","body_hex":"04"}`
opens the next stream on that owned connection and receives one JSON result.
It is intentionally a session socket, not TCP/serial byte forwarding.

`dmesh-cli` is the authoritative host test and shell tool. It owns direct
UART L2 sessions, UDP sessions, handler discovery, bounded `log-watch` polls,
and the optional local session socket used to expose a selected device
connection to other tools. For UART/multipath IPERF it starts the matching
temporary UDP server itself; a standalone UDP-server subcommand is a planned
extension. It does not depend on `lmesh-wifi`; that service is reserved for
raw ESP-NOW/action-frame validation because it owns the required WLAN
capabilities.

## Reproducible transport tests

Integration tests import the same `dmesh_cli::client` library entry points
rather than shelling out to `dmesh-cli`. Infra devices with recorded STA
addresses are the normal test targets: a host test can issue a QUIC-lite
IPERF handler request to one device, or request that one device's IPERF client
target another device. This exercises handler dispatch and device-to-device
paths without opening UART.

Use UART only for explicit bearer coverage: direct serial ownership at test
startup, PPP framing/MTU, queue saturation, and UART/STA spill/failover. The
CLI remains useful for ad-hoc diagnosis because it calls the same library; it
is not the test framework or a separate protocol implementation.

The optional `--socket PATH` is created only by an explicitly requested device
session. It exposes service streams on that one connection and is removed only
when the session owner exits; there are no per-forward sockets or TCP ports.

There is no UDS service adapter for UART control. Provisioning uses
[`scripts/flash-device.py`](../../scripts/flash-device.py), while direct
commands, logs, and service streams use the selected `dmesh-cli` session.
