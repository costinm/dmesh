# dmesh-object-store

The active transfer path is the bounded `protocol` module carried by lmesh
NAN data frames. It has no TCP/IP, UDP, filesystem, or allocator dependency and
keys sessions by source Wi-Fi MAC plus the dmesh-transport DCID. The same
envelope can be used in NAN action frames for diagnostics. ESP Main links this
core directly; its platform flash sink is separate.

The old host `std` server is retained for explicit comparison only. It is
disabled by default in lmesh; enable it with `LMESH_OBJECT_SERVER_TCP=1` (and
optionally `LMESH_OBJECT_STORE_ROOT`) when measuring the legacy path on port
3337.

Each legacy-server artifact gets a sibling `<artifact>.manifest.json`. The
server checks the source mtime and size recorded in that sidecar and streams
the file in 4 KiB blocks.

The host command `object.nan.dry_run` sizes a NAN transfer and reports packet
and byte overhead without opening a socket or touching a device.

## UDP diagnostics

The standalone DRS2 UDP server runs on port `3336`:

```sh
./scripts/object-store-udp.sh
```

It accepts a fresh HELLO from a peer even when that peer reuses an old UDP
source port, replacing the abandoned session. This is required after a Main
reset or a failed dry-run.

For benchmark tuning, `DMESH_UDP_MTU`, `DMESH_UDP_SEND_DELAY_MS`,
`DMESH_UDP_HELLO_DUPLICATE_DELAY_MS`, and `DMESH_UDP_WINDOW_PACKETS` control
packet size, pacing, HELLO duplicate delay, and the bounded number of ordered
stream packets in flight. `DMESH_UDP_WINDOW_PACKETS=1` preserves stop-and-wait.
`DMESH_UDP_RETRANSMIT_MS` controls the bounded data retransmission timer
(100 ms by default); retransmissions are only sent for packets whose exact
ACK has not arrived.

For a transport-only bidirectional test, run the fixed-port status responder
on `3338`:

```sh
./scripts/object-store-udp-status.sh
python3 scripts/udp-status-probe.py 10.78.0.200
```

Main exposes the matching diagnostic methods:

```text
wifi udp_status_server=true port=3338
wifi udp_status_probe=true server=10.78.0.1 port=3338 timeout_ms=3000
wifi udp_status_server_status
wifi udp_status_probe_status
```

The `DMSU` record is deliberately fixed-size: a 14-byte request carries a
nonce, and the 26-byte response echoes it with server uptime and IPv4 bytes.
The status exchange is separate from DRS2 so socket direction, ARP, and reply
delivery can be diagnosed without involving manifests or flash scheduling.

The full localhost object benchmark uses an in-repo client in the test module;
there is no separate client implementation:

```sh
source ./env.sh
./scripts/build.sh object-store-loopback
DMESH_LOOPBACK_ACK_DELAY_MS=1 ./scripts/build.sh object-store-loopback
```

`DMESH_LOOPBACK_WINDOW` selects the sender packet window and
`DMESH_LOOPBACK_ACK_DELAY_MS` injects deterministic delay before client ACKs.
`DMESH_LOOPBACK_SELECTIVE_ACK_PACKETS=N` sends a shared QUIC ACK-range frame
after each of the first `N` packets. The sender and receiver use the same
`dmesh-transport` endpoint state as the UDP implementation, including stream
and connection credit, ACK ranges, retransmission bookkeeping, and NewReno
congestion control.
`DMESH_LOOPBACK_DROP_ACK_PACKET=N` drops one exact ACK to exercise the host
sender's gap retransmission path; the benchmark asserts that a duplicate was
observed before completion.
`DMESH_LOOPBACK_IMAGE_BYTES=N` changes the benchmark payload size, which is
useful for crossing connection-credit windows without changing the protocol.

Main's corresponding client command is `wifi udp_flash=true server=...
port=3337 target=module`; it uses the same receiver and sink as the dry run,
but writes only after the module task has been quiesced. The legacy C TCP
worker is not part of this path.

For transport-only comparison, without object files or DRS2 framing:

```sh
source ./env.sh
./scripts/build.sh transport-compare
DMESH_STREAM_BYTES=134217728 ./scripts/build.sh transport-compare
```

The comparison uses identical synthetic bytes and 1168-byte application
chunks. The dmesh result is bearer-free in-memory packet simulation; the TCP
result uses a real localhost `TcpListener`. Neither path uses files, manifests,
DRS2, or object-store code. The separate object-store TCP baseline remains
available when file-backed protocol cost is desired:

```sh
./scripts/build.sh object-store-tcp-loopback
```

For the apples-to-apples real-socket comparison, use the two-process UDP
benchmark:

```sh
DMESH_STREAM_BYTES=67108864 ./scripts/build.sh transport-udp-compare
```

It starts separate UDP server and client processes, transfers the same
synthetic stream and 1168-byte chunks, and drops one ACK by default to exercise
retransmission. This is the real-socket benchmark for the bearer-neutral dmesh
transport; `transport-compare` remains useful for the in-process baseline.

To run all three socket baselines with the same synthetic stream:

```sh
DMESH_STREAM_BYTES=134217728 ./scripts/build.sh transport-socket-compare
```

This runs UDP, Unix-domain datagrams, and raw localhost TCP in sequence. Set
`DMESH_UDP_BENCH_DROP_PACKET=` to disable the deliberate UDP/Unix ACK loss.
