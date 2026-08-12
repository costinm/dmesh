# lmesh API

`lmesh` is the full mesh service. It combines discovery, object store, Wi-Fi,
and the remaining mesh adapters; the standalone services exist for independent
ownership and restart cycles during development. It links the UART dispatcher
for API compatibility but does not own or start UART forwards.

Detailed capabilities and method surfaces live in the component APIs:

- [`lmesh-wifi/API.md`](../lmesh-wifi/API.md) — Wi-Fi interface ownership, AP,
  STA, NAN, and wake/control operations.
- [`uart-codec/API.md`](../uart-codec/API.md) — shared no-std ESP32/host UART
  framing.
- [`lmesh-uart/API.md`](../lmesh-uart/API.md) — UART forwarding, ESP32 serial
  operations, logging, and the reusable command dispatcher.

Generic text, JSON, JSON-RPC, JSONL, CBOR, and schema loading belong to
[`ssh-mesh/crates/mesh`](../../../rust/ssh-mesh/crates/mesh/README.md).

During experiments, the service owns `wlan1` and starts raw-NAN monitoring on
that interface. The stable `lmesh-wifi` service owns `wlan0` and its open AP.
Use `mesh lmesh-wifi wifi.rawnan.*` for AP-side raw-NAN tests; do not use the
legacy `mesh lmesh wifi.nan.*` WPA control path for this setup.

## ESP32 QUIC-shaped transport test

The socket API already exposes a restart-free test loop for the DMTB
QUIC-shaped stream envelope. `wifi.raw.bench_send` sends a bounded stream from
the host; the firmware `wifi bench_stream_send=true` command sends the reverse
direction, and `wifi bench_stats=true` reports accepted frames, byte offsets,
sequence numbers, decode errors, and length errors. These are transport tests,
not a claim of end-to-end reliability: selective ACK/flow-control behavior is
still measured separately from raw frame delivery.

```sh
source ./env.sh

# Host -> ESP32. The command returns framing and wire-rate measurements.
mesh lmesh wifi.raw.bench_send iface=wlan1 destination=50:6f:9a:01:54:e6 \
  bssid=50:6f:9a:01:54:6c bytes=1048576 chunk_bytes=512 \
  tx_variant=monitor_active

# Clear the device receiver counters, then request the reverse stream.
mesh lmesh-uart esp.serial.command port=e6 \
  command='wifi bench_stats=true reset=true' timeout_sec=12
mesh lmesh-uart esp.serial.command port=e6 \
  command='wifi bench_stream_send=true dst=aa:bb:cc:dd:ee:ff bytes=1048576 delay_us=0' \
  timeout_sec=30
mesh lmesh-uart esp.serial.command port=e6 \
  command='wifi bench_stats=true' timeout_sec=12

# Size the same stream without opening a socket or touching the device.
mesh lmesh object.nan.dry_run image_size=1048576 mtu=1200
```

Run `wifi.raw.listen` (or a persistent `subscribe` on
`dmesh.event.wifi.rawnan.rx`) on a separate socket when frame-level evidence is
needed. The listener and benchmark commands are independent, so changing
payload size, chunk size, destination, BSSID, or pacing does not require a
`lmesh` restart. The firmware receiver is currently a bounded accounting
server: it recognizes DMTB stream frames and updates `bench_stats`; a future
HELLO extension can request an echo or parameterized reverse stream over the
same connection instead of using the UART control command.

The envelope and QUIC-shaped framing are shared by `dmesh-transport`:
`BENCH_MAGIC`, the fixed benchmark CID/stream ID, and the bounded
`encode_bench_stream`/`decode_bench_stream` helpers are used by both the Linux
sender and ESP32 receiver/sender. Bearer framing (NAN action/data headers,
monitor injection, MAC/BSSID selection) remains in the radio adapters.
