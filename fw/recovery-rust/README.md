# Rust Recovery

Rust Recovery is the standalone Recovery application for classic ESP32 and
ESP32-C6. Stage2 selects it for a one-shot Main update or explicit command
mode. The retired C Recovery is not a fallback.

Recovery currently owns:

- compact CBOR command/log records over PPP-like UART framing;
- persisted STA identity/network defaults and raw-bearer association settings;
- bearer-neutral signed-object transfer over authenticated UART, raw IPv6, or
  action-frame paths;
- the ESP datagram adapter for `quic-lite`;
- ordered object-stream consumption through `dmesh-server::SignedObjectReceiver`;
- manifest/signature policy, per-block integrity checks, bounded flash
  buffering, Main partition erase/write, commit, and Stage2 handoff.

The ESP bearer adapter supplies packet I/O only. `dmesh-server` owns service
framing and signed-object verification; `dmesh-fw-transport` owns durable
partition/Stage2 writes. ACK and retransmission remain QUIC-lite concerns.

Build an explicit CPU family:

```sh
scripts/build-recovery-rust.sh --help
scripts/build-recovery-rust.sh esp32
scripts/build-recovery-rust.sh esp32c6
```

The no-argument default is classic ESP32. Artifacts are CPU-specific under
`target/recovery-rust/flash/<family>/`; the build script never flashes a
board.

All provisioning and updates use the common tool:

```sh
scripts/flash-device.py e7 recovery
scripts/flash-device.py e7 main
scripts/flash-device.py e7 nvs --boot-target recovery
```

`flash-device.py` is the only supported flashing interface. It currently uses
esptool for all targets; do not invoke esptool directly. Production Recovery
will instead be served by `lmesh-wifi`, with UDP server ports selected per
session. Successful completion requires durable image completion, reboot, and
a fresh direct Main status; command acknowledgement alone is insufficient.

The paused Wi-Fi measurements, transport counters, and exact restart commands
are in
[`docs/lab/recovery-wifi-transport-baseline.md`](../../docs/lab/recovery-wifi-transport-baseline.md).
