# Rust Recovery

Rust Recovery is the standalone Recovery application for classic ESP32 and
ESP32-C6. Stage2 selects it for a one-shot Main update or explicit command
mode. The retired C Recovery is not a fallback.

Recovery currently owns:

- compact CBOR command/log records over PPP-like UART framing;
- persisted STA identity/network defaults plus temporary per-command benchmark
  settings;
- IPv4 object transfer and IPv6 link-local diagnostics;
- the ESP datagram adapter for `quic-lite`;
- ordered object-stream consumption through
  `dmesh-server::ImageReceiver`;
- manifest/signature policy, per-block integrity checks, bounded flash
  buffering, Main partition erase/write, commit, and Stage2 handoff.

`wifi.rs` is a bearer adapter and scheduler. `udp_flash.rs` consumes ordered
stream bytes and owns flash semantics; it must not contain ACK or
retransmission logic. `uart.rs` currently shares command records with the
temporary UDP control endpoint, but UART is not yet a full `quic-lite`
bearer. That migration is tracked in
[`docs/plans/main-recovery-transport-reuse.md`](../../docs/plans/main-recovery-transport-reuse.md).

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
