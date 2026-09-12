# Rust Recovery

Rust Recovery is a deliberately narrow, supported Wi-Fi update lane alongside
Main. Its current canaries are lora2 (classic ESP32) and one RISC-V board.
Stage2 selects its separate Recovery partition; it associates to the
provisioned STA and accepts authenticated QUIC-lite object updates that write
Main. It is not a general radio runtime: NAN, NOW, AP, modules, and generic
application handlers remain Main-only.

Recovery owns:

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

Build the explicit CPU family with the checked-in script, for example
`scripts/build-recovery-rust.sh esp32c6`. Use `scripts/build-fw.sh` for
ordinary Main images.

`flash-device.py` is the only supported provisioning interface; do not invoke
esptool directly. Provision the protected STA profile from the host-owned
input rather than exposing credentials in commands or logs. A successful
Wi-Fi Main update requires association, scoped UDP6 reachability, manifest and
block delivery, digest verification, durable commit, reboot, and fresh Main
health; command acknowledgement alone is insufficient.

The paused Wi-Fi measurements, transport counters, and exact restart commands
are in
[`docs/lab/recovery-wifi-transport-baseline.md`](../../docs/lab/recovery-wifi-transport-baseline.md).
