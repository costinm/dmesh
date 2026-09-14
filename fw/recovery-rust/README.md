# Rust Recovery

Rust Recovery is a deliberately narrow, supported Wi-Fi update lane alongside
Main. Its current canaries are lora2 (classic ESP32) and one RISC-V board.
Stage2 selects its separate Recovery partition; it associates to the
provisioned STA and accepts authenticated QUIC-lite object updates that write
Main. It is not a general radio runtime: NAN, NOW, AP, modules, and generic
application handlers remain Main-only.

Recovery owns:

- console-only boot, transition, error, and completion logging;
- persisted STA identity/network defaults;
- bearer-neutral signed-object transfer over associated-STA raw UDP6;
- the same raw IPv6/UDP frame adapter and QUIC-lite dispatcher used by Main;
- ordered object-stream consumption through `dmesh-server::SignedObjectReceiver`;
- manifest/signature policy, per-block integrity checks, bounded flash
  buffering, Main partition erase/write, commit, and Stage2 handoff.

ESP-IDF owns STA association, but Recovery does not install a separate lwIP
socket transport. The raw bearer adapter supplies complete-datagram packet I/O
only. `dmesh-server` owns service
framing and signed-object verification; `dmesh-fw-transport` owns durable
partition/Stage2 writes. ACK and retransmission remain QUIC-lite concerns.

Build the explicit CPU family with the checked-in script, for example
`scripts/build-recovery-rust.sh esp32c6`. Use `scripts/build-fw.sh` for
ordinary Main images.

## Controlled receive-window stress

Recovery's normal association profile is selected from live internal-memory
headroom. For a controlled host test, `dmesh-cli` may request a larger peer
receive profile in its OPEN by setting both
`DMESH_QUIC_REQUEST_PEER_MAX_DATA` and
`DMESH_QUIC_REQUEST_PEER_MAX_STREAM_DATA`. The device clamps that request to
its compiled 64-packet ceiling and reports the accepted values in OPEN_ACK;
the request is neither a flash setting nor persisted device state.

With the current 1200-byte transport MTU, a 32-packet test uses `38400` and
`19200` bytes respectively, while a 64-packet test uses `76800` and `38400`.
Use this only for a dry-run or controlled canary before an actual update. The
host test suite exercises the same 1 MiB transfer at both settings.

`flash-device.py` is the only supported provisioning interface; do not invoke
esptool directly. Provision the protected STA profile from the host-owned
input rather than exposing credentials in commands or logs. A successful
Wi-Fi Main update requires association, scoped UDP6 reachability, manifest and
block delivery, digest verification, durable commit, reboot, and fresh Main
health; command acknowledgement alone is insufficient.

The paused Wi-Fi measurements, transport counters, and exact restart commands
are in
[`docs/lab/recovery-wifi-transport-baseline.md`](../../docs/lab/recovery-wifi-transport-baseline.md).
