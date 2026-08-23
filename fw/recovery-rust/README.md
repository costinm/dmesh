# Rust Recovery (frozen)

Rust Recovery is retained as a low-priority historical/update lane while Main
is the active firmware. It is not part of the current build or e6/e7 runtime
workflow. Stage2 can still select the existing image, but new Recovery builds
are deliberately rejected by `scripts/build-recovery-rust.sh`. Set
`DMESH_ALLOW_RECOVERY_BUILD=1` only for a compile/size check.

The frozen Recovery lane historically owned:

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

Do not build this crate. Use `scripts/build-fw.sh` for the active Main image.

Historical Recovery provisioning is retained in the flasher for emergency
rollback only; it is not a current device workflow. Use Main for normal
firmware builds and deployment.

`flash-device.py` is the only supported flashing interface. It currently uses
esptool for all targets; do not invoke esptool directly. A future Recovery
cleanup may retain only the open-STA UDP6 flashing path, with UDP server ports
selected per session. Successful completion would require durable image
completion, reboot, and a fresh direct Main status; command acknowledgement
alone is insufficient.

The paused Wi-Fi measurements, transport counters, and exact restart commands
are in
[`docs/lab/recovery-wifi-transport-baseline.md`](../../docs/lab/recovery-wifi-transport-baseline.md).
