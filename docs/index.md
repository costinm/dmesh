# DMesh docs

These docs mix current implementation notes with older radio research. Use the
status labels below before treating a page as API documentation.

## Current

- [Current architecture](architecture.md): app layout, Rust JNI integration, and
  the SSH message transport.
- [Debugging](debugging.md): emulator setup, adb forwarding, SSH trust and
  binary-message transport checks, tcpdump, and remote adb notes.
- [L2 support](l2.md): Android local-link framework adapter and DirectBinder
  message surface.
- [Android device validation](lab/android-device-validation.md): physical-device
  install, SSH, telemetry, and app receipt checks.
- [ESP32 radio matrix](lab/esp32-radio-matrix.md): runnable lora1/lora4 and
  Android validation procedures.

## Design direction

- [Routing](routing.md): user-space routing and VPN addressing design goals.
- [Android SSH telemetry plan](../notes/ai/2026-08-25-android-ssh-telemetry.md)
- [Android service bridge plan](../notes/ai/2026-08-25-android-service-bridge.md)
- [ESP32 radio validation plan](plans/esp32-radio-validation.md)
- [Minimal NAN QUIC-shaped transport](plans/nan-quic-short-transport.md):
  reviewed raw-NAN connection/CBOR transport direction; not implemented yet.

## Research notes

- [IPv6 multicast and WiFi Direct](multicast6.md): historical experiments with
  Android P2P/AP interfaces, link-local IPv6, multicast, and interface binding.
- [Radio notes](notes.md): DNS-SD battery observations, multicast behavior,
  `iw` commands, and 802.11s/OpenWRT notes.
