# DMesh docs

These docs mix current implementation notes with older radio research. Use the
status labels below before treating a page as API documentation.

## Current

- [Current architecture](architecture.md): app layout, Rust JNI integration, and
  the SSH JSONL message bridge.
- [Debugging](debugging.md): emulator setup, adb forwarding, SSH JSONL smoke
  tests, tcpdump, and remote adb notes.
- [L2 support](l2.md): current `lib-lm3` message commands and events exposed
  through `MsgMux`.

## Design direction

- [Routing](routing.md): user-space routing and VPN addressing design goals.

## Research notes

- [IPv6 multicast and WiFi Direct](multicast6.md): historical experiments with
  Android P2P/AP interfaces, link-local IPv6, multicast, and interface binding.
- [Radio notes](notes.md): DNS-SD battery observations, multicast behavior,
  `iw` commands, and 802.11s/OpenWRT notes.
