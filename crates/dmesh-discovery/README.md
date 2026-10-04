# dmesh-discovery

Local discovery for DMesh: how a node finds the others near it. Every platform learns
about neighbours from the same signed CBOR `announce` record
(`dmesh_server::announce`), whatever carried it: UDP6/UDP4 multicast, NAN, ESP-NOW, BLE.

| Piece | What it does |
|---|---|
| `Identity` (`P256Identity`, `UnsignedIdentity`) | the stable device id, and the signature on our announce |
| `Inventory`, `Device` | typed discovered devices with per-bearer observations, expiry, and `resolve_udp` (`mesh://VIP`, hex id, name -> endpoint, or *why there is none*) |
| `Engine` | sans-IO: builds our announce, answers directed requests, validates and records what arrives (`on_datagram(&Carrier, bytes)`) |
| `endpoint::parse_udp_endpoint` | `udp://[fe80::1%wlan0]:3337` and friends, with the interface scope resolved locally |
| `interfaces` | enabled IPv6 interfaces, multicast scopes, live-scope checks |
| `udp::UdpDiscovery` (feature `tokio`) | multicast sockets, receive loop, `announce`, `solicit` (`discovery.active`), `directed` |

A bearer that is not UDP (the Linux monitor interface, Android's NAN callbacks, firmware)
calls `Engine::on_datagram` with a `Carrier::radio(..)` and sends what the engine builds;
it does not reimplement the protocol. A platform that owns the UDP socket passes it in
(`UdpDiscovery::from_fd`, or `new` with separate listeners and sender) and hands datagrams
it reads itself to `UdpDiscovery::on_datagram`.

```sh
cargo test -p dmesh-discovery --features tokio   # loopback tests, no network needed
```

Users: `dmesh-android` (descriptor handed over by Java), and `lmesh` once it stops
linking `lmesh-wifi` (see `notes/plans/lmesh-wifi-extraction.md`).

# TODO

- main - using quic-lite UDP bearer - announce, discover, build multi-hop map
