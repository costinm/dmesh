# lmesh API pointers

`lmesh` is the experimental superset and launcher. Shared Wi-Fi ownership,
AP/STA/raw-NAN operations, object-store flashing, benchmark requests, and
their JSONL contract are defined by [`lmesh-wifi/API.md`](../lmesh-wifi/API.md).
The `lmesh` UDS service imports that reviewed Wi-Fi catalog too, so a numeric
Wi-Fi CBOR request has the same wire identity on `lmesh` and `lmesh-wifi`.
`lmesh` does not open, proxy, or advertise serial paths. Direct board sessions
and E2E UART use belong exclusively to `dmesh-cli`; host-service requests use
the CBOR mesh/UDP/NAN bearers instead.

Other component contracts remain authoritative in:

- [`dmesh-cli/README.md`](../dmesh-cli/README.md) for direct UART and UDP
  device sessions. `lmesh` deliberately does not proxy or own serial devices.
- [`uart-codec/API.md`](../uart-codec/API.md)
- [`rawnan/API.md`](../rawnan/API.md)
- [`quic-lite`](../quic-lite/) and [`dmesh-server`](../dmesh-server/)

BLE HCI is experimental and is implemented only by `lmesh`; it is not part of
the stable `lmesh-wifi` API. This file intentionally contains pointers only;
update the owning component API instead of duplicating method documentation.

## Reviewed tagged-CBOR core

The following small discovery core is the first reviewed `lmesh` tagged-CBOR
surface. Its component index is 4. The remaining legacy commands stay in the
catalog without numeric IDs and therefore use the explicit JSON-RPC gateway;
they must be reviewed individually rather than auto-numbered.

Regenerate the mixed catalog with the sibling standalone generator. The base
is intentionally the existing catalog: reviewed entries replace matching
legacy names, while all other entries remain visible without wire tags.

```sh
cd ../rust/ssh-mesh
cargo run -p mesh-api-gen -- --api /ws/dmesh/crates/lmesh/API.md \
  --base-tools /ws/dmesh/crates/lmesh/resources/tools.json \
  --out-tools /ws/dmesh/crates/lmesh/resources/tools.json
```

The documented Rust request structs in [`src/api.rs`](src/api.rs) are also a
dependency-free source for a review draft. This is deliberately not an
automatic replacement for this file: reviewers must preserve or explicitly
change the stable numeric IDs here before publishing a new catalog.

```sh
cd ../rust/ssh-mesh
cargo run -p mesh-api-gen -- --rust /ws/dmesh/crates/lmesh/src/api.rs \
  --out-api /tmp/lmesh-api-from-rust.md
```

```mesh-api
id = "lmesh.nodes"
component = "lmesh"
method = "nodes"
component-index = 4
method-index = 1
summary = "List currently discovered local mesh nodes"
```

```mesh-api
id = "lmesh.announces"
component = "lmesh"
method = "announces"
component-index = 4
method-index = 11
summary = "List observed bearer-neutral announces"
```

```mesh-api
id = "lmesh.get_node"
component = "lmesh"
method = "get_node"
component-index = 4
method-index = 2
summary = "Return one discovered node by public key"
[request]
fields = [{ name = "public_key", index = 1, type = "string", required = true, position = 1 }]
```

```mesh-api
id = "lmesh.announce"
component = "lmesh"
method = "announce"
component-index = 4
method-index = 3
summary = "Send a multicast local mesh announcement"
[request]
fields = [{ name = "metadata", index = 1, type = "object" }]
```

```mesh-api
id = "lmesh.status"
component = "lmesh"
method = "status"
component-index = 4
method-index = 4
summary = "Return local discovery and radio status"
```

```mesh-api
id = "lmesh.neighbors"
component = "lmesh"
method = "neighbors"
component-index = 4
method-index = 5
summary = "Return recently observed neighbors"
[request]
fields = [{ name = "seen_within_sec", index = 1, type = "u64" }]
```

```mesh-api
id = "lmesh.links.list"
component = "lmesh"
method = "links.list"
component-index = 4
method-index = 6
summary = "Return local link observations and selected paths"
[request]
fields = [{ name = "seen_within_sec", index = 1, type = "u64" }]
```

```mesh-api
id = "lmesh.ping"
component = "lmesh"
method = "ping"
component-index = 4
method-index = 7
summary = "Discover peers over one radio or all radios"
[request]
fields = [
  { name = "radio", index = 1, type = "string" },
  { name = "wait_ms", index = 2, type = "u64" },
  { name = "nonce", index = 3, type = "string" },
]
```

```mesh-api
id = "lmesh.send"
component = "lmesh"
method = "send"
component-index = 4
method-index = 8
summary = "Send a mesh payload over the selected radio"
[request]
fields = [
  { name = "radio", index = 1, type = "string" },
  { name = "destination", index = 2, type = "string" },
  { name = "payload", index = 3, type = "string", required = true },
]
```

```mesh-api
id = "lmesh.radios.list"
component = "lmesh"
method = "radios.list"
component-index = 4
method-index = 9
summary = "Return configured local radio adapters"
```

```mesh-api
id = "lmesh.messages.history"
component = "lmesh"
method = "messages.history"
component-index = 4
method-index = 10
summary = "Return recent radio and backend message history"
[request]
fields = [
  { name = "keys", index = 1, type = "string" },
  { name = "limit", index = 2, type = "u64" },
]
```

```mesh-api
id = "wifi.mgmt.capture"
component = "wifi"
method = "mgmt.capture"
component-index = 5
method-index = 13
summary = "Capture a bounded host management-frame sample"
[request]
fields = [
  { name = "iface", index = 1, type = "string" },
  { name = "channel", index = 2, type = "u8" },
  { name = "capture_ms", index = 3, type = "u64" },
  { name = "max_frames", index = 4, type = "u64" },
  { name = "active", index = 5, type = "bool" },
]
```
