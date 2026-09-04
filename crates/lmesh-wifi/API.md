# lmesh-wifi Linux adapter

`lmesh-wifi` owns Linux Wi-Fi interfaces and implements platform operations;
it does not define a second public mesh API. Reviewed cross-platform records
and numeric identities live beside their structs and codecs in
[`dmesh-server/API.md`](../dmesh-server/API.md).

`LMESH_INTERFACES` is the comma-separated allowlist of interfaces owned by the
process. Linux-only AP, station, monitor, injection, and `iw` diagnostics are
internal adapter/test functions. They are intentionally absent from public
tool catalogs. Bearer lifecycle uses common `transport.set`; discovery uses
`discovery.nodes`; local NAN health uses
`telemetry.nan_status`; probing uses the bearer-neutral `probe` QUIC stream
service from the common `dmesh-server` schema.

The shared NAN frame/state implementation is documented in
[`dmesh-rawnan/API.md`](../rawnan/API.md). Direct UART sessions remain owned by
`dmesh-cli`; this crate does not open or proxy board serial devices.
