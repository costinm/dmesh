# lmesh-wifi Linux adapter

`lmesh-wifi` owns Linux Wi-Fi interfaces and implements platform operations.
Its local Linux request handlers and the shared cross-platform records are
specified in the [root API](../../API.md). The running service is named
`lmesh`.

`LMESH_INTERFACES` is the comma-separated allowlist of interfaces owned by the
process. Linux-only AP, station, monitor, injection, and `iw` diagnostics are
internal adapter/test functions. They are intentionally absent from public
tool catalogs. Bearer lifecycle uses common `transport.set`; discovery uses
`discovery.nodes`; local NAN health uses
`telemetry.nan_status`; probing uses the bearer-neutral `probe` QUIC stream
service from the common `dmesh-server` schema.

The shared NAN frame/state implementation is documented in
[`dmesh-rawnan/README.md`](../rawnan/README.md). Direct UART sessions remain owned by
`dmesh-cli`; this crate does not open or proxy board serial devices.
