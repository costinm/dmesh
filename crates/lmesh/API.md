# lmesh service bridge

`lmesh` is a launcher and generic local REST/tagged-record bridge; it is not a
portable API owner. Reviewed discovery, transport, probe, IPERF, raw-radio,
status, and metrics contracts live beside their structs/codecs in
[`dmesh-server/API.md`](../dmesh-server/API.md). Linux Wi-Fi implementation
details live in `lmesh-wifi` and are not public mesh methods.

Set `LMESH_HTTP_PORT` to a non-zero port to expose the generic ssh-mesh admin
bridge on loopback. `POST /_m/mesh/services/lmesh/records` accepts the common
tagged record, and `GET /_m/mesh/services/lmesh/tools` returns the catalog
generated from `dmesh-server/API.md`. A `to` destination forwards the record;
it does not select a second lmesh-specific command schema.

BLE HCI remains experimental and is outside this reviewed surface. Direct
board UART sessions are owned by `dmesh-cli`; `lmesh` does not proxy serial
devices.
