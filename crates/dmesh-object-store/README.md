# dmesh-object-store

The active transfer path is the bounded `protocol` module carried by lmesh
NAN data frames. It has no TCP/IP, UDP, filesystem, or allocator dependency and
keys sessions by source Wi-Fi MAC plus the dmesh-transport DCID. The same
envelope can be used in NAN action frames for diagnostics. ESP Main links this
core directly; its platform flash sink is separate.

The old host `std` server is retained for explicit comparison only. It is
disabled by default in lmesh; enable it with `LMESH_OBJECT_SERVER_TCP=1` (and
optionally `LMESH_OBJECT_STORE_ROOT`) when measuring the legacy path on port
3337.

Each legacy-server artifact gets a sibling `<artifact>.manifest.json`. The
server checks the source mtime and size recorded in that sidecar and streams
the file in 4 KiB blocks.

The host command `object.nan.dry_run` sizes a NAN transfer and reports packet
and byte overhead without opening a socket or touching a device.
