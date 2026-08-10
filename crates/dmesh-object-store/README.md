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

## UDP diagnostics

The standalone DRS2 UDP server runs on port `3336`:

```sh
./scripts/object-store-udp.sh
```

It accepts a fresh HELLO from a peer even when that peer reuses an old UDP
source port, replacing the abandoned session. This is required after a Main
reset or a failed dry-run.

For a transport-only bidirectional test, run the fixed-port status responder
on `3338`:

```sh
./scripts/object-store-udp-status.sh
python3 scripts/udp-status-probe.py 10.78.0.200
```

Main exposes the matching diagnostic methods:

```text
wifi udp_status_server=true port=3338
wifi udp_status_probe=true server=10.78.0.1 port=3338 timeout_ms=3000
wifi udp_status_server_status
wifi udp_status_probe_status
```

The `DMSU` record is deliberately fixed-size: a 14-byte request carries a
nonce, and the 26-byte response echoes it with server uptime and IPv4 bytes.
The status exchange is separate from DRS2 so socket direction, ARP, and reply
delivery can be diagnosed without involving manifests or flash scheduling.
