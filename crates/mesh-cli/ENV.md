# mesh CLI environment


| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_DEST_FORMAT` | `auto` | Encoding override. `auto` uses tagged-CBOR for a `.cbor` seqpacket endpoint and JSON-RPC for other current RPC endpoints. Catalog presence does not select the transport or encoding. `cbor` requires numeric tags; `mux` is a transport selector and is rejected here. |
| `MESH_TOOLS` | unset | Exact `tools.json` override for numeric tags, documentation, and named field mapping. Failure to load an explicit override is an error. |
| `MESH_SCHEMA_DIR` | unset | Common schema root. For logical service `S`, `mesh` checks all `.json` files under `$MESH_SCHEMA_DIR/S/` before installed package locations. |
| `MESH_SERVICE_DIR` | unset | Common mesh service TOML file, or directory containing `<service>.toml`. A bare service name resolves its `[Mesh].Address` or standard mesh socket from this definition. |
| `MESH_SSH_COMMAND` | `/usr/bin/ssh` | Real OpenSSH binary used for an unresolved bare host. This avoids recursion when `mesh` is symlinked as `ssh`. |

`--rpc-format auto|cbor|json-rpc` overrides `MESH_DEST_FORMAT` for one call.

Explicit UDS/TCP endpoints are RPC calls:

```sh
mesh unix:///run/mesh/example/mesh.sock example status
MESH_DEST_FORMAT=json-rpc mesh unix:///run/mesh/gateway.sock device listen
mesh https://gateway.example/rpc device status
```

An HTTP(S) address is the exact JSON-RPC endpoint. The HTTP stack negotiates
HTTP/1.1 or HTTP/2 normally; mesh-cli does not probe another encoding or replay
the request.

Configured local mesh endpoints under `/run/mesh` also have a namespace form:

```sh
mesh service1.example status
```

This resolves to `/run/mesh/example/service1.sock` and sends `example.status`.
The same rule applies to every runtime directory. Longer names such as
`service1.example.host.example` are reserved for remote
namespace routing and are not treated as local sockets.

`mesh FQDN help` is local discovery. It checks `MESH_TOOLS`, then all `.json`
files under `MESH_SCHEMA_DIR/FQDN/`, `/opt/FQDN/etc/schemas/`,
`$HOME/opt/FQDN/etc/schemas/`, and `$HOME/etc/schemas/`. It does not connect
to, activate, or query the service. `mesh FQDN help COMMAND` prints the
complete static descriptor for one command.

`mesh` is intentionally not an interactive text gateway. Use an explicit
command for typed tagged-CBOR RPC; use `dmesh-cli` for UART/device interaction
or a dedicated JSON/text gateway tool for manual debugging.

`mux:///path` or `-S /path` selects the native ControlMaster client. A bare
host retains normal SSH command and forwarding syntax.
