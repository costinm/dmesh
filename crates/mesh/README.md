# Client library for (SSH) Mesh

This create provides an optional library for interacting with a Mesh, i.e. a mechanism for running apps with configurable and (more) consistent security, telemetry, networking.

Any application using stdin/stdout/stderr or UDS can be used with no changes by SSH mesh - the library allows a few extra features like a JSONL control socket, activation support, and opinionated telemetry setup.



## Core service - networking

In many cases H2C is overkill - many apps can just expose their generated mesh
API over stdin/stdout or UDS. In this case the mesh proxy can handle HTTP2 or
SSH forwarding, with headers and metadata exposed as environment variables or
structured request fields.
The app will not include a HTTP or H2 library, keeping deps small.

A runnable, activation-only tagged-CBOR worker is in
[`examples/echo`](examples/echo), with its own `API.md`, generated catalog,
common mesh handlers, tracing, and matching mesh-init configuration.
[`examples/echo_json`](examples/echo_json) shows the equivalent
newline-delimited JSON-RPC and Serde adapter.

## Baseline protocols and binary framing

Tagged binary records are the primary programmatic interface. Tagged-CBOR is
the current encoding; canonical protobuf or another schema-driven tagged
encoding can reuse the same registry and handlers. JSON-RPC and text are
gateway/operator adapters over that dispatch surface.

`mesh::message::LineProtocolSession` provides the shared connection-level
protocol selector for line-capable control sockets and stdio services. The
first byte of the first packet selects the protocol for the whole connection:

- `{` selects JSON / JSON-RPC lines.
- An ASCII letter selects the shared text-record protocol.
- `0x00` selects the shared binary protocol.

The binary frame is compatible with the useful shape of an OpenSSH mux packet:

```text
u32-be length | 0 | message-type | flags | version | payload
```

`length` includes the four metadata bytes, but not its own four bytes. The zero
byte is padding. `message-type` reuses RFC 4254 SSH connection message numbers,
including global request (80), channel open (90), channel data (94), channel
request (98), and their replies. Consequently an SSH adapter can preserve
channel, forwarding, EOF, and close semantics instead of translating through a
second transport enum. Global forwarding uses the standard `tcpip-forward` and
`cancel-tcpip-forward` request names; channel opens use names such as `session`,
`direct-tcpip`, and `forwarded-tcpip`.

Message type 203 (`0xcb`) is the private mesh RPC record. Its payload is compact
CBOR on a binary baseline connection. Datagram transports such as LoRa, NAN,
BLE, and UDP carry that CBOR directly because their outer envelope already has
a length. Unix sockets may pass descriptors with the OpenSSH SCM_RIGHTS marker
convention. OpenSSH ControlMaster request IDs and framing helpers are also
provided by `mesh::mux` for direct interoperability.

`mesh` owns this unencrypted local transport and JSON/text/CBOR translation. It
does not depend on `russh`; `ssh-mesh` adds SSH, mTLS/H2, and other authenticated
remote transports.

The text protocol is logfmt-style: one newline-terminated record, record kind
as the first token, then `key=value` fields. Values with whitespace or shell
separators are double-quoted with backslash escapes. Examples:

```text
status name=ssh-mesh
response name=ssh-mesh state=running pid=42 success=true
event type=lora.rx rssi=-71 data_b64=AQID
error message="service not found"
```

Firmware uses its own bounded CBOR implementation for datagrams and the framed
CBOR form for TTY or another byte stream. Host service UDS and reliable mesh
bearers use `mesh::wire::serve_cbor_session`: the same tagged-CBOR dispatcher
and request/reply correlation applies to either transport. Text and JSON are
gateway/operator codecs, never a second programmatic service protocol.

If HTTP is needed, it belongs in `ssh-mesh` or the application itself. The `mesh` crate intentionally avoids Axum/Hyper/http dependencies and only provides the activation, peer-checked stream, JSONL, and telemetry primitives.

## Tools Catalogs

Services that expose a mesh command surface should keep structured `mesh-api`
blocks in their human-readable `API.md`. Generated `resources/tools.json`
catalogs are used by
`mesh.tools`, optional protocol adapters, ssh-mesh web/admin pages, and the
`mesh` CLI:

Mesh-init service definitions are node-local client connection policy. Their
`[Mesh]` section selects address, transport, encoding, and a local static tools
catalog; `mesh FQDN help` reads that catalog without contacting the service.
`ExecStart` is the local-exec connection mechanism. Existing process, socket,
network, environment, and resource fields remain in place for now; a future
`[Workload]` section is reserved for making provider runtime policy explicit.

```sh
mesh example tools
mesh example tool status
```

`API.md` remains the source of truth and may mark methods public or private;
the standalone `mesh-api-gen` emits the public catalog, JSON Schema, and
no-std numeric IDs. A documented Rust serde struct can generate a reviewed
API.md block as an authoring convenience, but no generator/reflection
dependency reaches services or firmware.

The core catalog is checked in at `resources/tools.json`, with matching
`resources/schema.json` and `src/generated_api_ids.rs`. The `mesh-cli` build
gate runs `mesh-api-gen --check` against all three artifacts.
During local development,
`MESH_RES_DIR` can point at a crate's `resources/` directory for service-owned
runtime resources. Client-side schema resolution is separate: `MESH_TOOLS` is
an exact override, `MESH_SCHEMA_DIR` is a multi-service root, and the shared
resolver scans `/opt/<service>/etc/schemas/`, `$HOME/opt/<service>/etc/schemas/`,
and `$HOME/etc/schemas/`, loading every `.json` file it finds. The directory
order, merge rules, and the gateway's `?view=all`/default catalog views are
documented in `src/catalog.rs`. Packaged services use the normal
`MESH_OPT_BASE`/`MESH_APP_OPT` resource lookup.

If the app is exposing HTTP over TCP without TLS - ideally localhost
is used, and normal port forwarding by the mesh proxy, with H2 or SSH
or Wireguard providing secure transport - can be used. Note that the 
model only works well for 'pods', with isolated network namespace.

If the app is exposing HTTPS or other secure protocol and handling its
own security - there is no need for a proxy or mesh library, but the
init pattern (systemd socket activation/serverless) can still be used.

## Resource management

The expectation is that a VM or Pod/Container will contain multiple binaries implementing one or more services. The mesh can start a binary
and run requests, keeping track of idle process and terminating them.

In addition the mesh should monitor memory pressure and take that into account on terminating processes or deciding to accept 
only specific requests when system is under heavy load. This needs to be more tightly integrated than in Istio or similar meshes.

### Jobs 

This is based in large part on Android JobScheduler: like serverless the app is loaded on demand and in response to requests/pubsub or scheduled periodic runs, but there are additional constraints and flexibility in
scheduling to allow better resource utilization. 

The problem with 'cron' and exact scheduling is that many of the 
jobs don't really need to execute at a precise time - and the system should make sure whatever runs is the higest priority set of work that can be done with the available memory/cpu, delaying lower priority or flexible jobs.

'power' and 'network' events are also very relevant for laptops
and also for servers.

## Telemetry

The core idea is that telemetry data is not only for upload to servers, with the associated tradeoffs (privacy, bandwidth, storage, etc.) - but it can be extremely useful locally for the app itself and for other cooperating components on the same node. 

Apps are usually telemetry producers, but can also be consumers for their own telemetry or for other components, with proper permissions/policy.

Keeping recent logs and traces in a local circular buffer is also very useful for debugging and for using the telemetry data as part of the application logic or in tests without extra complexity. Metrics (counters) can be accessed locally - if the telemetry libraries don't intentionally hide them. 

Consumers can do the local processing or send data to cloud/remote backends - with some extra buffering, or may not send
all the data. 

Traces/logs should be off by default - and dynamically configurable per app, with a collector or telemetry app 
getting access to recent events and the buffer and new logs.

# Future and other ideas

## MCP and Open-API

Workers ship static generated schemas and need no MCP library. The optional
`mesh-mcp` gateway adapter loads that metadata and translates MCP discovery and
tool calls to the worker's ordinary handler locally or through a forwarding
gateway. Static skills and agent documentation can use the same API source.

## Multi-codec

JSON is the most common format - but CBOR or Protobuf should also be possible, with translations in the mesh layer, so any-to-any format is possible.


This is an extension of 'serverless' - based in large part on Android JobScheduler: like serverless the app is loaded on demand and in response to requests/pubsub or scheduled periodic runs, but there are additional constraints and flexibility in
scheduling to allow better resource utilization. 

The problem with 'cron' and exact scheduling is that many of the 
jobs don't really need to execute at a precise time - and the system should make sure whatever runs is the higest priority set of work that can be done with the available memory/cpu, delaying lower priority or flexible jobs.

'power' and 'network' events are also very relevant for laptops
and also for servers.

## Sessions 

Need to expose 'session' as first class, tracking the list of sessions,
metadata (user/entity owning it), memory size - and possibly supporting 
persistence/reloading/freezing/migration

## Exec

Using containers or jails - via unshare, nsjail, bubblewrap, etc. - is a good pattern for limiting the resources and capabilities of the executed app, but with overhead and complexity, and with dependencies to another
component. 

Podman and user-mode containers are even heavier, while root daemons and K8S are another level of complexity and security risks.

There are really 2 modes for isolating exec:

1. As pure user-space - creating namespaces, cgroups, etc,
via system calls (library) like podman/unshare/bwrap or using one of them
as a wrapper. Child will use sub-uid - root in child is the main user ID,
each child has the same mapping. 

2. Using root - setuid or a daemon - with the main benefit 
of switching to a different UID and different privileges than the original user. 

In the first case, using a different user ID for each process with
no root access in the child provides some protection and isolation, but
root in a child will be the same as the user ID and volumes may give
the app access to user data. Nesting doesn't work very well, and
the app that calls exec must have all permissions needed by all children

The second is more risky - and needs to be greatly restricted to avoid
docker and systemd mistakes of giving too much power to the config owner.
The mesh-init crate provides an opinionated implementation of this.

Both are valid and important use cases, it is not a choice
on using one or the other, but to use both when appropriate.

### unshare

### Nsjail

### Bubblewrap
