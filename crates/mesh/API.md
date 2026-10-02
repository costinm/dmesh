# `mesh` API (2000)

Core methods supplied by `mesh::registry::ServiceRegistry`. They are common
service discovery, lifecycle, and trace controls; each service documents its
own component methods separately. These components use the reserved numbers
2000 (`mesh`) and 2001 (`trace`), outside any service's own range, so a
service can register them beside its own numbered methods. They dispatch by
number and CBOR; the name-keyed JSON dispatch remains for JSON-RPC/MCP
gateways. Transport and encoding rules are in
[mesh-api/PROTOCOLS.md](../mesh-api/PROTOCOLS.md); handler streams (a header, then an
optional body) are defined in its
[Handler streams](../mesh-api/PROTOCOLS.md#handler-streams-header-and-body) section. The generated public catalog
is `resources/tools.json` and can be adapted by CBOR, JSON-RPC, CLI, or MCP
gateways without changing these handlers.

`mesh.lifecycle` is private supervisor-to-service traffic. Services that need
to react call `mesh::lifecycle::subscribe()` before accepting requests. Public
`mesh.initialize` returns common identity and metadata, while `mesh.tools`
returns the generated method catalog.

## 3. `lifecycle` — Receive a supervisor freeze or unfreeze notification

**Visibility:** private

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `action` | `string` | |
| 2 | `cause` | `string` | |
| 3 | `observed` | `bool` | |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `subscribers` | `u64` | |

## 1. `initialize` — Return common service identity and descriptive metadata

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `name` | `string` | |
| 2 | `version` | `string` | |
| 3 | `title` | `string` | |
| 4 | `instructions` | `string` | |

## 2. `tools` — Return the service's generated method catalog

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `tools` | `array` | |


# `trace` API (2001)

## 1. `subscribe` — Acknowledge trace-subscription capability on this control endpoint

This acknowledges trace capability only. Live trace delivery uses the separate
local-trace subscription protocol.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `subscribed` | `bool` | |
| 2 | `service` | `string` | |

## 2. `set_level` — Set this process's reloadable tracing EnvFilter

Updates the reloadable process-wide tracing filter. An empty level restores
the configured default.

### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `level` | `string` | |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `level` | `string` | |
| 2 | `message` | `string` | |

## 3. `get_level` — Return this process's current configured tracing EnvFilter

Returns the last successfully configured filter.

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `level` | `string` | |
| 2 | `message` | `string` | |
