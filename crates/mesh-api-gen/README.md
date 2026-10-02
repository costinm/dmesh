# mesh-api-gen

`mesh-api-gen` turns a human-readable `API.md` into the checked-in catalogs,
schemas, numeric identifiers, and Rust types used by mesh services and their
gateways. It is a standalone host build tool; it is not linked into services,
firmware, or gateways.

This README defines the Markdown-first `API.md` contract implemented by the
parser and generators. See [API.md](API.md) for the complete fixture and the
[implementation plan](../../notes/ai/mesh-api-markdown-plan.md) for migration
scope and validation.

## Design goals

- `API.md` is useful directly to people and language models.
- One source generates `tools.json` for CLI and gateway adaptation, JSON
  Schema where useful, Rust request/response types, and compact numeric IDs.
- The API model is independent of CBOR, JSON, JSON-RPC, MCP, UDS, HTTP, and
  other encodings or transports.
- Numeric component and method IDs are optional. They are useful on embedded
  links, but host-only APIs need not allocate them.
- Request and response field tags are stable numeric wire identities. Field
  names remain the natural interface for JSON, CLIs, and source code.
- The schema stays deliberately small: tagged records, enums, scalar values,
  repeated values, and named types. It does not try to reproduce all of CDDL,
  JSON Schema, or Protobuf.

## Components and methods

A top-level heading declares a component. Put its optional numeric component
ID in parentheses:

```markdown
# `radio` API (3)

Radio inspection and configuration.

## 1. `status` — Return current radio status

**Response:** [RadioStatus](#radiostatus)
```

This defines `radio.status`, with component ID `3` and method ID `1`. Putting
the numeric method ID first makes the wire identity immediately visible to a
reader and straightforward for an LLM to extract. A host-only component or
method omits the number:

```markdown
# `diagnostics` API

## `version` — Return build information
```

The text after the em dash is the short method description used by generated
catalogs. Longer documentation follows as ordinary paragraphs. `1 =>
\`status\`` is intentionally not used: it reads like a mapping declaration,
whereas a Markdown heading is both a navigable documentation section and a
clear method boundary. Fields remain tables because readers need to compare
their tags, types, defaults, and limits across rows.

Another top-level ``# `name` API`` heading starts another component in the
same file. Component and method names may contain dots when that hierarchy is
part of the public fully qualified method name.

Method visibility is `public` by default. State only exceptions:

```markdown
**Visibility:** private
```

`**UI:** default` may mark a public method that generic interactive clients
should surface without an explicit method selection. This is presentation
metadata, not a wire rule.

## Requests and responses

Reference reusable named records when a shape is shared or deserves a domain
name:

```markdown
**Request:** [SetModeRequest](#setmoderequest)
**Response:** [RadioStatus](#radiostatus)
```

For a small method-local shape, put the table directly under the method:

```markdown
### Request

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `value` | `string` | Text to return. |

### Response

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `value` | `string` | The returned text. |
```

The generator normalizes these to implicit named messages, such as
`RadioEchoRequest` and `RadioEchoResponse`. An inline table and an equivalent
named type have the same wire model. Omit Request or Response entirely when
the message is empty.

All fields are optional on the wire. A handler may still reject a request
whose meaningful operation requires a missing field; that is method-level
validation, not a different field encoding. Defaults describe the semantic
value used when a field is absent. Add a Default column only when at least one
field in a table needs one:

```markdown
| Tag | Field | Type | Default | Description |
|---:|---|---|---|---|
| 1 | `limit` | `u32` | `100` | Maximum number of entries. |
| 2 | `cursor` | `bytes` | | Opaque continuation token. |
```

Table order is documentation order. CLI callers name fields, for example
`mesh mesh-init start name=radio`. Wire readers and writers use the tags.

## Method behavior, limits, and access

Use metadata only where it changes caller behavior or enforcement. Metadata is
ordinary bold Markdown so it stays readable without a schema tool:

```markdown
**Execution:** blocking
**Recommended timeout:** `8s`
**Access:** any of `system`, `mesh.owner`, `mesh.admin`
```

`blocking` means the method waits for the requested real-world operation to
finish; `non-blocking` means it returns after accepting or scheduling work.
The default is `non-blocking`. A recommended timeout tells callers how long to
wait before treating a response as absent; it does not override a caller's
deadline.

Access is declarative policy metadata. Use `anonymous` where an unauthenticated
caller is intended, `authenticated` where any authenticated mesh identity is
sufficient, `any of ...` for role alternatives, or a named permission such as
`com.example.permission.CONTROL`. Omitted Access leaves policy unspecified;
the generator must not silently make such a method public. Adapters can map
these terms to their local authorization system, including Android-style
permissions.

Apply a message-wide encoded-size ceiling directly under `### Request`,
`### Response`, or a named message. Add a `Max` column only when individual
fields need a stricter bound. Use units that explain the bound: `B`, `chars`,
`items`, or a numeric range in prose.

```markdown
### Request

**Max encoded size:** `1000 B`

| Tag | Field | Type | Max | Description |
|---:|---|---|---|---|
| 1 | `payload` | `bytes` | `768 B` | Data carried in one radio packet. |
| 2 | `peers` | `string[]` | `16 items` | Intended recipients. |
```

The encoded-size ceiling applies to the API message, excluding an adapter's
outer transport envelope. It lets constrained links state an MTU-derived
limit while JSON, HTTP, or RPC adapters account for their own framing.

Every API has these standard semantic errors: `unauthenticated`,
`permission_denied`, `timeout`, `remote_exception`, `invalid_argument`,
`not_found`, `conflict`, `unavailable`, and `internal`. Declare only
method-specific errors under `### Errors`; adapters map the semantic names to
their protocol's status or error envelope.

## Types

Put reusable declarations under a single `# Types` section. A record is a
second-level heading followed by its field table:

```markdown
# Types

## `RadioStatus`

Current state returned by radio methods.

| Tag | Field | Type | Description |
|---:|---|---|---|
| 1 | `mode` | [`RadioMode`](#enum-radiomode) | Active mode. |
| 2 | `channels` | `u16[]` | Enabled channels. |
```

An enum uses an explicit `enum` heading and stable integer values:

```markdown
## enum `RadioMode`

| Value | Name | Description |
|---:|---|---|
| 0 | `off` | Radio is disabled. |
| 1 | `station` | Station mode. |
```

The scalar vocabulary is `bool`, `u8`, `u16`, `u32`, `u64`, `i8`, `i16`,
`i32`, `i64`, `f32`, `f64`, `string`, and `bytes`. A named record or enum is
also a type. Append `[]` for a repeated value. The complete example proposes a
typed string-keyed map form for review. New compound forms should be added only
when an enrolled API needs them and every generated representation can preserve
their meaning.

An optional `Required` column marks fields that must appear even when their
value is zero or false. Without that column, fields retain their optional
default behavior.

Field tags and enum values must not be reused. Removed record tags can be
retained explicitly:

```markdown
**Reserved tags:** 4, 7-9
```

## Field documentation and examples

Keep the common one-line field description in the table. A field that needs
constraints, security notes, or lifecycle detail can have a matching
third-level section under its named type:

```markdown
### `cursor`

The token is opaque to callers and is valid only for the service instance
that returned it. An invalid or expired token produces `invalid_argument`.
```

Examples are ordinary Markdown and semantic JSON. They describe method values,
not a JSON-RPC, MCP, HTTP, or CBOR envelope:

````markdown
### Example: select station mode

Request:

```json
{"mode":"station"}
```

Response:

```json
{"mode":"station","channels":[1,6,11]}
```
````

A gateway can encode that value as named JSON fields or translate names to
integer tags for CBOR. Examples therefore remain useful across transports.

Method-specific errors may be documented as prose or a table under `###
Errors`.

## Generated artifacts

Generation and drift checking use this command shape:

```sh
cargo run -p mesh-api-gen -- \
  --api crates/service/API.md \
  --out-tools crates/service/resources/tools.json \
  --out-schema crates/service/resources/schema.json \
  --out-ids crates/service/src/generated_api_ids.rs \
  --out-rust crates/service/src/api.rs

cargo run -p mesh-api-gen -- \
  --api crates/service/API.md \
  --out-tools crates/service/resources/tools.json \
  --out-schema crates/service/resources/schema.json \
  --out-ids crates/service/src/generated_api_ids.rs \
  --out-rust crates/service/src/api.rs \
  --check
```

`--rust-tags` also implements `mesh::tagged::TaggedFields` for every generated
Rust type, so the same serde structs encode and decode the tag-keyed CBOR of
`API.md` (`mesh::tagged::{to_tagged_value, from_tagged_value, request_fields,
response_record}`) without a catalog at runtime. The consuming crate depends on
`mesh`.

`tools.json` is the machine-readable method catalog for CLIs and gateways. It
contains descriptions, field schemas, ordering, visibility/UI hints, and
optional numeric IDs derived from `API.md`. Generated Rust and ID files are
generated only and must not be edited.

Catalog import can create an API.md draft for review:

```sh
cargo run -p mesh-api-gen -- \
  --tools crates/service/resources/tools.json \
  --component service \
  --out-api crates/service/API.migration.md
```

Import cannot reconstruct prose, examples, access policy, limits, or numeric
IDs that were absent from the catalog. API definitions have one direction of
authority: `API.md` to generated artifacts.
