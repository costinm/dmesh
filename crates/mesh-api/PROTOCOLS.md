# Mesh protocols and transports

This is the shared contract for mesh APIs. Individual `API.md` files define
components, methods, request fields, response fields, authorization, and
platform-specific behavior; they do not redefine these transports or record
encodings.

## Transports

### Unix-domain sockets (UDS)

Local services normally expose an AF_UNIX socket. `SO_PEERCRED` authenticates
the kernel-reported local peer identity. The socket pathname and authorization
policy are service-specific.

`SOCK_STREAM` supports JSON-RPC and structured text lines, using first byte
in the connection to detect - '{' for JSON, ASCII letter for text.

A 0x00 followed by 3 bytes length is also supported with binary content.

`SOCK_SEQPACKET` is the programmatic local CBOR transport when an operation
needs file descriptors. One complete tagged-CBOR record and its `SCM_RIGHTS`
ancillary data form one packet; receivers reject truncated packets or
descriptor control messages. CBOR encodes request data, not OS descriptor
numbers—the UDS ancillary message transfers the descriptors.

The stream and seqpacket endpoints have distinct paths because a Unix path can
name only one socket type. Services retain legacy stream endpoints while
clients migrate.

### SSH

SSH is a remote user transport. SSH services authenticate the remote principal
then use local mesh APIs under their own authenticated UDS peer identity.

### HTTP/1.1

HTTP/1.1 is used in gateways and in ssh-mesh per-node server - authenticate using 
Authorization, Cookie or mTLS and may forward over one of the local protocol (UDS, virtio, 
localhost TCP). Only POST/GET - no duplex streaming supported.

### HTTP/2

Like HTTP/1.1 - but with H2 streaming, same features as SSH in terms of forwarding.

### WebSocket

Like HTTP/1.1 - but supports streaming. 

### QUIC-lite

Specific to device mesh - a subset of QUIC protocol, but with different association
that account for untrusted devices and local addresses - and supports multi-path 
adapted for unreliable/untrusted relays.

## Encodings

### Tagged CBOR

Tagged-CBOR is the primary programmatic record encoding. Every API document's
`mesh-api` blocks assign stable component, method, and field identifiers.
Generated catalogs translate those identifiers to method and field names at
service boundaries. Stream transports add a four-byte big-endian frame length;
seqpacket transports preserve each encoded record as one packet and do not need
an additional framing boundary.

#### Envelope keys

| Key | Name | Meaning |
|---:|---|---|
| 1 | `component` | Component number or name. |
| 2 | `method` | Method number or name. |
| 3 | `id` | Correlation id; a response carries the request's id. |
| 4 | `params` | Positional parameters. |
| 5 | `fields` | Named request fields, keyed by catalog tag. |
| 6 | `result` | Successful response value. |
| 7 | `error` | Failure response value. |
| 8 | `timeout` | Request only: milliseconds the caller allows. |
| 9 | `to` | Destination node; a forwarder consumes it. |
| 10 | `data` | Opaque binary payload. |
| 11 | `extensions` | Receiver-local facts beside a signed record. |

A response carries only `id` plus `result` or `error`.

#### Timeout

`timeout` is the time, in **milliseconds**, the caller allows for the whole
request, counted from when the receiver reads it. It is a duration, not a
deadline, because devices share no clock (as with gRPC's `grpc-timeout`).

- Absent means the handler's own default. A receiver may apply a lower limit of
  its own; it never extends the caller's.
- A node that forwards because of `to` sends on what remains after its own
  work, so a chain never allows more than the original request.
- When it runs out, the receiver abandons the handler (releasing any deferred
  job or body sink) and answers with the `timeout` error. The caller also stops
  waiting at that point. A synchronous handler cannot be interrupted; it is only
  refused if the time is already gone before it starts. Resetting the stream
  still cancels a request.
- Handlers read the allowance from their call context and may use it to size
  their own work: `probe.start` runs for the caller's `timeout`, else a default
  that grows with the transfer size.
- It applies to streams. A datagram has no response to time out; for a
  connectionless message it is currently unspecified.
- HTTP/JSON and the text forms spell it `timeout` (`timeout=2500`), unless the
  method declares a field of that name, which wins.

### JSON-RPC

JSON-RPC 2.0 is the human-facing and compatibility gateway: a request carries
`jsonrpc`, `id`, `method`, and object `params`; a response has the matching id
and either `result` or `error`. 

### Text

Text records are a human and shell-friendly gateway (`method key=value`). They
use string method names - may use tags as keys.

### Protobuf

Planned/possible - in particular for Meshtastic and other integrations. Tags in CBOR
should match the tags in proto schema.
## Handler streams: header and body

A handler serves one bidirectional stream, as an SSH `exec` or direct-tcpip
channel or an HTTP/2 stream does. The transport supplies ordered bytes in each
direction and an independent FIN per direction (a QUIC-lite stream on any
bearer, an SSH channel, an HTTP/2 stream, a WebSocket, a local socket). This
section is the contract every handler and every transport adapter shares; an
`API.md` documents only the methods and their fields.

Each direction is a **header** followed by a **body**:

```text
request:   [header: one CBOR item][body: raw bytes ...][FIN]
response:  [header: one CBOR item][body: raw bytes ...][FIN]
```

- **Header.** One tagged-CBOR map: the request has the `component`, `method`,
  `id`, optional destination `to` and the method's request fields; the response
  has the request `id` and either a `result` or an `error`. A response always
  starts with a header, so a caller never decides success or failure by looking
  at body bytes. A rejected request gets an error header and an empty body.
- **Body.** Raw bytes that are *not* CBOR, of any length, produced and consumed
  incrementally under the stream's flow control. Nothing in the framing
  announces its length. If a method needs the length, for example to validate
  it or to size storage, the length is an ordinary field of its header (an
  object size, a probe byte count). The body ends where its sender's direction
  ends.
- **FIN.** FIN is sent after the last body byte. A method without a body is
  the same stream with an empty body: header, then FIN. A short method is
  therefore header, FIN in each direction; nothing about registration or
  dispatch differs from a method that moves a lot of data. A method says in
  its `API.md` whether either direction has a body, and what the bytes are.

### Where the header ends

CBOR is self-delimiting, so no end-of-document marker or length prefix is
needed. A complete data item ends where its structure ends: a definite-length
map after its last value, an indefinite-length one at its break stop code
(`0xFF`). The first byte after that item is the first body byte. A receiver
reads the header incrementally until one complete item is available, bounded
by a header size limit, and a decoder reports either "complete, N bytes" or
"need more bytes" without allocating. Headers should be definite-length maps so
that fixed-buffer no_std decoders can size them; an indefinite-length header
is still valid.

Field `10` (`data`) of a record is a small binary value *inside* the header,
used by one-way messages and datagrams. It is not the stream body and does not
announce one.

### Framing

Transports that already have stream boundaries (QUIC-lite, SSH, HTTP/2) carry
the header at the start of the stream with no extra framing. Transports that
do not (a `SOCK_STREAM` socket) prefix the header with the four-byte length
described under Tagged CBOR; a `SOCK_SEQPACKET` packet is exactly one header
with no body.

### Registration

A handler is registered by component and method number and receives the
header and the stream; a method with no body simply never reads or writes
one. There is no second kind of handler for long-running or data-moving
methods, and no ingress may dispatch a method itself instead of calling the
registry.

## Delivery forms of one handler

A handler is registered once, by component and method, and the same
registration is reached by three delivery forms. The form is a property of how
the request arrived, not a kind of handler; no ingress dispatches a method
itself. QUIC is one transport that can carry all three; none of this is specific
to it or to DMesh.

| Form | Carried by | Association | Reliability | Response |
|---|---|---|---|---|
| Stream | a bidirectional stream (header, then body, FIN after the body) | required | reliable, ordered, flow controlled | header, then optional body |
| Message | one packet that is sent without an association | none | one packet, no retransmission by the transport | at most one response message |
| Datagram | a datagram on an established association | required | unreliable, may be dropped | none |

- **Stream.** As defined above. It is the only form with a body longer than a
  packet, multiplexing, or flow control per stream.
- **Message (connectionless).** An association is expensive and is needed only
  to multiplex streams, so a rare, small request can be sent without one. It is
  a variant of a versioned long-header packet that can be sent before the
  handshake: the packet carries one header (the same tagged-CBOR map) and, in
  field `10`, any small binary value, and nothing else. It is not a separate
  kind of handler and has no registration of its own: the receiver applies an
  **allow-list** of methods that may be invoked this way (an ingress policy,
  because there is no authenticated association), then dispatches through the
  registry like any other call. A handler that must not be reachable without an
  association is simply absent from the allow-list. Duplicates are expected
  (the sender may repeat) and a handler that is not idempotent must say so in its
  `API.md`.
- **Datagram.** Standard QUIC datagram semantics on an established
  association: a datagram may be dropped, is counted against the connection's
  flow control, and carries one complete header (and any small body) in the
  datagram itself, so every datagram is its own end of stream. The handler
  returns nothing. Only the send side differs from a stream call; the handler
  is registered the same way, and an `API.md` marks a method as usable as a
  datagram when it is one-way and safe to lose.

A handler may be reachable by several forms; its `API.md` entry lists which.
The registry gives the handler the form in the call context, so a handler that
should only run as a stream can decline the others.

A transport crate's own tests do not need any of this: they may attach the
protocol under test directly as the only handler on the far side, with no
header, registry or dispatch.
