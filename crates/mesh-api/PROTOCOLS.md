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

A transport crate's own tests do not need any of this: they may attach the
protocol under test directly as the only handler on the far side, with no
header, registry or dispatch.
