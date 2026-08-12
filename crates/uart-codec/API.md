# uart-codec API

`uart-codec` is the low-level crate behind the stable UART-forwarding service
and the ESP32 firmware UART transport. The std JSONL service binary is built by
[`lmesh-uart/API.md`](../lmesh-uart/API.md).

## Physical framing

Firmware UART records use an HDLC/PPP-style delimiter and escaping:

- delimiter: `0x7e`;
- escape: `0x7d`;
- escaped byte: `byte ^ 0x20`;
- maximum normal ESP record: 4,000 payload bytes.

`codec::encode_payload` wraps one raw payload. `codec::Decoder` accepts
fragmented input, resynchronizes on delimiters, drops oversized records until
the next delimiter, and reports raw payloads plus frame activity. The Linux
radio adapter converts those payloads to generic mesh CBOR stream frames.

The codec deliberately does not depend on `mesh`, JSON, ESP-IDF, or the host
runtime; it uses only `core` and `alloc`. This lets the host adapter and ESP32
firmware use the same framing implementation.
Generic CBOR stream conversion belongs to `ssh-mesh/crates/mesh` and the host
adapter.

## Service boundary

USB serial discovery, managed UDS/TCP forwards, RFC2217 compatibility, serial
logs, and ESP32 command handling are documented in
[`lmesh-uart/API.md`](../lmesh-uart/API.md). Its normal
mesh-init socket is `/run/mesh/lmesh-uart/mesh.sock`.

Generic text, JSON, JSON-RPC, CBOR, JSONL, and schema loading are supplied by
`ssh-mesh/crates/mesh` and are shared by all services.
