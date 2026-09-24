# uart-codec API

`uart-codec` is the low-level crate behind the UART transport.

## Physical framing

UART records use an HDLC/PPP-style delimiter and escaping:

- delimiter: `0x7e`;
- escape: `0x7d`;
- escaped byte: `byte ^ 0x20`;
- maximum record: 4,000 payload bytes.

`codec::encode_payload` wraps one raw payload. `codec::Decoder` accepts
fragmented input, resynchronizes on delimiters, drops oversized records until
the next delimiter, and reports raw payloads plus frame activity.

The codec deliberately does not depend on `mesh`, JSON, ESP-IDF, or the host
runtime; it uses only `core` and `alloc`. This lets the host adapter and ESP32
firmware use the same framing implementation.
