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

The framing core uses only `core` and `alloc`, so firmware and host share it.
The optional Linux `host` feature adds USB serial enumeration without opening
ports, inotify hotplug hints, explicit port ownership, baud and modem-line
control, and complete QUIC-lite frame or connectionless message records.
Unframed boot text is surfaced as a log record for the service layer to encode
as the one-way `log.record` message in the [root API](../../API.md).
