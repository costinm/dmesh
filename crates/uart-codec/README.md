# uart-codec API

`uart-codec` owns the DMesh UART and USB serial. 

UART is special: most transports are packet based (Wi-Fi and BLE) with framing and CRC.
- Uart is byte oriented
- may lose/mangle bytes at high speeds - byte parity is too much overhead and usually off
- may get mixed with line-oriented logs (boot logs, etc) - which are useful and need to be separated
- device reset on CTS
- changing transmit rates
- notifications when UART and USB devices are added/removed on linux

This crate implements a packet protocol for quic-lite - while separating the logs and special
features.

Note that a CRC is not yet added at this layer - the plan is to include an HMAC (for local auth
and to prevent changes), it will also detect accidental changes like a CRC.

## Physical framing

UART records use an HDLC/PPP-style delimiter and escaping:

- delimiter: `0x7e`;
- escape: `0x7d`;
- escaped byte: `byte ^ 0x20`;
- maximum record: 4,000 payload bytes - larger than Quic MTU because text may also be received.
- QUIC marker: `0xf7`- may be removed

Unframed boot text is surfaced as a log record for the service layer to encode
as the one-way `log.record` message in the [root API](../../API.md).
