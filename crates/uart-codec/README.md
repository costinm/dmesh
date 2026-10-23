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
- protocol marker: QUIC `0xf7 

PPP wastes 4 bytes with fixed 0xFF address, 0x03 'connection-less, unack', 2 bytes 'protocol' - with 
IPv4, IPv6, LCP (auth, MTU, header compression - which shring the 4 bytes to 1, connection close),
IPCP (old DHCP) protocols. It also has a 2 bytes FCS. Typically LCP removes 3 bytes - the 
result is '0x21' for IPv4, 0x57 IPv6. PPP quirk: first byte is odd, sort of varint using last bit.

PPP also used header compression (Van Jacobson - versus modern 6LoWPAN). 

VJ (RFC1144) is interesting - it looks at TCP. Both side keep 256 connections, compressing
20+20 bytes to ~3 - 1 byte connection ID, delta on Seq Number (packet number), ack and window.
That's what Quic-Lite is also doing - DCID is varint, quic frame handing connection flow control,
with the streams multiplexed and using their own flow control.
 
In 6LoWPAN - IPV6 and UDP are the trget (40+8). The local MAC is used to strip one address (or both
if the destination is local). NHC for UDP - result is 6 bytes in ideal case. 

Unframed boot text is surfaced as a log record for the service layer to encode
as the one-way `log.record` message in the [root API](../../API.md).

## Physical UART rate exchange

Before moving an owned `UartPort` into its asynchronous bearer, lmesh or another
client can call `port.negotiate_baud_blocking(baud)` from a blocking thread.
Supported rates are 115200, 230400, 460800 and 921600. The library waits for the device acknowledgement at the current rate before
changing local line coding. No QUIC session is required, and
neither side persists this volatile exchange. Configure `uart.baud` separately
through the console's NV method for a reboot default.

Negotiate before bearer traffic: records arriving during the exchange are
consumed. A timeout leaves the peer's rate uncertain; reset/reopen at a known
rate before retrying. Native USB-Serial/JTAG has no physical baud and does not
use this exchange. `UART_CODEC_NEGOTIATE_BAUD` remains an optional open-time
wrapper around this same shared method; it is not a dmesh-cli protocol.
