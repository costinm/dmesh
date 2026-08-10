# Recovery API

This file owns Recovery's UART control and flash-result contracts. Recovery
keeps its UART reader alive for its entire lifetime, including while Wi-Fi and
the flash worker are running.

## UART control packet

All input is PPP/HDLC-framed CBOR. Recovery does not accept plaintext, DMB1,
newline commands, or a second UART reader. The envelope is a normal method
packet: `{0:68,6:{...}}` (method `68` is `recovery`). Accepted payload keys:

| key | meaning |
|---|---|
| `op` | `reboot_main`, `retry_main`, or omitted for transport update |
| `server` | flash-server address; IPv4/IPv6 is a CBOR byte string in network order (4/16 bytes), with text accepted during migration |
| `ip` | local static address; IPv4/IPv6 is a CBOR byte string in network order (4/16 bytes), with text accepted during migration |
| `gateway` / `gw` | static route address, encoded the same way |
| `mask` | IPv4 netmask as a 4-byte CBOR byte string, with dotted text accepted during migration |
| `port` | flash-server TCP port |
| `ssid` | open Recovery STA SSID |
| `password` | reserved; non-empty passwords are rejected currently |
| `log_level` | ESP log level `0..5` |
| `dry_run` | boolean; receive and validate the transfer without flash writes |

Transport values are runtime-only. The active boot target is RTC state, not
NVS.

The current flash layout is fixed across boot, Recovery, and Main. Clients
advertise this in HELLO and go directly from HELLO to one manifest; they do
not send or receive a partition-table packet or a pre-flash hash list. The
server uses its canonical checked-in table for address and size bookkeeping.
Recovery carries `dry_run` through RTC custom byte `+28` and advertises it in
HELLO mode bit `0x08`; the persistent server copies that request into the
manifest and does not select the mode itself. The server is not restarted per
request.

The two device-side entry points are deliberately explicit:

```text
Main:     recovery dry_run=true reboot=true
Main:     recovery op=connect target=main ... dry_run=true
Recovery: recovery op=transport ... dry_run=true
```

Omitting `dry_run` means a normal flash. The host helper may choose which
request to send, but it cannot turn a normal request into a dry run after the
device has armed the TCP worker.

## Events

Recovery emits `boot.identity` event `60000` on startup. A successful transfer
emits `flash.complete` event `60001`; a failed transfer emits `flash.error`
event `60002`. The flash tuple is:

```text
[role, target, blocks, received_blocks, bytes, elapsed_ms, speed_bps,
 optional_error_bytes]
```

Recovery has role `2`. It emits the terminal event before returning the DRS2
result and before reboot scheduling.

Manifest byte 1 is a signed flags field. Bit 0 (`DRY_RUN`) requests receive
and SHA/bitmap validation without erase, write, or flash readback. The host
sets it with the device-side `dry_run=true` recovery command; a dry run must not update the
device's current-image record.

After joining the flash AP, Recovery emits `recovery.network_up` event `60003`
with tuple `[role, ip_text, bssid_bytes, rssi_dbm]`. Association polling is
not logged repeatedly.

## Manifest settings

Manifest version 2 may carry a bounded KV section. Records are typed and
validated before commit. Recovery rejects boot-selector keys and the `boot`
namespace; Main/Recovery handoff remains RTC-only.
