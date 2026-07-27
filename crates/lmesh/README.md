# Local mesh messaging and discovery

- Listens on multicast UDP - ff02::5227 on port 5227. Older IPv4 multicast
  support may exist for host compatibility, but DMesh raw Wi-Fi discovery uses
  the IPv6-derived multicast MAC 33:33:00:00:52:27.
- Send/Receive signed announcements, including the public key, cert and IPs
- respond to multicasts with directed signed response.
- send and receive signed unicast messages, using the discovery data.

This is not using DNS-SD because it is too noisy, and the signed UDP is not standard.

## Implementation

This is also a test to verify the UDS and 'job' style. The server
may run permanently, periodically or may be included in another app.

The primitive operations - start, announce and callbacks - are very 
simple and can be exposed as JSON commands over UDS or JNI/native.

`lmesh::radio_protocol` also owns the DMesh BLE/NAN `DM` v1 wire format used by
Android and firmware-adjacent tests. Keep hardware access outside this module:
Android Java owns Android BLE/WiFi Aware permissions and callbacks, while
future mesh-init Linux support should own `wpa_supplicant` and BLE adapter
control and call the shared protocol helpers.

Local adapters should use message/pubsub style boundaries with text command
metadata, raw byte payloads, and optional FDs. CBOR is a good future fit for
structured binary frames; protobuf is not planned.

The current radio architecture, verified Linux Wi-Fi/USB results, reproduction
commands, and next-session test order are in
`../../notes/ai/lmesh-radio-handoff.md`.

## TODO

- add the actual signature
- add a certificate
- use ssh to generate the key and certificate
- test signing and verification
- any info should be in the certificate
- include current list of public and mesh IPs, if any.
- save valid announcements to files, load from files, GC and timestamp if not updated in 1 day.
