# Local mesh messaging and discovery

Interact at low level with 'modem' devices and wifi for 'local' discovery and communication, with a Mesh-like protocol at a higher level.

The 'mesh' handles end-to-end encryption and will support QUIC or a QUIC-like
protocol adjusted for low-speed/small packets radios. Modems and middle boxes
are not trusted - will operate on 'destination connection/circuit ID' for
forwarding. The mesh will also have a 'control plane' that will aggregate the
local discovered nodes and push both (signed) configs, discovery and circuit
initiations, to simplify the modems. Multiple meshes may coexist and cooperate
in forwarding without trusting each other. This will be handled in other crates,
but important for context. 

LMesh runs as regular user but with CAP_NET_ADMIN. It may register a monitor
interface on wifi or take over a wifi interface, based on configuration, and use
it for NAN discovery, follow-ups and as a non-DS communication medium.

UART forwarding is owned by the separate `lmesh-uart` service. The full lmesh
process retains the shared dispatcher API but does not open or start USB/UART
forwards; it can still use the shared raw-NAN code for mesh operations.

Lmesh is only concerned with accepting and sending packets locally, based on 
control plane and config it may forward packets as well, but is not involved in
routing protocols.

Discovery and packets will track RSSI - and sending config may adjust the transmit
power and the radio used, for example use FSK or LoRA if the destination can't 
be reached with Wifi, or use a very low Wifi power if the destination is very close.

Lmesh is not meant for high-speed communication, but messaging and 'chat-like' 
sessions (including ssh/TUI/agents). If source and destination are close, they can
use P2P/Direct AP/STA - or if a chain of AP/STA gateways can be established to 
an internet point, it is also possible for high-speed.

Lmesh may configure the wifi in open AP/STA mode - zero trust, only QUIC packets
encrypted E2E accepted with the control plane handling auth out of band (similar
to TURN auth). 

The core idea (regarding Wifi) is that a mesh model - with zero trust in infra - does not require the complexity and limitations of WPA, can handle its own encryption
and ACK using QUIC - and build multiple paths for communication, providing a secure
IPv6 overlay network on top.

## Details 

Default:
- Listens on multicast UDP - ff02::5227 on port 5227. Older IPv4 multicast
  support exists for host compatibility, but DMesh raw Wi-Fi discovery uses
  the IPv6-derived multicast MAC 33:33:00:00:52:27.
  Not using DNS-SD because it is too noisy, and the signed UDP is not standard.

- Send/Receive signed announcements, including the public key, cert and IPs
  Respond to multicasts with directed signed response.

- send and receive signed unicast messages, using the discovery data.



## Implementation

`dmesh-rawnan::protocol` owns the shared DMesh BLE/NAN `DM` v1 wire format used
by Android and firmware-adjacent tests. `lmesh::radio_protocol` is a
compatibility re-export. Keep hardware access outside the protocol module:
Android Java owns Android BLE/WiFi Aware permissions and callbacks, while
`lmesh-wifi` owns the Wi-Fi bearer and raw-NAN monitor. The full `lmesh`
service uses the shared raw-NAN monitor through that bearer.

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
