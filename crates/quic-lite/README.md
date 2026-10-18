# Device Mesh Transport

The transport is based on - but not compatible with - QUIC (RFC9000), implementing the short packets and
flow/congestion control using same packet and frame formats and semantics.

Optional `packet-protection` provides pre-shared-key packet protection. This is
not a TLS handshake or full QUIC v1 interoperability. Application-level e2e
encryption remains useful when forwarding through untrusted devices.

The protocol is also not dependent on UDP and is not using the IP and port - relies only on a forwarder-specific
DCID and a chain of forwarders that swap the DCID at each hop. That means the packets can also be sent over 
ESP-NOW / NAN, custom FSK radio, LoRA - including via multiple paths.

There is no expectation that the forwarders will be reliable - it is expected some will be malicious, some will
be in a bad state and a few may work well enough. 

The device mesh - like Istio - is using 'control planes' managing sets of devices (Android, hosts, ESP32, etc) 
under the same org/user control. 

The forwarding paths should be optimized to reduce transmit power/air time - not for 'ownership of the path' -
if a packet can go trough 2-3 foreign hops at high speed/low power wifi - instead of one slow hop on same-owner
device - the first choice is preferred, falling back and avoiding unreliable forwarders.

## Application streams

Applications use reliable bidirectional byte streams. This is the same model
as a TCP connection, an HTTP/2 stream, or an SSH channel: an application opens
or accepts a stream, reads bytes, writes bytes, and closes its write side to
send the end of the stream. Applications do not handle packet numbers,
packet sizes, stream offsets, acknowledgements, or connection IDs.

On a Tokio host, a QUIC-lite stream implements `tokio::io::AsyncRead` and
`tokio::io::AsyncWrite`. A write waits when the peer's receive window, the
connection's send window, or the selected link cannot currently accept more
data. Incoming acknowledgements, window updates, and link send completion wake
the task in the same way that TCP socket readiness wakes a task.

Firmware uses the same stream state without requiring Tokio. It attempts one
write when notified that the stream can make progress. Receive data may be
handled immediately through a callback or retained as a packet-pool lease. A
retained chunk returns receive-window space and releases its packet only when
the application reports completion.

The host and firmware interfaces are views of the same stream state. They do
not maintain separate ordering, retransmission, or flow-control state. The
examples show the intended use:

- `tokio_stream.rs` uses the standard Tokio read and write traits.
- `nostd::NoStdRuntime` attaches bearers, advances one queued event at a time,
  and exposes the same association and stream operations without an async
  executor. Applications never pass packet bytes into it.
- `leased_stream.rs` retains received packet storage until the application is
  finished with a chunk.

Request/response helpers may be built on top of a stream, like an HTTP client
convenience method, but they are not the transport interface. Large requests,
uploads, downloads, and diagnostic probes use the same stream API.

## Pool-backed DATAGRAMs

RFC 9221 frame types `0x30` and `0x31` carry opaque, unreliable payloads.
DATAGRAMs are ACK-eliciting and share congestion control/pacing, but consume no
stream or connection flow-control credit and retain no payload for repair.

Support is enabled by default: `ConnectionLimits.max_datagram_frame_size` is
`DEFAULT_MAX_DATAGRAM_FRAME_SIZE` (currently 1071 bytes, including the frame
header; 1070 payload bytes with our encoding). Set it to zero to disable it;
association and driver receive limits
control advertisement/admission.
The advertised limit includes the frame header; the usable payload must also
fit the physical MTU, outer packet header and optional protection tag. There is
no fragmentation. Negotiation uses parameter `0x20` in an extended DMesh
bootstrap profile, not a QUIC v1 handshake. Disabled support preserves the old
bootstrap bytes; older peers cannot decode the enabled profile.

`QuicNode::send_datagram(association, packet, priority)` and
`TokioAssociation::send_datagram(packet, priority).await` consume an existing
pool-backed `OwnedPacket` on admission. Refusal returns `DatagramSendError`
containing its reason and the exact unchanged packet. Admission does not mean
physical transmission or peer/application delivery. Encapsulation uses existing
headroom without moving the payload. Each send uses one dedicated packet with
one DATAGRAM frame, never shared with STREAM or other data frames. Supply the
payload range in a pool lease with adequate prefix and suffix capacity for
packet framing, bearer requirements and optional protection. Both priorities obey congestion/pacing;
`Low` also checks spare pool capacity and advisory stream-window headroom and
runs after ordinary driver operations. Tokio packet handoff is capacity-charged
to a semaphore sized from the node pool at driver construction.

`set_datagram_handler` receives one `ReceivedDatagram` containing association,
ingress metadata and a public `packet: OwnedPacket` already ranged to the opaque
payload. The callback owns the packet, may change its range/prefix/suffix and
pass it directly to a bearer, retain it, or drop it to return storage to the pool.
Dedicated receive packets transfer the original pool lease with no payload copy.
For foreign peers coalescing several DATAGRAMs, earlier payloads are copied into
distinct pool packets and the last keeps the RX lease; exhausted fallback
capacity drops unreliable payloads, not reliable frames. An absent handler
drops payloads after transport accounting.
A handler must not await its own owner; use `try_send_datagram` to queue work.
Application CBOR envelopes, discovery and companion routing remain outside QUIC.

The pool keeps data in the middle: 80-byte prefix, 1100-byte middle region,
24-byte suffix. Crypto uses 16 bytes of that existing suffix, with 4 bytes for
hop-by-hop authentication and 4 spare/FCS bytes; do not reserve a second crypto
trailer. The prefix covers ESP station 802.11 + LLC + IPv6 + UDP framing without
teaching QUIC about those protocols. Outgoing payload placement also needs room
for the QUIC/DATAGRAM headers before it: conservatively 94 prefix bytes
(80 physical + 13 QUIC + 1 DATAGRAM).

Storage capacity and wire MTU are separate checks. The 1100-byte bearer
QUIC-packet MTU includes the crypto tag, so the conservative default opaque
payload is 1100 - 13 QUIC header - 1 DATAGRAM header - 16 tag = 1070 bytes.
The tag is counted once against this wire limit and uses existing pool tail
space in place. Actual bearer prefix/suffix requirements and MTU are preflighted
before packet ownership is consumed.

The direct node send/receive DATAGRAM path uses existing pool storage and
preallocated transmission metadata; the coalesced-peer fallback acquires pool
slots, not heap payload buffers or a metadata vector. The Tokio convenience
handoff still allocates a boxed command and oneshot reply state per submission;
it is not an allocation-free control path. Higher-level scheduling/convenience
APIs are separate from the direct packet-ownership primitive.

## Long headers and forwarding labels

Pre-connection traffic uses the RFC 9000 long-header field layout with the
DMesh extension version `0x444d0001`. An Initial-type packet carries connection
setup: the request has an empty DCID and the client's receive CID in SCID; the
response addresses that CID in DCID and advertises the server receive CID in
SCID. Initial protection and full QUIC transport-parameter negotiation are not
implemented yet, which is why this must not claim QUIC version 1.

Every nonzero local DCID has exactly one unified target at a node: either a
local endpoint or an opaque forwarding rule. A forwarding rule replaces only
the DCID in caller-supplied output storage and sends the unchanged packet
number and body to an adapter-owned next-hop handle. It does not parse CBOR or
QUIC frames, and it does not rely on source address, bearer, or ingress peer.

The forwarding machinery is available to the node runtimes once circuit setup
installs a forwarding rule. Runtimes submit the rewritten packet to the
rule's registered next-hop bearer and address. Forwarding policy, leases, and
quotas are enforced by the node's relay router.

## Differences from QUIC

- optional pre-shared-key protection rather than a TLS handshake
- out-of-band handshake - the association may be established by a NAN active sub packet, a LoRA message or by
the control plane.
- established packets use short headers; setup and connectionless extensions
  use the custom-version long header described above.

## Future changes

- Relay: each ESP32 device will get a secret key, shared with the control plane - and will derive keys for MAC signing.
No encryption at this level - there is still no trust in any of the nodes - but it may provide access control
and allow for priorities/QoS to be enforced when traffic transits cooperating/owned paths.

- short messages: streams with one packet and FIN, or with content-length in first frame (need to add part of envelope
  to quic level) and <3-4k should get priority. RPC tail latency

- Out-of-order is the main memory user, controlled by advertised window - for re-transmit buffers the sender can put back-pressure or app write. A 
  special write mode 'app backed' or 'callback to app' can be added to avoid retransmit buffers on app. Or app using
  and holding quic buffers (with space in front/back for marshalling), like logger.

## History 

My first attempt to implement an Android-only device mesh was based on chains of Android hotspots with devices
connected. Because at the time Android AP had a routing bug and all APs had the same IPv4 - the code was using
UDP and IPv6 link local. The bug was fixed long ago - the IP is still the same AFAIK. Instead of a one-off protocol
it is far better to use a subset of a standard. 

Almost the entire code in this package is LLM-generated - already implemented QUIC and H2 once, no fun to
do it again.
