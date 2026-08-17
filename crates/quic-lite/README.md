# Device Mesh Transport

The transport is based on - but not compatible with - QUIC (RFC9000), implementing the short packets and
flow/congestion control using same packet and frame formats and semantics.

It is intentionally NOT including encryption at the transport level: 
- the mesh is expected to use Istio HBONE or similar application level e2e encryption and overlay network
- there is zero trust between devices: this is not 'client to trusted server using ACME certs', but random
devices acting as completely untrusted proxies.

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

## Differences from QUIC

- no encryption
- out-of-band handshake - the association may be established by a NAN active sub packet, a LoRA message or by
the control plane.
- no long headers.

## Future changes

Each ESP32 device will get a secret key, shared with the control plane - and will derive keys for MAC signing.
No encryption at this level - there is still no trust in any of the nodes - but it may provide access control
and allow for priorities/QoS to be enforced when traffic transits cooperating/owned paths.


## History 

My first attempt to implement an Android-only device mesh was based on chains of Android hotspots with devices
connected. Because at the time Android AP had a routing bug and all APs had the same IPv4 - the code was using
UDP and IPv6 link local. The bug was fixed long ago - the IP is still the same AFAIK. Instead of a one-off protocol
it is far better to use a subset of a standard. 

Almost the entire code in this package is LLM-generated - already implemented QUIC and H2 once, no fun to
do it again. 