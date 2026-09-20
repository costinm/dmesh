# Device Mesh

The project goal is to provide communication paths across ad-hoc,
untrusted device-to-device links. Unlike other mesh projects it is 
not tied to a protocol, medium or device type - but attempts to use
multiple transports.

It expects a secure overlay on top of the mesh - like Istio H-Bone or 
SSH, HTTPS or other protocols, with a (virtual) IPv6 address that may 
optionally be routed via an egress gateway to the Internet and receive
requests via an ingress gateway.

Nodes can communicate using streams and messaging - and discover services
and other nodes using multiple (untrusted) control planes. 

Battery optimization is a MAJOR design factor - most of the project is designed
around keeping everything asleep and minimizing power.

The central sync and discovery is a custom subset of WifiAware/NAN implementation for ESP32 and Linux, interoperable with Android and allowing
ESP32 devices to enter light sleep between the discovery windows. The protocol
uses ESP-NOW as a transport for NAN frames if an Android NAN cluster is not discovered - since ESP32 can't send NAN beacons, but the rest of the discovery/sync protocol is unchanged.


## Devices

Current project support Linux (low end or normal servers/laptops) - but it is
mainly focused on Android and ESP32 devices. There are many old or cheap
phones - and ESP32 is very cheap, allowing very low cost middle boxes, 
with small solar pannels or batteries.

The firmware runs on ESP32 classic and the new RISC-V variants.

## Transports

- WiFi AP-STA chains: this is the baseline, works on Android/Linux/ESP32. Since the mesh doesn't 
rely on link-local security and doesn't trust APs or middle boxes - open networks or 'well-known keys' 
are fine.

- ESP-NOW - with an experimental Linux driver for ESP-NOW (using standard rate), for longer-range 
high speed. Unlike AP-STA, which is optimized for speed - NOW is optimized for range and battery,
using 'action frames' which are the only kind of data that common drivers give access to. 

- LoRA and FSK - if the ESP device has the required chip - longer range and lower speed, but good
enough for chat and shell

- USB and BLE - primariliy betewen android/linux and ESP32 - unrooted Android can't use ESP-NOW
and has (privacy driven) limitations on WiFi modes.

- (planned) 802.11ah - once I get some hardware, or any other radio that allows data send and receive

The idea is to use what you have available - at highest speed and lowest power to form a chain
to a gateway. The gateways can complete the path over the Internet or are local powered devices
that have better connectivity.


## Protocols

A subset of QUIC - for congestion and flow control and packet format - is used instead of a custom protocol.

Stream use normal QUIC short  data frames - but without IP/UDP dependency. On WiFi
or ethernet - UDP is still used, but ESP-NOW, FSK, USB send the QUIC packet
directly on the wire, using only the 'destination connection ID' for forwarding.

Communication uses short lived and dynamic multi-path circuits, with local
control planes (powered devices - or rotating battery devices) maintaining
discovery information.

