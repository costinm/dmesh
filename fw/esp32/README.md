# Local mesh firmware

This is intended for devices that may be used for local communication when 
Internet is not available - using alternative transports like Lora (MeshTastic, MeshCore, raw), FSK, ESP-NOW for longer distance messaging. Like Internet, should
be able to use each L2 as needed - and optimize for radio and battery efficiency
instead of single-transport consistency.

It is based on the idea that a controller should optimize for power by maximizing sleep - using interrupts and leaving routing and complex logic, including UI, to Android/iPhone/Linux.

For networking, the goal is to choose best L0 and neighbor to minimize air time
and transmit power - unlike Meshtastic/MeshCore and many single-transport meshes
it allows the host and control plane to use a mix of low-level protocols and wire formats. Devices do not forward automatically - frames are sent to an Android
or Linux server that may decide how to route. The radio
frames are broadcast - the payload is expected to be encrypted by host - a node
with internet connection that is not the intended destination or proxy can observe
the frame and route it over Internet, get an ack signed by receiver - and take
over 'next hop' role.

Like Tasmota, the pins are set at config time - so one binary can be installed
on any device with the right CPU - and commands may make use of analog, I2C and
other pins for additional functions, but primarily driven by the host.

## Security

Still WIP - UART and BLE pairings are currently used for commands. The plan is to
do no encryption on controllers for networking path. The devices will be 
provisioned with a cert and private key - for the admin/control path.

Because radio transmission consume air time for all devices in an area - it is 
better to forward low-speed/messaging traffic from untrusted/foreign devices over
high speed / lowerst power paths - keeping the FSK/LoRA only for long 
distance paths that can't be crossed otherwise. Because routers - and foreign 
control planes - can't be trusted, we need each 'mesh' (== common root CA and administrative/trust domain) to make routing decisions that may transit trough
other meshes, if a lower-power/air time path exists.

## Networking

The firmware is setting 'hop count' to 0 in MeshTastic mode, devices should be able to communicate but will not forward. Routing in mesh is using 'infrastructure' like
MeshCore and NAN - assuming a linux-class machine handling discovery and
picking Gateways - just like a Cloud Mesh.

Network is not trusted - the controllers are not involved in security or encription, 
nor in routing decisions. 

Discovery can select local 'egress gateways' - similar to NAN master elections.

The goal is for each device to pick a gateway that can be reached with Wifi frames,
fallback to LoRA only if nothing is in Wifi range or the Wifi paths can't find 
the destination device - or the Internet.

When selecting, signal strength should be used to pick close enough (but not too
close) devices that don't require max transmit power - and adjust the power and speed. Same for LoRA. Using MEDIUM_FAST (Bay Area) - but I expect to use 
discovery and switch to a different channel with higher speed/lower power if 
possible. An interesting question I'm trying to solve is what is the range
of 'raw Wifi' - vs LoRA.

## Changes from MeshTastic

- no UI, web server, AP or Client modes - just packet processing.
- clear separation between battery-powered 'companions' and 'infra'.
- deep sleep and BLE to the paired android in companions - using LoRA and raw Wifi for mesh transport. 
- raw Wifi is going to be used whenever possible, LoRA sparingly.

Not changed:
- packet format (with extensions), radio frequency. 
- a phone may process the meshtastic messages - just not handled on the low end ESP device. 
- forwarding may still be used by a phone using meshtastic text protocols.

Most important for battery operated is the use of deep sleep and optimizing the 
LoRA airtime by using directed circuits on infra nodes, with WiFi (ESP-Now like frames) when possible.

The firmware is generic - LoRA is configured by setting the PINs and chip type.
It uses a text protocol (with an optional CBOR planned), and has many probe and 
debug commands (inspired by old bus pirate)

## Other features

Main feature is 'no features' - no plan for UI on small LCDs, web servers, etc.

Ability to use the pins to read sensors or perform actions is partially available 
and may be extended - but will require some crypto and not a priority.