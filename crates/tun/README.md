# mesh-tun support

The intent of `mesh-tun` is to support packet capture and forwarding for:

- Android VPN through a caller-provided TUN fd.
- Bubblewrap/container namespaces through a TAP device created inside the target netns.
- user-only VMs as an addition/alternative to passt, with further encryption and tunneling.

Passt is still the reference design for QEMU/CrosVM integration. It is designed
for VM packet exchange over an AF_UNIX socket or vhost-user, with no host
`CAP_NET_ADMIN`. `vhost-device-net` provides a library for handling vhost-user.

The passt VM integration receives L2 frames from QEMU/CrosVM over UDS or
vhost-user. The pasta container integration creates a TAP interface inside the
target network namespace and reads/writes Ethernet frames from the TAP fd.

The smoltcp library was used for some experimental termination, but the intent is
to use packet parsing to route selected traffic to an H2 or ztunnel
VM/namespace. The original implementation in Go used gVisor and lwip for TUN and
Istio iptables for containers - but the 'passt' approach appears simpler and may
be faster.

This package may be a good extension to Istio, as an alternative to iptables and
to support VMs.

## Passt and Pasta

Pasta avoids TPROXY/REDIRECT - and one round through the kernel TCP stack - by
implementing a tiny subset of TCP and carefully managing the buffers and flow,
without the complexity of retries and general TCP stack.

For containers it works by creating a TAP device in the target namespace. The host-side process opens `/dev/net/tun` after entering that namespace, requests
`IFF_TAP | IFF_NO_PI`, configures the namespace interface, and then reads and
writes L2 frames on the TAP fd.

Passt avoid a full guest-side proxy stack by doing light parsing/generation for packets between VM/container and host while using the host's real addresses and ports for the connection. For mesh - we don't want to use the host real address,
but to tunnel the connection to another container or VM, encrypting over the wire
and preserving and verifying both ends. 

For egress to non-mesh destinations - even with Istio the destination typically sees a NAT address. 

If the destination is in same VPC, with Istio and K8S the Pod/VM
internal address would be visible - while with mesh-tun/passt the host address.
This is the main incompatibility/change - mainly for K8S environments, but
it makes the behavior more compatible with non-K8S workloads and bwrap/podman
and other isolation mechanisms that may be nested inside a Pod.

One of the observations with Istio/K8S is that Pods are often used to run build/test
systems or even dev machines, or agents. Having an nested user-space bwrap or 
podman, inside the Pod, to isolate specific features is quite useful - and the 
mesh-tun is optimized for this use case, trading off the in-VPC-no-mesh-egress use case which can't be supported without the expensive network infra.

Besides the performance benefits of skipping a TCP stack - the switch/route infrastructure doesn't have to handle the Pod/nested VM VIPs - only host IPs, and with a mesh overlay the only connections are H2 or SSH multiplexed connections between hosts. That means far fewer IPs and TCP connections (and associated
memory/cost) in the bridge/routers and less complexity on allocating infra IPs.

The main change between original Passt/Pasta and this package is the handling of
the host networking. Instead of proxying to an actual host socket for egress, it
is going to the ssh-mesh server (or ztunnel in future) or route to another 
container/VM on same host, with Istio-style policies/telemetry/identity..

This is an experiment. Passt/Pasta's implementation simplicity and focus are amazing, but policy and encryption are also important, and having Passt host
traffic go through ztunnel/etc is cutting both performance/simplicity and is losing information needed by mesh.


## TODO

Transform this package into a subset of Istio ztunnel, using Android TUN,
namespace TAP, and VM UDS/vhost-user capture instead of iptables, and passt-style
socket handling instead of terminating TCP and starting a second TCP stream over
H2/HBONE.

The flow will be:
1. Capture TCP/UDP packets from Android TUN, namespace TAP, or VM UDS/vhost-user.
2. `mesh-tun` creates the equivalent passt sockets, with hooks for policies
   such as limits, throttling, and monitoring.

[] Implement the passt mechanisms so Android TUN and VM/container packet sources
use regular sockets on the public net while still intercepting traffic.


[] add vhost-user mode, with multiple VMs supported (unlike passt) - supporting
coordinated policies across all VMs.

[] map the passt-like 'sockets' to SSH/H2 tunnels - and decode/route this on the other end. In this mode, for mesh-local traffic it is like hbone - but with raw IP
frames in the stream, without passing through the extra TCP stack. This adds encryption and the common policy control - like ztunnel
