One of the requirements for DMesh is to implement all routing in user space, since 
it needs to work on un-rooted, regular devices. Most devices will simply act as clients,
with few acting as 'routing nodes', in a round-robin to spread battery use. 

After many iterations, I decided it is best to start with something that is tried
and standard based, and implement user-space variant of 
[802.11s routing](https://en.wikipedia.org/wiki/Hybrid_Wireless_Mesh_Protocol)

I'm still debating on the best way to structure the address: I don't want to touch
the MAC address, since it's not clear how often will be rotated and how. However
the FE80:: link-local address is critical for node communication - and it effectively
encodes the MAC in most cases. So I could extract the 6-bytes MAC, use the full 8-bytes
local part of the IPv6, or use a 3-bytes hash.

The 3-bytes are appealing because after solving the routing, next step will be
to implement the VPN interfaces, so each app on the device can transparently 
use the DMesh. For that I'm planning to give each device a 10.x.y.z address -
so for most cases it'll be identified inside the mesh with 24 bits. A user-space
name server / DHCP will be needed in any case - so it could handle conflicts.
Not sure what's the conflict likelyhood in small nets - link-local addresses 
in 169.254 range have 16 bits of random, and for small networks probing and 
announcing all new nodes is easy. 

Current plan:
1. If a node is connected to a real Wifi network with internet access, it'll
act as a 'root' and advertise itself. 
2. If more nodes are 'root', the nodes on battery will stop advertising if 
some other nodes are on charging.
3. If a node has a single route, even if it acts as AP for multiple devices,
it'll simply forward to the default route, and advertise it's list of connections.
4. For the rest - a combination of RREQ and RREP, similar with HWMP.

If the DMesh has only <200 nodes - it seems practical for each routing node to simply
hold the full routing table, i.e. for each device the list of directly-connected 
devices. This is what I'm implementing first, broadcasting the 
[Node IP6]+[Connected IP6 list] from each router node to all other routers.
