# Device Mesh

I started this free-time project ~1 year ago with a simple goal: to communicate
with my family/friends while hiking/skiing in places with no internet or
mobile coverage.

Most of us have recent Android devices - perfectly capable of acting as access
points and communicating over Wifi with each other - however most messaging
applications rely on DNS and some central servers, and the few that allow local
communication that I tried were draining the battery. Also all apps I found
that allowed more than 1 access point (i.e. extended coverage) required rooting
the device - and drained battery even faster.

I realize I started on a very narrow 1st world problem, but most of the code
can help in other cases where people lack good internet connectivity, or
are in situations where the internet becomes unavailable. And I hope some
of the things I learned will help others solve more important problems.

My requirements:

1. Should allow communication even if no device is connected to the 'real' internet.
That means no dependency on DNS or any cloud servers.
2. Minimal battery use - my wife and kids would not use it otherwise (I tried!)
3. Work on non-rooted phones. No extra hardware (routers, etc) needed.
4. Discovery and automatic mesh formation, without manual configs.
5. End-to-end encryption and privacy (the mesh will include untrusted nearby
devices).
6. API should be close enough to GCM or webpush - to allow adaptation of open
source messaging apps (I'm not planning to write a chat app - too many already
and I'm not good at UI).

Non-requirements:
- Internet access - add-ons or other apps can provide SOCKS or VPN that
operates on top of the mesh - but this app is focused on connecting/forwarding
small messages.
- Large networks - worse (or best) case is to expect large group of friends,
or maybe a percentage of the people hiking/skiing/etc.

I've tried several existing applications - battery (2) and manual configs (4) was
the main problem, as well as (3) - rooting and turning ad-hoc. They were
also tied to a chat app that would be used only for local communication - and
didn't have a way to expand the mesh (unless rooted devices/ad-hoc drivers were
used).

There are now quite a few routers capable of mesh (ad-hoc or 802.11s) - but it's
not something you can carry on a hike, and they are focused on internet connectivity -
while my #1 goal is to chat/communicate when the internet is not available.
TODO: clean up the notes on 802.11s and how it fits with my project.



# Local Mesh

The first part of the project deals with the low-level P2P and Wifi. It took
about a year of experiments and false starts (well - only few hours a week
of free time...). Primarily it uses Wifi P2P mode - but it is possible to plug
other channels (bluetooth, or GCM/internet servers if some of the nodes have internet access).

I'll go over the problems and solutions I found so far.

Starting an AP on a regular android device (Requirement #3) is pretty easy using
the Wifi-Direct/P2P API. There is one small problem - it requires user interaction
for a device to connect. For that there is a simple solution - there are several
other projecs that use this - simply connect as a client, using a side-channel
to provision the Wifi keys.

As a side channel, it is natural to use the ability of the AP to announce
a DNS-SD record - again something well known, making it possible to do (2).

(4) is hard: a device in AP mode uses a lot of power, in particular if they
hold wake locks and keep the device from going to sleep. The
solution is to use a round-robin or other mechanism in which each device
in the network acts as an AP for short interval. However the real issue
was doze mode - regardless of an app 'foreground' or 'whitelisted' status
and any wake locks I tried, the DHCP server will not respond.

Without DHCP - the client connection times out and nothing works.

The solution I found is to simply use reflection and configure a random
static IPv4 address - and then use IPv6 for the actual communication.
Each device gets a 'local' address, usually based on the
MAC address.

The device acting as AP will announce it's SSID, password, and the local IPv6
address - with the "._dm._udp" suffix. It will also include few extra bits -
like battery status, still working on details (also looking at 802.11s specs
to keep it close, since for routing for larger nets I'll probably use it - not
there yet).

Any nearby device will configure a random IPv4 address, connect - and register with
the AP using the IPv6 from the announcement.

So far this works for chains of devices - I haven't found a good way for a device to act
as client on 2 networks, but most KitKat+ devices I've tested can connect
as client and run a P2P server - extending the network.

TODO: some drawing of a chain of APs, each with local devices connected.

Biggest problem is 'split' networks - i.e. the formation of 2 chains of
devices that can't communicate with each other - this is an issue to handle
at the cross-device layer. Possible options:
- sync between the chains, by having a client switch accorss multiple APs and
syncing with each AP is doable. Messages will have some delay - but they
can carry path info so the topology of the network may be changed
- bluetooth or other links between the nets
- negotiating the formation of a single chain (using the advertisment)
- a pair of cheap ESP8266 or other low-end wifi, with a battery, acting
as a bridge between each device chain. Only need to forward UDP packets, more
than 2 can be used. It is also possible to have the cheap devices act as AP.

Unfortunately I have too little free time...

TODO: document initial discovery / scanning / etc.

Code and details for the low level library in lib-lm.

# Cross Device Mesh

The second part of the project - code is still too embarasingly ugly to put on
github - handles forwarding of messages across clients and APs. It is
based on the Webpush protocol, with a bit of UDP for small messages. Each device
running in AP mode will also run a server - with webpush, gRPC and UDP (and HTTP).
I'm using a native component in golang for HTTP/2 and encryption - it only runs
in the intervals when each device has its rotation as 'master'. The UDP
is in a java service, using foreground (and optionally battery-optimization
whitelisting).

Goals:

2.1. No dependency on DNS or any Internet server
2.2. If one of the devices has Internet - it will _not_ be used by other
devices in the mesh - except for small messages.
2.3. Support poorly connected nodes - 'real time' messages while a node is connected,
and "email"-like behevior if the connection is spotty (similar with GCM and webpush)
2.4. Maximum possible privacy: packets are routed trough untrusted nodes.
2.5. Discovery of nearby known devices (friends) without leaking information to
non-friends.

On 2.2: it should be possible to whitelist a small set of devices (family) and
have each use the internet ( using a SOCKS proxy, etc - since all has to be user
 space ). This also precludes the use of the "AP hotspot" mode, since I can't
 block the forwarding of packets, they happen in kernel. With WifiDirect forwarding
 is not enabled - so my app can control and handle forwarding at the SOCKS
 or HTTP proxy level. (I plan to play with the VPN APIs as well).

On 2.4: while Wifi has encryption, in practice I don't think anyone should
trust random free Access points - the encryption is only between your phone
and an AP where a stranger can see all the traffic in clear. This project is
effectively creating an un-encrypted Wifi network (since the keys are shared) -
but it is not worse than connecting to the AP in a sky resort or coffee shop.
Webpush encryption is pretty good - the difficulty is actually in protecting
the identity of each node, few phones rotate the MAC address. My approach
is inspired from Onion router, but it's a bit harder, Onion relies on a number
of somewhat trusted servers on the internet.

Since the goal is to communicate in the absence of Internet connections, no way
for devices to get TLS certificates or rely on a central trusted identiy
provider. Each device will generate a self-signed cert - and remember the
public key of eacy pair, similar with SSH protocol.
While I know it's not best practice - the same key pair will also be used
for the end-to-end encryption, according to Webpush protocol.

In other words:
- each device gets an EC256 key pair, which acts as its primary identity in
the mesh
- using other mechanisms (pairing, etc) a subset of the keys are associated
with contacts.
- when the device acts as an AP/server, it'll present a self-signed cert and
its public key
- when a message is sent to a device, the 'address' is its public key, and
that is also used to encrypt the message (well - when I have time I plan
to use 2 public keys).
- each message includes a VAPID token (see webpush), signed by the private
key of the sender. Which is also the 'reply' address.
- mapping public key to contacts happens outside of the mesh (similar with
GCM/webpush)


TODO: more details on why webpush - e2e encryption, etc.

# Scale

I'm testing with all the old devices I have (and few cheap ones I bought), since
I didn't get to hacking an open-source chat app I can't yet test on real people.

But so far it seems getting ~10 AP nodes active and linked is pretty easy, and
each AP can hold at least 10 clients - I expect 100/node. So if about 1000
people go hiking and each has the app installed - it should work. Larger
networks, by linking multiple meshes are possible - but that would be a
different project, requiring some sharding and at least a couple of 'bridges'
(bluetooth or multi-client IoT devices).

