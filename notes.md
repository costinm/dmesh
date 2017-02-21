# DNS-SD discovery
Did some experiments - before finding that IPv4 won't work well or getting P2P discovery to work reliably.
Battery usage isn't good - DNS-SD requires a wake lock and it gets a lot of traffic. It doesn't seem to
work well in doze mode either.

The problem is that all devices in the net keep repeating theier announcement - and each
multicast wakes up the radio and sometimes the device ( read some sites claiming some phones handle
this in firmware, but I suspect it still costs battery ).  In android, if no multicast lock is help
the radio will not listen for any multicast, and helding multicast locks in doze isn't great.

## How it works
Did some tcpdumps and reading: each (local) multicast address is mapped to a MAC address. Sending 
doesn't require ARP - it is simply a direct send to the given MAC. The receiving node needs to
setup the Wifi controller's filters and add the required MAC. For non-local multicast there
are the standard ICMP packets - but there is no use for it in my project.

 
# DMesh discovery
For this project, there are 2 levels of discovery: at Wifi level the (rotating) active node
announces its own local IPv6 address. No multicast is needed - when a node connects it registers
with the 'active' master, which can send back the list of other known nodes or messages. It is
possible to slow down the 'pings' to match doze windows and minimize wakeups. A device using the
mesh mode doesn't need any multicast.

As an optimization I plan to transfer the 'directory' from nodes as part of a smarter rotation,
but simply re-creating the mesh seems to work well enough.

If a device is connected to a non-DMesh AP - possibly one with real Internet connection, it'll
listen on an IPv6 multicast address while in 'active' mode. On connect and in the doze window
it'll send discovery multicast packets. I'm not using the DNS-SD address since it's too noisy.
Multicast on IPv6 took a while to get right - the trick seems to be to allways specify the 
interface.

# IW
On rooted android (and linux) it's very useful to check the 'iw' output - it shows
among other things if the device supports P2P, real mesh (802.11s) - and in particular 
how what combinations of modes are possible at hardware level.

Unfortunately the Android framework state machine is pretty strict - you can't start
hotspot AP at the same time with a STA, and it doesn't appear possible to connect
to 2 APs at the same time, only one active Wifi STA.
# 802.11s

```
# Add virtual interface on phy device, managed, monitor, mesh, wds
iw phy wlxa42bb0bd00e3 interface add mesh0 type mp mesh_id dm-aps
iw m0 set channel 6
# rename the interface
ip link set  wlx00c0ca849758 name m0 

iw dev -> show all devices
iw list | grep "Supported in"  -A 9
# Look for 'mesh' mode.

iw wlan0 station dump -> shows all mesh stations

iw dev wlan0 get mesh_param
mesh_fwding = 1

# On OpenWRT /etc/config/wireless:
config wifi-iface
        option device 'radio0'
        option encryption 'none'
        option ssid 'dm-aps'
        option mode 'mesh'
        option mesh_id 'dm-aps'
        option network 'lan'
```

Important to remember: the 'mesh' interface can only connect with other 'mesh' nodes, it is 
not a 'real' AP. And most android devices seem to hate it - lots of logs about bad SSID.

The periodic broadcast is set to 1 second instead of 0.1 sec for regular AP - so less noise
and battery use. 

Proper way to setup is have the mesh interface bridged with an AP or STA virtual interface.
In my setup they are on a different VLAN than the rest of the house, with an open
'Guest' network - similar with DMesh. 

# IPv6 

Most useful commands, work on android (rooted): 
```
ip -6 route show
ip -6 neigh show
```

