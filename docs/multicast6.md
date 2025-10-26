There are few uses for multicast in this project.

1. Discovery of the master address in local net.  In normal dmesh using P2P APs, the 
P2P DNS-SD also announces the IPv6 of the master, so multicast is mostly a backup. When connected
to a regular AP, multicast is the main mechanism to find an active DMesh 'master'. Just like AP role,
the master role rotates to minimize (spread) battery use.
 
2. Address allocation (old devices). Since DHCP doesn't work reliably in power-saving mode 
(TODO: link to details), devices use a random address, and generate a multicast when connecting.
Everything is done in user space - so we have no good way to probe before allocating the address,
it has to be set before 'wifi connect'. In case of conflict, the 'master' will send back a new 
address, and the client will reconnect with the allocated address. The response will be sent
as multicast - to make sure the device gets it. Unicast wouldn't work since ARP may point to the other
device. This is not yet implemented (most of my tests are in IPv6-capable devices). Note that an IPv4
device can't run in both AP/GO and CLI mode: the 192.168.49.1 address will be active on both the 
dual-role client and the AP. Older devices don't allow binding to an interface (and even in newer
devices it doesn't appear to work). So an old device can connect to DMesh, expose services (share
storage, etc) - but it can't extend the network in pure 'mesh' mode. If the device is connected
 to a normal AP - it can also start GO mode and extend the coverage. 

3. Communication from AP to client: unfortunately I found no way to send an UDP6 from a device
running as 'group owner' - setting the network interface, binding, etc don't appear to work. It 
works ok from client to AP, just not the other way around.

```

 Device1: 
 p2p0: 192.168.49.1
 wlan0: 10.x.x.x -> connected to a real AP
 
 Device2:
 p2p0: 192.168.49.1
 wlan0: 192.168.49.2 -> connecte to Device1.p2p0
 
 Device3: 
 p2p0: 192.168.49.1
 wlan0: 192.168.49.2 -> connected to Device2.p2p0
 
 and so on...

```

Because DMesh devices act as both Wifi client and Wifi Direct server, the
same network - 192.168.49.0 - will be set on both wlan0 and p2p interfaces,
making it impossible to send packets from the p2p interface to clients.
In addition, in doze mode the DHCP server is not white-listed, making it impossible
to assing IPv4 addresses to clients. 

The solution to both problems is to use IPv6 link local addresses. However it appears
that sending an IPv6 packet from the p2p interface to a connected client is impossible - 
tcpdump shows receiving works, but nothing goes out. I haven't found the problem - 
it's not in java, it happens with 'netcat' or native programs. For a long time
I thought this effectively killed the project - with no way for the DMesh node to 
communicate with its clients. However it turns out that IP6 multicast does work,
and allows sending from the p2p interface to connected clients.

Once the wlan0 interface is up, a UDP server will be started on both normal 
FE80::MAC+FFFE but also on a FF02:MAC+FFFE. 

A client will use:

```
InetAddress ia = InetAddress.getByName(""FF02::" + localAddress);
MulticastSocket ms = new MulticastSocket(new InetSocketAddress(port));
ms.setNetworkInterface(wifiInterface); 
ms.joinGroup(new InetSocketAddress(ia, sport), wifiIf);
```

The server will listen for multicasts on both wifi and p2p interfaces. It 
uses 2 different multicast addresses - using different ports is not enough,
it seems multicasts are received on the p2p socket even if they are sent on
the wifi interface. A bit confusing, but using different addresses solves the 
problem. 

```
InetAddress ia = InetAddress.getByName(""FF02::5221");
MulticastSocket ms = new MulticastSocket(new InetSocketAddress(sport));
ms.setNetworkInterface(p2pInterface); 

ms.joinGroup(new InetSocketAddress(ia, sport), wifiIf);

InetAddress ia = InetAddress.getByName(""FF02::5223");
MulticastSocket ms = new MulticastSocket(new InetSocketAddress(sport));
ms.setNetworkInterface(wifiInterface); 
ms.joinGroup(new InetSocketAddress(ia, sport), wifiIf);

```

To check that everything is on  the right interface for a node acting as 
both client and server, i.e. connected to a wifi net and expanding it:

The interface is critical:

```
// When running as P2P Group Owner / AP
WifiP2pGroup info; // from WIFI_P2P_CONNECTION_CHANGED_ACTION
NetworkInterface.getByName(info.getInterface());

// As Wifi STA/client (LMP+):
Network[] nets = cm.getAllNetworks();
for (Network n: nets) {
   // if connected, type WIFI
   LinkProperties lp = ctl.cm.getLinkProperties(n);
   ni = NetworkInterface.getByName(lp.getInterfaceName());
}
```


```
cat /proc/net/igmp6

5    wlan0           ff020000000000000000000000005223     1 00000004 0
6    wlan0           ff02000000000000......fffe......     1 00000006 0

(by default it tends to be on p2p0)

For 'group owner/AP'
157  p2p-p2p0-1      ff020000000000000000000000005221     1 00000004 0
```

The NetworkInterface object is critical - on L+ the new cm.getAllNetworks()
call doesn't return the p2p interface - so it has to be retrieved in the 
P2P_CONNECTION_CHANGED callback. 

```
// P2P master
WifiP2pGroup info; // from WIFI_P2P_CONNECTION_CHANGED_ACTION
NetworkInterface.getByName(info.getInterface());

// client - from CONNECTIVITY_ACTION
 Network[] nets = cm.getAllNetworks();
 for (Network n: nets) {
   // if connected and type WIFI
   LinkProperties lp = ctl.cm.getLinkProperties(n);
   ni = NetworkInterface.getByName(lp.getInterfaceName());
 }
```

A simpler (and a bit hacky) solution, but works pre-L (at least on KLP):

```
WifiInfo info = ctl.wm.getConnectionInfo();
wifi4Address = NetUtil.toInetAddress(info.getIpAddress());

Enumeration e = NetworkInterface.getNetworkInterfaces();
...
for (InterfaceAddress ia :networkIf.getInterfaceAddresses()) {
  // get the IPv4 address and the link local IPv6 address
}
if (wifi4Address == inteface IPv4) -> this is the wifi NetworkInterface
if (192.168.49.1 == interface IPv4) -> this is the AP NetworkInterface
```

