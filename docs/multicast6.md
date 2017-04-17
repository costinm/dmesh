The dmesh project relies heavily on IPv6, and link-local multicast in particular.

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

