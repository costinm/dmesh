
Quick notes on IPv6 multicast on android - in particular link-local.

After many experiments, the magic incantation is:

```
InetAddress ia = InetAddress.getByName(""FF02::5228");
MulticastSocket ms = new MulticastSocket(new InetSocketAddress(sport));
ms.setNetworkInterface(wifiIf); // probably not needed, but why not
ms.joinGroup(new InetSocketAddress(ia, sport), wifiIf);
```

To check that it is on  the right interface:

```
cat /proc/net/igmp6

5    wlan0           ff020000000000000000000000005228     1 00000004 0

(by default it tends to be on p2p0)

For 'group owner/AP'
157  p2p-p2p0-1      ff020000000000000000000000005228     1 00000004 0
```

The interface is critical, to get it:

```
// P2P master
WifiP2pGroup info; // from WIFI_P2P_CONNECTION_CHANGED_ACTION
NetworkInterface.getByName(info.getInterface());

// client - from CONNECTIVITY_ACTION
 Network[] nets = cm.getAllNetworks();
 for (Network n: nets) {
   // if connected, type WIFI
   LinkProperties lp = ctl.cm.getLinkProperties(n);
   ni = NetworkInterface.getByName(lp.getInterfaceName());
 }
```

