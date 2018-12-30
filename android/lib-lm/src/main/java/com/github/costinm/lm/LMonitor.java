package com.github.costinm.lm;

import android.annotation.TargetApi;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pGroup;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.PowerManager;
import android.support.annotation.NonNull;
import android.util.Log;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static android.net.wifi.WifiManager.WIFI_STATE_CHANGED_ACTION;

/**
 * Monitors the AP, Wifi and connectivity status.
 * Send the info to the native process.
 */
@SuppressWarnings("WeakerAccess")
public class LMonitor extends BroadcastReceiver {
    public static final String TAG = "LM-Mon";

    // Connectivity event, refresh may be needed.
    public static final int EV_NETUPDATE = 38;
    public static final int EV_APUPDATE = 39;
    public static final int EV_WIFIUPDATE = 32;

    // Hidden in WifiManager, to detect hotspot mode.
    static final String WIFI_AP_STATE_CHANGED_ACTION = "android.net.wifi.WIFI_AP_STATE_CHANGED";
    static final String EXTRA_WIFI_AP_STATE = "wifi_state";
    public static InetAddress GW4;

    static {
        try {
            GW4 = InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 49, 1});
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    // ------------ AP control --------------

    private final Handler handler;
    public WifiManager wm;
    public String ssid;
    /**
     * Link-local IPv6 addess for the AP.
     * Includes the scope, which identifies the interface.
     * Android doesn't typically list the AP interface.
     */
    public Inet6Address ap6Address;
    /**
     * Set if the 'client' wifi interface is connected.
     */
    public InetAddress wifi4Address; // ip4 preferred
    public NetworkInterface wifiIf;
    public Inet6Address wifi6LocalAddress;
    public List<InetAddress> mobileAddress = new ArrayList<>(); // ap6Address preferred
    Context ctx;
    ConnectivityManager cm;
    boolean started;
    boolean apRunning;
    NetworkInterface apIface;
   // Set in case of L+, to the client Wifi address. Null if not connected or pre-L.
    // Can be used for binding - but in current mode it doesn't seem to be needed.
    Network wifiNetwork;

    public LMonitor(Context ctx, Handler h) {
        this.ctx = ctx;
        this.handler = h;
        wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);

        cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    /**
     * Will monitor network changes. Active while 'client' is active. If DMesh is disabled
     * call close() to stop monitoring (will also close all sockets and stop foreground mode
     * and all services)
     */
    public synchronized void start() {
        if (started) {
            return;
        }
        IntentFilter mIntentFilter = new IntentFilter();

        // To know if hotspot AP is on/off
        mIntentFilter.addAction(WIFI_AP_STATE_CHANGED_ACTION);

        mIntentFilter.addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION);

        mIntentFilter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);

        mIntentFilter.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        mIntentFilter.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);

        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION);

        ctx.registerReceiver(this, mIntentFilter);
        started = true;
    }

    public synchronized void stop() {
        if (!started) {
            return;
        }
        started = false;
        ctx.unregisterReceiver(this);
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        Bundle extras = intent.getExtras();
        if (ConnectivityManager.CONNECTIVITY_ACTION.equals(action)) {
            // Cause the native process to refresh the interfaces and possibly reconnect to VPN
            // using a different path.
            boolean noCon = intent.getBooleanExtra(ConnectivityManager.EXTRA_NO_CONNECTIVITY, false);

            StringBuilder sb = toString(extras);
            if (noCon) {
                event(EV_NETUPDATE, sb.toString());
            } else {
                event(EV_NETUPDATE, sb.toString());
            }

            onConnectivityChange(context, noCon);
        } else if (WIFI_STATE_CHANGED_ACTION.equals(action)) {
            StringBuilder sb = toString(extras);
            event(EV_WIFIUPDATE, sb.toString());

            int state = intent.getIntExtra(WifiManager.EXTRA_WIFI_STATE, 0);
            if (state == WifiManager.WIFI_STATE_ENABLED) {
                onConnectivityChange(context, false);
            } else {
                onConnectivityChange(context, true);
            }
        } else if (WIFI_AP_STATE_CHANGED_ACTION.equals(action)) {
            // See TetherSettings - only  legacy ap mode
            int state = intent.getIntExtra(EXTRA_WIFI_AP_STATE, 0);
            if (state == 13) {
                onConnectivityChange(context, false);
                //dm.onAPStart();
            } else if (state == 11 || state == 10) {
                onConnectivityChange(context, false);
                //dm.onAPStop();
            }
            StringBuilder sb = toString(extras);
            event(EV_APUPDATE, sb.toString());
            Log.d(TAG, "Wifi AP state: " + intent.getExtras());

        } else {
            StringBuilder sb = toString(extras);
            event(EV_APUPDATE, sb.toString());

            // Wifi Direct
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
                if (WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION.equals(action)) {
                    WifiP2pGroup group = intent.getParcelableExtra(WifiP2pManager.EXTRA_WIFI_P2P_GROUP);
                    // Typically second callback, after WIFI_P2P_STATE_CHANGED_ACTION 'state_changed(true)'
                    // It is also called every time a device connects.
                    if (group != null && group.isGroupOwner()) {
                        if (!apRunning) {
                            // Skip update network if it'vpnClient a client connect notification.
                            onConnectivityChange(context, false);
                            // Just check
                            try {
                                NetworkInterface apIface2 = NetworkInterface.getByName(group.getInterface());
                                if (apIface2 != apIface) {
                                    Log.w(TAG, "Group interface different than detected " + apIface2 + " " +
                                            apIface);
                                }
                                if (ap6Address != null) {
                                    Log.d(TAG, "DMAP started: " + group.getNetworkName() +
                                            " " + group.getPassphrase() + " " + group.getInterface() + " " + ap6Address.getHostAddress());
                                } else {
                                    Log.d(TAG, "AP started, no IPv6: " + group.getNetworkName() +
                                            " " + group.getPassphrase() + " " + group.getInterface());
                                }
                            } catch (IOException ex) {
                                Log.w(TAG, "Could not obtain address of network interface "
                                        + group.getInterface(), ex);
                            }
                            //dm.onAPStart();
                        } else {
                            Log.d(TAG, "AP P2PConnectionChanged directConnections: " + group.getClientList());
                        }
                    } else {
                        onConnectivityChange(context, false);
                        //dm.onAPStop();
                    }
                    return;
                } else {
                    intent.getStringExtra("");
                    Log.d(TAG, "Event: " + action + " " + intent.getExtras());
                }
            }
        }
    }

    private void event(int evWifiupdate, String s) {
        Message m = handler.obtainMessage(evWifiupdate);
        m.obj = s;
        m.sendToTarget();
    }

    @NonNull
    private StringBuilder toString(Bundle b) {
        StringBuilder sb = new StringBuilder();
        if (b == null) {
            return sb;
        }
        for (String k: b.keySet()) {
            Object o = b.get(k);
            sb.append(k).append(":").append(o.toString()).append(" ");
        }
        return sb;
    }

    /**
     * Called from EventReceiver when the connectivity has changed,
     * in receiver thread ( main thread ).
     *
     * @param noConnectivity - lost all connections
     */
    public void onConnectivityChange(Context ctx, boolean noConnectivity) {
        if (noConnectivity) {
            Log.d(TAG, "NO CONNECTIVITY ");
            // TODO: disable all.
        }

        // TODO: legacy update is cleaner and does pretty much all we need.
        // only thing that may work only in L is having multiple wifi client
        // interfaces. Also 'legacy' correctly detects the AP interface.
        updateConnectivityLegacy();

        if (Build.VERSION.SDK_INT >= 21) { // L
            // In theory L may allow multiple Wifi client ( or maybe multiple APs).
            // New interface allows detecting them - not used right now but would be great
            // if it worked (I don't have any device where this happens).
            updateConnectivityL();
        }

    }

    /**
     * Use pre-L API, with some hacks to determine the AP interface.
     * <p>
     * The AP interface is updated by Wifi direct events, but in hotspot mode this seems
     * the only way.
     */
    void updateConnectivityLegacy() {
        // < L21: G9, I14, J16
        // Assumes a single WifiConnection
        WifiInfo info = wm.getConnectionInfo();
        wifi4Address = toInetAddress(info.getIpAddress());
        ssid = info.getSSID();

        try {
            List<InetAddress> allMobile = new ArrayList<>();
            List<InetAddress> allLL = new ArrayList<>();

            Inet6Address wifi6ll = null;
            Inet6Address ap6ll = null;

            Enumeration e = NetworkInterface.getNetworkInterfaces();
            while (e.hasMoreElements()) {
                NetworkInterface ni = (NetworkInterface) e.nextElement();

                if (ni.isLoopback()) {
                    continue;
                }
                if (ni.getName().contains("dummy")) {
                    continue;
                }
                if (!ni.isUp()) {
                    continue;
                }

                Inet4Address ip4 = null;
                List<InetAddress> ip6 = new ArrayList<>();
                Inet6Address ip6ll = null;

                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    InetAddress a = ia.getAddress();
                    if (a instanceof Inet6Address) {
                        if (a.isLinkLocalAddress()) {
                            if (ip6ll != null) {
                                Log.d(TAG, "!!!!!! Multiple link local addresses " + ni + " " + ip6ll + " " + a);
                            }
                            allLL.add(a);
                            ip6ll = (Inet6Address) a;
                        } else if (a instanceof Inet6Address) {
                            ip6.add(a); // external - can be a list
                        }
                    } else {
                        ip4 = (Inet4Address) a;
                    }
                }

                if (ip4 != null && ip4.equals(wifi4Address)) {
                    // TODO: find better way to identify the wifi interface
                    wifi6ll = ip6ll;
                    //dm.updateID();
                    wifiIf = ni;
                } else if (ip4 != null && GW4.equals(ip4)) {
                    // This is the AP address. Also set by the P2P interface -
                    // which gets notifications of AP stop/start.
                    ap6ll = ip6ll;
                    apIface = ni;
                } else if (ni.getName().contains("tun")) {
                    // Ignore own tunnel
                } else {
                    // TODO: could be ethernet, mobile, etc
                    if (ip4 != null) {
                        allMobile.add(ip4);
                    }
                    allMobile.addAll(ip6);
                }
            }

            wifi6LocalAddress = wifi6ll;
            if (wifi6ll == null) {
                wifiIf = null;
            }
            mobileAddress = allMobile;
            ap6Address = ap6ll;
            if (ap6ll == null) {
                apIface = null;
            }

            // TODO: if wifi SSID is DIRECT, or nextHop is 192.168.49 - connected to dmesh.
            // Else - we may have internet connection.

            // Also check mobile.

            NetworkInfo active = cm.getActiveNetworkInfo();
//            if (active != null) {
//                // The network with the default route.
//                Log.d(TAG, ((mobileAddress.size() > 0) ? "Mobile: " + mobileAddress : "")
//                        + ((wifi6LocalAddress != null) ? "WiFi6: " + wifi6LocalAddress : "")
//                        + ((ap6Address != null) ? "AP6: " + ap6Address : "")
//                        + " Active: " + active.getType() + active);
//            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    NetworkInfo oldActive;

    /**
     * Updates connectivity-related fields, in particular:
     * - ssid - current wifi SSID, or null if not connected to wifi
     * - wifi6LocalAddress - the link local address associated with the wifi connection,
     * used for communication in dmesh
     * <p>
     * Also updates:
     * - dm.wifi4Address - used if connected to a non-dmesh network
     * - dm.mobileAddress - address on the mobile connection, if device is connected
     * to mobile (will be used for future routing outside of the mesh)
     *
     * @return true if the wifi SSID changed (which requires updating the udp servers)
     */
    @TargetApi(21)
    public void updateConnectivityL() {
        Network[] nets = cm.getAllNetworks();

        // Will not see the AP interface - only mobile, wifi - possibly other special ones
        for (Network n : nets) {
            NetworkInfo cni = cm.getNetworkInfo(n);
            LinkProperties lp = cm.getLinkProperties(n);

            if (cni == null || !cni.isConnected()) {
                continue;
            }

            try {
                NetworkInterface ni = NetworkInterface.getByName(lp.getInterfaceName());
                if (ni == null) {
                    Log.e(TAG, "Interface not found but listed " + lp.getInterfaceName() + " " + lp);
                    continue;
                }
                if (ni.isLoopback()) {
                    continue;
                }
                if (ni.getName().contains("dummy")) {
                    continue;
                }
                if (!ni.isUp()) {
                    continue;
                }

                if (cni.getType() == ConnectivityManager.TYPE_WIFI) {
                    wifiNetwork = n;
                    wifiIf = ni;
                    //dm.udp.wifiMC = new MulticastSocket();
                    //dm.udp.wifiMC.setNetworkInterface(ni);
                    //wifi4Address = get4(lp);


                } else if (cni.getType() == ConnectivityManager.TYPE_MOBILE) {
                    List<InetAddress> newMobile = get6(lp);
                    if (!newMobile.equals(mobileAddress)) {
                        Log.d(TAG, "Mobile change " + mobileAddress + " " + newMobile);
                        mobileAddress = newMobile;
                    }
                } else {
                    // I'll assume the 'other' is the mobile.
                    // TODO: this will be used to mark the node as internet connected, and to route
                    // across multiple dmesh networks. It'vpnClient not real mobile, but 'other', will include
                    // BT and USB links
                    // VPN: [type: VPN[], state: CONNECTED/CONNECTED, reason: agentConnect, extra: (none), failover: false, available: true, roaming: false, metered: false]
                    Log.d(TAG, "Other " + cni);
                }
            } catch (Throwable e) {
                e.printStackTrace();
            }

            // Typical link address:
            // {InterfaceName: wlan0
            // LinkAddresses: [fe80::bef5:acff:feb3:a272/64,192.168.49.120/24,]
            //  Routes: [fe80::/64 -> :: wlan0,
            //     192.168.49.0/24 -> 0.0.0.0 wlan0,
            //     0.0.0.0/0 -> 192.168.49.1 wlan0,]
            // DnsAddresses: [192.168.49.1,]
            // Domains: null MTU: 0
            // TcpBufferSizes: 524288,1048576,2097152,262144,524288,1048576} /
            //
            // 120
        }
    }

    public static InetAddress toInetAddress(int addr) {
        try {
            return InetAddress.getByAddress(toIPByteArray(addr));
        } catch (UnknownHostException e) {
            //should never happen
            return null;
        }
    }

    static byte[] toIPByteArray(int addr) {
        return new byte[]{(byte) addr, (byte) (addr >>> 8), (byte) (addr >>> 16), (byte) (addr >>> 24)};
    }

    /**
     * Get non-link local address.
     */
    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public static List<InetAddress> get6(LinkProperties lp) {
        List<InetAddress> ll = new ArrayList<>();
        for (LinkAddress l : lp.getLinkAddresses()) {
            if (l.getAddress() instanceof Inet6Address) {
                Inet6Address ip6 = (Inet6Address) l.getAddress();
                boolean isLL = ip6.isLinkLocalAddress();
                //ip6.getDatagramAddress()[0] == (byte) 0xfe;
                if (!isLL && !ip6.isSiteLocalAddress() && !ip6.isAnyLocalAddress()) {
                    ll.add(ip6);
                }
            }
        }
        return ll;
    }


}
