package com.github.costinm.dmesh.lm3;

import static android.net.NetworkCapabilities.TRANSPORT_WIFI;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WpsInfo;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.UiUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
Debug:
2019-05-18 19:41:24.893 1260-1470/? D/SupplicantP2pIfaceHal: groupAdd(DIRECT-BD-angler_n6p, <Non-Empty>, true, 0, 02:00:00:00:00:00, true) completed successfully.
2019-05-18 19:41:26.248 2401-2401/? D/wpa_supplicant: p2p0: Request association with 26:1f:a0:30:26:e0
2019-05-18 19:41:26.250 2401-2401/? D/wpa_supplicant: p2p0: Starting radio work 'connect'@0x7a88e13240 after 0.001833 second wait
2019-05-18 19:41:26.256 2401-2401/? D/wpa_supplicant: p2p0: P2P: WLAN AP allows cross connection
2019-05-18 19:41:26.256 2401-2401/? D/wpa_supplicant: p2p0: State: SCANNING -> ASSOCIATING
2019-05-18 19:41:26.299 2401-2401/? D/wpa_supplicant: nl80211: Connect request send successfully
2019-05-18 19:41:26.299 2401-2401/? D/wpa_supplicant: p2p0: Setting authentication timeout: 10 sec 0 usec

2019-05-18 19:41:26.365 1260-1507/? D/WifiVendorHal: onRadioModeChange [{.radioId = 0, .bandInfo = BAND_5GHZ, .ifaceInfos = [{.name = wlan0, .channel = 5785}, {.name = p2p0, .channel = 5785}]}]

2019-05-18 19:41:26.492 2401-2401/? D/wpa_supplicant: nl80211: Connect event (status=0 ignore_next_local_disconnect=0)
2019-05-18 19:41:26.494 1260-1306/? I/EthernetTracker: interfaceLinkStateChanged, iface: p2p0, up: true
2019-05-18 19:41:26.498 2401-2401/? D/wpa_supplicant: nl80211: Associated on 5785 MHz
2019-05-18 19:41:26.498 2401-2401/? D/wpa_supplicant: nl80211: Associated with 26:1f:a0:30:26:e0
2019-05-18 19:41:26.498 2401-2401/? D/wpa_supplicant: nl80211: Operating frequency for the associated BSS from scan results: 5785 MHz
2019-05-18 19:41:26.498 2401-2401/? D/wpa_supplicant: nl80211: Associated on 5785 MHz
2019-05-18 19:41:26.498 2401-2401/? D/wpa_supplicant: nl80211: Associated with 26:1f:a0:30:26:e0
2019-05-18 19:41:26.498 2401-2401/? D/wpa_supplicant: nl80211: Set drv->mySSID based on scan res info to 'DIRECT-BD-angler_n6p'


2019-05-18 19:41:26.542 2401-2401/? I/wpa_supplicant: P2P-GROUP-STARTED p2p0 client mySSID="DIRECT-BD-angler_n6p" freq=5785 go_dev_addr=26:1f:a0:30:a6:e0 [PERSISTENT]

2019-05-18 19:41:26.544 1260-1470/? D/WifiP2pService: GroupNegotiationState{ when=0 what=147485 obj=network: DIRECT-BD-angler_n6p

2019-05-18 19:41:26.583 752-9556/? I/netd: interfaceSetEnableIPv6("false", "p2p0") <7.553491ms>
2019-05-18 19:41:26.584 752-9556/? I/netd: interfaceClearAddrs("p2p0") <0.454532ms>


2019-05-18 19:41:26.589 12529-12529/com.github.costinm.dmwifi D/MsgMux: /wifi/P2P [GO, -1, groupOnwerAddress, ]
2019-05-18 19:41:26.589 12529-12529/com.github.costinm.dmwifi D/MsgMux: /wifi/AP [on, 0]

2019-05-18 19:41:26.592 1801-12650/? D/DhcpClient: Broadcasting DHCPDISCOVER

2019-05-18 19:42:02.598 1801-12650/? D/DhcpClient: doQuit
2019-05-18 19:42:02.598 1260-1470/? E/WifiP2pService: IP provisioning failed


.....

2019-05-18 19:57:37.051 2401-2401/? D/wpa_supplicant: P2P: Group Formation timed out
2019-05-18 19:57:37.052 2401-2401/? D/wpa_supplicant: P2P: No pending Group Formation - ignore group formation failure notification
2019-05-18 19:57:37.052 2401-2401/? I/wpa_supplicant: P2P-GROUP-FORMATION-FAILURE
2019-05-18 19:57:37.052 2401-2401/? D/wpa_supplicant: Notifying P2P Group formation failure to hidl control:
2019-05-18 19:57:37.052 2401-2401/? D/wpa_supplicant: Notifying P2P Group removed to hidl control: 9
2019-05-18 19:57:37.053 2401-2401/? D/wpa_supplicant: p2p0: Request to deauthenticate - bssid=42:4e:36:81:d4:1f pending_bssid=00:00:00:00:00:00 reason=3 state=DISCONNECTED
2019-05-18 19:57:37.053 2401-2401/? D/wpa_supplicant: TDLS: Tear down peers
2019-05-18 19:57:37.053 2401-2401/? D/wpa_supplicant: wpa_driver_nl80211_disconnect(reason_code=3)
2019-05-18 19:57:37.053 2401-2401/? D/wpa_supplicant: p2p0: Event DEAUTH (11) received
2019-05-18 19:57:37.053 2401-2401/? D/wpa_supplicant: p2p0: Deauthentication notification
2019-05-18 19:57:37.053 2401-2401/? D/wpa_supplicant: p2p0:  * reason 3 (locally generated)
 */

/*

TODO:
- BLE, BT and NAN allow sending some messages without connecting. This can be integrated.


 */

/**
 * Local mesh - Wifi NAN/P2P, BLE. The main local protocol is NAN - with BLE used to communicate
 * with 'modem' like devices - like LoRA or ESP raw WiFi protocls.
 *
 * P2P was used in the past, before NAN was broadly available on phones. Same for BT.
 *
 * This requires a lot of permissions - and a persistent foreground service
 * that is not frozen. It can also be used from a system app.
 *
 * Will generate signals for devices in range.
 *
 * It can interact with the devices in range using messages, including control messages for
 * getting their neighbor info or requesting forwarding.
 *
 *
 * REST API:
 * <p>
 * -  net/{NET}: ap, wlan, p2p, inet, ... - network interfaces
 * --  on: 0|1
 * --  if: wlan0, ...
 * --  ip: IP1, IP2, ...
 * --  ll: IP6LL, ...
 * --  s: ... // SSID
 * --  p: ... // PSK
 * --  n: ... // NET - for meshed interfaces with upstream net ( from SD )
 * --  i: ... // Info/details about the caps
 * <p>
 * - peer/{PEER}: discovered peer. May be visible or recently visible
 * -- c: 1 // Set to 1 to attempt a connection. Will be 1 while the attempt is in progress.
 * -- l: N // signal level, if SSID visible
 * -- s: SSID // if scan finds the object
 * -- f: FREQ // same
 * -- p: PSK  // if it was previously discovered with SD
 * -- i: ID   // same
 * -- n: NET  // same
 * -- name: P2P name // if found as peer
 */
public class LocalMesh extends BroadcastReceiver implements MessageHandler {
    public static final int UPDATE = 3;
    public static final int MSG = 2;
    static final Map<String, String> empty = new HashMap<>();
    // Used for P2P announce
    static final String TAG = "DM/wifi";
    private static final String PREF_ENABLED = "wifi_enabled";


    // end raw data
    static String lastCap = "";
    private static LocalMesh singleton;

    // -------------------------

    Context ctx;

    // All callbacks from system for P2P (and others) will trigger messages on this thread.
    // Callbacks run on this thread, should be non-blocking.
    final Looper looper;

    // Handler is used for postDelayed() or other similar operations - on the looper.
    final Handler delayHandler;

    // Used for discovery
    public Nan nan;

    public Ble ble;

    // P2P support - includes WifiManager and scanning.
    // No longer the mechanism for forming the mesh, it was used before NAN.
    public P2P p2p;

    ConnectivityManager cm;

    // Advertised URL - for NAN, BLE, TXT
    // Current format: 16 bytes, PSK8 + SSIDHASH4 + ID4
    String adv = "12345678SSIDID04";
    // Last requested state for the AP.
    // TODO: leave it as is at startup.
    boolean requestedAp;
    String id4 = "0000";
    // Last scan results. Updated when result happens. Data is merged with txt info to
    // select DMesh APs.
    List<ScanResult> lscanResults;

    public static synchronized LocalMesh get(Context ctx) {
        if (singleton == null) {
            HandlerThread ht = new HandlerThread("dmesh");
            ht.start();

            // all messages from wifi posted here
            Handler h = new Handler(ht.getLooper()) {
                @Override
                public void handleMessage(Message msg) {
                    super.handleMessage(msg);
                }
            };

            singleton = new LocalMesh(ctx.getApplicationContext(), h, ht.getLooper());
        }
        return singleton;
    }


    private LocalMesh(Context appContext, Handler delayHandler, Looper mainLooper) {
        ctx = appContext.getApplicationContext();

        looper = mainLooper;
        this.delayHandler = delayHandler;
        p2p = new P2P(this);

        cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);

        cm.registerNetworkCallback(new NetworkRequest.Builder().build(), new ConnectivityCallback(this));

        nan = new Nan(this);

        ble = new Ble(appContext, this, this.delayHandler);
        //bt = new Bt2(appContext, this.delayHandler);


        nan.onCreate();
        p2p.onCreate();

//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
//            nan.sub(delayHandler, true);
//        }

    }

    // Only send those devices
    public static boolean isLM(String ssid) {
        if (ssid == null) {
            return false;
        }
        if (ssid.startsWith("DM-")) {
            return true;
        }
        if (!ssid.startsWith("DIRECT-")) {
            return false;
        }
        // exclude known non-android DIRECT servers
        if (ssid.length() > 10 &&
                (ssid.substring(10).startsWith("HP "))) {
            return false;
        }
        return true;
    }

    /**
     * Called when all Bind (subscribers) disconnect.
     * <p>
     * Will leave AP and connections in last known state. May exit.
     */
    public void onDestroy() {
        ctx.unregisterReceiver(this);
        p2p.stopPeerAndSDDiscovery();
        //bt.close();
    }

    /**
     * Update p2p link based on status specified in mst.
     */
    private void updateP2P(Message msg) {
        Bundle data = msg.getData();
        String ap = data.getString("ap", "");
        if (ap.length() > 0) {
            requestedAp = "1".equals(ap);
            p2p.apOn(requestedAp);
        }

        // Intended state/type of discovery.
        String disc = data.getString("disc", "");
        if (disc.length() > 0) {
            if ("1".equals(disc)) { // Start Peer discovery, with SD. Can be used for P2P and similar
                p2p.discoverPeersStart(msg);
            } else if ("0".equals(disc)) {
                p2p.stopPeerAndSDDiscovery();
            }
        }

        // P2P connection to a different node.
        String con = data.getString("con", "");
        if (con.length() > 0) {
            con(msg, con, data.getString("mode", ""));
        }
    }

    /**
     * Called from a periodic job. May also be used without persistent notification,
     * the server will run while the periodic job is active only.
     */
    public void update() {
        scan();
    }

    public void scan() {

        // Method is deprecated, will be removed. System can scan.
        boolean s = p2p.mWifiManager.startScan();
        if (!s) {
            Log.d(TAG, "Request wifi scan failed " + s);
        }

        delayHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                ble.scan();
            }
        }, 3000);

        // Will activate nan - but not detach, so beacons will continue to be sent.
        // Also requires the other end to be attached - sending beacons. If we take the hit of
        // sending beacons - P2P mode is more efficient anyways.
        // Using NAN for discovery doesn't seem to present any benefits.

            delayHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    nan.update(delayHandler);
                }
            }, 6000);
    }

    public void send(String uri, String... parms) {
        Message m = Message.obtain();
        m.what = 1;
        m.getData().putString(":uri", uri);

        Bundle b = m.getData();
        for (int i = 0; i < parms.length; i += 2) {
            b.putString(parms[i], parms[i + 1]);
        }
        String[] args = uri.split("/");
        handleMessage(args[1], args[2], m, null, args);
    }

    /**
     * Handle all incoming requests for the service.
     * <p>
     * Expects a :uri, with a path starting with /wifi/${ACTION}/${PARAMS...}
     * <p>
     * Additional params sent in the message bundle.
     * <p>
     * May send a direct response using msg.replyTo - should include the :id parameter.
     * May send at any time broadcasts using the delayHandler to all subscribers.
     * Broadcasts start with "/wifi/" or /net/
     */
    @Override
    public void handleMessage(String topic, String type, Message msg, MsgConn replyTo, String[] args) {

        switch (topic) {
            case "I":
                id4 = type.substring(0, 4);
                announce(true);
                return;
        }

        Bundle b = msg.getData();
        Log.d(TAG, "WIFI Command: " + Arrays.toString(args) + " " + b);

        switch (type) {
            case "p2p":
                updateP2P(msg);
                break;

            // Actions and testing

            case "scan":
                // Wifi, BLE and NAN scan. No BT yet.
                scan();
                break;

            case "disc":
                // Should be used after wifi scan, if new DIRECT devices are
                // found - to show the neigbor info.
                //
                // about 6 seconds
                p2p.discoveryWifiP2POnce();
                break;

            // p2p discovery must be started for con
            case "con":
                if ("start".equals(args[3])) {
                    p2p.discoverPeersStart(msg);
                } else if ("stop".equals(args[3])) {
                    p2p.stopPeerAndSDDiscovery();
                } else if ("cancel".equals(args[3])) {
                    p2p.disconnect();
                } else if ("peer".equals(args[3])) {
                    con(msg, args[4], args[5]);
                }
                break;


            case "nan":
                Log.d(TAG, "NAN command " + args);
                if (nan != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && args.length >= 4) {
                    if ("con".equals(args[3]) && args.length >= 5) {
                        nan.conNan(args[4]);
                    } else if ("ping".equals(args[3])) {
                        if (args.length >= 5) {
                            nan.sendAll(args[4]);
                        } else {
                            nan.sendAll("PING");
                        }
                    } else if ("msg".equals(args[3]) && args.length >= 6) {
                        nan.send(args[4], args[5]);
                    }
                }
                break;
            case "ble":

                break;

            // Controls BLE, NAN advertising. Param: id4 - the 4-byte short for of identifier.
            case "adv":
                if (null != b.getString("id4", null)) {
                    id4 = b.getString("id4");
                }

                String advOn = b.getString("on", "-1");
                if ("1".equals(advOn)) {
                    announce(true);
                } else if ("0".equals(advOn)) {
                    announce(false);
                }

                String p2pv = b.getString("p2p", "-1");
                if ("1".equals(p2pv)) {
                    // TODO: optional parameters, use BLE/BT as well
                    p2p.announceWifiP2P(true);
                } else if ("0".equals(p2pv)) {
                    p2p.announceWifiP2P(false);
                }
                break;

        }
    }

    // List of currently visible devices and status (/wifi/status)
    //
    // 1. List of devices - as a ArrayList<Bundle> "scan".
    //
    // Includes:
    //  - last wifi scan (typie DIRECT- and DM-) - with additional info if SD txt available
    //  - P2P discovery - name and p2p address, excluding SD/scan
    //  - TODO: Nan discovery
    //  - TODO: BLE discovery
    //
    // 2.
    //
    //
    // Merging:
    // -
    public void sendWifiDiscoveryStatus(String event, String id) {

        // Key is SSID - combines last scan results and DNS-SD ( based on P2P peers and
        // previous or current DNS-SD TXT records that addMap2Bundle the SSID and ID )
        Map<String, Device> devicesBySSID = new HashMap<>();

        // Key is P2P discovery address - only if SSID is not found (peer without SD).
        // The devices can still be paired with - or may be DMesh devices that failed DNS-SD.
        // TODO: do we need this ? Can be safely ignored for must purposes, good mostly for debugging.
        // It also includes connected clients.
        Map<String, Device> p2pPeersWithoutDNSSDByMAC = new HashMap<>();

        // Used to avoid dups for connected clients. All p2p peers.
        Map<String, Device> allP2PDiscovered = new HashMap<>();

        Bundle scanStatusMsg = new Bundle();


        // Add other P2P devices - some may be visible as SSID, but we don't know the association
        // because we didn't discover TXT yet.
        if (p2p.wifiP2pDeviceList != null) {
            for (WifiP2pDevice pd : p2p.wifiP2pDeviceList.getDeviceList()) {
                Device d = new Device(pd);
                // will populate TXT records, if previous SD found them. We cache since SD is not
                // very reliable.
                String ssid = d.data.getString(Device.SSID);
                if (ssid != null) {
                    devicesBySSID.put(ssid, d);
                } else {
                    p2pPeersWithoutDNSSDByMAC.put(pd.deviceAddress, d);
                }
                allP2PDiscovered.put(pd.deviceAddress, d);
            }
        }
        if (lscanResults != null) {
            for (ScanResult sr : lscanResults) {
                if (!isLM(sr.SSID)) {
                    continue;
                }
                Device d = devicesBySSID.get(sr.SSID);
                if (d == null) {
                    d = new Device(sr);
                    devicesBySSID.put(sr.SSID, d);
                } else {
                    d.setScanResult(sr);
                }
            }
        }
        for (WifiP2pDevice c : p2p.currentClientList) {
            Device d = allP2PDiscovered.get(c.deviceAddress);
            if (d == null) {
                d = new Device(c);
                p2pPeersWithoutDNSSDByMAC.put(c.deviceAddress, d);
                allP2PDiscovered.put(c.deviceAddress, d);
            }
            d.data.putString("gc", "1");
        }

        ArrayList<Bundle> scanList = new ArrayList<>();
        for (Device d : devicesBySSID.values()) {
            scanList.add(d.data);
        }
        for (Device d : p2pPeersWithoutDNSSDByMAC.values()) {
            scanList.add(d.data);
        }
        for (Device d : Ble.devices.values()) {
            scanList.add(d.data);
        }
        if (nan != null) {
            for (Device d : Nan.devices.values()) {
                scanList.add(d.data);
            }
        }
        scanStatusMsg.putParcelableArrayList("scan", scanList);

        // Normal key/value pairs, next to :uri
        ArrayList<String> extra = new ArrayList<>();
        extra.add("visible");
        extra.add(lscanResults == null ? "0" : "" + lscanResults.size());

        extra.add("s");
        extra.add(p2p.mySSID);
        extra.add("p");
        extra.add(p2p.psk);

        WifiP2pInfo pinfo = p2p.pinfo;
        if (pinfo != null && pinfo.groupFormed && !pinfo.isGroupOwner) {
            // if groupOnwer - group will be set and used in next block
            extra.add("go");
            extra.add("0");
            if (pinfo.groupOwnerAddress != null) {
                extra.add("goAddress");
                extra.add(pinfo.groupOwnerAddress.toString());
            }
        }

        if (p2p.group != null) {
            if (!p2p.group.isGroupOwner()) {
                WifiP2pDevice owner = p2p.group.getOwner();
                if (owner != null) {
                    extra.add("owner");
                    extra.add(owner.toString());
                }
            } else {
                extra.add("go");
                extra.add("1");
                if (pinfo.groupOwnerAddress != null) {
                    extra.add("goAddress");
                    extra.add(pinfo.groupOwnerAddress.toString());
                }
                WifiP2pDevice owner = p2p.group.getOwner();
                if (owner != null) {
                    extra.add("owner");
                    extra.add(owner.toString());
                }

                extra.add("ap");
                extra.add("1");
            }
        }

        extra.add("event");
        extra.add(event);

        if (id.length() > 0) {
            extra.add("eventTarget");
            extra.add(id);
        }

        if (nan.nanId != null) {
            extra.add("nan");
            extra.add(nan.nanId);
        }

        String wifiSsid = p2p.mWifiManager.getConnectionInfo().getSSID();
        if (wifiSsid != null) {
            extra.add(Device.WIFISSID);
            extra.add(wifiSsid);
            extra.add(Device.FREQ);
            extra.add("" + p2p.mWifiManager.getConnectionInfo().getFrequency());
            extra.add(Device.LEVEL);
            extra.add("" + p2p.mWifiManager.getConnectionInfo().getRssi());
        }

        MsgMux.get(ctx).publish("/net/status", scanStatusMsg, extra.toArray(new String[]{}));
    }

    /**
     * Advertise the presence of the device using BLE.
     * <p>
     * NAN is not activated - attaching will send beacons.
     *
     * @param on
     */
    public void announce(boolean on) {
        if (!on) {
//            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
//                if (nan != null) {
//                    nan.stopPub();
//                }
//            }
            ble.advertise(null);
            return;
        }

        if (p2p.mySSID.isEmpty() || p2p.psk.isEmpty()) {
            adv = "0000" + id4;
        } else {
            // psk=8, delim=1 - remaining 9
            // ssidHash returns 4 bytes, leaving 5 for ID
            adv = p2p.psk + Device.ssidHash(p2p.mySSID) + id4;
        }

//        // Usually NAN doesn't work when AP is on
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
//            if (nan != null) {
//                nan.pub(false);
//            }
//        }

        // We have 20 bytes for advertisment
        // - PSK key - 8 bytes ( if needed )
        // - SSID hash - 2 bytes ?
        // - public key hash - 4 or 8 bytes
        // 2 or 6 remaining

        adv = "X1234567890123456789";

        ble.advertise(adv.getBytes());
    }


    /**
     * @param devId - P2P device MAC ( found in discovery ) or SSID.
     * @param modeS - connect mode to attempt
     */
    public void con(Message msg, final String devId, String modeS) {
        Bundle param = msg.getData();
        Log.d(TAG, "CONNECT " + param);
        int mode = -1;
        switch (modeS) {
            case "":
            case "Q":
                mode = -1;
                p2p.con(param, mode);
                return;
            case "PBC":
                mode = WpsInfo.PBC;
                break;
            case "DISPLAY":
                mode = WpsInfo.DISPLAY;
                break;
            case "KEYPAD":
                mode = WpsInfo.KEYPAD;
                break;
            case "LABEL":
                mode = WpsInfo.LABEL;
                break;
            default:
                return;
        }

        p2p.con(param, mode);
    }



    // Will be needed for privacy - change name when wifi mac changes
//    public void setDeviceName(String name) {
//        try {
//            Reflect.callMethod(mP2PManager, "setDeviceName",
//                    new Class[]{WifiP2pManager.Channel.class, String.class, WifiP2pManager.ActionListener.class},
//                    new Object[]{getmChannel(), name, new WifiP2pManager.ActionListener() {
//                        @Override
//                        public void onSuccess() {
//                            Log.d(TAG, "XXX setName ");
//                        }
//
//                        @Override
//                        public void onFailure(int reason) {
//                            Log.d(TAG, "XXX setName error " + reason);
//                        }
//                    }});
//        } catch (ClassNotFoundException e) {
//            e.printStackTrace();
//        } catch (IllegalAccessException e) {
//            e.printStackTrace();
//        } catch (InvocationTargetException e) {
//            e.printStackTrace();
//        } catch (NoSuchMethodException e) {
//            e.printStackTrace();
//        }
//    }


    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();

        intent.getStringExtra("");
        Log.d(TAG, "/ERR/UnknownBroadcast " + intent.getAction() + " " + UiUtil.toString(intent.getExtras()));

    }


    static class ConnectivityCallback extends ConnectivityManager.NetworkCallback {
        private final LocalMesh wifi;

        ConnectivityCallback(LocalMesh wifi) {
            this.wifi = wifi;
        }

        @Override
        public void onAvailable(Network network) {
            super.onAvailable(network);
            // On addMap2Bundle. Only network handle (number) is provided. Network allows binding and
            // interface specific operations, but not much else.
            // LPCHANGE provides more info
            NetworkCapabilities cap = wifi.cm.getNetworkCapabilities(network);
            LinkProperties lp = wifi.cm.getLinkProperties(network);
            NetworkInfo ninfo = wifi.cm.getNetworkInfo(network);

            String ssid = "";
            if (wifi.p2p != null && wifi.p2p.mWifiManager != null) {
                WifiInfo connectionInfo = wifi.p2p.mWifiManager.getConnectionInfo();
                ssid = connectionInfo == null ? "" : connectionInfo.getSSID();
            }

            MsgMux.get(wifi.ctx).publish("/wifi/net/" + lp.getInterfaceName(),
                    "addr", lp.getLinkAddresses().toString(),
                    "cap", cap.toString(),
                    "s", ssid == null ? "" : ssid,
                    "ninfo", ninfo.toString());
        }

        @Override
        public void onLinkPropertiesChanged(Network network, LinkProperties lp) {

            // Routes: check if it has a FE80 and 0.0.0.0

            super.onLinkPropertiesChanged(network, lp);
            NetworkCapabilities cap = wifi.cm.getNetworkCapabilities(network);
            NetworkInfo ninfo = wifi.cm.getNetworkInfo(network);
            WifiInfo connectionInfo = wifi.p2p.mWifiManager.getConnectionInfo();
            String ssid = connectionInfo == null ? "" : connectionInfo.getSSID();

            MsgMux.get(wifi.ctx).publish("/wifi/net/" + lp.getInterfaceName(),
                    "addr", lp.getLinkAddresses().toString(),
                    "cap", cap == null ? "" : cap.toString(),
                    "s", ssid == null ? "" : ssid,
                    "ninfo", ninfo == null ? "" : ninfo.toString());
        }

        @Override
        public void onLosing(Network network, int maxMsToLive) {
            super.onLosing(network, maxMsToLive);
            MsgMux.get(wifi.ctx).publish("/wifi/CON/LOSING/" + network.toString());
        }

        @Override
        public void onLost(Network network) {
            super.onLost(network);
            MsgMux.get(wifi.ctx).publish("/wifi/CON/LOST/" + network.toString());
        }

        @Override
        public void onUnavailable() {
            super.onUnavailable();
            MsgMux.get(wifi.ctx).publish("/wifi/CON/UNAVAIL");
        }

        @Override
        public void onCapabilitiesChanged(Network network, NetworkCapabilities caps) {
            super.onCapabilitiesChanged(network, caps);
            // Usually the SignalStrength changes - frequently
            // Transports: WIFI
            //NOT_METERED&INTERNET&NOT_RESTRICTED&TRUSTED&NOT_VPN&VALIDATED&NOT_ROAMING&FOREGROUND&NOT_CONGESTED&NOT_SUSPENDED

            //Transports: CELLULAR Capabilities: MMS&SUPL&FOTA&CBS&INTERNET&NOT_RESTRICTED&TRUSTED&NOT_VPN&VALIDATED&NOT_ROAMING&NOT_CONGESTED&NOT_SUSPENDED

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                long handle = network.getNetworkHandle();


            }
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);

            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                Log.d(TAG, "/CON/CAPCHANGE/" + caps);
            } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE)) {
                Log.d(TAG, "/CON/CAPCHANGE/" + "/" + caps);
            } else if (caps.hasTransport(TRANSPORT_WIFI)) {

            } else {
                Log.d(TAG, "/CON/CAPCHANGE/" + "/" + caps);
            }
        }

        public void onBlockedStatusChanged(Network network, boolean blocked) {
            super.onBlockedStatusChanged(network, blocked);
        }
    }


}
