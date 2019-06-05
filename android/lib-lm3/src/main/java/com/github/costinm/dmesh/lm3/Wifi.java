package com.github.costinm.dmesh.lm3;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WpsInfo;
import android.net.wifi.aware.WifiAwareManager;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pGroup;
import android.net.wifi.p2p.WifiP2pInfo;
import android.net.wifi.p2p.WifiP2pManager;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceInfo;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;

import com.github.costinm.dmesh.android.util.MsgMux;
import com.github.costinm.dmesh.android.util.Reflect;
import com.github.costinm.dmesh.android.util.UiUtil;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static android.net.NetworkCapabilities.TRANSPORT_WIFI;

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
2019-05-18 19:41:26.498 2401-2401/? D/wpa_supplicant: nl80211: Set drv->ssid based on scan res info to 'DIRECT-BD-angler_n6p'


2019-05-18 19:41:26.542 2401-2401/? I/wpa_supplicant: P2P-GROUP-STARTED p2p0 client ssid="DIRECT-BD-angler_n6p" freq=5785 go_dev_addr=26:1f:a0:30:a6:e0 [PERSISTENT]

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


/**
 * Wifi related code - targetting L-Q
 * <p>
 * Singleton - Wifi commands don't work well with concurrent access.
 * <p>
 * Message/REST based API:
 * <p>
 * Prefix: /wifi/
 * <p>
 * Objects:
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
public class Wifi extends BroadcastReceiver implements MsgMux.MessageHandler {
    public static final int UPDATE = 3;
    public static final int MSG = 2;
    static final Map<String, String> empty = new HashMap<>();
    // Used for P2P announce
    static final String SD_SUFFIX_PART = "_dm._udp";
    private static final String TAG = "DM/wifi";
    // Database with recent discovered addresses.

    // Key is 'discovery address' - p2p device address or nan or ble mac
    public static Map<String, Device> sdDevByAddr = new HashMap<>();

    public static Map<String, Device> p2pDevBySdSSID = new HashMap<>();

    // Raw data from callbacks:
    // Last 'group' info, or null if the group is not started.
    WifiP2pGroup group;
    // Last p2p discovery. Empty if discovery not in progress.
    static WifiP2pDeviceList wifiP2pDeviceList;
    // Last scan results. Updated when result happens.
    private List<ScanResult> lscanResults;

    /**
     * If AP active, contains the list of devices connected to this server.
     */
    public static ArrayList<WifiP2pDevice> currentClientList = new ArrayList<>();

    // end raw data


    // SD discovery info, keyed by the P2P discAddr.
    // The debug app depends on SD discovery working, doesn't persist any data.
    // The mesh app may persist and get the data from other nodes. When visibility reports are sent,
    // it'll merge with its own SD discovery data.
    // TODO: expire after some time. The address is rotated periodically - this needs to be cleaned up.
    public static Map<String, Map<String, String>> txtDiscoveryByP2P = new HashMap<>();
    public static Map<String, Map<String, String>> txtDiscoveryBySSID = new HashMap<>();


    static boolean discovering = false;

    static String lastCap = "";

    final Looper looper;
    // Handler used to send broadcasts to all connected clients.
    final Handler broadcastHandler;

    Context ctx;
    static WifiP2pManager.Channel mChannel;
    WifiManager mWifiManager;
    WifiP2pManager mP2PManager;
    WifiP2pDnsSdServiceInfo si;
    ConnectivityManager cm;
    Nan nan;

    boolean p2pGroupStarted;


    // Advertised URL - for NAN, BLE, TXT
    String adv = "/dmesh";

    private WifiP2pManager.DnsSdTxtRecordListener discoveryListener;

    // State reported by broadcast, 2 == started, 1 == stopped.
    // Will be stopped during connect
    // Should not be relevant to the higher layers - this class should just track it.
    // May be reported in 'scan' events.
    private int discoveryState;

    private boolean p2pEnabled;
    private WifiP2pInfo pinfo;

    public Wifi(Context appContext, Handler broadcaster, Looper mainLooper) {
        ctx = appContext.getApplicationContext();
        looper = mainLooper;
        broadcastHandler = broadcaster;
        mP2PManager = (WifiP2pManager) appContext.getSystemService(Context.WIFI_P2P_SERVICE);
        mWifiManager = (WifiManager) appContext.getSystemService(Context.WIFI_SERVICE);
        cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        cm.registerNetworkCallback(new NetworkRequest.Builder().build(), new ConnectivityCallback(this));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nan = new Nan(this);
        }
        registerReceiver(appContext);
    }

    /**
     * Called when all Bind (subscribers) disconnect.
     *
     * Will leave AP and connections in last known state. May exit.
     */
    public void onDestroy() {
        ctx.unregisterReceiver(this);
        stopPeerAndSDDiscovery();
    }

    // Last requested state for the AP.
    // TODO: leave it as is at startup.
    boolean requestedAp;
    String requestedWifi;
    String requestedP2P;

    /**
     * Update p2p link based on status specified in mst.
     */
    private void updateP2P(Message msg) {
        Bundle data = msg.getData();
        String ap = data.getString("ap", "");
        if (ap.length() > 0) {
            requestedAp = "1".equals(ap);
            apOn(requestedAp);
        }

        // Intended state/type of discovery.
        String disc = data.getString("disc", "");
        if (disc.length() > 0) {
            if ("1".equals(disc)) { // Start Peer discovery, with SD. Can be used for P2P and similar
                discoverPeersStart(msg);
            } else if ("0".equals(disc)) {
                stopPeerAndSDDiscovery();
            }
        }

        // P2P connection to a different node.
        String con = data.getString("con", "");
        if (con.length() > 0) {
            con(msg, con, data.getString("mode", ""));
        }
    }

    /**
     * Handle all incoming requests for the service.
     * <p>
     * Expects a :uri, with a path starting with /wifi/${ACTION}/${PARAMS...}
     *
     * Additional params sent in the message bundle.
     * <p>
     * May send a direct response using msg.replyTo - should include the :id parameter.
     * May send at any time broadcasts using the broadcastHandler to all subscribers.
     * Broadcasts start with "/wifi/" or /net/
     */
    @Override
    public void handleMessage(Message msg, Messenger replyTo, String[] args) {
        if (args.length < 2 || ! (args[1].equals("wifi")||args[1].equals("net") ) ) {
            return;
        }

        Log.d(TAG, "Command: " + Arrays.toString(args));

        switch (args[2]) {
            case "p2p":
                updateP2P(msg);

                break;

            // Actions and testing

            case "scan":
                boolean s = mWifiManager.startScan();
                Log.d(TAG, "Request scan " + s);
                break;

            case "disc":
                discoveryWifiP2POnce(msg);
                break;

            // p2p discovery must be started for con
            case "con":
                if ("start".equals(args[3])) {
                    discoverPeersStart(msg);
                } else if ("stop".equals(args[3])) {
                    stopPeerAndSDDiscovery();
                } else if ("cancel".equals(args[3])) {
                    disconnect();
                } else if ("peer".equals(args[3])) {
                    con(msg, args[4], args[5]);
                }
                break;


            case "nan":
                if (nan != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    if ("start".equals(args[3])) {
                        nan.startNan();
                    } else if ("con".equals(args[3])) {
                        nan.conNan(args[4]);
                    } else if ("ping".equals(args[3])) {
                        nan.pingNan(args[4]);
                    } else if ("stop".equals(args[3])) {
                        nan.stopNan();
                    }
                }
                break;


            case "adv":
                // For internal debug - it is started automatically on ap start.
                //
                if ("start".equals(args[3])) {
                    // TODO: optional parameters, use BLE/BT as well
                    announceWifiP2P(true);
                } else {
                    announceWifiP2P(false);
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
    public void sendWifiDiscoveryStatus(String event) {

        // Key is SSID or device address.
        Map<String, Device> newscanResults = new HashMap<>();

        // Key is P2P discovery address - only if SSID is not found (peer without SD)
        Map<String, Device> newscanResultsByP2P = new HashMap<>();

        Map<String, Device> allP2PDiscovered = new HashMap<>();

        Bundle b = new Bundle();
        // Normal key/value pairs, next to :uri
        ArrayList<String> extra = new ArrayList<>();

        boolean newFound = false;

        // Add other P2P devices - some may be visible as SSID, but we don't know the association
        // because we didn't discover TXT yet.
        if (wifiP2pDeviceList != null) {
            for (WifiP2pDevice pd: wifiP2pDeviceList.getDeviceList()) {
                if (newscanResultsByP2P.get(pd.deviceAddress) != null) {
                    continue;
                }
                Device d = new Device(pd);
                // will populate TXT records, if previous SD found them. We cache since SD is not
                // very reliable.
                String ssid = d.data.getString(Device.SSID);
                if (ssid != null) {
                    newscanResults.put(ssid, d);
                } else {
                    newscanResultsByP2P.put(pd.deviceAddress, d);
                }
                allP2PDiscovered.put(pd.deviceAddress, d);
            }
        }
        if (nan != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (nan.isAvailable()) {
                extra.add("nan");
                extra.add(nan.nanId);
            }
        }

        if (lscanResults != null) {
            for (ScanResult sr : lscanResults) {
                if (!isLM(sr.SSID)) {
                    continue;
                }
                Device d = newscanResults.get(sr.SSID);
                if (d == null) {
                    d = new Device(sr);
                    newscanResults.put(sr.SSID, d);
                } else {
                    d.setScanResult(sr);
                }
            }
        }

        sdDevByAddr = allP2PDiscovered;


        ArrayList<Bundle> blist = new ArrayList<>();
        for (Device d: newscanResults.values()) {
            blist.add(d.data);
        }
        for (Device d: newscanResultsByP2P.values()) {
            blist.add(d.data);
        }
        b.putParcelableArrayList("scan", blist);

        extra.add("visible");
        extra.add(lscanResults == null ? "0" : "" + lscanResults.size());

        if (pinfo != null && pinfo.groupFormed) {
            if (pinfo.isGroupOwner) {
                extra.add("go");
                extra.add("1");
                if (pinfo.groupOwnerAddress != null) {
                    extra.add("goAddress");
                    extra.add(pinfo.groupOwnerAddress.toString());
                }
                MsgMux.get(ctx).broadcastTxt("/wifi/P2P", "GO", "1",
                        "groupOnwerAddress", pinfo.groupOwnerAddress != null ? pinfo.groupOwnerAddress.toString() : "");
            } else {
                extra.add("go");
                extra.add("0");
                if (pinfo.groupOwnerAddress != null) {
                    extra.add("goAddress");
                    extra.add(pinfo.groupOwnerAddress.toString());
                }
                // client
                MsgMux.get(ctx).broadcastTxt("/wifi/P2P", "GO", "0",
                        "groupOnwerAddress", pinfo.groupOwnerAddress != null ? pinfo.groupOwnerAddress.toString() : "");
            }
        } else {
            extra.add("go");
            extra.add("-1");
            if (pinfo != null) {
                MsgMux.get(ctx).broadcastTxt("/wifi/P2P", "GO", "-1",
                        "groupOnwerAddress", pinfo.groupOwnerAddress != null ? pinfo.groupOwnerAddress.toString() : "");
            }
            currentClientList.clear();
        }

        if (group == null) {
            if (p2pGroupStarted) {
                announceWifiP2P(false);
                p2pGroupStarted = false;
            }
            MsgMux.get(ctx).broadcastTxt("/wifi/AP",
                    "on", "0");
            currentClientList.clear();

        } else {
            currentClientList = new ArrayList<>(group.getClientList());
            if (group.isGroupOwner()) {
                if (!p2pGroupStarted) {
                    p2pGroupStarted = true;
                    announceWifiP2P(true);
                }
                extra.add("ap");
                extra.add("1");
                extra.add("s");
                extra.add(group.getNetworkName());
                extra.add("p");
                extra.add(group.getPassphrase());

            } else {
                MsgMux.get(ctx).broadcastTxt("/wifi/AP",
                        "on", "0");
                currentClientList.clear();
                if (p2pGroupStarted) {
                    announceWifiP2P(false);
                    p2pGroupStarted = false;
                }
            }
            WifiP2pDevice owner = group.getOwner();
            if (owner != null) {
                extra.add("owner");
                extra.add(owner.toString());
            }
        }

        for (WifiP2pDevice c: currentClientList) {
            Device d = allP2PDiscovered.get(c.deviceAddress);
            if (d == null) {
                d = new Device(c);
                newscanResultsByP2P.put(c.deviceAddress, d);
                allP2PDiscovered.put(c.deviceAddress, d);
            }
            d.data.putString("gc", "1");
        }

        extra.add("event");
        extra.add(event);

        String wifiSsid = mWifiManager.getConnectionInfo().getSSID();
        if (wifiSsid != null) {
            extra.add(Device.WIFISSID);
            extra.add(wifiSsid);
            extra.add(Device.FREQ);
            extra.add("" + mWifiManager.getConnectionInfo().getFrequency());
            extra.add(Device.LEVEL);
            extra.add("" + mWifiManager.getConnectionInfo().getRssi());
        }

        MsgMux.get(ctx).broadcastParcelable("/wifi/status", b, extra.toArray(new String[]{}));
    }


    /**
     * Control the WifiP2P announce. Usually after AP starts/stops.
     * @param on
     */
    public void announceWifiP2P(boolean on) {

        if (on) {
            adv = "/" + group.getNetworkName() + "/" + group.getPassphrase();
            mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
                @Override
                public void onGroupInfoAvailable(WifiP2pGroup group) {
                    if (group == null) {
                        return;
                    }
                    Map<String, String> map = new HashMap<>();
                    map.put(Device.SSID, group.getNetworkName());
                    map.put(Device.PSK, group.getPassphrase());
                    String ssid = mWifiManager.getConnectionInfo().getSSID();
                    if (ssid != null && !ssid.startsWith("<")) {
                        map.put(Device.NET, ssid);
                    }

                    si = WifiP2pDnsSdServiceInfo.newInstance("dm", SD_SUFFIX_PART, map);

                    mP2PManager.addLocalService(getmChannel(), si, new MyActionListener("addLocalService"));

                }
            });
        } else {
            //adv = "/dmesh";
            if (si != null) {
                mP2PManager.removeLocalService(getmChannel(), si, new MyActionListener("SD-Announce-OFF"));
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (nan != null) {
                nan.updateAnnounce();
            }
        }
    }

    /**
     * Start AP.
     * A broadcast will be sent if the status changes, from the BroadcastReceiver.
     */
    @SuppressLint("NewApi")
    public void apOn(boolean started) {
        if (started) {
            if (Build.VERSION.SDK_INT >= 28 && Build.VERSION.PREVIEW_SDK_INT > 0) {
                WifiP2pConfig cfg = new WifiP2pConfig.Builder().enablePersistentMode(false)
                        .setNetworkName("DIRECT-DM-ESH").setPassphrase(Device.DEFAULT_PSK).build();
                mP2PManager.createGroup(getmChannel(), cfg, new MyActionListener("createGroupQ"));
            } else {
                mP2PManager.createGroup(getmChannel(), new MyActionListener("createGroup"));
            }
        } else {
            mP2PManager.removeGroup(getmChannel(), new MyActionListener("removeGroup"));
        }
    }

    /**
     * @param devId - P2P device MAC ( found in discovery ) or SSID.
     * @param modeS - connect mode to attempt
     */
    public void con( Message msg, final String devId, String modeS) {
        Bundle param = msg.getData();
        Log.d(TAG, "CONNECT " +  param);
        int mode = -1;
        switch (modeS) {
            case "":
            case "REFLECT":
                mode = -2;
                new ConnectLegacy().connect(mWifiManager,
                        msg.getData().getString(Device.SSID),
                        msg.getData().getString(Device.PSK));
                return;
            case "Q":
                mode = -1;
                con(param, mode);
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

        con(param, mode);
    }

    public void con(final Bundle data, final int mode) {
        mP2PManager.cancelConnect(getmChannel(), new MyActionListener("cancelConnect") {
            public void onSuccess() {
                con2(data, mode);
            }

            public void onFailure(int i) {
                con2(data, mode);
            }
        });
    }

    /**
     * Stop the attempt to connect using P2P methods.
     */
    public void disconnect() {
        mP2PManager.cancelConnect(getmChannel(), new MyActionListener("cancelConnect"));
    }

    @SuppressLint("NewApi")
    public void con2(Bundle msg, int mode) {
        if (mode == -1 && Build.VERSION.SDK_INT >= 28 && Build.VERSION.PREVIEW_SDK_INT > 0) {
            if (null == msg.getString(Device.PSK) ||
                    null == msg.getString(Device.SSID)) {

                return;
            }

            WifiP2pConfig cfg = new WifiP2pConfig.Builder()
                    .enablePersistentMode(true)
                    .setPassphrase(msg.getString(Device.PSK))
                    .setNetworkName(msg.getString(Device.SSID))
                    .build();
            mP2PManager.connect(getmChannel(), cfg, new MyActionListener("connectQ"));
        } else {
            if (mode == -1) {
                mode = WpsInfo.PBC;
            }
            WifiP2pConfig cfg = new WifiP2pConfig();
            cfg.deviceAddress = msg.getString(Device.P2PAddr);
            cfg.wps = new WpsInfo();
            cfg.wps.setup = mode;
            mP2PManager.connect(getmChannel(), cfg, new MyActionListener("connect" + mode));

        }
    }

    /**
     * Start Peer discovery.
     *
     * If "sd" optional parameter is "0" - will not include SD request, just do discoverPeers.
     *
     * @param msg
     */
    public void discoverPeersStart(Message msg) {

        discovering = true;

        if (msg.getData().getString("sd", "1").equals("0")) {
            mP2PManager.discoverPeers(getmChannel(), new MyActionListener("discoverPeers"));
        } else {
            sddisc1(0);
        }

    }

    /**
     * Scan - discover and stop.
     *
     * @param msg
     */
    public void discoveryWifiP2POnce(Message msg) {
        if (discovering) {
            stopPeerAndSDDiscovery();
            _sleep(500);
        }
        discovering = true;
        sddisc1(5000);
    }

    /**
     * Start wifi P2P discovery, including DNS-SD query.
     * @param delayMs if 0 will stay on.
     */
    public void sddisc1(final int delayMs) {

        // It appears that in P, Q the TXT are returned all when discovery is turned off.
        discoveryListener = new WifiP2pManager.DnsSdTxtRecordListener() {
            @Override
            public void onDnsSdTxtRecordAvailable(String fullDomainName, Map<String, String> txt, WifiP2pDevice wifiP2pDevice) {
                if (!fullDomainName.equals("dm._dm._udp.local.") || txt == null) {
                    return;
                }

                MsgMux.get(ctx).broadcastTxt("/wifi/peer/DISC/" + txt);

                txtDiscoveryByP2P.put(wifiP2pDevice.deviceAddress, txt);

                txt.put(Device.P2PName, wifiP2pDevice.deviceName);
                txt.put(Device.P2PAddr, wifiP2pDevice.deviceAddress);

                String ssid = txt.get("s");
                if (ssid != null) {
                    txtDiscoveryBySSID.put(ssid, txt);
                    p2pDevBySdSSID.put(ssid, new Device(wifiP2pDevice));
                }

                // Update wifi status - may include additional info
                sendWifiDiscoveryStatus("/p2psd/" + txt);
            }
        };

        mP2PManager.setDnsSdResponseListeners(getmChannel(),
                null,
                discoveryListener);

        _sleep(200);

        mP2PManager.stopPeerDiscovery(getmChannel(),
                new MyActionListener("discoveryWifiP2POnce/stopPeerDiscovery") {
                    public void onSuccess() {
                        super.onSuccess();
                        sddisc2(delayMs);
                    }
                });
    }

    public void sddisc2(final int delayMs) {
        mP2PManager.clearServiceRequests(getmChannel(),
                new MyActionListener("discoveryWifiP2POnce/clearServiceRequest") {
                    public void onSuccess() {
                        super.onSuccess();
                        sddisc3(delayMs);

                    }
                });
    }

    private void sddisc3(int delayMs) {
        mP2PManager.addServiceRequest(getmChannel(), WifiP2pDnsSdServiceRequest.newInstance(),
                new MyActionListener("addServiceRequest") {
                    public void onSuccess() {
                        super.onSuccess();

                    }
                });
        _sleep(100);
        mP2PManager.discoverServices(getmChannel(), new MyActionListener("discoverServices"));
        _sleep(100);
        mP2PManager.addServiceRequest(getmChannel(), WifiP2pDnsSdServiceRequest.newInstance(),
                new MyActionListener("addServiceRequest") {
                    public void onSuccess() {
                        super.onSuccess();

                    }
                });
        MsgMux.get(ctx).broadcastTxt("/wifi/SD/START");

        if (delayMs > 0) {
            broadcastHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    stopPeerAndSDDiscovery();
                }
            }, delayMs);
        }
    }

    public void stopPeerAndSDDiscovery() {
        mP2PManager.stopPeerDiscovery(getmChannel(), new MyActionListener("stopPeer"));
        mP2PManager.clearServiceRequests(getmChannel(), new MyActionListener("clearServiceRequest"));
//        try {
//            Thread.sleep(2000);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
        discovering = false;
    }

    // Will be needed for privacy - change name when wifi mac changes
    public void setDeviceName(String name) {
        try {
            Reflect.callMethod(mP2PManager, "setDeviceName",
                    new Class[]{WifiP2pManager.Channel.class, String.class, WifiP2pManager.ActionListener.class},
                    new Object[]{getmChannel(), name, new WifiP2pManager.ActionListener() {
                        @Override
                        public void onSuccess() {
                            Log.d(TAG, "XXX setName ");
                        }

                        @Override
                        public void onFailure(int reason) {
                            Log.d(TAG, "XXX setName error " + reason);
                        }
                    }});
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
    }

    private void registerReceiver(Context appContext) {
        IntentFilter f = new IntentFilter();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (nan != null) {
                f.addAction(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED);
            }
        }

        f.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        f.addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION);
        f.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
        f.addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION);
        f.addAction(WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION);
        f.addAction(ConnectivityManager.CONNECTIVITY_ACTION);

        appContext.registerReceiver(this, f);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (action.equals(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED)) {
                nan.onWifiAwareStateChanged(intent);
                sendWifiDiscoveryStatus("nan");
            }
        }

        if (action.equals(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)) {
            lscanResults = mWifiManager.getScanResults();

            sendWifiDiscoveryStatus("scan");

            return; // don't update
        } else if (WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION.equals(action)) {
            wifiP2pDeviceList = intent.getParcelableExtra(WifiP2pManager.EXTRA_P2P_DEVICE_LIST);

            sendWifiDiscoveryStatus("p2p");

            // Peers added/updated/removed.

            // When stop is called, all peers are removed - the status will not include the
            // peers ( so no connect attempt using P2P methods )

            // TODO: debounce, send last or when wifi scan is sent.

            // Only visible peers can be connected to using P2P methods.
        } else if (WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION.equals(action)) {
            NetworkInfo ninfo = intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO);
            pinfo = intent.getParcelableExtra(WifiP2pManager.EXTRA_WIFI_P2P_INFO);
            // also available via: mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
            // This is a sticky broadcast, so no need to do that.
            group = intent.getParcelableExtra(WifiP2pManager.EXTRA_WIFI_P2P_GROUP);

            Log.d(TAG, "/wifi/P2P " + pinfo.toString() + " " + ninfo.toString() + " " + group);

            sendWifiDiscoveryStatus(action);

            // }
//            });
        } else if (WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION.equals(action)) {
            // P2P enabled or disable, EXTRA_WIFI_STATE
            // Also at startup
            p2pEnabled = WifiP2pManager.WIFI_P2P_STATE_ENABLED == intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, 0);

        } else if (ConnectivityManager.CONNECTIVITY_ACTION.equals(action)) {
            // Just for debug to confirm receiver works
            // networkInfo - type WIFI, state CONNECTED,
            // networkType
            Log.d(TAG, "CONNECTIVITY_ACTION Broadcast:" + intent + " " + UiUtil.toString(intent.getExtras()));
        } else if (WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION.equals(action)) {
            // Also at startup.
            discoveryState = intent.getIntExtra(WifiP2pManager.EXTRA_DISCOVERY_STATE, 0);
            MsgMux.get(ctx).broadcastTxt("/wifi/p2p/discState",
                    "on", discoveryState == 2 ? "1" : "0");
        } else {
            intent.getStringExtra("");
            Log.d(TAG, "/ERR/UnknownBroadcast " + intent.getAction() + " " + UiUtil.toString(intent.getExtras()));
        }

        // TODO: remove, private
        MsgMux.get(ctx).broadcastParcelable("/wifi/INTENT/" + intent.getAction(), intent.getExtras());
    }


    static class ConnectivityCallback extends ConnectivityManager.NetworkCallback {
        private final Wifi wifi;

        ConnectivityCallback(Wifi wifi) {
            this.wifi = wifi;
        }

        @Override
        public void onAvailable(Network network) {
            super.onAvailable(network);
            // On add. Only network handle (number) is provided. Network allows binding and
            // interface specific operations, but not much else.
            // LPCHANGE provides more info
            NetworkCapabilities cap = wifi.cm.getNetworkCapabilities(network);
            LinkProperties lp = wifi.cm.getLinkProperties(network);
            NetworkInfo ninfo = wifi.cm.getNetworkInfo(network);

            WifiInfo connectionInfo = wifi.mWifiManager.getConnectionInfo();
            String ssid= connectionInfo == null ? "": connectionInfo.getSSID();


            MsgMux.get(wifi.ctx).broadcastTxt("/wifi/net/" + lp.getInterfaceName(),
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
            WifiInfo connectionInfo = wifi.mWifiManager.getConnectionInfo();
            String ssid= connectionInfo == null ? "": connectionInfo.getSSID();

            MsgMux.get(wifi.ctx).broadcastTxt("/wifi/net/" + lp.getInterfaceName(),
                    "addr", lp.getLinkAddresses().toString(),
                    "cap", cap.toString(),
                    "s", ssid == null ? "" : ssid,
                    "ninfo", ninfo.toString());
        }

        @Override
        public void onLosing(Network network, int maxMsToLive) {
            super.onLosing(network, maxMsToLive);
            MsgMux.get(wifi.ctx).broadcastTxt("/wifi/CON/LOSING/" + network.toString());
        }

        @Override
        public void onLost(Network network) {
            super.onLost(network);
            MsgMux.get(wifi.ctx).broadcastTxt("/wifi/CON/LOST/" + network.toString());
        }

        @Override
        public void onUnavailable() {
            super.onUnavailable();
            MsgMux.get(wifi.ctx).broadcastTxt("/wifi/CON/UNAVAIL");
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

    private class MyActionListener implements WifiP2pManager.ActionListener {
        private final String name;

        public MyActionListener(String name) {
            this.name = name;
        }

        @Override
        public void onSuccess() {
            Log.d(TAG, "OK " + name);
        }

        public void onFailure(int reason) {
            MsgMux.get(ctx).broadcastTxt("/ERR/" + name + "/" + reason);
        }
    }

    private void _sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
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

    public WifiP2pManager.Channel getmChannel() {
        if (mChannel == null) {
            mChannel = mP2PManager.initialize(ctx, looper, new WifiP2pManager.ChannelListener() {
                @Override
                public void onChannelDisconnected() {
                    Log.d(TAG, "Channel disconnected");
                    mChannel = null;
                }
            });
        }
        return mChannel;
    }

}
