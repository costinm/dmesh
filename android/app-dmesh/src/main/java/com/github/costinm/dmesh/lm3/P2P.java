package com.github.costinm.dmesh.lm3;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WpsInfo;
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
import android.os.Message;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.MsgMux;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;


public class P2P extends BroadcastReceiver {
    static final String SD_SUFFIX_PART = "_dm._udp";
    private WifiP2pManager.DnsSdTxtRecordListener discoveryListener;

    LocalMesh lm;
    Context ctx;
    //public Bt2 bt;
    // True if AP started in P2P mode
    public boolean p2pGroupStarted;
    // State reported by broadcast, 2 == started, 1 == stopped.
    // Will be stopped during connect
    // Should not be relevant to the higher layers - this class should just track it.
    // May be reported in 'scan' events.
    public int discoveryState;
    String mySSID = "";
    String psk = "";
    WifiP2pDnsSdServiceInfo si;
    // Database with recent discovered P2P devices, with DNS-SD completed and with a valid
    // SSID
    // Key is the SSID, so we can match against scan data.
    public static Map<String, Device> p2pDevBySdSSID = new HashMap<>();
    /**
     * If AP active, contains the list of devices connected to this server.
     */
    public static ArrayList<WifiP2pDevice> currentClientList = new ArrayList<>();
    // SD discovery info, keyed by the P2P id.
    // The debug app depends on SD discovery working, doesn't persist any data.
    // The mesh app may persist and get the data from other nodes. When visibility reports are sent,
    // it'll merge with its own SD discovery data.
    // TODO: expire after some time. The address is rotated periodically - this needs to be cleaned up.
    // Last p2p discovery. Empty if discovery not in progress. This has only WifiP2pDevice info,
    // no discovery info. SD may be cached in txtDiscoveryByP2P or BySSID.
    static WifiP2pDeviceList wifiP2pDeviceList;

    public static Map<String, Map<String, String>> txtDiscoveryByP2P = new HashMap<>();
    public static Map<String, Map<String, String>> txtDiscoveryBySSID = new HashMap<>();

    // Raw data from callbacks:
    // Last 'group' info, or null if the group is not started.
    public WifiP2pGroup group;

    WifiP2pManager mP2PManager;
    static WifiP2pManager.Channel mChannel;
    boolean p2pEnabled;
     WifiP2pInfo pinfo;
    WifiManager mWifiManager;

    static boolean discovering = false;

    public P2P(LocalMesh localMesh) {
        lm = localMesh;
        ctx = lm.ctx;
        mP2PManager = (WifiP2pManager) ctx.getSystemService(Context.WIFI_P2P_SERVICE);
        mWifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
    }

    void onCreate() {

        IntentFilter f = new IntentFilter();

        f.addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION);
        f.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
        f.addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION);
        f.addAction(WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION);
        f.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);

        ctx.registerReceiver(this, f);

    }

    /**
     * Control the WifiP2P announce. Usually after AP starts/stops.
     *
     * @param on
     */
    @SuppressLint("MissingPermission")
    public void announceWifiP2P(boolean on) {
        if (on && group != null) {
            Map<String, String> map = new HashMap<>();
            // TODO: use the short form as well ?
            map.put(Device.SSID, group.getNetworkName());
            map.put(Device.PSK, group.getPassphrase());
            map.put(Device.ID4, lm.id4);

            String ssid = mWifiManager.getConnectionInfo().getSSID();
            if (ssid != null && !ssid.startsWith("<")) {
                map.put(Device.NET, ssid);
            }

            si = WifiP2pDnsSdServiceInfo.newInstance("dm", SD_SUFFIX_PART, map);

            mP2PManager.addLocalService(getmChannel(), si, new MyActionListener("addLocalService"));

        } else {
            if (si != null) {
                mP2PManager.removeLocalService(getmChannel(), si, new MyActionListener("SD-Announce-OFF"));
            }
        }
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (action.equals(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)) {
            if (context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                return;
            }
            lm.lscanResults = mWifiManager.getScanResults();

            lm.sendWifiDiscoveryStatus("scan", "");
        } else if (WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION.equals(action)) {
            wifiP2pDeviceList = intent.getParcelableExtra(WifiP2pManager.EXTRA_P2P_DEVICE_LIST);

            lm.sendWifiDiscoveryStatus("p2p", "");

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

            Log.d(lm.TAG, "wifi.P2P " + pinfo.toString() + " " + ninfo.toString() + " " + group);

            if (group == null || !group.isGroupOwner()) {
                if (p2pGroupStarted) {
                    announceWifiP2P(false);
                    p2pGroupStarted = false;
                    MsgMux.get(ctx).publish("wifi.AP", "on", "0");
                }
                currentClientList.clear();
            } else {
                if (!group.getNetworkName().equals(mySSID) ||
                        !group.getPassphrase().equals(psk)) {

                    mySSID = group.getNetworkName();
                    psk = group.getPassphrase();

                    MsgMux.get(ctx).publish("wifi.ApIdChange",
                            "mySSID", group.getNetworkName(),
                            "psk", group.getPassphrase(),
                            "oldssid", "" + mySSID);

                    lm.announce(true);
                }
                mySSID = group.getNetworkName();
                psk = group.getPassphrase();
                currentClientList = new ArrayList<>(group.getClientList());
                if (!p2pGroupStarted) {
                    p2pGroupStarted = true;
                    announceWifiP2P(true);
                    MsgMux.get(ctx).publish("wifi.AP", "on", "1");
                }
            }

            lm.sendWifiDiscoveryStatus(action, "");

            // }
//            });
        } else if (WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION.equals(action)) {
            // P2P enabled or disable, EXTRA_WIFI_STATE
            // Also at startup
            p2pEnabled = WifiP2pManager.WIFI_P2P_STATE_ENABLED == intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, 0);

        } else if (WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION.equals(action)) {
            // Also at startup.
            discoveryState = intent.getIntExtra(WifiP2pManager.EXTRA_DISCOVERY_STATE, 0);
            MsgMux.get(ctx).publish("wifi.p2p.discState",
                    "on", discoveryState == 2 ? "1" : "0");
        }
    }
    void _sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }



    private class MyActionListener implements WifiP2pManager.ActionListener {
        private final String name;

        public MyActionListener(String name) {
            this.name = name;
        }

        @Override
        public void onSuccess() {
            Log.d(lm.TAG, "OK " + name);
        }

        public void onFailure(int reason) {
            MsgMux.get(ctx).publish("wifi.ERR." + name + "." + reason);
        }
    }

    public static final String DEFAULT_PSK = "12345678";


    /**
     * Start AP.
     * A broadcast will be sent if the status changes, from the BroadcastReceiver.
     */
    @SuppressLint({"NewApi", "MissingPermission"})
    public void apOn(boolean started) {
        if (started) {
            if (Build.VERSION.SDK_INT >= 28) {
                // Android requires the Wi-Fi Direct group name to begin
                // `DIRECT-xy`. Keep that prefix, but also keep the common
                // `-dmesh` suffix so host, Android, and ESP channel-6 scans
                // can classify this as a DMesh AP without OEM-specific P2P
                // metadata.
                WifiP2pConfig cfg = new WifiP2pConfig.Builder().enablePersistentMode(false)
                        .setNetworkName("DIRECT-DM-" + lm.id4 + "-dmesh")
                        .setPassphrase(DEFAULT_PSK).build();
                mP2PManager.createGroup(getmChannel(), cfg, new MyActionListener("createGroupQ"));
            } else {
                // Override the P2P device name with the ID.
                // TODO: use a setting, and maybe only do it if user allows.
                // The name is not frequently used.
                //setDeviceName(id4);

                mP2PManager.createGroup(getmChannel(), new MyActionListener("createGroup"));
            }
        } else {
            mP2PManager.removeGroup(getmChannel(), new MyActionListener("removeGroup"));
        }
    }

    public void stopAll() {
        stopPeerAndSDDiscovery();
        if (si != null) {
            mP2PManager.removeLocalService(getmChannel(), si, new MyActionListener("removeLocalService"));
            si = null;
        }
        mP2PManager.cancelConnect(getmChannel(), new MyActionListener("cancelConnect"));
        mP2PManager.removeGroup(getmChannel(), new MyActionListener("removeGroup"));
        p2pGroupStarted = false;
        group = null;
        currentClientList.clear();
        MsgMux.get(ctx).publish("wifi.p2p.STOP");
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
        if (mode == -1 && Build.VERSION.SDK_INT >= 29) {
            if (null == msg.getString(Device.PSK) ||
                    null == msg.getString(Device.SSID)) {

                return;
            }

            WifiP2pConfig cfg = new WifiP2pConfig.Builder()
                    .enablePersistentMode(true)
                    .setPassphrase(msg.getString(Device.PSK))
                    .setNetworkName(msg.getString(Device.SSID))
                    .build();
            if (ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
                    ctx.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                // TODO: Consider calling
                //    ActivityCompat#requestPermissions
                // here to request the missing permissions, and then overriding
                //   public void onRequestPermissionsResult(int requestCode, String[] permissions,
                //                                          int[] grantResults)
                // to handle the case where the user grants the permission. See the documentation
                // for ActivityCompat#requestPermissions for more details.
                return;
            }
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
     * <p>
     * If "sd" optional parameter is "0" - will not include SD request, just do discoverPeers.
     *
     * @param msg
     */
    @SuppressLint("MissingPermission")
    public void discoverPeersStart(Message msg) {

        discovering = true;

        if (msg.getData().getString("sd", "1").equals("0")) {
            mP2PManager.discoverPeers(getmChannel(), new MyActionListener("discoverPeers"));
        } else {
            sddisc1(0);
        }

    }

    /**
     * Scan - discover and stop. About 6 seconds.
     */
    public void discoveryWifiP2POnce() {
        if (discovering) {
            stopPeerAndSDDiscovery();
            _sleep(500);
        }
        discovering = true;
        sddisc1(5000);
    }

    /**
     * Start wifi P2P discovery, including DNS-SD query.
     *
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

                MsgMux.get(ctx).publish("wifi.peer.DISC." + txt);

                txtDiscoveryByP2P.put(wifiP2pDevice.deviceAddress, txt);

                txt.put(Device.P2PName, wifiP2pDevice.deviceName);
                txt.put(Device.P2PAddr, wifiP2pDevice.deviceAddress);

                String ssid = txt.get("s");
                if (ssid != null) {
                    txtDiscoveryBySSID.put(ssid, txt);
                    p2pDevBySdSSID.put(ssid, new Device(wifiP2pDevice));
                }

                // Update wifi status - may include additional info
                lm.sendWifiDiscoveryStatus("/p2psd/" + txt, "");
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

    @SuppressLint("MissingPermission")
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
        MsgMux.get(ctx).publish("wifi.SD.START");

        if (delayMs > 0) {
            lm.delayHandler.postDelayed(new Runnable() {
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
        discovering = false;
    }

    public WifiP2pManager.Channel getmChannel() {
        if (mChannel == null) {
            // 3rd param is called on disconnect.
            // messages are sent on the looper
            mChannel = mP2PManager.initialize(ctx, lm.looper, new WifiP2pManager.ChannelListener() {
                @Override
                public void onChannelDisconnected() {
                    Log.d(lm.TAG, "Channel disconnected");
                    mChannel = null;
                }
            });
        }
        return mChannel;
    }

}
