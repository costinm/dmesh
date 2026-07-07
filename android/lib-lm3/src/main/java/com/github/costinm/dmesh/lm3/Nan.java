package com.github.costinm.dmesh.lm3;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.NetworkSpecifier;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.net.wifi.aware.AttachCallback;
import android.net.wifi.aware.Characteristics;
import android.net.wifi.aware.DiscoverySessionCallback;
import android.net.wifi.aware.IdentityChangedListener;
import android.net.wifi.aware.PeerHandle;
import android.net.wifi.aware.PublishConfig;
import android.net.wifi.aware.PublishDiscoverySession;
import android.net.wifi.aware.SubscribeConfig;
import android.net.wifi.aware.SubscribeDiscoverySession;
import android.net.wifi.aware.WifiAwareManager;
import android.net.wifi.aware.WifiAwareNetworkSpecifier;
import android.net.wifi.aware.WifiAwareSession;
import android.os.Build;
import android.os.Handler;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.Hex;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Nan {
    private static final String TAG = "nan";
    static Map<String, Device> devices = new HashMap<>();
    public WifiAwareManager nanMgr;
    public String nanId;
    Context ctx;
    LocalMesh lm;
    WifiAwareSession nanSession;
    // Not null if publish session active and nan active
    PublishDiscoverySession pubSession;
    // Not null if sub session active
    SubscribeDiscoverySession subSession;
    // Intended status of NAN subscription. subType indicates the type.
    boolean nanSub;
    boolean enabled;

    // Active subscription/passive pub seem better for this use case, but
    // it's a subtle difference: sending when looking for something, not
    // advertising it
    int subType = SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE;

    int pubType = PublishConfig.PUBLISH_TYPE_SOLICITED;

    byte[] nanMac;

    String pubServiceName = "dmesh";

    // called when mgr reports 'isAvailable'. NAN may be turned off when P2P is enabled or in
    // many other cases. When it returns, if we sub or adv attach will be called again.
    int msgId;

    public Nan(LocalMesh wifi) {
        this.lm = wifi;
        this.ctx = wifi.ctx;
    }

    public void onCreate() {
        if (!ctx.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)) {
            return;
        }

        IntentFilter filter =
                new IntentFilter(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED);
        BroadcastReceiver myReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                onWifiAwareStateChanged(intent);
            }
        };
        ctx.registerReceiver(myReceiver, filter);
    }

    public void start() {
        enabled = true;
        onWifiAwareStateChanged(new Intent());
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void stop() {
        enabled = false;
        if (pubSession != null) {
            pubSession.close();
            pubSession = null;
        }
        if (nanSession != null) {
            nanSession.close();
        }
        nanSub = false;
        if (subSession != null) {
            subSession.close();
            subSession = null;
        }

        nanSession = null;
        MsgMux.get(ctx).publish("/net/NAN/STOP");
        nanId = null;
    }

    public void update(Handler delayHandler) {
        if (!enabled) {
            return;
        }
        startNanSub();
        delayHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                stopSub();
            }
        }, 10000);

    }

    public String info() {
        WifiManager mWifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
        StringBuilder title = new StringBuilder();
        // May be used to reduce scans
        if (ctx.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)) {
            if (nanMgr == null) {
                title.append(" NAN=FEATURE");
            } else if (!nanMgr.isAvailable()) {
                title.append(" NAN=UNAVAILABLE");
            } else {
                Characteristics ch = nanMgr.getCharacteristics();

                title.append("SUP_DP=" + ch.getNumberOfSupportedDataPaths());
                title.append(" SINFO_LEN=" + ch.getMaxServiceSpecificInfoLength());
                title.append(" SN_LEN=" + ch.getMaxServiceNameLength());
                title.append(" DI_LEN=" + ch.getNumberOfSupportedDataInterfaces());
                title.append(" PUB_LEN=" + ch.getNumberOfSupportedPublishSessions());
                title.append(" SUB_LEN=" + ch.getNumberOfSupportedSubscribeSessions());
                title.append("DP=" + nanMgr.getAvailableAwareResources().getAvailableDataPathsCount() +
                        " PUB=" + nanMgr.getAvailableAwareResources().getAvailablePublishSessionsCount() +
                        " SUB=" + nanMgr.getAvailableAwareResources().getAvailableSubscribeSessionsCount());
            }
            title.append("\n");
        }

        title.append("WifiFeatures: ");
        // This includes many non-wifi features.
        // The methods that translate to feature:
        // - isEnhancedPowerReportingSupported() -> LINK_LAYER_STATS
        // - isTdlsSupported -> TDLS
        // - isP2pSupported
        // - is EasyConnectSupported
        FeatureInfo[] fi = ctx.getPackageManager().getSystemAvailableFeatures();
        for (FeatureInfo f : fi) {
            if (f.name != null && f.name.toLowerCase().contains("wifi")) {
                title.append(f.name + "\n");
            }
        }
        if (mWifiManager.is5GHzBandSupported()) {
            title.append("5G, ");
        }
        if (mWifiManager.isPreferredNetworkOffloadSupported()) {
            title.append("Offload_Scan, ");
        }
        return title.toString();
    }

    public void onWifiAwareStateChanged(Intent i) {
        if (!enabled) {
            return;
        }
        i.getBooleanExtra("foo", true);

        if (ctx.checkSelfPermission(Manifest.permission.ACCESS_WIFI_STATE) != PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Missing permissions");
            return;
        }
        try {
            nanMgr = ctx.getSystemService(WifiAwareManager.class);
            if (nanMgr == null) {
                Log.d(TAG, "State changed - no system service" + i.getAction() + " " + i.getExtras());
                return;
            }
            if (nanMgr.isAvailable()) {
                if (nanMgr.getCharacteristics() != null) {
                    Log.d(TAG, "/NAN/Char" + nanMgr.getCharacteristics().getMaxServiceNameLength() +
                            "/" + nanMgr.getCharacteristics().getMaxServiceSpecificInfoLength() + " " +
                            nanMgr.isAvailable());
                } else {
                    Log.d(TAG, "WifiAware available");
                }
                if (Build.VERSION.SDK_INT >= 34) {
                    nanMgr.setOpportunisticModeEnabled(true);
                }
                // TODO: add a setting to control 'on' or 'off' for local mesh.
                // if local mesh is on - Nan is best option.
                nanMgr.attach(new AttachCallback() {
                    @Override
                    public void onAttached(WifiAwareSession session) {
                        super.onAttached(session);
                        nanSession = session;

                        // No point being attached and not using discovery.
                        if (enabled) {
                            publish();
                            startNanSub();
                        }

                        MsgMux.get(ctx).publish("/net/NAN/Attach");
                    }

                    @Override
                    public void onAttachFailed() {
                        super.onAttachFailed();
                        MsgMux.get(ctx).publish("/net/NAN/AttachError");
                    }
                }, new IdentityChangedListener() {
                    @Override
                    public void onIdentityChanged(byte[] mac) {
                        super.onIdentityChanged(mac);
                        nanMac = mac;
                        nanId = new String(Hex.encode(mac));
                        MsgMux.get(ctx).publish("/net/NAN/MAC/" + nanId);
                        lm.sendWifiDiscoveryStatus("/nan/id", "");
                    }
                }, null);
            } else {
                Log.d(TAG, "WifiAware unavailabe");
                stop();
            }
        } catch(Throwable t) {
            t.printStackTrace();
        }
    }

    void onDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, boolean byPublisher) {
        Device bd = new Device(peerHandle, serviceSpecificInfo);
        Device old = devices.get(bd.id);
        if (old == null) {
            onDiscovery(bd, bd.id, true);
        } else {
            // See BLE - it keeps discovering device in range.
            if (SystemClock.elapsedRealtime() - old.lastScan > 120000) {
                onDiscovery(bd, bd.id, false);
            }
        }
        devices.put(bd.id, bd);


        String info = new String(serviceSpecificInfo);

        // for debugging
        if (byPublisher) {
            // Used with active sub and passive pub
            MsgMux.get(ctx).publish("/net/NAN/PubServiceDiscovered/" + info + "/" + peerHandle);
            bd.nanSession = pubSession;
        } else {
            // Used with active pub and passive sub
            MsgMux.get(ctx).publish("/net/NAN/SubServiceDiscovered/" + info + "/" + peerHandle);
            bd.nanSession = subSession;
        }
        // Send a message to the found device to verify messaging works and introduce ourselves.
        //
        send(bd.id, "FOUNDP " + lm.id4 + " " + new String(serviceSpecificInfo) + " " +
                (byPublisher ? "P" : "S"));
    }

    private void onDiscovery(Device bd, String id, boolean b) {
        lm.sendWifiDiscoveryStatus("nan", "");
    }

    private void publish() {
        if (ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Missing permissions");
            return;
        }
        // According to docs, 6-byte hashed service name is sent on the wire - along with the 6 byte local MAC.
        // This is sufficient for discovery and communication - security is at higher level.
        //
        // adv is about 255 bytes.
        PublishConfig pub = new PublishConfig.Builder().setServiceName(pubServiceName)
                .setPublishType(pubType) // silent, but respond to active requests
                .setTerminateNotificationEnabled(true)
                .setServiceSpecificInfo(lm.adv.getBytes())
                .setInstantCommunicationModeEnabled(true, ScanResult.WIFI_BAND_5_GHZ)
                .build();
        if (nanSession == null) {
                return;
        }
        nanSession.publish(pub, new NanDiscoveryCallback(true), null);
    }

    public void stopSub() {
        nanSub = false;
        if (subSession == null) {
            return;
        }
        subSession.close();
        subSession = null;
    }

    /**
     * Start a subscribe discovery session.
     * <p>
     * Will stay active until 'stop' is called.
     */
    private void startNanSub() {
        SubscribeConfig cfg = new SubscribeConfig.Builder()
                .setServiceName("dmesh")
                .setServiceSpecificInfo(lm.adv.getBytes())
                .setSubscribeType(subType)
                .setTerminateNotificationEnabled(true)
                .setInstantCommunicationModeEnabled(true, ScanResult.WIFI_BAND_5_GHZ)
                .build();
        Log.d(TAG, "/NAN/Subscribe");
        if (ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Missing permissions");
            return;
        }
        if (nanSession == null) {
            return;
        }

        nanSession.subscribe(cfg, new NanDiscoveryCallback(false), null);

    }

    /**
     * Connect to a NAN device.
     *
     * @param id - the primary ID, from the pub announce.
     */
    public void conNan(String id) {
        if ("0".equals(id) || "*".equals(id)) {
            // This is unlikely to work well - there are limits on how many.
            // Good to identify them...
            for (Device d : devices.values()) {
                subSession.sendMessage(d.nan, msgId++, "CON".getBytes());
                if ("0".equals(id)) {
                    return;
                }
            }
            return;
        }
        Device d = devices.get(id);
        if (d == null || subSession == null) {
            return;
        }

        if (d.nan != null) {
            subSession.sendMessage(d.nan, msgId++, "CON".getBytes());
        }
    }

    public void sendAll(String id) {
        if (subSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == subSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send " + d.id + " " + d.nan + " " + msgId);
                    subSession.sendMessage(d.nan, msgId++, id.getBytes());
                }
            }
        }
        if (pubSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == pubSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send pub " + d.id + " " + d.nan + " " + msgId);
                    pubSession.sendMessage(d.nan, msgId++, id.getBytes());
                }
            }
        }
    }

    public void send(String id, String msg) {
        Device d = devices.get(id);
        if (d != null && d.nan != null && d.nanSession != null) {
            d.nanSession.sendMessage(d.nan, msgId++, msg.getBytes());
        }
    }

    /**
     * Used for both publish and subscribe, get notified of nearby
     * devices.
     */
    class NanDiscoveryCallback extends DiscoverySessionCallback {
        private final boolean pub;

        public NanDiscoveryCallback(boolean pub) {
            this.pub = pub;
        }


        /**
         * It appears only subscriber discovers the publisher, not the other way around.
         * <p>
         * For both ends to know, we need to send a message (further discovery).
         *
         * @param peerHandle
         * @param serviceSpecificInfo
         * @param matchFilter
         */
        @Override
        public void onServiceDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter) {
            Log.d(TAG, "/NAN/ServiceDiscovered " + (pub ? "pub" : "sub"));

            super.onServiceDiscovered(peerHandle, serviceSpecificInfo, matchFilter);

            onDiscovered(peerHandle, serviceSpecificInfo, pub);
        }


        @Override
        public void onSessionConfigUpdated() {
            super.onSessionConfigUpdated();
            Log.d(TAG, "/NAN/PubSessionConfigUpdated");
        }

        @Override
        public void onSessionConfigFailed() {
            super.onSessionConfigFailed();
            MsgMux.get(ctx).publish("/net/NAN/PubSessionConfigFailed");
        }

        @Override
        public void onServiceDiscoveredWithinRange(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter, int distanceMm) {
            onServiceDiscovered(peerHandle, serviceSpecificInfo, matchFilter);
        }

        @Override
        public void onMessageSendSucceeded(int messageId) {
            super.onMessageSendSucceeded(messageId);
            Log.d(TAG, "/NAN/SENT/" + messageId);
        }

        @Override
        public void onMessageSendFailed(int messageId) {
            super.onMessageSendFailed(messageId);
            MsgMux.get(ctx).publish("/net/NAN/MSGERR", "id", Integer.toString(messageId));
        }

        @Override
        public void onSubscribeStarted(SubscribeDiscoverySession session) {
            super.onSubscribeStarted(session);
            Log.d(TAG, "/NAN/SubStart" + session);
            MsgMux.get(ctx).publish("/net/NAN/SubStart");
            subSession = session;
        }

        @Override
        public void onPublishStarted(PublishDiscoverySession session) {
            super.onPublishStarted(session);
            Log.d(TAG, "/NAN/PubStart");
            MsgMux.get(ctx).publish("/net/NAN/PubStart");
            pubSession = session;
        }

        @Override
        public void onSessionTerminated() {
            super.onSessionTerminated();
            devices.clear(); // TODO: only devices of given type
            pubSession = null;
            if (pub) {
                MsgMux.get(ctx).publish("/net/NAN/PubStop", "dev", "" + devices);
            } else {
                MsgMux.get(ctx).publish("/net/NAN/SubStop", "dev", "" + devices);
            }
        }

        @Override
        public void onMessageReceived(PeerHandle peerHandle, byte[] message) {
            super.onMessageReceived(peerHandle, message);
            String msg = new String(message);

            if (msg.equals("CONS")) {
                lm.delayHandler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        NetworkSpecifier ns;
                        ns = new WifiAwareNetworkSpecifier.Builder(subSession, peerHandle).build();
                        NetworkRequest nr = new NetworkRequest.Builder()
                                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                                .setNetworkSpecifier(ns).build();
                        lm.cm.requestNetwork(nr, new LocalMesh.ConnectivityCallback(lm), 10000);
                    }
                }, 3000);
            } else if (msg.startsWith("PING")) {
                pubSession.sendMessage(peerHandle, 1, "PONGP".getBytes());
            } else if (msg.equals("CON")) {
                NetworkSpecifier ns;
                if (Build.VERSION.SDK_INT >= 29) {
                    ns = new WifiAwareNetworkSpecifier.Builder(pubSession, peerHandle).build();
                } else {
                    ns = pubSession.createNetworkSpecifierOpen(peerHandle);
                }
                NetworkRequest nr = new NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                        .setNetworkSpecifier(ns).build();
                lm.cm.requestNetwork(nr, new LocalMesh.ConnectivityCallback(lm), 10000);
                pubSession.sendMessage(peerHandle, 1, "CONS".getBytes());
            }

            MsgMux.get(ctx).publish("/net/NAN/TXT/" + msg + "/" + peerHandle);
            Log.d(TAG, "NAN received: " + msg + " " + peerHandle);
        }

    }


}
