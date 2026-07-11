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
import com.github.costinm.dmeshnative.MeshNode;

import java.nio.charset.StandardCharsets;
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
    boolean attachInProgress;
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
    int wakeCount;

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
        MsgMux.get(ctx).publish("net.NAN.START");
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
        attachInProgress = false;
        nanSub = false;
        if (subSession != null) {
            subSession.close();
            subSession = null;
        }

        nanSession = null;
        MsgMux.get(ctx).publish("net.NAN.STOP");
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
            MsgMux.get(ctx).publish("net.NAN.ERR.permission");
            return;
        }
        try {
            nanMgr = ctx.getSystemService(WifiAwareManager.class);
            if (nanMgr == null) {
                Log.d(TAG, "State changed - no system service" + i.getAction() + " " + i.getExtras());
                MsgMux.get(ctx).publish("net.NAN.ERR.service");
                return;
            }
            if (nanMgr.isAvailable()) {
                if (nanSession != null) {
                    MsgMux.get(ctx).publish("net.NAN.Status", "state", "attached");
                    return;
                }
                if (attachInProgress) {
                    MsgMux.get(ctx).publish("net.NAN.Status", "state", "attaching");
                    return;
                }
                if (nanMgr.getCharacteristics() != null) {
                    Log.d(TAG, "/NAN/Char" + nanMgr.getCharacteristics().getMaxServiceNameLength() +
                            "/" + nanMgr.getCharacteristics().getMaxServiceSpecificInfoLength() + " " +
                            nanMgr.isAvailable());
                } else {
                    Log.d(TAG, "WifiAware available");
                }
                if (Build.VERSION.SDK_INT >= 34) {
                    try {
                        nanMgr.setOpportunisticModeEnabled(true);
                    } catch (SecurityException se) {
                        Log.w(TAG, "Unable to enable NAN opportunistic mode", se);
                        MsgMux.get(ctx).publish("net.NAN.OpportunisticError",
                                "error", se.toString());
                    } catch (RuntimeException re) {
                        Log.w(TAG, "Unable to enable NAN opportunistic mode", re);
                        MsgMux.get(ctx).publish("net.NAN.OpportunisticError",
                                "error", re.toString());
                    }
                }
                // TODO: add a setting to control 'on' or 'off' for local mesh.
                // if local mesh is on - Nan is best option.
                attachInProgress = true;
                MsgMux.get(ctx).publish("net.NAN.AttachStart");
                nanMgr.attach(new AttachCallback() {
                    @Override
                    public void onAttached(WifiAwareSession session) {
                        super.onAttached(session);
                        attachInProgress = false;
                        nanSession = session;

                        // No point being attached and not using discovery.
                        if (enabled) {
                            publish();
                            startNanSub();
                        }

                        MsgMux.get(ctx).publish("net.NAN.Attach");
                    }

                    @Override
                    public void onAttachFailed() {
                        super.onAttachFailed();
                        attachInProgress = false;
                        enabled = false;
                        MsgMux.get(ctx).publish("net.NAN.AttachError", "retry", "explicit-start-required");
                    }
                }, new IdentityChangedListener() {
                    @Override
                    public void onIdentityChanged(byte[] mac) {
                        super.onIdentityChanged(mac);
                        nanMac = mac;
                        nanId = new String(Hex.encode(mac));
                        MsgMux.get(ctx).publish("net.NAN.MAC." + nanId);
                        lm.sendWifiDiscoveryStatus("/nan/id", "");
                    }
                }, null);
            } else {
                Log.d(TAG, "WifiAware unavailabe");
                MsgMux.get(ctx).publish("net.NAN.unavailable");
                stop();
            }
        } catch(Throwable t) {
            Log.w(TAG, "NAN attach failed", t);
            attachInProgress = false;
            MsgMux.get(ctx).publish("net.NAN.AttachError",
                    "error", t.getClass().getName(),
                    "message", t.toString());
        }
    }

    void onDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, boolean byPublisher) {
        Device bd = new Device(peerHandle, serviceSpecificInfo);
        String parsed = MeshNode.parseNanServiceInfo(serviceSpecificInfo);
        String deviceId = jsonField(parsed, "device_id");
        if (deviceId.length() > 0) {
            bd.id = deviceId;
            bd.data.putString(Device.P2PAddr, "/nan/" + deviceId);
            bd.data.putString("proto", "dmesh_nan");
            bd.data.putString("nan", parsed);
        }
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


        // for debugging
        if (byPublisher) {
            // Used with active sub and passive pub
            MsgMux.get(ctx).publish("net.NAN.PubServiceDiscovered",
                    "peer", peerHandle.toString(),
                    "id", bd.id,
                    "json", parsed);
            bd.nanSession = pubSession;
        } else {
            // Used with active pub and passive sub
            MsgMux.get(ctx).publish("net.NAN.SubServiceDiscovered",
                    "peer", peerHandle.toString(),
                    "id", bd.id,
                    "json", parsed);
            bd.nanSession = subSession;
        }
        sendFollowup(bd, "hello", new byte[0]);
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
        if (nanSession == null) {
                return;
        }
        if (pubSession != null) {
            return;
        }
        try {
            nanSession.publish(buildPublishConfig(true), new NanDiscoveryCallback(true), null);
        } catch (IllegalArgumentException | SecurityException e) {
            Log.w(TAG, "NAN publish with instant mode failed; retrying without instant mode", e);
            MsgMux.get(ctx).publish("net.NAN.PubInstantError", "error", e.toString());
            try {
                nanSession.publish(buildPublishConfig(false), new NanDiscoveryCallback(true), null);
            } catch (RuntimeException retryError) {
                Log.w(TAG, "NAN publish failed", retryError);
                MsgMux.get(ctx).publish("net.NAN.PubError", "error", retryError.toString());
            }
        }
    }

    private PublishConfig buildPublishConfig(boolean instant) {
        PublishConfig.Builder builder = new PublishConfig.Builder().setServiceName(pubServiceName)
                .setPublishType(pubType) // silent, but respond to active requests
                .setTerminateNotificationEnabled(true)
                .setServiceSpecificInfo(MeshNode.buildNanServiceInfo("android",
                        lm.deviceIdBytes(),
                        wakeCount++));
        if (instant) {
            builder.setInstantCommunicationModeEnabled(true, ScanResult.WIFI_BAND_5_GHZ);
        }
        return builder.build();
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
        Log.d(TAG, "/NAN/Subscribe");
        if (ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Missing permissions");
            return;
        }
        if (nanSession == null) {
            return;
        }
        if (subSession != null || nanSub) {
            return;
        }
        nanSub = true;

        try {
            nanSession.subscribe(buildSubscribeConfig(true), new NanDiscoveryCallback(false), null);
        } catch (IllegalArgumentException | SecurityException e) {
            Log.w(TAG, "NAN subscribe with instant mode failed; retrying without instant mode", e);
            MsgMux.get(ctx).publish("net.NAN.SubInstantError", "error", e.toString());
            try {
                nanSession.subscribe(buildSubscribeConfig(false), new NanDiscoveryCallback(false), null);
            } catch (RuntimeException retryError) {
                Log.w(TAG, "NAN subscribe failed", retryError);
                MsgMux.get(ctx).publish("net.NAN.SubError", "error", retryError.toString());
            }
        }

    }

    private SubscribeConfig buildSubscribeConfig(boolean instant) {
        SubscribeConfig.Builder builder = new SubscribeConfig.Builder()
                .setServiceName("dmesh")
                .setServiceSpecificInfo(MeshNode.buildNanServiceInfo("android",
                        lm.deviceIdBytes(),
                        wakeCount++))
                .setSubscribeType(subType)
                .setTerminateNotificationEnabled(true);
        if (instant) {
            builder.setInstantCommunicationModeEnabled(true, ScanResult.WIFI_BAND_5_GHZ);
        }
        return builder.build();
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
                sendFollowup(d, "wake_request", new byte[0]);
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
            sendFollowup(d, "wake_request", new byte[0]);
        }
    }

    public void sendAll(String id) {
        if (subSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == subSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send " + d.id + " " + d.nan + " " + msgId);
                    sendFollowup(d, "command_text", id.getBytes(StandardCharsets.UTF_8));
                }
            }
        }
        if (pubSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == pubSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send pub " + d.id + " " + d.nan + " " + msgId);
                    sendFollowup(d, "command_text", id.getBytes(StandardCharsets.UTF_8));
                }
            }
        }
    }

    public void send(String id, String msg) {
        Device d = devices.get(id);
        sendFollowup(d, "command_text", msg.getBytes(StandardCharsets.UTF_8));
    }

    private void sendFollowup(Device d, String msgType, byte[] payload) {
        if (d == null || d.nan == null || d.nanSession == null) {
            return;
        }
        byte[] target = parseDeviceId(d.id);
        byte[] body = MeshNode.buildNanFollowup(msgType, lm.deviceIdBytes(), target, payload);
        d.nanSession.sendMessage(d.nan, msgId++, body);
        MsgMux.get(ctx).publish("net.NAN.FollowupTx",
                "id", d.id == null ? "" : d.id,
                "type", msgType,
                "bytes", Integer.toString(body.length));
    }

    private byte[] parseDeviceId(String id) {
        byte[] out = new byte[6];
        if (id == null || id.length() < 12) {
            return out;
        }
        for (int i = 0; i < out.length; i++) {
            try {
                out[i] = (byte) Integer.parseInt(id.substring(i * 2, i * 2 + 2), 16);
            } catch (RuntimeException e) {
                return new byte[6];
            }
        }
        return out;
    }

    private String jsonField(String json, String field) {
        if (json == null) {
            return "";
        }
        String needle = "\"" + field + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) {
            return "";
        }
        start += needle.length();
        int end = json.indexOf('"', start);
        if (end < 0) {
            return "";
        }
        return json.substring(start, end);
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
            MsgMux.get(ctx).publish("net.NAN.PubSessionConfigFailed");
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
            MsgMux.get(ctx).publish("net.NAN.MSGERR", "id", Integer.toString(messageId));
        }

        @Override
        public void onSubscribeStarted(SubscribeDiscoverySession session) {
            super.onSubscribeStarted(session);
            Log.d(TAG, "/NAN/SubStart" + session);
            MsgMux.get(ctx).publish("net.NAN.SubStart");
            subSession = session;
        }

        @Override
        public void onPublishStarted(PublishDiscoverySession session) {
            super.onPublishStarted(session);
            Log.d(TAG, "/NAN/PubStart");
            MsgMux.get(ctx).publish("net.NAN.PubStart");
            pubSession = session;
        }

        @Override
        public void onSessionTerminated() {
            super.onSessionTerminated();
            devices.clear(); // TODO: only devices of given type
            pubSession = null;
            if (pub) {
                MsgMux.get(ctx).publish("net.NAN.PubStop", "dev", "" + devices);
            } else {
                MsgMux.get(ctx).publish("net.NAN.SubStop", "dev", "" + devices);
            }
        }

        @Override
        public void onMessageReceived(PeerHandle peerHandle, byte[] message) {
            super.onMessageReceived(peerHandle, message);
            String msg = new String(message);
            String parsed = MeshNode.parseNanFollowup(message);
            MsgMux.get(ctx).publish("net.NAN.FollowupRx",
                    "peer", peerHandle.toString(),
                    "json", parsed);

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

            MsgMux.get(ctx).publish("net.NAN.TXT." + msg + "." + peerHandle);
            Log.d(TAG, "NAN received: " + msg + " " + peerHandle);
        }

    }


}
