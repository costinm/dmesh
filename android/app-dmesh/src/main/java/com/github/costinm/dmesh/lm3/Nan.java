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
import android.net.wifi.WifiManager;
import android.net.wifi.aware.AttachCallback;
import android.net.wifi.aware.Characteristics;
import android.net.wifi.aware.DiscoverySession;
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
    volatile WifiAwareSession nanSession;
    boolean attachInProgress;
    // Not null if publish session active and nan active
    volatile PublishDiscoverySession pubSession;
    // publish()/subscribe() complete asynchronously. State-change broadcasts
    // may arrive before their Started callbacks; these guards prevent duplicate
    // discovery sessions and peer handles scoped to a superseded session.
    volatile boolean pubStarting;
    // Not null if sub session active
    volatile SubscribeDiscoverySession subSession;
    // Intended status of NAN subscription. subType indicates the type.
    volatile boolean nanSub;
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
    final Map<Integer, String> pendingFollowups = new HashMap<>();

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
        pubStarting = false;
        attachInProgress = false;
        nanSub = false;
        // Discovery sessions are children of the aware attachment. Close and
        // clear them first: closing the parent before either child makes the
        // Android Wi-Fi Aware service reject the later close with an invalid
        // uid/client mapping, and the following start remains attached but
        // cannot recreate discovery sessions.
        PublishDiscoverySession publishing = pubSession;
        SubscribeDiscoverySession subscribing = subSession;
        pubSession = null;
        subSession = null;
        if (publishing != null) {
            try {
                publishing.close();
            } catch (IllegalStateException ignored) {
                // The session may already have terminated asynchronously.
            }
        }
        if (subscribing != null) {
            try {
                subscribing.close();
            } catch (IllegalStateException ignored) {
                // The session may already have terminated asynchronously.
            }
        }
        WifiAwareSession attachment = nanSession;
        nanSession = null;
        if (attachment != null) {
            try {
                attachment.close();
            } catch (IllegalStateException ignored) {
                // The attachment may already have terminated asynchronously.
            }
        }
        devices.clear();
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
                    // Discovery sessions can terminate independently while the
                    // attachment stays valid. Recreate only the missing side so
                    // a clean test/app restart does not remain attached but
                    // permanently undiscoverable.
                    if (pubSession == null && !pubStarting) {
                        publish();
                    }
                    if (subSession == null && !nanSub) {
                        startNanSub();
                    }
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
                        // onAttached() normally starts discovery before the framework has
                        // delivered this identity callback. Refresh the session descriptors
                        // rather than retaining the legacy placeholder identity in service
                        // specific information (or tearing down peer handles mid-test).
                        refreshDiscoveryIdentity();
                        lm.sendWifiDiscoveryStatus("/nan/id", "");
                    }
                }, lm.delayHandler);
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

    void onDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, boolean byPublisher,
                      DiscoverySession discoverySession) {
        if (discoverySession == null) {
            return;
        }
        Device bd = new Device(peerHandle, serviceSpecificInfo);
        String parsed = MeshNode.parseNanServiceInfo(serviceSpecificInfo);
        String deviceId = jsonField(parsed, "device_id");
        if (isUsableDmeshIdentity(deviceId)) {
            bd.id = deviceId;
            bd.data.putString(Device.P2PAddr, "/nan/" + deviceId);
            bd.data.putString("proto", "dmesh_nan");
            bd.data.putString("nan", parsed);
        } else {
            // A stale app version advertised the ASCII value "000000" here.
            // Never retain it as a peer: its shared map key caused follow-ups
            // to be routed through arbitrary stale discovery handles.
            MsgMux.get(ctx).publish("net.NAN.InvalidServiceIdentity",
                    "peer", peerHandle.toString(), "id", deviceId);
            return;
        }
        bd.nanSession = discoverySession;
        Device old = devices.get(bd.id);
        if (old == null) {
            onDiscovery(bd, bd.id, true);
        } else {
            // See BLE - it keeps discovering device in range.
            if (SystemClock.elapsedRealtime() - old.lastScan > 120000) {
                onDiscovery(bd, bd.id, false);
            }
        }
        // for debugging
        if (byPublisher) {
            // Used with active sub and passive pub
            MsgMux.get(ctx).publish("net.NAN.PubServiceDiscovered",
                    "peer", peerHandle.toString(),
                    "id", bd.id,
                    "json", parsed);
        } else {
            // Used with active pub and passive sub
            MsgMux.get(ctx).publish("net.NAN.SubServiceDiscovered",
                    "peer", peerHandle.toString(),
                    "id", bd.id,
                    "json", parsed);
        }
        // Peer handles are scoped to a discovery session. Replace the old handle only after
        // this callback's session has been recorded, so callers cannot send on a stale one.
        devices.put(bd.id, bd);
        // Do not send a debug hello here. Some Android Wi-Fi Aware HALs leave a
        // queued message unresolved when a raw peer disappears between discovery
        // windows, which blocks every later application command in their single
        // transmit queue. A caller sends only when it has real data.
        MsgMux.get(ctx).publish("net.NAN.PeerReady",
                "id", bd.id == null ? "" : bd.id,
                "peer", peerHandle.toString());
    }

    private static boolean isUsableDmeshIdentity(String deviceId) {
        if (deviceId == null || !deviceId.matches("[0-9A-Fa-f]{12}")) {
            return false;
        }
        return !"000000000000".equals(deviceId) && !"303030303030".equals(deviceId);
    }

    private void onDiscovery(Device bd, String id, boolean b) {
        lm.sendWifiDiscoveryStatus("nan", "");
    }

    private synchronized void publish() {
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
        if (pubSession != null || pubStarting) {
            return;
        }
        try {
            // Classic ESP32 raw NAN runs on 2.4 GHz channel 6. Do not ask the
            // Android HAL for 5 GHz instant communication here: a discovery
            // callback can still be observed while follow-ups are scheduled on
            // a radio the ESP cannot receive.
            pubStarting = true;
            nanSession.publish(buildPublishConfig(), new NanDiscoveryCallback(true), lm.delayHandler);
        } catch (RuntimeException e) {
            pubStarting = false;
            Log.w(TAG, "NAN publish failed", e);
            MsgMux.get(ctx).publish("net.NAN.PubError", "error", e.toString());
        }
    }

    private PublishConfig buildPublishConfig() {
        PublishConfig.Builder builder = new PublishConfig.Builder().setServiceName(pubServiceName)
                .setPublishType(pubType) // silent, but respond to active requests
                .setTerminateNotificationEnabled(true)
                .setServiceSpecificInfo(MeshNode.buildNanServiceInfo("android",
                        lm.deviceIdBytes(),
                        wakeCount++));
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
    private synchronized void startNanSub() {
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
            // Keep discovery and follow-ups on the normal 2.4 GHz aware
            // cluster while validating a raw classic-ESP peer.
            nanSession.subscribe(buildSubscribeConfig(), new NanDiscoveryCallback(false), lm.delayHandler);
        } catch (RuntimeException e) {
            nanSub = false;
            Log.w(TAG, "NAN subscribe failed", e);
            MsgMux.get(ctx).publish("net.NAN.SubError", "error", e.toString());
        }

    }

    private SubscribeConfig buildSubscribeConfig() {
        SubscribeConfig.Builder builder = new SubscribeConfig.Builder()
                .setServiceName("dmesh")
                .setServiceSpecificInfo(MeshNode.buildNanServiceInfo("android",
                        lm.deviceIdBytes(),
                        wakeCount++))
                .setSubscribeType(subType)
                .setTerminateNotificationEnabled(true);
        return builder.build();
    }

    /** Update active discovery descriptors after Wi-Fi Aware supplies our NAN MAC. */
    private synchronized void refreshDiscoveryIdentity() {
        if (pubSession != null) {
            try {
                pubSession.updatePublish(buildPublishConfig());
                MsgMux.get(ctx).publish("net.NAN.PubIdentityUpdated", "id", nanId);
            } catch (IllegalStateException e) {
                MsgMux.get(ctx).publish("net.NAN.PubIdentityUpdateError", "error", e.toString());
            }
        }
        if (subSession != null) {
            try {
                subSession.updateSubscribe(buildSubscribeConfig());
                MsgMux.get(ctx).publish("net.NAN.SubIdentityUpdated", "id", nanId);
            } catch (IllegalStateException e) {
                MsgMux.get(ctx).publish("net.NAN.SubIdentityUpdateError", "error", e.toString());
            }
        }
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

    public int sendAll(String id) {
        int sent = 0;
        if (subSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == subSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send " + d.id + " " + d.nan + " " + msgId);
                    sendFollowup(d, "command_text", id.getBytes(StandardCharsets.UTF_8));
                    sent++;
                }
            }
        }
        if (pubSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == pubSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send pub " + d.id + " " + d.nan + " " + msgId);
                    sendFollowup(d, "command_text", id.getBytes(StandardCharsets.UTF_8));
                    sent++;
                }
            }
        }
        return sent;
    }

    /**
     * Send the same follow-up on a bounded cadence for discovery-window tests.
     *
     * This is deliberately a test surface rather than a reliability policy:
     * production callers keep their own pending payload and send only when the
     * selected transport is available.  The fixed cadence lets the ESP record
     * exactly which 512-TU interval accepted a frame advertised by its NAN
     * Availability attribute.
     */
    public void probeFollowupCadence(String text, int count, long intervalMs) {
        int boundedCount = Math.max(1, Math.min(count, 32));
        long boundedIntervalMs = Math.max(128L, Math.min(intervalMs, 4_000L));
        for (int index = 0; index < boundedCount; index++) {
            final int probeIndex = index;
            lm.delayHandler.postDelayed(() -> {
                int sent = sendAll(text + "#" + probeIndex);
                MsgMux.get(ctx).publish("net.NAN.FollowupProbe",
                        "index", Integer.toString(probeIndex),
                        "intervalMs", Long.toString(boundedIntervalMs),
                        "sent", Integer.toString(sent));
            }, probeIndex * boundedIntervalMs);
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
        int messageId = msgId++;
        pendingFollowups.put(messageId,
                (d.id == null ? "" : d.id) + ":" + msgType);
        try {
            d.nanSession.sendMessage(d.nan, messageId, body);
        } catch (IllegalStateException | SecurityException e) {
            pendingFollowups.remove(messageId);
            devices.remove(d.id, d);
            MsgMux.get(ctx).publish("net.NAN.MSGERR",
                    "id", Integer.toString(messageId),
                    "device", d.id == null ? "" : d.id,
                    "phase", "send",
                    "error", e.toString());
            Log.w(TAG, "NAN follow-up send failed for " + d.id, e);
            return;
        }
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
        private DiscoverySession discoverySession;

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

            if (discoverySession == null) {
                return;
            }
            onDiscovered(peerHandle, serviceSpecificInfo, pub, discoverySession);
        }


        @Override
        public void onSessionConfigUpdated() {
            super.onSessionConfigUpdated();
            Log.d(TAG, "/NAN/PubSessionConfigUpdated");
        }

        @Override
        public void onSessionConfigFailed() {
            super.onSessionConfigFailed();
            synchronized (Nan.this) {
                if (pub) {
                    pubStarting = false;
                    MsgMux.get(ctx).publish("net.NAN.PubSessionConfigFailed");
                } else {
                    nanSub = false;
                    MsgMux.get(ctx).publish("net.NAN.SubSessionConfigFailed");
                }
            }
        }

        @Override
        public void onServiceDiscoveredWithinRange(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter, int distanceMm) {
            onServiceDiscovered(peerHandle, serviceSpecificInfo, matchFilter);
        }

        @Override
        public void onMessageSendSucceeded(int messageId) {
            super.onMessageSendSucceeded(messageId);
            String pending = pendingFollowups.remove(messageId);
            MsgMux.get(ctx).publish("net.NAN.FollowupTxOk",
                    "id", Integer.toString(messageId),
                    "message", pending == null ? "" : pending);
            Log.d(TAG, "/NAN/SENT/" + messageId);
        }

        @Override
        public void onMessageSendFailed(int messageId) {
            super.onMessageSendFailed(messageId);
            String pending = pendingFollowups.remove(messageId);
            MsgMux.get(ctx).publish("net.NAN.MSGERR",
                    "id", Integer.toString(messageId),
                    "message", pending == null ? "" : pending);
        }

        @Override
        public void onSubscribeStarted(SubscribeDiscoverySession session) {
            super.onSubscribeStarted(session);
            Log.d(TAG, "/NAN/SubStart" + session);
            MsgMux.get(ctx).publish("net.NAN.SubStart");
            synchronized (Nan.this) {
                discoverySession = session;
                subSession = session;
                // IdentityChanged may have arrived before this asynchronous
                // callback. Apply the real NAN identity in either ordering.
                refreshDiscoveryIdentity();
            }
        }

        @Override
        public void onPublishStarted(PublishDiscoverySession session) {
            super.onPublishStarted(session);
            Log.d(TAG, "/NAN/PubStart");
            MsgMux.get(ctx).publish("net.NAN.PubStart");
            synchronized (Nan.this) {
                discoverySession = session;
                pubSession = session;
                pubStarting = false;
                // IdentityChanged may have arrived before this asynchronous
                // callback. Apply the real NAN identity in either ordering.
                refreshDiscoveryIdentity();
            }
        }

        @Override
        public void onSessionTerminated() {
            super.onSessionTerminated();
            DiscoverySession endedSession = discoverySession;
            devices.entrySet().removeIf(entry -> entry.getValue().nanSession == endedSession);
            pendingFollowups.clear();
            discoverySession = null;
            if (pub) {
                pubStarting = false;
                if (pubSession == endedSession) {
                    pubSession = null;
                }
                MsgMux.get(ctx).publish("net.NAN.PubStop", "dev", "" + devices);
            } else {
                if (subSession == endedSession) {
                    subSession = null;
                    nanSub = false;
                }
                MsgMux.get(ctx).publish("net.NAN.SubStop", "dev", "" + devices);
            }
        }

        @Override
        public void onMessageReceived(PeerHandle peerHandle, byte[] message) {
            super.onMessageReceived(peerHandle, message);
            String msg = new String(message);
            String parsed = MeshNode.parseNanFollowup(message);
            MeshNode.injectNanFollowup(message, 0);
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
