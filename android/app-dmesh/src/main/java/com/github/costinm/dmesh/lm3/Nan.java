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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Nan {
    private static final String TAG = "nan";
    // A radio personality replacement (LocalOnly AP/P2P) can leave the HAL
    // briefly unavailable after the framework reports the old request closed.
    // This is deliberately not a tight callback retry, but it is short enough
    // to restore the default discovery state without waiting for maintenance.
    private static final long ATTACH_RETRY_DELAY_MS = 5_000;
    private static final String PREF_DISCOVERY_ROLE = "nan_discovery_role";
    private static final String ROLE_BOTH = "both";
    private static final String ROLE_SUB_ACTIVE = "sub-active";
    private static final String ROLE_SUB_PASSIVE = "sub-passive";
    private static final String ROLE_SUB_PASSIVE_EMPTY_SSI = "sub-passive-empty-ssi";
    private static final String ROLE_PUB_SOLICITED = "pub-solicited";
    private static final String ROLE_PUB_UNSOLICITED = "pub-unsolicited";
    static Map<String, Device> devices = new HashMap<>();
    public WifiAwareManager nanMgr;
    public String nanId;
    Context ctx;
    LocalMesh lm;
    volatile WifiAwareSession nanSession;
    boolean attachInProgress;
    boolean retryScheduled;
    // Not null if publish session active and nan active
    volatile PublishDiscoverySession pubSession;
    // Separate service type for low-rate boot/periodic presence. It never
    // replaces `dmesh`, whose Service Info remains the connection command.
    volatile PublishDiscoverySession announcePubSession;
    volatile SubscribeDiscoverySession announceSubSession;
    // publish()/subscribe() complete asynchronously. State-change broadcasts
    // may arrive before their Started callbacks; these guards prevent duplicate
    // discovery sessions and peer handles scoped to a superseded session.
    volatile boolean pubStarting;
    // A framework can deliver several config-failure callbacks for the same
    // invalidated publish session (notably during Wi-Fi Direct coexistence).
    // Keep one delayed recovery attempt outstanding instead of turning that
    // transient condition into an unbounded callback/retry storm.
    volatile boolean publishRetryScheduled;
    // Not null if sub session active
    volatile SubscribeDiscoverySession subSession;
    // Intended status of NAN subscription. subType indicates the type.
    volatile boolean nanSub;
    boolean enabled;
    // This is the common transport.start `ndp=0/1` epoch setting. It does
    // not create a data path without a discovered peer; it authorizes the
    // Android adapter to accept or initiate one when the control plane asks.
    private boolean ndpEnabled;

    public synchronized void setNdpEnabled(boolean enabled) {
        ndpEnabled = enabled;
        MsgMux.get(ctx).publish("net.NAN.DataPathPolicy", "enabled", enabled ? "1" : "0");
    }

    public synchronized boolean isNdpEnabled() {
        return ndpEnabled;
    }

    // Discovery roles are deliberately independent.  A normal DMesh service
    // uses both, while lab runs can isolate Android framework matching rules.
    private boolean publishEnabled = true;
    private boolean subscribeEnabled = true;
    private boolean subscribeServiceInfoEnabled = true;
    private String discoveryRole = ROLE_BOTH;

    // Test and production discovery actively advertises from every node and
    // actively subscribes. Android calls the publish alternatives solicited
    // and unsolicited; the latter is the continuously advertised form, while
    // "active" applies to the subscribe type.
    int subType = SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE;

    int pubType = PublishConfig.PUBLISH_TYPE_UNSOLICITED;

    byte[] nanMac;

    String pubServiceName = "dmesh";

    // Called when the manager reports availability. Platform radio or concurrency policy may
    // revoke NAN; when it returns, existing subscribe/publish state is attached again.
    int msgId;
    int wakeCount;
    final Map<Integer, String> pendingFollowups = new HashMap<>();
    // One explicitly armed lab follow-up. Unlike the retired automatic hello,
    // this is consumed only by the requested peer's next discovery callback.
    // It proves the Android framework's immediate post-match route without
    // retaining a message across a match-expiry/session-replacement boundary.
    private String armedPeerId;
    private String armedFollowupText;
    // An explicit NAN Service Info payload is a complete CBOR command, with
    // the same meaning as a UART direct record. It is deliberately ephemeral:
    // restarting the Android service returns to identity advertising.
    private byte[] publishServiceInfoCbor;
    // `updatePublish()` only queues a framework operation. Keep the pending
    // bit until the Android callback confirms the new Service Info is live;
    // a local AP must not claim that its STA transport.start reached RF just
    // because the synchronous Java call returned.
    private boolean publishServiceInfoPending;
    // The active-subscribe test surface uses the same bounded Service Info
    // bytes. A matching publisher gets one follow-up response, allowing the
    // caller to prove matching and the post-match path separately.
    private byte[] subscribeServiceInfoCbor;
    private byte[] activeSubscribeFollowup =
            "NAN_ACTIVE_SUB_ACK".getBytes(StandardCharsets.UTF_8);
    // Framework callbacks are asynchronous. Keep an explicit in-flight bit
    // for each announce session so periodic maintenance cannot submit a new
    // publish/subscribe while the prior request is still pending.
    private boolean announcePubStarting;
    private boolean announceSubStarting;

    private long startCount;
    private long attachAttempts;
    private long attachSuccesses;
    private long attachFailures;
    private long publishStarts;
    private long publishFailures;
    private long subscribeStarts;
    private long subscribeFailures;
    private long discoveredByPublish;
    private long discoveredBySubscribe;
    private long followupTx;
    private long followupTxOk;
    private long followupTxFailed;
    private long followupRx;

    private byte[] announceServiceInfo(String kind) {
        return MeshNode.buildNanAnnounce(kind, lm.deviceIdBytes(),
                SystemClock.elapsedRealtime() / 1000, 0,
                discoveredByPublish + discoveredBySubscribe + followupRx);
    }

    private PublishConfig buildAnnouncePublishConfig(String kind) {
        return new PublishConfig.Builder()
                .setServiceName("dmesh-announce")
                .setPublishType(PublishConfig.PUBLISH_TYPE_UNSOLICITED)
                .setServiceSpecificInfo(announceServiceInfo(kind))
                .setTerminateNotificationEnabled(true)
                .build();
    }

    private SubscribeConfig buildAnnounceSubscribeConfig() {
        return new SubscribeConfig.Builder()
                .setServiceName("dmesh-announce")
                .setSubscribeType(SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE)
                .setTerminateNotificationEnabled(true)
                .build();
    }

    public Nan(LocalMesh wifi) {
        this.lm = wifi;
        this.ctx = wifi.ctx;
        applyDiscoveryRole(ctx.getSharedPreferences("dmesh", Context.MODE_PRIVATE)
                .getString(PREF_DISCOVERY_ROLE, ROLE_BOTH));
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
        startCount++;
        rustEvent("start", "", null);
        MsgMux.get(ctx).publish("net.NAN.START");
        onWifiAwareStateChanged(new Intent());
    }

    /** Keep the desired NAN attachment and both discovery sessions alive. */
    public void ensureActive() {
        if (!enabled) {
            start();
        } else if (!retryScheduled) {
            onWifiAwareStateChanged(new Intent());
        }
    }

    /**
     * Recreate the complete Aware attachment after another Wi-Fi personality
     * owned the radio. This is intentionally distinct from `ensureActive()`:
     * an unchanged NAN control record normally leaves healthy sessions alone,
     * while Android P2P can invalidate child sessions behind our back.
     */
    public void restartAfterRadioReplacement() {
        stop();
        start();
    }

    private void retryLater() {
        if (!enabled || retryScheduled) {
            return;
        }
        retryScheduled = true;
        lm.delayHandler.postDelayed(() -> {
            retryScheduled = false;
            if (enabled) {
                onWifiAwareStateChanged(new Intent());
            }
        }, ATTACH_RETRY_DELAY_MS);
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Select the discovery sessions owned by this Android instance.
     *
     * <p>The default {@code both} is the production state.  The single-role
     * modes are a lab surface used to establish whether a raw ESP SDF needs an
     * active subscriber, a solicited publisher, or a passive subscriber.</p>
     */
    public synchronized void setDiscoveryRole(String requestedRole) {
        String role = normalizeDiscoveryRole(requestedRole);
        applyDiscoveryRole(role);
        ctx.getSharedPreferences("dmesh", Context.MODE_PRIVATE).edit()
                .putString(PREF_DISCOVERY_ROLE, role).apply();

        if (!publishEnabled && pubSession != null) {
            pubSession.close();
            pubSession = null;
            pubStarting = false;
        }
        if (!subscribeEnabled && subSession != null) {
            subSession.close();
            subSession = null;
            nanSub = false;
        }
        emitStatus();
        if (enabled) {
            onWifiAwareStateChanged(new Intent());
        }
    }

    /** Publish the bounded state/counters used by shell and SSH evidence collection. */
    public synchronized void emitStatus() {
        rustEvent("status", "", null);
        MsgMux.get(ctx).publish("net.NAN.Status",
                "enabled", Boolean.toString(enabled),
                "role", discoveryRole,
                "publish", Boolean.toString(publishEnabled),
                "publishType", publishTypeName(),
                "publishSession", Boolean.toString(pubSession != null),
                "subscribe", Boolean.toString(subscribeEnabled),
                "subscribeType", subscribeTypeName(),
                "subscribeSession", Boolean.toString(subSession != null),
                "attached", Boolean.toString(nanSession != null),
                "peers", Integer.toString(devices.size()),
                "pending", Integer.toString(pendingFollowups.size()),
                "starts", Long.toString(startCount),
                "attachAttempts", Long.toString(attachAttempts),
                "attachOk", Long.toString(attachSuccesses),
                "attachFail", Long.toString(attachFailures),
                "pubStarts", Long.toString(publishStarts),
                "pubFail", Long.toString(publishFailures),
                "subStarts", Long.toString(subscribeStarts),
                "subFail", Long.toString(subscribeFailures),
                "discoverPub", Long.toString(discoveredByPublish),
                "discoverSub", Long.toString(discoveredBySubscribe),
                "tx", Long.toString(followupTx),
                "txOk", Long.toString(followupTxOk),
                "txFail", Long.toString(followupTxFailed),
                "rx", Long.toString(followupRx));
    }

    private void applyDiscoveryRole(String role) {
        discoveryRole = role;
        publishEnabled = ROLE_BOTH.equals(role) || ROLE_PUB_SOLICITED.equals(role)
                || ROLE_PUB_UNSOLICITED.equals(role);
        subscribeEnabled = ROLE_BOTH.equals(role) || ROLE_SUB_ACTIVE.equals(role)
                || ROLE_SUB_PASSIVE.equals(role) || ROLE_SUB_PASSIVE_EMPTY_SSI.equals(role);
        // A passive subscribe needs only the service name for discovery. This
        // lab role isolates vendor handling of SubscribeConfig service-specific
        // info without changing the production `sub-passive` descriptor.
        subscribeServiceInfoEnabled = !ROLE_SUB_PASSIVE_EMPTY_SSI.equals(role);
        // `both` is the stable interoperable mode: every peer advertises its
        // Service Info without first requiring a matching active subscribe.
        // Keep `pub-solicited` only as a focused framework experiment.
        pubType = ROLE_PUB_SOLICITED.equals(role)
                ? PublishConfig.PUBLISH_TYPE_SOLICITED : PublishConfig.PUBLISH_TYPE_UNSOLICITED;
        subType = (ROLE_SUB_PASSIVE.equals(role) || ROLE_SUB_PASSIVE_EMPTY_SSI.equals(role))
                ? SubscribeConfig.SUBSCRIBE_TYPE_PASSIVE : SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE;
    }

    private static String normalizeDiscoveryRole(String role) {
        if (ROLE_SUB_ACTIVE.equals(role) || ROLE_SUB_PASSIVE.equals(role)
                || ROLE_SUB_PASSIVE_EMPTY_SSI.equals(role)
                || ROLE_PUB_SOLICITED.equals(role) || ROLE_PUB_UNSOLICITED.equals(role)) {
            return role;
        }
        return ROLE_BOTH;
    }

    private String publishTypeName() {
        return pubType == PublishConfig.PUBLISH_TYPE_UNSOLICITED ? "unsolicited" : "solicited";
    }

    private String subscribeTypeName() {
        return subType == SubscribeConfig.SUBSCRIBE_TYPE_PASSIVE ? "passive" : "active";
    }

    public void stop() {
        rustEvent("stop", "", null);
        enabled = false;
        pubStarting = false;
        publishRetryScheduled = false;
        attachInProgress = false;
        nanSub = false;
        synchronized (this) {
            armedPeerId = null;
            armedFollowupText = null;
        }
        // Discovery sessions are children of the aware attachment. Close and
        // clear them first: closing the parent before either child makes the
        // Android Wi-Fi Aware service reject the later close with an invalid
        // uid/client mapping, and the following start remains attached but
        // cannot recreate discovery sessions.
        PublishDiscoverySession publishing = pubSession;
        SubscribeDiscoverySession subscribing = subSession;
        PublishDiscoverySession announcePublishing = announcePubSession;
        SubscribeDiscoverySession announceSubscribing = announceSubSession;
        pubSession = null;
        subSession = null;
        announcePubSession = null;
        announceSubSession = null;
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
        if (announcePublishing != null) {
            try { announcePublishing.close(); } catch (IllegalStateException ignored) { }
        }
        if (announceSubscribing != null) {
            try { announceSubscribing.close(); } catch (IllegalStateException ignored) { }
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
        rustEvent("state_changed", "", null);
        if (!enabled) {
            return;
        }
        // A failed attachment is retried by retryLater().  `ensureActive()`
        // is intentionally called by several service lifecycle paths, so it
        // must not bypass that backoff and turn a platform-unavailable NAN
        // radio into a tight attach loop.
        if (retryScheduled && nanSession == null) {
            return;
        }
        i.getBooleanExtra("foo", true);

        if (ctx.checkSelfPermission(Manifest.permission.ACCESS_WIFI_STATE) != PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Missing permissions");
            rustEvent("permission_missing", "", null);
            MsgMux.get(ctx).publish("net.NAN.ERR.permission");
            return;
        }
        try {
            nanMgr = ctx.getSystemService(WifiAwareManager.class);
            if (nanMgr == null) {
                Log.d(TAG, "State changed - no system service" + i.getAction() + " " + i.getExtras());
                rustEvent("manager_unavailable", "", null);
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
                    if (publishEnabled && pubSession == null && !pubStarting) {
                        publish();
                    }
                    if (subscribeEnabled && subSession == null && !nanSub) {
                        startNanSub();
                    }
                    startAnnounceSessions();
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
                        rustEvent("opportunistic_error", "", null);
                    } catch (RuntimeException re) {
                        Log.w(TAG, "Unable to enable NAN opportunistic mode", re);
                        MsgMux.get(ctx).publish("net.NAN.OpportunisticError",
                                "error", re.toString());
                        rustEvent("opportunistic_error", "", null);
                    }
                }
                // TODO: add a setting to control 'on' or 'off' for local mesh.
                // if local mesh is on - Nan is best option.
                attachInProgress = true;
                attachAttempts++;
                MsgMux.get(ctx).publish("net.NAN.AttachStart");
                nanMgr.attach(new AttachCallback() {
                    @Override
                    public void onAttached(WifiAwareSession session) {
                        super.onAttached(session);
                        attachInProgress = false;
                        nanSession = session;
                        attachSuccesses++;
                        rustEvent("attached", "", null);

                        // No point being attached and not using discovery.
                        if (enabled) {
                            if (publishEnabled) {
                                publish();
                            }
                            if (subscribeEnabled) {
                                startNanSub();
                            }
                            startAnnounceSessions();
                        }

                        MsgMux.get(ctx).publish("net.NAN.Attach");
                    }

                    @Override
                    public void onAttachFailed() {
                        super.onAttachFailed();
                        attachInProgress = false;
                        attachFailures++;
                        // Keep NAN desired. A foreground service and its
                        // 15-minute repair job both retry attachment; a
                        // transient framework failure must not silently
                        // turn the always-on discovery cluster off.
                        rustEvent("attach_failed", "", null);
                        MsgMux.get(ctx).publish("net.NAN.AttachError", "retry", "scheduled");
                        retryLater();
                    }
                }, new IdentityChangedListener() {
                    @Override
                    public void onIdentityChanged(byte[] mac) {
                        super.onIdentityChanged(mac);
                        nanMac = mac;
                        nanId = new String(Hex.encode(mac));
                        MsgMux.get(ctx).publish("net.NAN.MAC." + nanId);
                        rustEvent("identity", nanId, mac);
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
                rustEvent("unavailable", "", null);
                MsgMux.get(ctx).publish("net.NAN.unavailable");
                retryLater();
            }
        } catch(Throwable t) {
            Log.w(TAG, "NAN attach failed", t);
            attachInProgress = false;
            MsgMux.get(ctx).publish("net.NAN.AttachError",
                    "error", t.getClass().getName(),
                    "message", t.toString());
            rustEvent("attach_exception", "", null);
            retryLater();
        }
    }

    void onDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, boolean byPublisher,
                      DiscoverySession discoverySession) {
        if (discoverySession == null) {
            return;
        }
        Device bd = new Device(peerHandle, serviceSpecificInfo);
        // Rust owns retained discovery state and expiry. Java holds only the
        // session-scoped PeerHandle needed to call Android's NAN APIs.
        String parsed = MeshNode.observeNanServiceInfo(peerHandle.toString(), serviceSpecificInfo);
        // A NAN Service Info control command has the exact same tagged-CBOR
        // wire as UART. Rust validates/decodes it; Java only performs the
        // Android-specific requested transition. Repeated Publish/Subscribe
        // callbacks are safe because LocalMesh compares the immutable mode.
        try {
            lm.applyTransportStart(MeshNode.decodeTransportStart(serviceSpecificInfo),
                    "nan_sd", peerHandle.toString());
        } catch (RuntimeException ignored) {
            // Ordinary discovery/announce records are not control commands.
        }
        String deviceId = jsonField(parsed, "device_id");
        if (isUsableDmeshIdentity(deviceId)) {
            bd.id = deviceId;
            bd.data.putString(Device.RADIO_ADDR, "/nan/" + deviceId);
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
            discoveredByPublish++;
            // Used with active sub and passive pub
            MsgMux.get(ctx).publish("net.NAN.PubServiceDiscovered",
                    "peer", peerHandle.toString(),
                    "id", bd.id,
                    "json", parsed);
        } else {
            discoveredBySubscribe++;
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
        rustEvent("service_discovered", peerHandle.toString(), serviceSpecificInfo);
        // Android delivers a matching active subscribe to the publisher's
        // callback. Respond once per callback with the configured bounded
        // follow-up; this is intentionally not an unbounded hello loop.
        if (byPublisher && activeSubscribeFollowup != null) {
            sendFollowup(bd, "command_cbor", activeSubscribeFollowup);
        }
        sendArmedFollowupIfMatched(bd);
    }

    /**
     * Arrange one follow-up to be submitted directly from the next matching
     * discovery callback. This is a bounded test surface, not a persistent
     * delivery queue: a caller must re-arm after each test/session restart.
     */
    public synchronized boolean armFollowupOnDiscovery(String peerId, String text) {
        if (!isUsableDmeshIdentity(peerId) || text == null || text.isEmpty()) {
            return false;
        }
        armedPeerId = peerId.toLowerCase();
        armedFollowupText = text;
        MsgMux.get(ctx).publish("net.NAN.FollowupArmed", "id", armedPeerId);
        return true;
    }

    private void sendArmedFollowupIfMatched(Device device) {
        String text;
        synchronized (this) {
            if (device.id == null || armedPeerId == null
                    || !armedPeerId.equalsIgnoreCase(device.id)) {
                return;
            }
            text = armedFollowupText;
            armedPeerId = null;
            armedFollowupText = null;
        }
        MsgMux.get(ctx).publish("net.NAN.FollowupArmedMatch", "id", device.id);
        sendFollowup(device, "command_text", text.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isUsableDmeshIdentity(String deviceId) {
        if (deviceId == null || !deviceId.matches("[0-9A-Fa-f]{12}")) {
            return false;
        }
        return !"000000000000".equals(deviceId) && !"303030303030".equals(deviceId);
    }

    private void rustEvent(String event, String peer, byte[] payload) {
        try {
            MeshNode.recordNanEvent(event, peer == null ? "" : peer,
                    payload == null ? new byte[0] : payload);
        } catch (RuntimeException ignored) {
            // NAN must keep running if the optional native event store is
            // temporarily unavailable during process startup/teardown.
        }
    }

    private void onDiscovery(Device bd, String id, boolean b) {
        lm.sendWifiDiscoveryStatus("nan", "");
    }

    private synchronized void publish() {
        if (!publishEnabled) {
            return;
        }
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
            publishFailures++;
            Log.w(TAG, "NAN publish failed", e);
            MsgMux.get(ctx).publish("net.NAN.PubError", "error", e.toString());
        }
    }

    private PublishConfig buildPublishConfig() {
        byte[] serviceInfo = publishServiceInfoCbor != null
                ? publishServiceInfoCbor
                : MeshNode.buildNanServiceInfo("android", lm.deviceIdBytes(), wakeCount++);
        PublishConfig.Builder builder = new PublishConfig.Builder().setServiceName(pubServiceName)
                .setPublishType(pubType) // silent, but respond to active requests
                .setTerminateNotificationEnabled(true)
                .setServiceSpecificInfo(serviceInfo);
        return builder.build();
    }

    /** Publish one bounded CBOR command as NAN Service Info. */
    public synchronized boolean setServiceInfoCbor(byte[] command) {
        if (command == null || command.length == 0 || command.length > 255) {
            return false;
        }
        publishServiceInfoCbor = Arrays.copyOf(command, command.length);
        publishServiceInfoPending = true;
        if (pubSession != null) {
            try {
                pubSession.updatePublish(buildPublishConfig());
                MsgMux.get(ctx).publish("net.NAN.ServiceInfoQueued",
                        "bytes", Integer.toString(command.length));
            } catch (IllegalStateException error) {
                MsgMux.get(ctx).publish("net.NAN.ServiceInfoUpdateError",
                        "error", error.toString());
                return false;
            }
        }
        return true;
    }

    /** Enable/disable the normal active publisher without changing NAN attachment. */
    public synchronized void setActivePublishEnabled(boolean enabled) {
        publishEnabled = enabled;
        if (!enabled && pubSession != null) {
            pubSession.close();
            pubSession = null;
            pubStarting = false;
        } else if (enabled) {
            publish();
        }
        MsgMux.get(ctx).publish("net.NAN.ActivePublish",
                "enabled", Boolean.toString(enabled));
    }

    /** Configure active-subscribe SSI and its bounded response follow-up. */
    public synchronized boolean setActiveSubscribe(byte[] serviceInfo, byte[] followup) {
        if (serviceInfo == null || serviceInfo.length == 0 || serviceInfo.length > 255
                || followup == null || followup.length == 0 || followup.length > 231) {
            return false;
        }
        subscribeServiceInfoCbor = Arrays.copyOf(serviceInfo, serviceInfo.length);
        activeSubscribeFollowup = Arrays.copyOf(followup, followup.length);
        subscribeEnabled = true;
        subType = SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE;
        if (subSession != null) {
            try {
                subSession.updateSubscribe(buildSubscribeConfig());
            } catch (IllegalStateException error) {
                return false;
            }
        }
        MsgMux.get(ctx).publish("net.NAN.ActiveSubscribe",
                "serviceInfoBytes", Integer.toString(serviceInfo.length),
                "followupBytes", Integer.toString(followup.length));
        return true;
    }

    /** Clear an explicit CBOR command and resume normal DMesh identity SSI. */
    public synchronized void clearServiceInfoCbor() {
        publishServiceInfoCbor = null;
        publishServiceInfoPending = false;
        if (pubSession != null) {
            try {
                pubSession.updatePublish(buildPublishConfig());
            } catch (IllegalStateException error) {
                MsgMux.get(ctx).publish("net.NAN.ServiceInfoUpdateError",
                        "error", error.toString());
            }
        }
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
        if (!subscribeEnabled) {
            return;
        }
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
            subscribeFailures++;
            Log.w(TAG, "NAN subscribe failed", e);
            MsgMux.get(ctx).publish("net.NAN.SubError", "error", e.toString());
        }

    }

    /** Start the separate low-rate boot/discovery Service-Info type. */
    private synchronized void startAnnounceSessions() {
        if (nanSession == null) {
            return;
        }
        if (announcePubSession == null && !announcePubStarting) {
            announcePubStarting = true;
            try {
                nanSession.publish(buildAnnouncePublishConfig("boot"), new DiscoverySessionCallback() {
                    @Override public void onPublishStarted(PublishDiscoverySession session) {
                        synchronized (Nan.this) {
                            announcePubStarting = false;
                            announcePubSession = session;
                        }
                        rustEvent("announce_publish_started", "", null);
                    }
                    @Override public void onSessionTerminated() {
                        synchronized (Nan.this) {
                            announcePubStarting = false;
                            announcePubSession = null;
                        }
                        rustEvent("announce_publish_terminated", "", null);
                        // Aware can terminate one discovery session while the
                        // attachment survives. Do not wait for the 15-minute
                        // job: the shared retry coalesces all callback races.
                        retryLater();
                    }
                    @Override public void onSessionConfigFailed() {
                        synchronized (Nan.this) { announcePubStarting = false; }
                        rustEvent("announce_publish_failed", "", null);
                        retryLater();
                    }
                    @Override public void onSessionConfigUpdated() {
                        rustEvent("announce_publish_updated", "", null);
                    }
                }, lm.delayHandler);
            } catch (RuntimeException e) {
                announcePubStarting = false;
                rustEvent("announce_publish_exception", "", null);
            }
        }
        if (announceSubSession == null && !announceSubStarting) {
            announceSubStarting = true;
            try {
                nanSession.subscribe(buildAnnounceSubscribeConfig(), new DiscoverySessionCallback() {
                    @Override public void onSubscribeStarted(SubscribeDiscoverySession session) {
                        synchronized (Nan.this) {
                            announceSubStarting = false;
                            announceSubSession = session;
                        }
                        rustEvent("announce_subscribe_started", "", null);
                    }
                    @Override public void onServiceDiscovered(PeerHandle peer, byte[] serviceInfo,
                                                               List<byte[]> matchFilter) {
                        String parsed = MeshNode.observeNanServiceInfo(peer.toString(), serviceInfo);
                        rustEvent("announce_discovered", peer.toString(), serviceInfo);
                        MsgMux.get(ctx).publish("net.NAN.AnnounceDiscovered",
                                "peer", peer.toString(), "json", parsed);
                    }
                    @Override public void onSessionTerminated() {
                        synchronized (Nan.this) {
                            announceSubStarting = false;
                            announceSubSession = null;
                        }
                        rustEvent("announce_subscribe_terminated", "", null);
                        retryLater();
                    }
                    @Override public void onSessionConfigFailed() {
                        synchronized (Nan.this) { announceSubStarting = false; }
                        rustEvent("announce_subscribe_failed", "", null);
                        retryLater();
                    }
                    @Override public void onSessionConfigUpdated() {
                        rustEvent("announce_subscribe_updated", "", null);
                    }
                }, lm.delayHandler);
            } catch (RuntimeException e) {
                announceSubStarting = false;
                rustEvent("announce_subscribe_exception", "", null);
            }
        }
    }

    /** Called at the Android periodic-job cadence: update only the announce SSI. */
    public synchronized void publishDiscoveryAnnounce() {
        ensureActive();
        startAnnounceSessions();
        if (announcePubSession != null) {
            try {
                announcePubSession.updatePublish(buildAnnouncePublishConfig("discovery"));
                rustEvent("announce_discovery", "", null);
            } catch (IllegalStateException e) {
                announcePubSession = null;
                rustEvent("announce_update_failed", "", null);
            }
        }
    }

    private SubscribeConfig buildSubscribeConfig() {
        SubscribeConfig.Builder builder = new SubscribeConfig.Builder()
                .setServiceName("dmesh")
                .setSubscribeType(subType)
                .setTerminateNotificationEnabled(true);
        if (subscribeServiceInfoEnabled) {
            builder.setServiceSpecificInfo(subscribeServiceInfoCbor != null
                    ? subscribeServiceInfoCbor
                    : MeshNode.buildNanServiceInfo("android", lm.deviceIdBytes(), wakeCount++));
        }
        return builder.build();
    }

    /**
     * Record the framework NAN MAC after it becomes available.
     *
     * DMesh Service Info identifies this node with the stable Rust device id,
     * not the randomized framework NAN MAC.  Re-submitting identical publish
     * and subscribe descriptors from this callback used to create a perpetual
     * onSessionConfigFailed -> retry loop on some Android HALs.  Explicit
     * Service Info changes still use updatePublish/updateSubscribe at their
     * owning API entry point.
     */
    private synchronized void refreshDiscoveryIdentity() {
        MsgMux.get(ctx).publish("net.NAN.IdentityReady", "id", nanId == null ? "" : nanId);
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
        followupTx++;
        try {
            d.nanSession.sendMessage(d.nan, messageId, body);
        } catch (IllegalStateException | SecurityException e) {
            pendingFollowups.remove(messageId);
            followupTxFailed++;
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
            rustEvent(pub ? "publish_config_updated" : "subscribe_config_updated", "", null);
            synchronized (Nan.this) {
                if (pub && publishServiceInfoPending) {
                    publishServiceInfoPending = false;
                    MsgMux.get(ctx).publish("net.NAN.ServiceInfoApplied", "ok", "1",
                            "bytes", Integer.toString(publishServiceInfoCbor == null
                                    ? 0 : publishServiceInfoCbor.length));
                }
            }
        }

        @Override
        public void onSessionConfigFailed() {
            super.onSessionConfigFailed();
            rustEvent(pub ? "publish_config_failed" : "subscribe_config_failed", "", null);
            synchronized (Nan.this) {
                if (pub) {
                    // A failed update leaves the old service descriptor on
                    // air. Close exactly that session and retry once through
                    // the normal publisher so its initial configuration uses
                    // the latest complete CBOR Service Info.
                    // Framework callbacks may arrive after an earlier
                    // termination already cleared both references. Do not
                    // turn that recoverable NAN configuration failure into
                    // an application-process crash.
                    if (pubSession != null && pubSession == discoverySession) {
                        pubSession.close();
                        pubSession = null;
                    }
                    pubStarting = false;
                    publishFailures++;
                    MsgMux.get(ctx).publish("net.NAN.PubSessionConfigFailed");
                    if (!publishRetryScheduled) {
                        publishRetryScheduled = true;
                        lm.delayHandler.postDelayed(() -> {
                            synchronized (Nan.this) {
                                publishRetryScheduled = false;
                                publish();
                            }
                        }, 1_000);
                    }
                } else {
                    nanSub = false;
                    subscribeFailures++;
                    MsgMux.get(ctx).publish("net.NAN.SubSessionConfigFailed");
                }
            }
        }

        @Override
        public void onServiceDiscoveredWithinRange(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter, int distanceMm) {
            rustEvent("service_discovered_within_range", peerHandle.toString(), serviceSpecificInfo);
            onServiceDiscovered(peerHandle, serviceSpecificInfo, matchFilter);
        }

        @Override
        public void onMessageSendSucceeded(int messageId) {
            super.onMessageSendSucceeded(messageId);
            rustEvent("followup_tx_ok", Integer.toString(messageId), null);
            String pending = pendingFollowups.remove(messageId);
            followupTxOk++;
            MsgMux.get(ctx).publish("net.NAN.FollowupTxOk",
                    "id", Integer.toString(messageId),
                    "message", pending == null ? "" : pending);
            Log.d(TAG, "/NAN/SENT/" + messageId);
        }

        @Override
        public void onMessageSendFailed(int messageId) {
            super.onMessageSendFailed(messageId);
            rustEvent("followup_tx_failed", Integer.toString(messageId), null);
            String pending = pendingFollowups.remove(messageId);
            followupTxFailed++;
            MsgMux.get(ctx).publish("net.NAN.MSGERR",
                    "id", Integer.toString(messageId),
                    "message", pending == null ? "" : pending);
        }

        @Override
        public void onSubscribeStarted(SubscribeDiscoverySession session) {
            super.onSubscribeStarted(session);
            rustEvent("subscribe_started", "", null);
            Log.d(TAG, "/NAN/SubStart" + session);
            MsgMux.get(ctx).publish("net.NAN.SubStart");
            synchronized (Nan.this) {
                discoverySession = session;
                subSession = session;
                subscribeStarts++;
                // IdentityChanged may have arrived before this asynchronous
                // callback. Apply the real NAN identity in either ordering.
                refreshDiscoveryIdentity();
            }
        }

        @Override
        public void onPublishStarted(PublishDiscoverySession session) {
            super.onPublishStarted(session);
            rustEvent("publish_started", "", null);
            Log.d(TAG, "/NAN/PubStart");
            MsgMux.get(ctx).publish("net.NAN.PubStart");
            synchronized (Nan.this) {
                discoverySession = session;
                pubSession = session;
                pubStarting = false;
                publishRetryScheduled = false;
                publishStarts++;
                if (publishServiceInfoPending) {
                    publishServiceInfoPending = false;
                    MsgMux.get(ctx).publish("net.NAN.ServiceInfoApplied", "ok", "1",
                            "bytes", Integer.toString(publishServiceInfoCbor == null
                                    ? 0 : publishServiceInfoCbor.length));
                }
                // IdentityChanged may have arrived before this asynchronous
                // callback. Apply the real NAN identity in either ordering.
                refreshDiscoveryIdentity();
            }
        }

        @Override
        public void onSessionTerminated() {
            super.onSessionTerminated();
            rustEvent(pub ? "publish_terminated" : "subscribe_terminated", "", null);
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
            // `nanSession` is still attached, but its independently owned
            // publish/subscribe counterpart has gone away. Repair promptly;
            // retryLater is coalesced and keeps framework callbacks off the
            // immediate callback stack.
            retryLater();
        }

        @Override
        public void onMessageReceived(PeerHandle peerHandle, byte[] message) {
            super.onMessageReceived(peerHandle, message);
            rustEvent("followup_rx", peerHandle.toString(), message);
            String msg = new String(message);
            followupRx++;
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
