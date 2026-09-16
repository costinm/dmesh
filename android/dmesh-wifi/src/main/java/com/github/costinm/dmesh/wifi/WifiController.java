package com.github.costinm.dmesh.wifi;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.NetworkInfo;
import android.net.ConnectivityManager;
import android.net.MacAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.aware.AttachCallback;
import android.net.wifi.aware.DiscoverySessionCallback;
import android.net.wifi.aware.PublishConfig;
import android.net.wifi.aware.PublishDiscoverySession;
import android.net.wifi.aware.PeerHandle;
import android.net.wifi.aware.SubscribeConfig;
import android.net.wifi.aware.SubscribeDiscoverySession;
import android.net.wifi.aware.WifiAwareManager;
import android.net.wifi.aware.WifiAwareSession;
import android.net.wifi.SoftApConfiguration;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.net.wifi.WifiSsid;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pGroup;
import android.net.wifi.p2p.WifiP2pManager;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceInfo;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest;
import android.os.Build;
import android.util.Base64;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Platform-API-only lifecycle harness. It deliberately mirrors the AOSP test
 * pattern: retain callback evidence, explicitly wait for the group-info
 * callback, and treat an Aware attach plus a publish callback as success.
 */
/**
 * The single Android Wi-Fi owner shared by DMesh and the standalone
 * qualifier. It began as the qualifier's public-API lifecycle sequence;
 * retain that ordering while the remaining DMesh Wi-Fi adapters migrate here.
 */
public final class WifiController {
    // Wi-Fi Aware derives its six-byte service identifier from this name.
    // Keep it aligned with dmesh_rawnan::DMESH_SERVICE_ID (SHA-256("dmesh")
    // prefix) so Android, Linux raw-NAN, and ESP use one discovery service.
    private static final String NAN_SERVICE = "dmesh";
    /** Shared fixed AP name. It satisfies the Android P2P DIRECT-xy rule. */
    private static final String P2P_SSID = "DIRECT-dmesh";
    /** Shared default WPA2 key; an absent transport.start PSK selects it. */
    private static final String DMESH_WPA2_PASSPHRASE = "untrusted-open-mode";
    private static final String LOHS_SSID = "DIRECT-dmesh";
    private static final String LOHS_PASSPHRASE = DMESH_WPA2_PASSPHRASE;
    private static final int MAX_LOG_LINES = 120;
    private static final long GROUP_REMOVAL_TIMEOUT_MS = 10_000;
    private static final long GROUP_REMOVAL_POLL_MS = 250;
    private static WifiController instance;

    public interface Observer { void onStateChanged(); }

    private interface EventMatch { boolean matches(String event); }

    public static synchronized WifiController get(Context context) {
        if (instance == null) instance = new WifiController(context.getApplicationContext());
        return instance;
    }

    /** Obtain the process-wide radio owner and replace only its event sink. */
    public static synchronized WifiController create(Context context, WifiEventSink eventSink) {
        WifiController controller = get(context);
        controller.eventSink = eventSink;
        return controller;
    }

    private final Context context;
    private final HandlerThread callbacksThread = new HandlerThread("P2pNanReproCallbacks");
    private final Handler handler;
    private final WifiP2pManager p2p;
    private final WifiAwareManager aware;
    private final WifiManager wifi;
    private final ConnectivityManager connectivity;
    private final ArrayDeque<String> log = new ArrayDeque<>();
    private WifiP2pManager.Channel p2pChannel;
    private WifiP2pDnsSdServiceInfo localService;
    private WifiP2pDnsSdServiceRequest serviceRequest;
    private boolean localServiceAdding;
    private WifiAwareSession awareSession;
    private PublishDiscoverySession publishSession;
    private SubscribeDiscoverySession subscribeSession;
    // Android's public active-Subscribe API does not consistently expose its
    // Service Specific Info in the raw SDEA received by ESP peers. Keep one
    // bounded directed message for the temporary discovery instead.
    private byte[] directedNanMessage;
    private int discoveryResponseMessageId;
    private WifiManager.LocalOnlyHotspotReservation lohsReservation;
    private ConnectivityManager.NetworkCallback staAttachment;
    private Network staNetwork;
    private String staSsid = "";
    private boolean p2pGroupRequested;
    private boolean advertiseAfterGroup;
    private Announce announce = Announce.empty();
    private Discover discover = Discover.empty();
    /** Last successfully applied immutable transport.start declaration. */
    private String appliedTransportKey = "";
    private String lastEvent = "created";
    private Observer observer;
    private WifiEventSink eventSink;
    private EventMatch awaitingEvent;
    private CountDownLatch awaitingLatch;
    private boolean closed;

    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override public void onReceive(Context ignored, Intent intent) {
            String action = intent.getAction();
            if (WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION.equals(action)) {
                NetworkInfo info = intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO);
                note("p2p.broadcast connected=" + (info != null && info.isConnected()));
                requestGroupInfo("broadcast");
            } else if (WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED.equals(action)) {
                note("aware.broadcast available=" + aware.isAvailable());
            }
        }
    };

    private WifiController(Context context) {
        this.context = context;
        callbacksThread.start();
        handler = new Handler(callbacksThread.getLooper());
        p2p = context.getSystemService(WifiP2pManager.class);
        aware = context.getSystemService(WifiAwareManager.class);
        wifi = context.getSystemService(WifiManager.class);
        connectivity = context.getSystemService(ConnectivityManager.class);
        IntentFilter filter = new IntentFilter();
        filter.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
        filter.addAction(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED);
        context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
        note("created sdk=" + Build.VERSION.SDK_INT + " aware_present=" + (aware != null));
    }

    public void setObserver(Observer observer) {
        synchronized (this) { this.observer = observer; }
    }

    /** Release every framework allocation owned by this process-wide radio owner. */
    public void close() {
        handler.post(() -> {
            if (closed) return;
            closed = true;
            releaseStaAttachment();
            stopNanInternal();
            stopP2pInternal(() -> { });
            try { context.unregisterReceiver(receiver); }
            catch (IllegalArgumentException ignored) { }
            callbacksThread.quitSafely();
        });
    }

    /**
     * Apply the Java projection of the canonical Rust transport.start request.
     * Infrastructure STA is an app-scoped {@link WifiNetworkSpecifier} lease:
     * it never persists a credential or changes the user's global Wi-Fi
     * selection. It remains distinct from NAN and P2P even when the device
     * can keep those radio roles concurrent.
     */
    public void start(TransportStart request, Completion<TransportResult> done) {
        new Thread(() -> {
            if (request == null || request.kind == null) {
                done.complete(result(TransportResult.Outcome.ERROR, request,
                        "invalid_request", false, false));
                return;
            }
            if (request.kind == TransportStart.Kind.STA) {
                String key = transportKey(request);
                synchronized (this) {
                    if (key.equals(appliedTransportKey)) {
                        done.complete(result(TransportResult.Outcome.UNCHANGED, request,
                                "", true, false));
                        return;
                    }
                }
                String failure = startStaAndAwait(request);
                boolean restored = false;
                if (failure != null) restored = startNanAfterP2pAndAwait();
                TransportResult.Outcome outcome = failure == null
                        ? TransportResult.Outcome.APPLIED : TransportResult.Outcome.ERROR;
                if (outcome == TransportResult.Outcome.APPLIED) {
                    synchronized (this) { appliedTransportKey = key; }
                }
                done.complete(result(outcome, request, failure == null ? "" : failure,
                        failure == null || restored, restored));
                return;
            }
            String key = transportKey(request);
            synchronized (this) {
                if (key.equals(appliedTransportKey)) {
                    done.complete(result(TransportResult.Outcome.UNCHANGED, request,
                            "", true, false));
                    return;
                }
            }
            boolean p2p = request.ap == 1;
            boolean terminal = p2p ? startP2pGroupWithServiceAndAwait()
                    : startNanAfterP2pAndAwait();
            boolean failed = lastEvent.startsWith("p2p.create_group failed=")
                    || lastEvent.startsWith("p2p.create_group exception=")
                    || lastEvent.equals("aware.on_attach_failed")
                    || lastEvent.equals("aware.on_publish_config_failed");
            boolean restored = false;
            if (!terminal || failed) restored = startNanAfterP2pAndAwait();
            TransportResult.Outcome outcome = terminal && !failed
                    ? TransportResult.Outcome.APPLIED : TransportResult.Outcome.ERROR;
            if (outcome == TransportResult.Outcome.APPLIED) {
                synchronized (this) { appliedTransportKey = key; }
            }
            done.complete(result(outcome,
                    request, terminal && !failed ? "" : lastEvent,
                    !p2p || restored, restored));
        }, "DmeshWifiTransportStart").start();
    }

    /** Set the desired opaque record for NAN Service Info or P2P DNS-SD. */
    public void setAnnounce(Announce value, Completion<String> done) {
        handler.post(() -> {
            Announce next = value == null ? Announce.empty() : value;
            if (Arrays.equals(announce.payload, next.payload) && announce.options.equals(next.options)) {
                done.complete("unchanged");
                return;
            }
            announce = next;
            note("announce.set bytes=" + announce.payload.length + " options=" + announce.options);
            if (p2pChannel != null && localService != null) {
                clearP2pServices(p2pChannel, () -> {
                    if (!announce.isEmpty()) addLocalService(p2pChannel);
                });
            }
            if (publishSession != null) {
                publishSession.close();
                publishSession = null;
                publishNan();
            }
            done.complete("applied");
        });
    }

    /** Configure opaque NAN subscribe bytes/options; discoveries use WifiEventSink. */
    public void setDiscover(Discover value, Completion<String> done) {
        handler.post(() -> {
            Discover next = value == null ? Discover.empty() : value;
            if (Arrays.equals(discover.payload, next.payload) && discover.options.equals(next.options)) {
                done.complete("unchanged");
                return;
            }
            discover = next;
            note("discover.set bytes=" + discover.payload.length + " options=" + discover.options);
            if (subscribeSession != null) {
                subscribeSession.close();
                subscribeSession = null;
            }
            // A production baseline subscribes to the common service name
            // without a service-info filter. Recreate after any update even
            // if the prior baseline did not have a session yet.
            if (awareSession != null) subscribeNan();
            done.complete("applied");
        });
    }

    public void snapshot(Completion<String> done) { handler.post(() -> done.complete(snapshot())); }

    private TransportResult result(TransportResult.Outcome outcome, TransportStart request,
                                   String error, boolean replyAvailable, boolean restored) {
        return new TransportResult(outcome, request == null ? "" : request.correlationId,
                request == null ? 0 : request.generation, snapshot(), error,
                replyAvailable, restored);
    }

    private static String transportKey(TransportStart request) {
        return request.kind + "|" + request.ssid + "|" + request.passphrase + "|"
                + Arrays.toString(request.bssid) + "|" + request.channel + "|"
                + request.rawTxRate + "|" + request.staDriverTx + "|"
                + request.staBssidCheckDisabled + "|" + request.staAmpduEnabled + "|"
                + request.sta11bRatesDisabled + "|" + request.staRawRxEnabled + "|"
                + request.espnowCapture + "|" + request.nanDwInterval + "|" + request.now
                + "|" + request.ndp + "|" + request.ap + "|" + request.uart;
    }

    /**
     * Request a volatile, app-scoped infrastructure STA attachment. This is
     * the exact Android public API used by the previous DMesh adapter: it
     * never persists a credential or changes the user's global Wi-Fi choice.
     */
    private String startStaAndAwait(TransportStart request) {
        CountDownLatch complete = new CountDownLatch(1);
        String[] failure = { null };
        handler.post(() -> stopP2pInternal(() -> requestSta(request, failure, complete)));
        try {
            if (!complete.await(25_000, TimeUnit.MILLISECONDS)) return "sta_timeout";
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return "sta_interrupted";
        }
        return failure[0];
    }

    @SuppressLint("MissingPermission")
    private void requestSta(TransportStart request, String[] failure, CountDownLatch complete) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || request.ssid.isEmpty()) {
            failure[0] = request.ssid.isEmpty() ? "missing_ssid" : "requires_android_10";
            note("sta.error=" + failure[0]);
            complete.countDown();
            return;
        }
        if (connectivity == null || context.checkSelfPermission(
                android.Manifest.permission.NEARBY_WIFI_DEVICES)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            failure[0] = "missing_NEARBY_WIFI_DEVICES";
            note("sta.error=" + failure[0]);
            complete.countDown();
            return;
        }
        WifiNetworkSpecifier.Builder specifier = new WifiNetworkSpecifier.Builder().setSsid(request.ssid);
        if (request.bssid.length != 0) {
            if (request.bssid.length != 6) {
                failure[0] = "invalid_bssid";
                note("sta.error=" + failure[0]);
                complete.countDown();
                return;
            }
            try {
                specifier.setBssid(MacAddress.fromBytes(request.bssid));
            } catch (IllegalArgumentException error) {
                failure[0] = "invalid_bssid";
                note("sta.error=" + failure[0]);
                complete.countDown();
                return;
            }
        }
        // The shared control schema never requests an open STA. An omitted
        // PSK denotes the fixed DMesh key, while a supplied value joins a
        // different protected AP. This mirrors the ESP radio adapter.
        String passphrase = request.passphrase.isEmpty()
                ? DMESH_WPA2_PASSPHRASE : request.passphrase;
        try {
            specifier.setWpa2Passphrase(passphrase);
        } catch (IllegalArgumentException error) {
            failure[0] = "invalid_passphrase";
            note("sta.error=" + failure[0]);
            complete.countDown();
            return;
        }
        releaseStaAttachment();
        NetworkRequest networkRequest = new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .setNetworkSpecifier(specifier.build())
                .build();
        staAttachment = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) {
                staNetwork = network;
                staSsid = request.ssid;
                note("sta.available ssid=" + request.ssid);
                complete.countDown();
            }
            @Override public void onUnavailable() {
                failure[0] = "sta_unavailable";
                note("sta.unavailable ssid=" + request.ssid);
                releaseStaAttachment();
                complete.countDown();
            }
            @Override public void onLost(Network network) {
                if (network.equals(staNetwork)) { staNetwork = null; staSsid = ""; }
                synchronized (WifiController.this) { appliedTransportKey = ""; }
                note("sta.lost ssid=" + request.ssid);
            }
        };
        try {
            connectivity.requestNetwork(networkRequest, staAttachment, 20_000);
            note("sta.requested ssid=" + request.ssid);
        } catch (RuntimeException error) {
            failure[0] = "sta_request_exception";
            note("sta.error=" + failure[0]);
            releaseStaAttachment();
            complete.countDown();
        }
    }

    private void releaseStaAttachment() {
        if (staAttachment == null || connectivity == null) return;
        try {
            connectivity.unregisterNetworkCallback(staAttachment);
        } catch (IllegalArgumentException ignored) {
            // The framework already retired this app-scoped request.
        }
        staAttachment = null;
        staNetwork = null;
        staSsid = "";
        note("sta.released");
    }

    /** Current DMesh-managed STA SSID, or empty when no STA attachment exists. */
    public synchronized String currentStaSsid() { return staSsid; }

    /** True when this adapter owns an AP/GO endpoint. */
    public synchronized boolean apActive() { return p2pGroupRequested || lohsReservation != null; }

    public void startP2pGroup() {
        startP2pGroup(false);
    }

    /**
     * Reproduce the DMesh GO path sufficiently to isolate DNS-SD ownership:
     * create a GO, add a local service, then perform all-service cleanup
     * before group removal and Channel close.
     */
    private void startP2pGroup(boolean advertise) {
        handler.post(() -> {
            releaseStaAttachment();
            stopNanInternal();
            if (!ensureP2pChannel()) return;
            p2pGroupRequested = true;
            advertiseAfterGroup = advertise;
            // Begin each run from a public removeGroup request. This makes a
            // leftover group visible in the callback history rather than
            // incorrectly attributing ERROR_BUSY to the P2P-to-NAN sequence.
            try {
                p2p.removeGroup(p2pChannel, chain("p2p.remove_before_create",
                        this::createP2pGroup));
            } catch (RuntimeException e) {
                note("p2p.remove_before_create exception=" + describe(e));
                createP2pGroup();
            }
        });
    }

    /**
     * Shell calls must retain process importance until a meaningful P2P result
     * arrives. A provider-only process otherwise may be frozen immediately
     * after its binder reply, before the framework callback is delivered.
     */
    public boolean startP2pGroupAndAwait() {
        return runAndAwait(event ->
                        (event.startsWith("p2p.group_info broadcast=")
                                && !event.endsWith("=null"))
                                || event.startsWith("p2p.create_group failed=")
                                || event.startsWith("p2p.create_group exception="),
                15_000, this::startP2pGroup);
    }

    public boolean startP2pGroupWithServiceAndAwait() {
        return runAndAwait(event -> event.equals("p2p.local_service active")
                        || event.startsWith("p2p.local_service failed=")
                        || event.startsWith("p2p.create_group failed=")
                        || event.startsWith("p2p.create_group exception="),
                15_000, () -> startP2pGroup(true));
    }

    /** Issue the DMesh DNS-SD query through Android's public P2P API. */
    public boolean discoverP2pServicesAndAwait() {
        return runAndAwait(event -> event.equals("p2p.discover_services accepted")
                        || event.startsWith("p2p.discover_services failed=")
                        || event.startsWith("p2p.discover_services exception="),
                15_000, () -> handler.post(this::discoverP2pServices));
    }

    private void discoverP2pServices() {
        stopNanInternal();
        if (!ensureP2pChannel()) return;
        WifiP2pManager.Channel channel = p2pChannel;
        p2p.setDnsSdResponseListeners(channel,
                (instance, type, device) -> note("p2p.dnssd_service instance=" + instance
                        + " type=" + type + " peer=" + device.deviceAddress),
                (domain, record, device) -> note("p2p.dnssd_txt domain=" + domain
                        + " peer=" + device.deviceAddress + " keys=" + record.keySet()));
        try {
            p2p.clearServiceRequests(channel, chain("p2p.clear_service_requests", () -> {
                WifiP2pDnsSdServiceRequest request =
                        WifiP2pDnsSdServiceRequest.newInstance("dmesh", "_dmesh._tcp");
                try {
                    p2p.addServiceRequest(channel, request, new WifiP2pManager.ActionListener() {
                        @Override public void onSuccess() {
                            serviceRequest = request;
                            note("p2p.service_request active");
                            try {
                                p2p.discoverServices(channel, action("p2p.discover_services"));
                            } catch (RuntimeException error) {
                                note("p2p.discover_services exception=" + describe(error));
                            }
                        }
                        @Override public void onFailure(int reason) {
                            note("p2p.service_request failed=" + reason);
                        }
                    });
                } catch (RuntimeException error) {
                    note("p2p.service_request exception=" + describe(error));
                }
            }));
        } catch (RuntimeException error) {
            note("p2p.clear_service_requests exception=" + describe(error));
        }
    }

    private void createP2pGroup() {
        if (p2pChannel == null) return;
        note("p2p.create_group request frequency_mhz=2437 ssid=" + P2P_SSID);
        try {
            // Public API 29+: known WPA2 credentials make the generated GO
            // reproducible while still exercising only platform P2P APIs.
            WifiP2pConfig config = new WifiP2pConfig.Builder()
                    .setNetworkName(P2P_SSID)
                    .setPassphrase(DMESH_WPA2_PASSPHRASE)
                    .setGroupOperatingFrequency(2437)
                    .build();
            p2p.createGroup(p2pChannel, config, action("p2p.create_group"));
        } catch (RuntimeException e) {
            note("p2p.create_group exception=" + describe(e));
        }
    }

    /** The NAN button is the complete public P2P teardown followed by Aware attach. */
    public void startNanAfterP2p() {
        handler.post(() -> {
            releaseStaAttachment();
            stopNanInternal();
            stopP2p(this::startNanInternal);
        });
    }

    /** Shell equivalent of the NAN button, returning after a terminal callback. */
    public boolean startNanAfterP2pAndAwait() {
        return runAndAwait(event -> event.equals("aware.on_publish_started")
                        || event.equals("aware.on_attach_failed")
                        || event.equals("aware.on_publish_config_failed")
                        || event.startsWith("aware.attach exception="),
                30_000, this::startNanAfterP2p);
    }

    public void stopNan() { handler.post(this::stopNanInternal); }

    /** ADB-only LocalOnly Hotspot configuration check, following the CTS custom-config test. */
    public void startLocalOnlyHotspot() {
        handler.post(() -> {
            if (wifi == null) {
                note("lohs.start unsupported");
                return;
            }
            if (lohsReservation != null) {
                note("lohs.start already_active");
                return;
            }
            try {
                WifiManager.LocalOnlyHotspotCallback callback = new WifiManager.LocalOnlyHotspotCallback() {
                            @Override public void onStarted(WifiManager.LocalOnlyHotspotReservation reservation) {
                                lohsReservation = reservation;
                                SoftApConfiguration actual = reservation.getSoftApConfiguration();
                                boolean matches = actual != null
                                        && LOHS_SSID.equals(actual.getSsid())
                                        && LOHS_PASSPHRASE.equals(actual.getPassphrase());
                                note("lohs.on_started configured_credentials_match=" + matches);
                            }
                            @Override public void onStopped() {
                                lohsReservation = null;
                                note("lohs.on_stopped");
                            }
                            @Override public void onFailed(int reason) {
                                lohsReservation = null;
                                note("lohs.on_failed=" + reason);
                            }
                        };
                if (Build.VERSION.SDK_INT >= 37) {
                    // Android 17 adds the public configured-LOHS API. This is
                    // the same SSID/passphrase construction exercised by CTS.
                    SoftApConfiguration config = new SoftApConfiguration.Builder()
                            .setWifiSsid(WifiSsid.fromBytes(LOHS_SSID.getBytes(StandardCharsets.UTF_8)))
                            .setPassphrase(LOHS_PASSPHRASE,
                                    SoftApConfiguration.SECURITY_TYPE_WPA2_PSK)
                            .build();
                    note("lohs.start configured request ssid=" + LOHS_SSID + " security=wpa2_psk");
                    wifi.startLocalOnlyHotspotWithConfiguration(config, handler::post, callback);
                } else {
                    // Older public SDKs expose only the framework-generated
                    // credential reservation API; record that distinction.
                    note("lohs.start legacy request sdk=" + Build.VERSION.SDK_INT);
                    wifi.startLocalOnlyHotspot(callback, handler);
                }
            } catch (RuntimeException e) {
                note("lohs.start exception=" + e.getClass().getSimpleName());
            }
        });
    }

    public void stopLocalOnlyHotspot() {
        handler.post(() -> {
            if (lohsReservation == null) {
                note("lohs.stop inactive");
                return;
            }
            lohsReservation.close();
            note("lohs.reservation_close called");
        });
    }

    public void stopP2p(Runnable after) { handler.post(() -> stopP2pInternal(after)); }

    private boolean ensureP2pChannel() {
        if (p2p == null) {
            note("p2p.initialize unavailable");
            return false;
        }
        if (p2pChannel != null) return true;
        p2pChannel = p2p.initialize(context, handler.getLooper(), () -> {
            note("p2p.channel_disconnected");
            p2pChannel = null;
        });
        note("p2p.initialize channel=" + (p2pChannel != null));
        return p2pChannel != null;
    }

    private void stopP2pInternal(Runnable after) {
        if (p2pChannel == null) {
            note("p2p.stop channel_absent");
            p2pGroupRequested = false;
            after.run();
            return;
        }
        WifiP2pManager.Channel channel = p2pChannel;
        note("p2p.stop begin");
        clearP2pServices(channel, () -> cancelConnectThenStop(channel, after));
    }

    private void cancelConnectThenStop(WifiP2pManager.Channel channel, Runnable after) {
        try {
            p2p.cancelConnect(channel, chain("p2p.cancel_connect", () ->
                    stopListening(channel, () -> stopPeerDiscovery(channel, () ->
                            removeGroupAndClose(channel, after)))));
        } catch (RuntimeException e) {
            note("p2p.cancel_connect exception=" + e.getClass().getSimpleName());
            stopListening(channel, () -> stopPeerDiscovery(channel, () ->
                    removeGroupAndClose(channel, after)));
        }
    }

    private void addLocalService(WifiP2pManager.Channel channel) {
        if (localService != null || localServiceAdding) return;
        localServiceAdding = true;
        Map<String, String> attributes = new HashMap<>();
        // The radio ownership test needs a bounded opaque TXT value, not a
        // second control schema. Android DNS-SD TXT fields are strings.
        attributes.put("cbor", base64UrlNoPadding(announce.payload));
        WifiP2pDnsSdServiceInfo candidate = WifiP2pDnsSdServiceInfo.newInstance(
                "dmesh", "_dmesh._tcp", attributes);
        try {
            p2p.addLocalService(channel, candidate, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() {
                    localService = candidate;
                    localServiceAdding = false;
                    note("p2p.local_service active");
                }
                @Override public void onFailure(int reason) {
                    localServiceAdding = false;
                    note("p2p.local_service failed=" + reason);
                }
            });
        } catch (RuntimeException e) {
            localServiceAdding = false;
            note("p2p.local_service exception=" + describe(e));
        }
    }

    /** Clear every service record and discovery request before releasing P2P. */
    private void clearP2pServices(WifiP2pManager.Channel channel, Runnable after) {
        try {
            p2p.clearLocalServices(channel, chain("p2p.clear_local_services", () -> {
                localService = null;
                localServiceAdding = false;
                clearServiceRequests(channel, after);
            }));
        } catch (RuntimeException e) {
            note("p2p.clear_local_services exception=" + describe(e));
            localService = null;
            localServiceAdding = false;
            clearServiceRequests(channel, after);
        }
    }

    private void clearServiceRequests(WifiP2pManager.Channel channel, Runnable after) {
        try {
            p2p.clearServiceRequests(channel, chain("p2p.clear_service_requests", () -> {
                serviceRequest = null;
                after.run();
            }));
        } catch (RuntimeException e) {
            note("p2p.clear_service_requests exception=" + describe(e));
            serviceRequest = null;
            after.run();
        }
    }

    private void stopListening(WifiP2pManager.Channel channel, Runnable after) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            after.run();
            return;
        }
        try { p2p.stopListening(channel, chain("p2p.stop_listening", after)); }
        catch (RuntimeException e) { note("p2p.stop_listening exception=" + describe(e)); after.run(); }
    }

    private void stopPeerDiscovery(WifiP2pManager.Channel channel, Runnable after) {
        try { p2p.stopPeerDiscovery(channel, chain("p2p.stop_peer_discovery", after)); }
        catch (RuntimeException e) { note("p2p.stop_peer_discovery exception=" + describe(e)); after.run(); }
    }

    private void removeGroupAndClose(WifiP2pManager.Channel channel, Runnable after) {
        try {
            p2p.removeGroup(channel, chain("p2p.remove_group", () -> {
                awaitGroupAbsent(channel, after,
                        SystemClock.elapsedRealtime() + GROUP_REMOVAL_TIMEOUT_MS);
            }));
        } catch (RuntimeException e) {
            note("p2p.remove_group exception=" + describe(e));
            awaitGroupAbsent(channel, after,
                    SystemClock.elapsedRealtime() + GROUP_REMOVAL_TIMEOUT_MS);
        }
    }

    /**
     * AOSP tests wait for state callbacks rather than treating removeGroup's
     * ActionListener acknowledgement as teardown completion. Do the same here
     * before closing the client channel and attempting NAN allocation.
     */
    private void awaitGroupAbsent(WifiP2pManager.Channel channel, Runnable after, long deadlineMs) {
        try {
            p2p.requestGroupInfo(channel, group -> {
                if (group == null) {
                    note("p2p.group_info removal_complete=null");
                    // Keep this short settle interval explicit in the evidence:
                    // it distinguishes a completed group removal from HAL
                    // interface lifetime, which is the issue under test.
                    handler.postDelayed(() -> closeP2pChannel(channel, after), 2_000);
                } else if (SystemClock.elapsedRealtime() < deadlineMs) {
                    note("p2p.group_info removal_pending=" + group.getNetworkName());
                    handler.postDelayed(() -> awaitGroupAbsent(channel, after, deadlineMs),
                            GROUP_REMOVAL_POLL_MS);
                } else {
                    note("p2p.group_info removal_timeout=" + group.getNetworkName());
                    closeP2pChannel(channel, after);
                }
            });
        } catch (RuntimeException e) {
            note("p2p.group_info removal exception=" + describe(e));
            closeP2pChannel(channel, after);
        }
    }

    private void closeP2pChannel(WifiP2pManager.Channel channel, Runnable after) {
        requestGroupInfo("before_channel_close");
        try {
            channel.close();
            note("p2p.channel_close called");
        } catch (RuntimeException e) {
            note("p2p.channel_close exception=" + describe(e));
        }
        if (channel == p2pChannel) p2pChannel = null;
        p2pGroupRequested = false;
        advertiseAfterGroup = false;
        after.run();
    }

    private void requestGroupInfo(String reason) {
        WifiP2pManager.Channel channel = p2pChannel;
        if (p2p == null || channel == null) return;
        try {
            p2p.requestGroupInfo(channel, group -> {
                note("p2p.group_info " + reason + "="
                        + (group == null ? "null" : group.getNetworkName()));
                if (advertiseAfterGroup && group != null && localService == null) {
                    addLocalService(channel);
                }
            });
        } catch (RuntimeException e) {
            note("p2p.group_info " + reason + " exception=" + describe(e));
        }
    }

    @SuppressLint("MissingPermission")
    private void startNanInternal() {
        if (aware == null) {
            note("aware.attach unavailable");
            return;
        }
        note("aware.attach request available=" + aware.isAvailable());
        try {
            aware.attach(new AttachCallback() {
                @Override public void onAttached(WifiAwareSession session) {
                    awareSession = session;
                    note("aware.on_attached");
                    publishNan();
                    subscribeNan();
                }
                @Override public void onAttachFailed() { note("aware.on_attach_failed"); }
                @Override public void onAwareSessionTerminated() {
                    awareSession = null;
                    publishSession = null;
                    note("aware.on_session_terminated");
                }
            }, handler);
        } catch (RuntimeException e) {
            note("aware.attach exception=" + describe(e));
        }
    }

    private void stopNanInternal() {
        if (subscribeSession != null) {
            subscribeSession.close();
            subscribeSession = null;
            note("aware.subscribe_close");
        }
        if (publishSession != null) {
            publishSession.close();
            publishSession = null;
            note("aware.publish_close");
        }
        if (awareSession != null) {
            awareSession.close();
            awareSession = null;
            note("aware.session_close");
        }
    }

    private void publishNan() {
        if (awareSession == null) return;
        PublishConfig config = new PublishConfig.Builder().setServiceName(NAN_SERVICE)
                .setServiceSpecificInfo(announce.payload).build();
        awareSession.publish(config, new DiscoverySessionCallback() {
            @Override public void onPublishStarted(PublishDiscoverySession publish) {
                publishSession = publish;
                note("aware.on_publish_started");
            }
            @Override public void onSessionConfigFailed() { note("aware.on_publish_config_failed"); }
            @Override public void onSessionTerminated() { note("aware.on_publish_terminated"); }
        }, handler);
    }

    private void subscribeNan() {
        if (awareSession == null) return;
        SubscribeConfig.Builder builder = new SubscribeConfig.Builder().setServiceName(NAN_SERVICE);
        // `Discover.options` is the platform-neutral projection used by the
        // Android bridge. The default Subscribe type is passive on several
        // Android releases, which creates a session but does not emit the
        // over-the-air active-Subscribe request needed to wake/responding
        // firmware.
        if (discover.options.contains("active")) {
            builder.setSubscribeType(SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE);
        }
        // Empty means "all DMesh services" rather than "do not subscribe".
        if (!discover.isEmpty()) builder.setServiceSpecificInfo(discover.payload);
        SubscribeConfig config = builder.build();
        awareSession.subscribe(config, new DiscoverySessionCallback() {
            @Override public void onSubscribeStarted(SubscribeDiscoverySession subscribe) {
                subscribeSession = subscribe;
                note("aware.on_subscribe_started");
            }
            @Override public void onServiceDiscovered(PeerHandle peer, byte[] info,
                                                      List<byte[]> matchFilter) {
                WifiEventSink sink = eventSink;
                if (sink != null) sink.onDiscovered(new WifiDiscovery("nan", String.valueOf(peer),
                        info, -1, SystemClock.elapsedRealtime()));
                note("aware.on_service_discovered bytes=" + (info == null ? 0 : info.length));
                if (DmeshControl.isDiscoveryRequest(info)) {
                    respondToActiveDiscover(peer);
                }
                sendDirectedNanMessage(peer);
            }
            @Override public void onMessageReceived(PeerHandle peer, byte[] message) {
                byte[] payload = message == null ? new byte[0] : message;
                note("aware.on_message_received bytes=" + payload.length);
                // An active DMesh discovery request receives the cached
                // signed announce as a Follow-up. That callback already
                // carries the framework PeerHandle, even when the peer's
                // short DW did not produce a separate onServiceDiscovered
                // callback in this Subscribe session. Use it for a pending
                // target-checked wake control record as well.
                sendDirectedNanMessage(peer);
                WifiEventSink sink = eventSink;
                if (sink != null) {
                    // WifiAware does not expose per-message RSSI through this
                    // public callback. Keep -1 as an explicit unavailable
                    // value; the common observation record must not invent it.
                    sink.onReceived("nan", String.valueOf(peer), payload, -1);
                }
            }
            @Override public void onSessionConfigFailed() { note("aware.on_subscribe_config_failed"); }
            @Override public void onSessionTerminated() { note("aware.on_subscribe_terminated"); }
        }, handler);
    }

    /**
     * Attach one bounded Follow-up payload to the current temporary
     * discovery. This remains separate from Discover.serviceInfo because
     * some Wi-Fi Aware implementations omit that value from active-Subscribe
     * SDEAs visible to raw-NAN peers.
     */
    public void setDirectedNanMessage(byte[] payload) {
        final byte[] copy = payload == null ? null : Arrays.copyOf(payload, payload.length);
        handler.post(() -> directedNanMessage = copy);
    }

    private void sendDirectedNanMessage(PeerHandle peer) {
        byte[] payload = directedNanMessage;
        SubscribeDiscoverySession subscribe = subscribeSession;
        if (payload == null || payload.length == 0 || subscribe == null) return;
        try {
            subscribe.sendMessage(peer, ++discoveryResponseMessageId, payload);
            note("aware.directed_message bytes=" + payload.length);
        } catch (RuntimeException error) {
            note("aware.directed_message exception=" + describe(error));
        }
    }

    /**
     * A common active discovery request is presence-only: it never changes a
     * P2P/STA/NAN epoch. Re-advertise immediately and return the current
     * canonical announce through Wi-Fi Aware's directed message lane. Rust
     * observes the request through {@link WifiEventSink} and may replace the
     * opaque announce before the next request when its signed record changes.
     */
    private void respondToActiveDiscover(PeerHandle peer) {
        if (announce.isEmpty()) {
            note("aware.discover_request ignored=no_announce");
            return;
        }
        PublishDiscoverySession publish = publishSession;
        if (publish != null) {
            try {
                publish.sendMessage(peer, ++discoveryResponseMessageId, announce.payload);
                note("aware.discover_response bytes=" + announce.payload.length);
            } catch (RuntimeException error) {
                note("aware.discover_response exception=" + describe(error));
            }
        }
        // The directed reply above is the immediate presence response. Keep
        // the long-lived publish session intact: closing and recreating it
        // for every active discovery request races Android's session
        // callbacks, briefly removes the advertised service, and leaves the
        // common NAN status falsely inactive. Announce updates themselves
        // still recreate publication through setAnnounce(), where changing
        // Service Info is actually required.
    }

    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder(value.length * 2);
        for (byte b : value) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }

    /** Shared P2P DNS-SD TXT spelling: printable, URL-safe, and denser than hex. */
    private static String base64UrlNoPadding(byte[] value) {
        return Base64.encodeToString(value,
                Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private WifiP2pManager.ActionListener action(String name) {
        return chain(name, () -> { });
    }

    private WifiP2pManager.ActionListener chain(String name, Runnable next) {
        return new WifiP2pManager.ActionListener() {
            @Override public void onSuccess() { note(name + " accepted"); next.run(); }
            @Override public void onFailure(int reason) { note(name + " failed=" + reason); next.run(); }
        };
    }

    public synchronized String snapshot() {
        return "p2p_channel=" + (p2pChannel != null)
                + " p2p_group_requested=" + p2pGroupRequested
                + " p2p_local_service=" + (localService != null)
                + " aware_available=" + (aware != null && aware.isAvailable())
                + " aware_session=" + (awareSession != null)
                + " aware_publish=" + (publishSession != null)
                + " aware_subscribe=" + (subscribeSession != null)
                + " announce_bytes=" + announce.payload.length
                + " discover_bytes=" + discover.payload.length
                + " sta=" + (staAttachment != null)
                + " sta_network=" + (staNetwork != null)
                + " lohs=" + (lohsReservation != null)
                + " last=" + lastEvent;
    }

    public synchronized String logText() { return String.join("\n", log); }

    private boolean runAndAwait(EventMatch match, long timeoutMs, Runnable command) {
        CountDownLatch latch = new CountDownLatch(1);
        synchronized (this) {
            if (awaitingLatch != null) {
                note("shell.await rejected=already_waiting");
                return false;
            }
            awaitingEvent = match;
            awaitingLatch = latch;
        }
        command.run();
        boolean observed = false;
        try {
            observed = latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            note("shell.await interrupted");
        } finally {
            synchronized (this) {
                if (awaitingLatch == latch) {
                    awaitingEvent = null;
                    awaitingLatch = null;
                }
            }
        }
        if (!observed) note("shell.await timeout_ms=" + timeoutMs);
        return observed;
    }

    private static String describe(RuntimeException error) {
        String message = error.getMessage();
        return error.getClass().getSimpleName()
                + (message == null || message.isEmpty() ? "" : ":" + message);
    }

    private void note(String event) {
        CountDownLatch latch = null;
        synchronized (this) {
            lastEvent = event;
            if (log.size() == MAX_LOG_LINES) log.removeFirst();
            log.addLast(SystemClock.elapsedRealtime() + " " + event);
            if (awaitingEvent != null && awaitingEvent.matches(event)) latch = awaitingLatch;
        }
        if (latch != null) latch.countDown();
        WifiEventSink sink = eventSink;
        if (sink != null) sink.onEvent(event);
        Observer current;
        synchronized (this) { current = observer; }
        if (current != null) new Handler(context.getMainLooper()).post(current::onStateChanged);
    }
}
