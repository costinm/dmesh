package com.github.costinm.dmesh.lm3;

import static android.net.NetworkCapabilities.TRANSPORT_WIFI;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.MacAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.SoftApConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.net.wifi.WifiSsid;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.UiUtil;
import com.github.costinm.dmesh.android.util.Hex;
import com.github.costinm.dmeshnative.MeshNode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;

/**
 * Local mesh - Wi-Fi Aware NAN and BLE. NAN is the Wi-Fi discovery and timing
 * mechanism; LocalOnly Hotspot is the optional AP/STA data fallback.
 * with 'modem' like devices - like LoRA or ESP raw WiFi protocls.
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
 * -  net/{NET}: ap, wlan, inet, ... - network interfaces
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
 * -- name: radio-advertised name, when available
 */
public class LocalMesh extends BroadcastReceiver implements MessageHandler {
    public static final int UPDATE = 3;
    public static final int MSG = 2;
    static final Map<String, String> empty = new HashMap<>();
    static final String TAG = "DM/wifi";
    /**
     * Lab-only WPA2 credential for Android releases which expose configured
     * LocalOnly Hotspot. It is intentionally volatile transport-start data,
     * never a preference or discovery identity.
     */
    private static final String LOCAL_ONLY_HOTSPOT_WPA2_PASSPHRASE = "untrusted-open-mode";
    private static final String PREF_ENABLED = "wifi_enabled";


    // end raw data
    static String lastCap = "";
    private static LocalMesh singleton;

    // -------------------------

    Context ctx;

    // All platform callbacks are marshalled to this thread.
    // Callbacks run on this thread, should be non-blocking.
    final Looper looper;

    // Handler is used for postDelayed() or other similar operations - on the looper.
    final Handler delayHandler;

    // Used for discovery
    public Nan nan;

    public Ble ble;

    // Wi-Fi manager is used only for LocalOnly Hotspot and observational scans.
    private final WifiManager wifiManager;

    ConnectivityManager cm;
    // A requested infrastructure STA attachment.  It is intentionally
    // App-scoped infrastructure attachment: separate from NAN and the local
    // hotspot so a transport.start can replace only its intended radio epoch.
    ConnectivityManager.NetworkCallback staAttachment;
    private WifiManager.LocalOnlyHotspotReservation localOnlyHotspot;
    private boolean localOnlyHotspotStarting;
    // Volatile framework credentials: never preferences/NVS. Retain only for
    // the life of this reservation so an idempotent repeated request can
    // return the same usable AP target to its privileged caller.
    private String localOnlyHotspotSsid = "";
    private String localOnlyHotspotPassphrase = "";
    private String appliedTransportStart = "";

    /**
     * Stable lab SSID for a configured local-only hotspot.  The suffix is the
     * short node identity already used by the local radio advertisements.
     * Android versions which only expose the legacy LocalOnlyHotspot API own
     * the resulting SSID and passphrase; callers must use the returned values
     * rather than assuming this name.
     */
    private String configuredLocalOnlyHotspotSsid() {
        String suffix = id4 == null ? "0000" : id4;
        if (suffix.length() > 4) {
            suffix = suffix.substring(0, 4);
        }
        return "DIRECT-dmesh-" + suffix;
    }

    // Advertised URL - for NAN, BLE, TXT
    // Current format: 16 bytes, PSK8 + SSIDHASH4 + ID4
    String adv = "12345678SSIDID04";
    byte[] deviceId = new byte[] {'A', 'N', 'D', 'R', '0', '0'};
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
        wifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);

        cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);

        cm.registerNetworkCallback(new NetworkRequest.Builder().build(), new ConnectivityCallback(this));

        nan = new Nan(this);

        ble = new Ble(appContext, this, this.delayHandler);
        //bt = new Bt2(appContext, this.delayHandler);


        nan.onCreate();
        delayHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                listen();
            }
        }, 1000);

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
        return ssid.startsWith("dmesh-");
    }

    /**
     * Called when all Bind (subscribers) disconnect.
     * <p>
     * Will leave AP and connections in last known state. May exit.
     */
    public void onDestroy() {
        releaseStaAttachment();
        releaseLocalOnlyHotspot();
        ctx.unregisterReceiver(this);
        //bt.close();
    }

    /**
     * Ask Android to attach this app to one explicit infrastructure AP.
     *
     * This is deliberately an app-scoped {@link WifiNetworkSpecifier}
     * request: it does not save credentials, change the user's global Wi-Fi
     * choice, or tear down NAN. Android may present its normal approval
     * UI and an OEM may reject AP+STA concurrency; both outcomes are emitted
     * so the shared probe response can report measured capability.
     */
    private void requestStaAttachment(Bundle data) {
        String ssid = data.getString("ssid", "");
        String bssid = data.getString("bssid", "");
        String passphrase = data.getString("passphrase", "");
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || ssid.isEmpty()) {
            MsgMux.get(ctx).publish("net.StaAttach", "ok", "0", "error",
                    ssid.isEmpty() ? "missing_ssid" : "requires_android_10");
            return;
        }
        if (ctx.checkSelfPermission(android.Manifest.permission.NEARBY_WIFI_DEVICES)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("net.StaAttach", "ok", "0", "error",
                    "missing_NEARBY_WIFI_DEVICES");
            return;
        }

        WifiNetworkSpecifier.Builder specifier = new WifiNetworkSpecifier.Builder().setSsid(ssid);
        if (!bssid.isEmpty()) {
            try {
                specifier.setBssid(MacAddress.fromString(bssid));
            } catch (IllegalArgumentException error) {
                MsgMux.get(ctx).publish("net.StaAttach", "ok", "0", "error",
                        "invalid_bssid", "detail", String.valueOf(error.getMessage()));
                return;
            }
        }
        if (!passphrase.isEmpty()) {
            try {
                specifier.setWpa2Passphrase(passphrase);
            } catch (IllegalArgumentException error) {
                // Never include the passphrase itself in an event/log.
                MsgMux.get(ctx).publish("net.StaAttach", "ok", "0", "error",
                        "invalid_passphrase", "detail", String.valueOf(error.getMessage()));
                return;
            }
        }

        releaseStaAttachment();
        NetworkRequest request = new NetworkRequest.Builder()
                .addTransportType(TRANSPORT_WIFI)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .setNetworkSpecifier(specifier.build())
                .build();
        staAttachment = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                MsgMux.get(ctx).publish("net.StaAttach", "ok", "1", "state",
                        "available", "ssid", ssid, "bssid", bssid);
            }

            @Override
            public void onUnavailable() {
                MsgMux.get(ctx).publish("net.StaAttach", "ok", "0", "state",
                        "unavailable", "ssid", ssid, "bssid", bssid);
            }

            @Override
            public void onLost(Network network) {
                MsgMux.get(ctx).publish("net.StaAttach", "ok", "0", "state",
                        "lost", "ssid", ssid, "bssid", bssid);
            }
        };
        cm.requestNetwork(request, staAttachment, 20_000);
        MsgMux.get(ctx).publish("net.StaAttach", "ok", "1", "state", "requested",
                "ssid", ssid, "bssid", bssid);
    }

    private void releaseStaAttachment() {
        if (staAttachment == null) {
            return;
        }
        try {
            cm.unregisterNetworkCallback(staAttachment);
        } catch (IllegalArgumentException ignored) {
            // Android already retired the request.
        }
        staAttachment = null;
        MsgMux.get(ctx).publish("net.StaAttach", "ok", "1", "state", "released");
    }

    /**
     * Apply the platform portion of a validated shared transport.start.
     *
     * Android keeps NAN desired throughout. `sta` requests an app-scoped
     * attachment; `nan` releases it. `ap=1` requests Android's local-only
     * hotspot. The framework chooses its credentials, so this is a measured
     * local AP capability, not a claim that unprivileged Android can create
     * an arbitrary open SoftAP.
     */
    public synchronized void applyTransportStart(String json, String source, String peer) {
        applyTransportStart(json, source, peer, "", null);
    }

    /**
     * Apply a shared transport.start and keep the caller's request id through
     * the asynchronous Android Wi-Fi callback.  The direct result is the
     * control-plane response; the matching broadcast is retained for status
     * subscribers and historical diagnostics.
     */
    private synchronized void applyTransportStart(String json, String source, String peer,
                                                  String requestId, MsgConn replyTo) {
        String mode = jsonField(json, "mode");
        if (!"sta".equals(mode) && !"nan".equals(mode)) {
            publishTransportResult(requestId, replyTo, "error", "invalid_mode", "", "");
            return;
        }
        String ssidHex = jsonField(json, "ssid_hex");
        String passphraseHex = jsonField(json, "passphrase_hex");
        String bssidHex = jsonField(json, "bssid_hex");
        String ndp = jsonField(json, "ndp");
        String ap = jsonField(json, "ap");
        String key = mode + ":" + ssidHex + ":" + passphraseHex + ":" + bssidHex + ":" + ndp + ":" + ap;
        if (key.equals(appliedTransportStart)) {
            MsgMux.get(ctx).publish("net.TransportStart", "ok", "1", "state", "unchanged",
                    "source", source, "peer", peer, "mode", mode, "request_id", requestId);
            publishTransportResult(requestId, replyTo, "unchanged", "", "", "");
            return;
        }
        if ("sta".equals(mode)) {
            Bundle target = new Bundle();
            target.putString("ssid", hexText(ssidHex));
            target.putString("passphrase", hexText(passphraseHex));
            target.putString("bssid", colonMac(bssidHex));
            requestStaAttachment(target);
        } else {
            releaseStaAttachment();
            if (nan != null) nan.ensureActive();
        }
        if (nan != null) nan.setNdpEnabled("1".equals(ndp));
        if ("1".equals(ap)) requestLocalOnlyHotspot(requestId, replyTo); else {
            releaseLocalOnlyHotspot();
            publishTransportResult(requestId, replyTo, "ap_stopped", "", "", "");
        }
        appliedTransportStart = key;
        MsgMux.get(ctx).publish("net.TransportStart", "ok", "1", "state", "applied",
                "source", source, "peer", peer, "mode", mode, "ndp", ndp, "ap", ap,
                "request_id", requestId);
    }

    private static String hexText(String value) {
        if (value == null || (value.length() & 1) != 0) return "";
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            try { bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16); }
            catch (RuntimeException error) { return ""; }
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String jsonField(String json, String field) {
        if (json == null) return "";
        String needle = "\"" + field + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) return "";
        start += needle.length();
        int end = json.indexOf('"', start);
        return end < 0 ? "" : json.substring(start, end);
    }

    private static String colonMac(String value) {
        if (value == null || value.length() != 12) return "";
        StringBuilder out = new StringBuilder(17);
        for (int index = 0; index < value.length(); index += 2) {
            if (index != 0) out.append(':');
            out.append(value, index, index + 2);
        }
        return out.toString();
    }

    private static String argumentValue(String[] args, String key, String fallback) {
        String prefix = key + "=";
        for (String arg : args) if (arg.startsWith(prefix)) return arg.substring(prefix.length());
        return fallback;
    }

    private void requestLocalOnlyHotspot(String requestId, MsgConn replyTo) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            MsgMux.get(ctx).publish("wifi.ap.local", "ok", "0", "error",
                    "requires_android_8");
            publishTransportResult(requestId, replyTo, "error", "requires_android_8", "", "");
            return;
        }
        if (localOnlyHotspot != null) {
            MsgMux.get(ctx).publish("wifi.ap.local", "ok", "1", "state", "already_active");
            publishTransportResult(requestId, replyTo, "already_active", "",
                    localOnlyHotspotSsid, localOnlyHotspotPassphrase);
            return;
        }
        if (localOnlyHotspotStarting) {
            MsgMux.get(ctx).publish("wifi.ap.local", "ok", "1", "state", "starting");
            publishTransportResult(requestId, replyTo, "accepted", "", "", "");
            return;
        }
        if (wifiManager == null) {
            MsgMux.get(ctx).publish("wifi.ap.local", "ok", "0", "error",
                    "wifi_manager_unavailable");
            publishTransportResult(requestId, replyTo, "error", "wifi_manager_unavailable", "", "");
            return;
        }
        localOnlyHotspotStarting = true;
        MsgMux.get(ctx).publish("wifi.ap.local", "ok", "1", "state", "requested",
                "request_id", requestId);
        WifiManager.LocalOnlyHotspotCallback callback = new WifiManager.LocalOnlyHotspotCallback() {
                @Override public void onStarted(WifiManager.LocalOnlyHotspotReservation reservation) {
                    localOnlyHotspotStarting = false;
                    localOnlyHotspot = reservation;
                    // WifiConfiguration was deprecated in API 30 and may be
                    // null for a valid modern hotspot. SoftApConfiguration is
                    // the credential source on the API 33/35 pool and SDK 36.
                    // The common ESP/Android station path currently supports
                    // WPA2-PSK. WPA3 transition mode is also attachable: it
                    // advertises a WPA2-PSK option, unlike WPA3-SAE-only.
                    SoftApConfiguration config = reservation.getSoftApConfiguration();
                    String ssid = config.getSsid();
                    String passphrase = config.getPassphrase();
                    MacAddress bssid = config.getBssid();
                    String bssidHex = bssid == null ? ""
                            : String.valueOf(Hex.encode(bssid.toByteArray()));
                    int securityType = config.getSecurityType();
                    boolean wpa2Compatible = securityType == SoftApConfiguration.SECURITY_TYPE_WPA2_PSK
                            || securityType == SoftApConfiguration.SECURITY_TYPE_WPA3_SAE_TRANSITION;
                    Log.i(TAG, "LocalOnlyHotspot started ssid=" + ssid
                            + " securityType=" + securityType
                            + " passphraseLength=" + (passphrase == null ? 0 : passphrase.length()));
                    if (ssid == null || ssid.isEmpty() || passphrase == null || passphrase.isEmpty()) {
                        localOnlyHotspot.close();
                        localOnlyHotspot = null;
                        localOnlyHotspotSsid = "";
                        localOnlyHotspotPassphrase = "";
                        String securityError = "missing_softap_credentials type=" + securityType;
                        MsgMux.get(ctx).publish("wifi.ap.local", "ok", "0", "error",
                                securityError, "request_id", requestId);
                        publishTransportResult(requestId, replyTo, "error", securityError, "", "");
                        return;
                    }
                    localOnlyHotspotSsid = ssid;
                    localOnlyHotspotPassphrase = passphrase;
                    String compatibilityError = wpa2Compatible ? "" : "unsupported_softap_security type="
                            + securityType + " passphrase_length=" + passphrase.length();
                    MsgMux.get(ctx).publish("wifi.ap.local", "ok", "1", "state", "started",
                            "ssid", ssid,
                            // This stays local to the privileged control-plane
                            // event. A later NAN SD transport.start may carry
                            // it as volatile association data; it is never an
                            // Android preference or ESP NVS setting.
                            "passphrase", passphrase, "request_id", requestId);
                    // A reservation without a WPA2-compatible option is observable and may still be
                    // used to test AP/NAN coexistence, but must never be
                    // treated as an attachable ESP target.
                    publishTransportResult(requestId, replyTo,
                            wpa2Compatible ? "started" : "started_unusable_for_esp",
                            compatibilityError, ssid, passphrase);
                    // The Android AP is ready before its peers can attach.
                    // Publish the complete ephemeral STA target through the
                    // common NAN Service Info control wire; e6 handles it
                    // through the exact UART/NAN profile path, with normal
                    // repeated-SD idempotence.
                    if (nan != null && !ssid.isEmpty()) {
                        byte[] transportStart = MeshNode.buildTransportStart(
                                "sta", ssid, passphrase, bssidHex, false, false);
                        if (nan.setServiceInfoCbor(transportStart)) {
                            nan.ensureActive();
                            MsgMux.get(ctx).publish("net.TransportStartSd", "ok", "1",
                                    "state", "queued", "bytes",
                                    Integer.toString(transportStart.length));
                        }
                    }
                }
                @Override public void onStopped() {
                    localOnlyHotspotStarting = false;
                    localOnlyHotspot = null;
                    localOnlyHotspotSsid = "";
                    localOnlyHotspotPassphrase = "";
                    MsgMux.get(ctx).publish("wifi.ap.local", "ok", "1", "state", "stopped");
                }
                @Override public void onFailed(int reason) {
                    localOnlyHotspotStarting = false;
                    String error = Integer.toString(reason);
                    MsgMux.get(ctx).publish("wifi.ap.local", "ok", "0", "reason", error,
                            "request_id", requestId);
                    publishTransportResult(requestId, replyTo, "error", error, "", "");
                }
            };
        try {
            if (Build.VERSION.SDK_INT >= 36
                    && Build.VERSION.SDK_INT_FULL >= Build.VERSION_CODES_FULL.BAKLAVA_1) {
                // Android 16 QPR2 (36.1) is the first public API with both
                // setters. It gives every capable Android device the same
                // DMesh AP family and WPA2 credential as the ESP validation
                // path, with no reflection or hidden API use.
                SoftApConfiguration.Builder builder = new SoftApConfiguration.Builder();
                builder.setWifiSsid(WifiSsid.fromBytes(
                                configuredLocalOnlyHotspotSsid().getBytes(StandardCharsets.UTF_8)))
                        .setPassphrase(LOCAL_ONLY_HOTSPOT_WPA2_PASSPHRASE,
                                SoftApConfiguration.SECURITY_TYPE_WPA2_PSK);
                SoftApConfiguration config = builder.build();
                wifiManager.startLocalOnlyHotspotWithConfiguration(config,
                        command -> delayHandler.post(command), callback);
            } else {
                // API 26 through 36.0: the public request has a
                // framework-chosen SSID and security type. onStarted rejects
                // anything other than WPA2-PSK before advertising it to ESP.
                wifiManager.startLocalOnlyHotspot(callback, delayHandler);
            }
        } catch (RuntimeException error) {
            localOnlyHotspotStarting = false;
            String reason = error.toString();
            MsgMux.get(ctx).publish("wifi.ap.local", "ok", "0", "error", reason,
                    "request_id", requestId);
            publishTransportResult(requestId, replyTo, "error", reason, "", "");
        }
    }

    private void publishTransportResult(String requestId, MsgConn replyTo, String state,
                                        String error, String ssid, String passphrase) {
        if (requestId == null || requestId.isEmpty()) return;
        MsgFrame result = new MsgFrame("wifi.transport.result");
        result.id = requestId;
        result.fields.put("state", state);
        if (error != null && !error.isEmpty()) result.fields.put("error", error);
        if (ssid != null && !ssid.isEmpty()) result.fields.put("ssid", ssid);
        if (passphrase != null && !passphrase.isEmpty()) result.fields.put("passphrase", passphrase);
        if (replyTo != null) replyTo.sendFrame(result);
        MsgMux.get(ctx).publish("wifi.transport.result", "request_id", requestId,
                "state", state, "error", error, "ssid", ssid, "passphrase", passphrase);
    }

    private void releaseLocalOnlyHotspot() {
        if (localOnlyHotspot != null) localOnlyHotspot.close();
        localOnlyHotspot = null;
        localOnlyHotspotStarting = false;
        localOnlyHotspotSsid = "";
        localOnlyHotspotPassphrase = "";
    }

    /**
     * Called from a periodic job. May also be used without persistent notification,
     * the server will run while the periodic job is active only.
     */
    public void update() {
        listen();
        if (nan != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Android's periodic-job floor is 15 minutes, suitable for a
            // low-rate presence refresh but never for radio timing.
            nan.publishDiscoveryAnnounce();
        }
    }

    public void listen() {
        if (ble != null) {
            ble.scan();
        }
        if (nan != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nan.ensureActive();
        }
    }

    public void scan() {
        scan("", null);
    }

    /**
     * Request an observational Wi-Fi scan.  A request with an id receives the
     * completed bounded result directly; the broadcast remains the source for
     * status subscribers.  It deliberately does not alter STA, NAN, or
     * AP state.
     */
    public void scan(String requestId, MsgConn replyTo) {

        if (wifiManager == null) {
            publishWifiScanResult(requestId, replyTo, false, 0, 0, 0, 0, "", "", "wifi_manager_unavailable");
            return;
        }

        // Method is deprecated, will be removed. System can scan.
        boolean s = wifiManager.startScan();
        if (!s) {
            Log.d(TAG, "Request wifi scan failed " + s);
        }

        delayHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                publishWifiScanResults(requestId, replyTo);
                ble.scan();
            }
        }, 3000);

        if (nan != null) nan.ensureActive();
    }

    /**
     * Publish the bounded common scan summary after Android completes the
     * requested scan. This is observational only: it neither attaches STA nor
     * changes NAN state. Channel 6 is the current probe scope; the full
     * count remains useful to distinguish an empty scan from no DMesh AP.
     */
    private void publishWifiScanResults(String requestId, MsgConn replyTo) {
        if (wifiManager == null) {
            publishWifiScanResult(requestId, replyTo, false, 0, 0, 0, 0, "", "", "wifi_manager_unavailable");
            return;
        }
        try {
            List<ScanResult> results = wifiManager.getScanResults();
            int total = results == null ? 0 : results.size();
            int channel6 = 0;
            int directAny = 0;
            int dmeshAny = 0;
            StringBuilder allDirect = new StringBuilder();
            StringBuilder dmesh = new StringBuilder();
            if (results != null) for (ScanResult result : results) {
                if (result.frequency >= 2432 && result.frequency <= 2442) channel6++;
                String ssid = result.SSID == null ? "" : result.SSID;
                boolean isDirect = ssid.startsWith("DIRECT-");
                // LocalOnly Hotspot chooses its own SSID on current Android
                // releases. A future configurable SoftAP uses `dmesh-`; keep
                // that discovery class distinct from arbitrary DIRECT peers.
                boolean isDmesh = ssid.endsWith("-dmesh") || ssid.startsWith("dmesh-");
                if (isDirect) {
                    directAny++;
                }
                if (isDirect && directAny <= 16) {
                    if (allDirect.length() != 0) allDirect.append(',');
                    allDirect.append(ssid).append('@').append(result.BSSID)
                            .append(':').append(result.level);
                }
                if (!isDmesh) continue;
                dmeshAny++;
                if (dmeshAny > 16) continue;
                if (dmesh.length() != 0) dmesh.append(',');
                // The bounded event is sufficient for probe persistence:
                // SSID, observed BSSID, and RSSI. Android may randomize its
                // own MAC, but the observed AP BSSID is still meaningful.
                dmesh.append(ssid).append('@').append(result.BSSID)
                        .append(':').append(result.level);
            }
            publishWifiScanResult(requestId, replyTo, true, total, channel6, directAny,
                    dmeshAny, allDirect.toString(), dmesh.toString(), "");
        } catch (SecurityException error) {
            publishWifiScanResult(requestId, replyTo, false, 0, 0, 0, 0, "", "",
                    "missing_wifi_scan_permission");
        }
    }

    private void publishWifiScanResult(String requestId, MsgConn replyTo, boolean succeeded,
                                       int total, int channel6, int direct, int dmesh,
                                       String allDirect, String dmeshEntries, String error) {
        String ok = succeeded ? "1" : "0";
        MsgMux.get(ctx).publish("wifi.scan", "ok", ok,
                "count", Integer.toString(total),
                "channel6_count", Integer.toString(channel6),
                "direct_count", Integer.toString(direct),
                "direct", allDirect,
                "dmesh_count", Integer.toString(dmesh),
                "dmesh", dmeshEntries,
                // Keep the old names during the control-plane migration.
                "direct_dmesh_count", Integer.toString(dmesh),
                "direct_dmesh", dmeshEntries,
                "error", error);
        if (requestId == null || requestId.isEmpty()) return;
        MsgFrame result = new MsgFrame("wifi.scan.result");
        result.id = requestId;
        result.fields.put("ok", ok);
        result.fields.put("count", Integer.toString(total));
        result.fields.put("channel6_count", Integer.toString(channel6));
        result.fields.put("direct_count", Integer.toString(direct));
        result.fields.put("direct", allDirect);
        result.fields.put("dmesh_count", Integer.toString(dmesh));
        result.fields.put("dmesh", dmeshEntries);
        if (error != null && !error.isEmpty()) result.fields.put("error", error);
        if (replyTo != null) replyTo.sendFrame(result);
    }

    public void send(String method, String... parms) {
        Message m = Message.obtain();
        m.what = 1;
        m.getData().putString(":uri", method);

        Bundle b = m.getData();
        for (int i = 0; i < parms.length; i += 2) {
            b.putString(parms[i], parms[i + 1]);
        }
        String[] args = method.split("\\.");
        handleMessage(args.length > 0 ? args[0] : "", args.length > 1 ? args[1] : "", m, null, args);
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
     * Broadcasts start with "wifi." or /net/
     */
    @Override
    public void handleMessage(String topic, String type, Message msg, MsgConn replyTo, String[] args) {

        switch (topic) {
            case "I":
                id4 = type.substring(0, 4);
                updateDeviceId();
                announce(true);
                return;
        }

        Bundle b = msg.getData();
        Log.d(TAG, "WIFI Command: " + Arrays.toString(args) + " " + b);

        switch (type) {
            case "transport":
                if (args.length >= 3 && "start".equals(args[2])) {
                    // Local control-plane entry point. NAN SD uses the same
                    // method through Nan.applyTransportStart after Rust has
                    // decoded the tagged CBOR record.
                    String mode = b.getString("mode", argumentValue(args, "mode", "nan"));
                    String ssid = b.getString("ssid", argumentValue(args, "ssid", ""));
                    String passphrase = b.getString("passphrase", argumentValue(args, "passphrase", ""));
                    String bssid = b.getString("bssid", argumentValue(args, "bssid", ""));
                    String ndp = b.getString("ndp", argumentValue(args, "ndp", "0"));
                    String ap = b.getString("ap", argumentValue(args, "ap", "0"));
                    String json = "{\"mode\":\"" + mode + "\",\"ssid_hex\":\""
                            + new String(Hex.encode(ssid.getBytes(StandardCharsets.UTF_8)))
                            + "\",\"passphrase_hex\":\""
                            + new String(Hex.encode(passphrase.getBytes(StandardCharsets.UTF_8)))
                            + "\",\"bssid_hex\":\"" + bssid.replace(":", "")
                            + "\",\"ndp\":\"" + ndp
                            + "\",\"ap\":\"" + ap + "\"}";
                    applyTransportStart(json, "local_control", "", b.getString(":rid", ""), replyTo);
                }
                break;
            // `wifi.sta.attach` is the platform half of a signed
            // transport.start/probe request. Rust supplies the policy and
            // records the result; Java only asks Android to attach to the
            // explicit SSID/BSSID. `wifi.sta.detach` releases only this
            // request, never NAN or an independently running AP.
            case "sta":
                if (args.length >= 3 && "attach".equals(args[2])) {
                    requestStaAttachment(b);
                } else if (args.length >= 3 && "detach".equals(args[2])) {
                    releaseStaAttachment();
                }
                break;

            // Actions and testing

            case "scan":
                // Wifi, BLE and NAN scan. No BT yet.
                scan(b.getString(":rid", ""), replyTo);
                break;


            // Rust reaches this Android-only Wi-Fi Aware adapter through the
            // native SSH/proxy bridge -> MsgMux. Keep platform calls here;
            // Rust owns the command meaning, event inventory, and CBOR wire.
            case "nan":
                Log.d(TAG, "NAN command " + args);
                if (nan != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && args.length >= 3) {
                    if ("start".equals(args[2])) {
                        nan.start();
                    } else if ("stop".equals(args[2])) {
                        nan.stop();
                    } else if ("sub".equals(args[2])) {
                        nan.setDiscoveryRole("sub-active");
                        nan.start();
                    } else if ("adv".equals(args[2])) {
                        nan.setDiscoveryRole("pub-solicited");
                        nan.start();
                    } else if ("both".equals(args[2])) {
                        nan.setDiscoveryRole("both");
                        nan.start();
                    } else if ("role".equals(args[2])) {
                        String role = args.length >= 4 ? args[3] : b.getString("role", "both");
                        nan.setDiscoveryRole(role);
                        nan.start();
                    } else if ("status".equals(args[2])) {
                        nan.emitStatus();
                    } else if ("sd".equals(args[2])) {
                        String cborHex = args.length >= 4 ? args[3]
                                : b.getString("cbor_hex", b.getString("cbor", ""));
                        if ("clear".equalsIgnoreCase(cborHex)) {
                            nan.clearServiceInfoCbor();
                            MsgMux.get(ctx).publish("net.NAN.ServiceInfoCleared");
                        } else {
                            byte[] cbor = decodeHex(cborHex);
                            if (nan.setServiceInfoCbor(cbor)) {
                                // Start is idempotent and ensures a publisher exists when
                                // this command arrives before NAN attachment completes.
                                nan.start();
                                MsgMux.get(ctx).publish("net.NAN.ServiceInfoActive",
                                        "bytes", Integer.toString(cbor.length));
                            } else {
                                MsgMux.get(ctx).publish("net.NAN.ServiceInfoError",
                                        "error", "cbor must be 1..255 bytes of hex");
                            }
                        }
                    } else if ("publish".equals(args[2])) {
                        String value = args.length >= 4 ? args[3]
                                : b.getString("enabled", "on");
                        boolean enabled = !"off".equalsIgnoreCase(value)
                                && !"0".equals(value) && !"false".equalsIgnoreCase(value);
                        nan.setActivePublishEnabled(enabled);
                        if (enabled) {
                            nan.start();
                        }
                    } else if ("active-sub".equals(args[2])) {
                        String serviceHex = args.length >= 4 ? args[3]
                                : b.getString("service_info_hex", "");
                        String followupHex = args.length >= 5 ? args[4]
                                : b.getString("followup_hex", "");
                        byte[] serviceInfo = decodeHex(serviceHex);
                        byte[] followup = decodeHex(followupHex);
                        if (nan.setActiveSubscribe(serviceInfo, followup)) {
                            nan.start();
                        } else {
                            MsgMux.get(ctx).publish("net.NAN.ActiveSubscribeError",
                                    "error", "service info must be 1..255 bytes and follow-up 1..231 bytes of hex");
                        }
                    } else if ("con".equals(args[2])) {
                        String peerId = args.length >= 4 ? args[3]
                                : b.getString("peer", b.getString("id"));
                        if (peerId != null) {
                            nan.conNan(peerId);
                        }
                    } else if ("ping".equals(args[2])) {
                        String message = args.length >= 4 ? args[3] : b.getString("text");
                        if (message != null && !message.isEmpty()) {
                            nan.sendAll(message);
                        } else {
                            nan.sendAll("PING");
                        }
                    } else if ("probe".equals(args[2])) {
                        String message = args.length >= 4 ? args[3] : b.getString("text", "NANPROBE");
                        int count = 16;
                        long intervalMs = 512L;
                        try {
                            count = Integer.parseInt(b.getString("count", "16"));
                            intervalMs = Long.parseLong(b.getString("interval_ms", "512"));
                        } catch (NumberFormatException ignored) {
                            // Use the bounded probe defaults for malformed shell input.
                        }
                        nan.probeFollowupCadence(message, count, intervalMs);
                    } else if ("arm".equals(args[2])) {
                        String peerId = args.length >= 4 ? args[3]
                                : b.getString("peer", b.getString("id"));
                        String message = args.length >= 5 ? args[4] : b.getString("text");
                        if (!nan.armFollowupOnDiscovery(peerId, message)) {
                            MsgMux.get(ctx).publish("net.NAN.FollowupArmError",
                                    "peer", peerId == null ? "" : peerId);
                        }
                    } else if ("msg".equals(args[2])) {
                        // Shell/JSON callers retain named fields, while the in-app command
                        // path uses positional argv. Support both forms at this boundary.
                        String peerId = args.length >= 4 ? args[3]
                                : b.getString("peer", b.getString("id"));
                        String message = args.length >= 5 ? args[4] : b.getString("text");
                        if (peerId != null && message != null) {
                            nan.send(peerId, message);
                        }
                    }
                }
                break;
            case "ble":
                if (ble != null) {
                    ble.handleMessage(topic, type, msg, replyTo, args);
                }
                break;

            // Controls BLE, NAN advertising. Param: id4 - the 4-byte short for of identifier.
            case "adv":
        if (null != b.getString("id4", null)) {
                    id4 = b.getString("id4");
                    updateDeviceId();
                }

                String advOn = b.getString("on", "-1");
                if ("1".equals(advOn)) {
                    announce(true);
                } else if ("0".equals(advOn)) {
                    announce(false);
                }

                break;

        }
    }

    /** Publish the current scan, BLE, and NAN observations. */
    public void sendWifiDiscoveryStatus(String event, String id) {
        Map<String, Device> devicesBySSID = new HashMap<>();
        Bundle scanStatusMsg = new Bundle();
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

        ArrayList<Bundle> scanList = new ArrayList<>();
        for (Device d : devicesBySSID.values()) {
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

        ArrayList<String> extra = new ArrayList<>();
        extra.add("visible");
        extra.add(lscanResults == null ? "0" : "" + lscanResults.size());
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

        WifiInfo connectionInfo = wifiManager == null ? null : wifiManager.getConnectionInfo();
        String wifiSsid = connectionInfo == null ? "" : connectionInfo.getSSID();
        if (wifiSsid != null && !wifiSsid.isEmpty()) {
            extra.add(Device.WIFISSID);
            extra.add(wifiSsid);
            extra.add(Device.FREQ);
            extra.add("" + connectionInfo.getFrequency());
            extra.add(Device.LEVEL);
            extra.add("" + connectionInfo.getRssi());
        }

        MsgMux.get(ctx).publish("net.status", scanStatusMsg, extra.toArray(new String[]{}));
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

        byte[] payload = new byte[0];
        adv = new String(MeshNode.buildBleServiceData("wake_request", deviceIdBytes(), payload, 0, 0),
                StandardCharsets.ISO_8859_1);
        ble.advertise(MeshNode.buildBleServiceData("wake_request", deviceIdBytes(), payload, 0, 0));
    }

    public byte[] deviceIdBytes() {
        updateDeviceId();
        return Arrays.copyOf(deviceId, deviceId.length);
    }

    private void updateDeviceId() {
        // Wi-Fi Aware peers are scoped by the framework's NAN interface MAC.
        // Do not use the old short-ID placeholder: it produced the shared
        // ASCII identity "000000", causing every
        // discovered DMesh NAN peer to collide and follow-ups to be routed to
        // stale zero-ID entries.
        if (nan != null && nan.nanMac != null && nan.nanMac.length == deviceId.length) {
            System.arraycopy(nan.nanMac, 0, deviceId, 0, deviceId.length);
            return;
        }
        String src = (id4 == null ? "" : id4) + "000000";
        byte[] raw = src.getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < deviceId.length; i++) {
            deviceId[i] = i < raw.length ? raw[i] : (byte) '0';
        }
    }


    // Will be needed for privacy - change name when wifi mac changes
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();

        intent.getStringExtra("");
        Log.d(TAG, "/ERR/UnknownBroadcast " + intent.getAction() + " " + UiUtil.toString(intent.getExtras()));

    }


    private static byte[] decodeHex(String value) {
        if (value == null) {
            return new byte[0];
        }
        String hex = value.startsWith("hex:") ? value.substring(4) : value;
        if ((hex.length() & 1) != 0) {
            return new byte[0];
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                return new byte[0];
            }
            result[i] = (byte) ((high << 4) | low);
        }
        return result;
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
            if (wifi.wifiManager != null) {
                WifiInfo connectionInfo = wifi.wifiManager.getConnectionInfo();
                ssid = connectionInfo == null ? "" : connectionInfo.getSSID();
            }

            MsgMux.get(wifi.ctx).publish("wifi.net." + lp.getInterfaceName(),
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
            WifiInfo connectionInfo = wifi.wifiManager == null ? null : wifi.wifiManager.getConnectionInfo();
            String ssid = connectionInfo == null ? "" : connectionInfo.getSSID();

            MsgMux.get(wifi.ctx).publish("wifi.net." + lp.getInterfaceName(),
                    "addr", lp.getLinkAddresses().toString(),
                    "cap", cap == null ? "" : cap.toString(),
                    "s", ssid == null ? "" : ssid,
                    "ninfo", ninfo == null ? "" : ninfo.toString());
        }

        @Override
        public void onLosing(Network network, int maxMsToLive) {
            super.onLosing(network, maxMsToLive);
            MsgMux.get(wifi.ctx).publish("wifi.CON.LOSING." + network.toString());
        }

        @Override
        public void onLost(Network network) {
            super.onLost(network);
            MsgMux.get(wifi.ctx).publish("wifi.CON.LOST." + network.toString());
        }

        @Override
        public void onUnavailable() {
            super.onUnavailable();
            MsgMux.get(wifi.ctx).publish("wifi.CON.UNAVAIL");
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
