package com.github.costinm.dmeshnative;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.Build;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;

import com.github.costinm.dmesh.wifi.Ble;
import com.github.costinm.dmesh.wifi.Announce;
import com.github.costinm.dmesh.wifi.Discover;
import com.github.costinm.dmesh.wifi.TransportEventSink;
import com.github.costinm.dmesh.wifi.WifiController;
import com.github.costinm.dmesh.wifi.WifiDiscovery;
import com.github.costinm.dmesh.wifi.WifiEventSink;
import com.github.costinm.dmesh.wifi.TransportStart;

import org.json.JSONObject;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;

/** The sole app-dmesh adapter that binds Rust messages to Android transports. */
public final class AndroidTransportBridge {
    // Shared five-minute passive-presence cadence; firmware Main and host
    // NAN/UDP publishers use the same interval.
    private static final long NAN_PRESENCE_REFRESH_MS = 5 * 60 * 1000L;
    private static AndroidTransportBridge instance;
    private final WifiController wifi;
    private final WifiManager wifiManager;
    private final Ble ble;
    private final Handler presenceHandler = new Handler(Looper.getMainLooper());
    private byte[] nanDeviceId;
    private long nanStartedElapsedMs;
    // Framework-observed endpoints supplied by DMService's shared local
    // network snapshot. They are advisory route data, never identity.
    private volatile String staLinkLocalV6 = "";
    private volatile String apLinkLocalV6 = "";
    // Replaced only when the DMesh NAN identity/session is configured again.
    // Wifi Aware may retransmit the Subscribe many times in that session.
    private long nanDiscoveryRequestId;
    private final Runnable refreshNanPresence = new Runnable() {
        @Override public void run() {
            publishNanPresence(false);
            presenceHandler.postDelayed(this, NAN_PRESENCE_REFRESH_MS);
        }
    };

    public static synchronized AndroidTransportBridge get(Context context) {
        if (instance == null) instance = new AndroidTransportBridge(context.getApplicationContext());
        return instance;
    }
    private AndroidTransportBridge(Context context) {
        wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        wifi = WifiController.create(context, new WifiEventSink() {
            @Override public void onEvent(String event) {
                MeshNode.recordNanEvent("framework", "", event.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }

            @Override public void onDiscovered(WifiDiscovery discovery) {
                MeshNode.observeNanServiceInfo(discovery.peer, discovery.payload);
            }

            @Override public void onReceived(String transport, String peer, byte[] payload,
                                             int rssiDbm) {
                // A directed NAN response is a normal received packet. Rust
                // retains the packet fact and, when it is a DMesh follow-up,
                // adds it to the same bounded discovery inventory used by
                // Linux and ESP adapters.
                if ("nan".equals(transport)) {
                    String result = MeshNode.observeNanPacket(peer, payload, rssiDbm);
                    // Keep the framework callback and Rust admission distinct:
                    // delivery proves the Android session matched, while the
                    // Rust result proves the bounded DMesh envelope parsed.
                    // This diagnostic contains no payload bytes.
                    MeshNode.recordNanEvent("aware.message_ingress", peer,
                            result.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
        });
        ble = new Ble(context, new Handler(Looper.getMainLooper()), new TransportEventSink() {
            @Override public void onTransportEvent(String transport, String event, byte[] payload) {
                MeshNode.radioMessage("radio.transport.event",
                        "transport=" + transport + " event=" + event, payload, -1);
            }

        });
    }
    public void startBaseline() { wifi.startNanAfterP2p(); }

    /**
     * Publish the same stable DMesh presence descriptor over Wi-Fi Aware as
     * Rust emits over local UDP. The public key remains the identity source;
     * Java only projects it to the Android framework's opaque byte API.
     */
    public void configureNanIdentity(String publicKey) {
        if (publicKey == null || publicKey.isEmpty()) return;
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(publicKey.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            nanDeviceId = Arrays.copyOf(digest, 16);
            nanStartedElapsedMs = android.os.SystemClock.elapsedRealtime();
            nanDiscoveryRequestId = nanStartedElapsedMs & 0xffff_ffffL;
            presenceHandler.removeCallbacks(refreshNanPresence);
            // Keep the boot descriptor published long enough for a nearby raw
            // NAN observer to receive it before replacing it with periodic
            // discovery descriptors.
            publishNanPresence(true);
            presenceHandler.postDelayed(refreshNanPresence, NAN_PRESENCE_REFRESH_MS);
            // A NAN Subscribe carries the same tagged `transport.discover`
            // record as Linux and ESP.  Keep this ID stable for the whole
            // Subscribe session: Android repeats the SDF, and a sleepy peer
            // must answer once per discovery ping, not once per repeated RF
            // packet.
            wifi.setDiscover(new Discover(nanDiscoverRecord(), Collections.singletonList("active")),
                    ignored -> { });
        } catch (Exception ignored) {
            // The framework lifecycle retains its event history; do not crash
            // the foreground service merely because a provider is unavailable.
        }
    }
    private void publishNanPresence(boolean boot) {
        byte[] deviceId = nanDeviceId;
        if (deviceId == null) return;
        long uptimeSecs = Math.max(0, (android.os.SystemClock.elapsedRealtime()
                - nanStartedElapsedMs) / 1000);
        String staSsid = currentStaSsid();
        byte[] announce = MeshNode.buildNanAnnounce(boot ? "boot" : "discovery", deviceId,
                uptimeSecs, staSsid.isEmpty() ? 0 : 1, 0, shortDeviceName(), staSsid,
                staLinkLocalV6, apLinkLocalV6);
        if (announce.length == 0) return;
        wifi.setAnnounce(new Announce(announce, Collections.singletonList("active")),
                ignored -> { });
    }

    /** Canonical CBOR: {1: control, 2: transport.discover, 3: id,
     * 5: {nan: true}}.  Java projects the shared fixed wire form; Rust still
     * owns its meaning and all response validation. */
    private byte[] nanDiscoverRecord() {
        long id = nanDiscoveryRequestId;
        return new byte[] {
                (byte) 0xa4, 0x01, 0x01, 0x02, 0x06, 0x03, 0x1a,
                (byte) (id >>> 24), (byte) (id >>> 16), (byte) (id >>> 8), (byte) id,
                0x05, (byte) 0xa1, 0x16, (byte) 0xf5
        };
    }
    /** Network callbacks use this to publish a changed STA mode/SSID promptly. */
    public void refreshNanPresence() { publishNanPresence(false); }

    /** Update shared observed IPv6 endpoints before publishing presence. */
    public void updateLinkLocalAddresses(String sta, String ap) {
        staLinkLocalV6 = cleanLinkLocal(sta);
        apLinkLocalV6 = cleanLinkLocal(ap);
        refreshNanPresence();
    }
    private static String shortDeviceName() {
        String model = Build.MODEL == null ? "android" : Build.MODEL;
        StringBuilder out = new StringBuilder(8);
        for (int i = 0; i < model.length() && out.length() < 8; i++) {
            char value = model.charAt(i);
            if (value >= 0x20 && value <= 0x7e) out.append(value);
        }
        return out.length() == 0 ? "android" : out.toString();
    }
    public void scanBle() { ble.scan(); }
    /**
     * Current station SSID as a bounded transport observation.  Prefer the
     * DMesh-owned network request, then report an already-associated system
     * Wi-Fi network when Android grants the framework visibility.  This is
     * routing metadata only, never device identity or authorization.
     */
    public String currentStaSsid() {
        String managed = wifi.currentStaSsid();
        if (managed != null && !managed.isEmpty()) return managed;
        try {
            WifiInfo info = wifiManager == null ? null : wifiManager.getConnectionInfo();
            return cleanSsid(info == null ? null : info.getSSID());
        } catch (SecurityException ignored) {
            return "";
        }
    }
    public boolean apActive() { return wifi.apActive(); }

    private static String cleanSsid(String value) {
        if (value == null || value.isEmpty() || "<unknown ssid>".equals(value)) return "";
        if (value.length() >= 2 && value.charAt(0) == '"' && value.charAt(value.length() - 1) == '"') {
            value = value.substring(1, value.length() - 1);
        }
        return value.length() <= 32 ? value : value.substring(0, 32);
    }
    private static String cleanLinkLocal(String value) {
        if (value == null || value.isEmpty()) return "";
        int zone = value.indexOf('%');
        value = zone < 0 ? value : value.substring(0, zone);
        return value.startsWith("fe80:") && value.length() <= 45 ? value : "";
    }
    public String snapshot() { return wifi.snapshot() + " " + ble.snapshot(); }
    /** Execute only the operation selected by Rust's validated projection. */
    public String applyRustProjection(String projection) {
        try {
            String operation = new JSONObject(projection).optString("operation", "");
            if ("nan".equals(operation)) return "nan=" + wifi.startNanAfterP2pAndAwait();
            if ("p2p_go".equals(operation)) return "p2p_go=" + wifi.startP2pGroupWithServiceAndAwait();
            if ("sta".equals(operation)) return startSta(projection);
            if ("stop".equals(operation)) { wifi.stopP2p(() -> { }); return "stop=accepted"; }
            return "rejected=" + operation;
        } catch (Exception e) { return "invalid_projection=" + e; }
    }
    private String startSta(String projection) throws Exception {
        JSONObject request = new JSONObject(projection).optJSONObject("request");
        JSONObject params = request == null ? null : request.optJSONObject("params");
        String ssid = params == null ? "" : params.optString("ssid", "");
        String passphrase = params == null ? "" : params.optString("passphrase", "");
        byte[] bssid = hex(params == null ? "" : params.optString("bssid_hex", ""));
        int channel = params == null ? 0 : params.optInt("channel", 0);
        CountDownLatch done = new CountDownLatch(1);
        String[] result = { "pending" };
        wifi.start(new TransportStart("rust-shell-sta", 1, TransportStart.Kind.STA,
                ssid, passphrase, bssid, channel, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1),
                value -> { result[0] = value.outcome + " state=" + value.state + " error=" + value.error; done.countDown(); });
        return done.await(40, TimeUnit.SECONDS) ? "sta=" + result[0] : "sta=timeout";
    }
    private static byte[] hex(String value) {
        if (value == null || value.isEmpty()) return new byte[0];
        if ((value.length() & 1) != 0) throw new IllegalArgumentException("bssid_hex");
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    public void close() { presenceHandler.removeCallbacks(refreshNanPresence); ble.close(); wifi.close(); }
    public static void handlePendingIntent(Context context, Intent intent) { Ble.handlePendingIntentScan(context, intent); }
}
