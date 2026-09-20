package com.github.costinm.dmeshnative;

import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbDevice;
import android.os.Handler;
import android.os.Looper;
import android.os.Build;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;

import com.github.costinm.dmesh.usb.UsbDmesh;
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
public final class AndroidTransportBridge implements Ble.BearerBridge {
    // Shared five-minute passive-presence cadence; firmware Main and host
    // NAN/UDP publishers use the same interval.
    private static final long NAN_PRESENCE_REFRESH_MS = 5 * 60 * 1000L;
    // A DW8 peer can be unavailable for 4.194 s, and the ESP repeats a
    // targeted wake across more than one DW. Keep Android's active Subscribe
    // alive for four complete DW8 periods plus framework callback margin.
    // A framework PeerHandle may arrive after its first matching SDF; a
    // two-period transaction can restore the baseline before that callback
    // has a chance to send the Follow-up. This is bounded explicit wake work,
    // never the passive discovery cadence.
    private static final long NAN_WAKE_TRANSACTION_MS = 20_000L;
    private static AndroidTransportBridge instance;
    private final WifiController wifi;
    private final WifiManager wifiManager;
    private final Ble ble;
    private final UsbDmesh usb;
    private MeshNode meshNode;
    private volatile boolean usbBearerConnected;
    private volatile boolean usbBearerOpen;
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
    // One active Subscribe is a bounded transaction, not a permanent radio
    // personality.  Retain the passive/baseline record so discovery or a
    // targeted sleepy-device activation restores it after the DW interval.
    private byte[] baselineNanDiscoverRecord;
    private final Runnable restoreNanDiscovery = new Runnable() {
        @Override public void run() {
            wifi.setDirectedNanMessage(null);
            byte[] baseline = baselineNanDiscoverRecord;
            if (baseline == null) return;
            wifi.setDiscover(new Discover(baseline, Collections.singletonList("active")),
                    ignored -> { });
            MeshNode.recordNanEvent("aware.active_discovery_restored", "", new byte[0]);
        }
    };
    private final Runnable refreshNanPresence = new Runnable() {
        @Override public void run() {
            publishNanPresence();
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
                // Keep the framework lifecycle name as the Rust event name.
                // The shared telemetry handler derives attach/publish/subscribe
                // state from this bounded chronology; collapsing every callback
                // to `framework` made a live Aware session look inactive.
                MeshNode.recordNanEvent(event, "", event.getBytes(java.nio.charset.StandardCharsets.UTF_8));
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
                // The Rust history (radio.transport.event) owns radio
                // debugging; logcat stays reserved for framework-level
                // detail per AGENTS.md.
                MeshNode.radioMessage("radio.transport.event",
                        "transport=" + transport + " event=" + event, payload, -1);
            }
        });
        ble.setBearerBridge(this);
        usb = new UsbDmesh(context, new UsbDmesh.Bridge() {
            @Override public void onUsbOpen(String info) {
                usbBearerConnected = true;
                openUsbBearer();
                MeshNode.radioMessage("radio.transport.event",
                        "transport=usb event=opened", info.getBytes(java.nio.charset.StandardCharsets.UTF_8), -1);
            }

            @Override public void onUsbClose(String info) {
                usbBearerConnected = false;
                closeUsbBearer();
                MeshNode.radioMessage("radio.transport.event",
                        "transport=usb event=closed", info.getBytes(java.nio.charset.StandardCharsets.UTF_8), -1);
            }

            @Override public void onUsbChunk(byte[] data, int length) {
                if (meshNode != null) meshNode.bearerChunk("usb", data, length);
            }
        });
        usb.start();
    }

    public void setMeshNode(MeshNode node) {
        this.meshNode = node;
        openUsbBearer();
    }
    private void openUsbBearer() {
        if (usbBearerConnected && meshNode != null && !usbBearerOpen) {
            usbBearerOpen = meshNode.bearerOpen("usb", "");
        }
    }
    private void closeUsbBearer() {
        if (usbBearerOpen) {
            if (meshNode != null) meshNode.bearerClose("usb");
            usbBearerOpen = false;
        }
    }
    @Override public void onBearerConnected(String bearer) {
        if ("ble".equals(bearer) && meshNode != null) meshNode.bearerOpen(bearer, "");
    }
    @Override public void onBearerDisconnected(String bearer) {
        if ("ble".equals(bearer) && meshNode != null) meshNode.bearerClose(bearer);
    }
    @Override public void onBearerChunk(String bearer, byte[] data, int length) {
        if ("ble".equals(bearer) && meshNode != null) meshNode.bearerChunk(bearer, data, length);
    }
    @Override public boolean sendBearerFrame(String bearer, byte[] frame, int length) {
        if ("ble".equals(bearer)) return ble.writeFrame(frame, length);
        if ("usb".equals(bearer)) return usb.writeFrame(frame, length);
        return false;
    }
    public void onUsbPermission(UsbDevice device, boolean granted) { usb.onPermissionGranted(device, granted); }
    public String usbCommand(String method, String params) {
        try {
            JSONObject request = new JSONObject(params == null || params.isEmpty() ? "{}" : params);
            if ("usb.status".equals(method)) {
                JSONObject status = new JSONObject(usb.status());
                status.put("bearer", meshNode == null ? "" : meshNode.bearerStatus("usb"));
                return status.toString();
            }
            if ("usb.devices".equals(method)) return usb.devices();
            if ("usb.open".equals(method)) {
                boolean accepted;
                if (request.has("vendor_id") && request.has("product_id")) {
                    accepted = usb.open(request.optInt("vendor_id", -1), request.optInt("product_id", -1));
                } else {
                    accepted = usb.openAuto();
                }
                if (accepted) return "{\"status\":\"accepted\",\"operation\":\"usb.open\"}";
                try {
                    JSONObject status = new JSONObject(usb.status());
                    // A pending system permission dialog is asynchronous
                    // progress, not failure; callers must not treat it as a
                    // refusal and retry while the dialog is still up.
                    boolean pending = "permission_pending".equals(status.optString("state", ""));
                    JSONObject result = new JSONObject();
                    result.put("status", pending ? "pending" : "rejected");
                    result.put("operation", "usb.open");
                    if (!pending) {
                        result.put("error", status.optString("error",
                                status.optString("state", "usb_open_failed")));
                    }
                    return result.toString();
                } catch (Exception e) {
                    return "{\"status\":\"rejected\",\"operation\":\"usb.open\",\"error\":\"usb_open_failed\"}";
                }
            }
            if ("usb.close".equals(method)) {
                usb.close();
                return "{\"status\":\"accepted\",\"operation\":\"usb.close\"}";
            }
            return "{\"status\":\"unsupported\",\"operation\":\"" + method + "\"}";
        } catch (Exception e) {
            return "{\"status\":\"invalid\",\"error\":\"" + e.getClass().getSimpleName() + "\"}";
        }
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
            publishNanPresence();
            presenceHandler.postDelayed(refreshNanPresence, NAN_PRESENCE_REFRESH_MS);
            // A NAN Subscribe carries the same directed `announce.discovery`
            // record as Linux and ESP.  Keep this ID stable for the whole
            // Subscribe session: Android repeats the SDF, and a sleepy peer
            // must answer once per discovery ping, not once per repeated RF
            // packet.
            baselineNanDiscoverRecord = nanDiscoverRecord();
            wifi.setDiscover(new Discover(baselineNanDiscoverRecord,
                    Collections.singletonList("active")), ignored -> { });
        } catch (Exception ignored) {
            // The framework lifecycle retains its event history; do not crash
            // the foreground service merely because a provider is unavailable.
        }
    }
    private void publishNanPresence() {
        byte[] deviceId = nanDeviceId;
        if (deviceId == null) return;
        long uptimeSecs = Math.max(0, (android.os.SystemClock.elapsedRealtime()
                - nanStartedElapsedMs) / 1000);
        String staSsid = currentStaSsid();
        byte[] announce = MeshNode.buildNanAnnounce(deviceId,
                uptimeSecs, staSsid.isEmpty() ? 0 : 1, 0, shortDeviceName(), staSsid,
                staLinkLocalV6, apLinkLocalV6);
        if (announce.length == 0) return;
        wifi.setAnnounce(new Announce(announce, Collections.singletonList("active")),
                ignored -> { });
    }

    /** Canonical CBOR: {1: announce, 2: discovery, 3: id, 5: {}}.
     * Java projects the shared fixed wire form; Rust still
     * owns its meaning and all response validation. */
    private byte[] nanDiscoverRecord() {
        long id = nanDiscoveryRequestId;
        return new byte[] {
                (byte) 0xa4, 0x01, 0x06, 0x02, 0x02, 0x03, 0x1a,
                (byte) (id >>> 24), (byte) (id >>> 16), (byte) (id >>> 8), (byte) id,
                0x05, (byte) 0xa0
        };
    }

    /**
     * Emit one bounded active NAN discovery transaction.  The payload is the
     * common directed `announce.discovery` CBOR record; Android only supplies
     * the Wi-Fi Aware scheduling API.
     */
    public void requestActiveNanDiscovery() {
        byte[] baseline = baselineNanDiscoverRecord;
        if (baseline == null) {
            MeshNode.recordNanEvent("aware.active_discovery_rejected", "", new byte[0]);
            return;
        }
        nanDiscoveryRequestId = (nanDiscoveryRequestId + 1) & 0xffff_ffffL;
        byte[] request = nanDiscoverRecord();
        requestTemporaryActiveSubscribe(request, "aware.active_discovery_requested");
    }

    /**
     * Carry a pre-validated common direct control record in one temporary
     * active NAN Subscribe.  The target ESP verifies `wake_target`; Java
     * neither decodes nor rewrites the control profile.
     */
    public void requestNanActivation(byte[] wakeTarget) {
        byte[] source = nanDeviceId;
        if (wakeTarget == null || wakeTarget.length != 6 || source == null || source.length < 6
                || baselineNanDiscoverRecord == null) {
            MeshNode.recordNanEvent("aware.nan_activation_rejected", "", new byte[0]);
            return;
        }
        byte[] transportSet = MeshNode.buildNanWakeup(Arrays.copyOf(source, 6), wakeTarget);
        if (transportSet.length == 0) {
            MeshNode.recordNanEvent("aware.nan_activation_rejected", "", new byte[0]);
            return;
        }
        // A DW8 peer cannot supply Android with a PeerHandle before it is
        // awake. Keep an active discovery record in SDEA, then send the
        // common target-checked record as a Follow-up on its PeerHandle. Some
        // Android Aware implementations do not expose arbitrary SDEA bytes
        // to raw-NAN peers, while Follow-up delivery is portable.
        nanDiscoveryRequestId = (nanDiscoveryRequestId + 1) & 0xffff_ffffL;
        requestTemporaryActiveSubscribe(nanDiscoverRecord(), transportSet,
                "aware.nan_activation_requested");
    }

    private void requestTemporaryActiveSubscribe(byte[] payload, String event) {
        requestTemporaryActiveSubscribe(payload, null, event);
    }

    private void requestTemporaryActiveSubscribe(byte[] payload, byte[] directedMessage, String event) {
        presenceHandler.removeCallbacks(restoreNanDiscovery);
        wifi.setDirectedNanMessage(directedMessage);
        wifi.setDiscover(new Discover(payload, Collections.singletonList("active")), ignored -> { });
        MeshNode.recordNanEvent(event, "", payload);
        // Keep a targeted wake across two DW8 periods. It remains bounded and
        // is restored to the ordinary discovery Subscribe afterwards.
        presenceHandler.postDelayed(restoreNanDiscovery, NAN_WAKE_TRANSACTION_MS);
    }
    /** Network callbacks use this to publish a changed STA mode/SSID promptly. */
    public void refreshNanPresence() { publishNanPresence(); }

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
    public String bleCommand(String method, String params) {
        try {
            JSONObject request = new JSONObject(params == null || params.isEmpty() ? "{}" : params);
            if ("ble.status".equals(method)) {
                JSONObject status = new JSONObject();
                status.put("snapshot", ble.snapshot());
                status.put("bearer", meshNode == null ? "" : meshNode.bearerStatus("ble"));
                return status.toString();
            }
            if ("ble.scan".equals(method)) {
                ble.scan();
                return "{\"status\":\"accepted\",\"operation\":\"ble.scan\"}";
            }
            if ("ble.scan_stop".equals(method)) {
                ble.scanStop();
                return "{\"status\":\"accepted\",\"operation\":\"ble.scan_stop\"}";
            }
            if ("ble.connect".equals(method)) {
                boolean started = ble.connect(
                        request.optString("address", ""), request.optInt("psm", 128));
                return started
                        ? "{\"status\":\"accepted\",\"operation\":\"ble.connect\"}"
                        : "{\"status\":\"rejected\",\"operation\":\"ble.connect\"}";
            }
            if ("ble.disconnect".equals(method)) {
                ble.disconnect();
                return "{\"status\":\"accepted\",\"operation\":\"ble.disconnect\"}";
            }
            return "{\"status\":\"unsupported\",\"operation\":\"" + method + "\"}";
        } catch (Exception e) {
            return "{\"status\":\"invalid\",\"error\":\"" + e.getClass().getSimpleName() + "\"}";
        }
    }
    public String wifiCommand(String method, String params) {
        try {
            if ("wifi.status".equals(method)) {
                JSONObject status = new JSONObject();
                status.put("enabled", wifiManager == null ? false : wifiManager.isWifiEnabled());
                status.put("ssid", currentStaSsid());
                status.put("ap_active", apActive());
                status.put("snapshot", wifi.snapshot());
                return status.toString();
            }
            if ("wifi.scan".equals(method)) {
                if (wifiManager == null || !wifiManager.isWifiEnabled()) {
                    return "{\"status\":\"rejected\",\"operation\":\"wifi.scan\",\"reason\":\"wifi_unavailable\"}";
                }
                try {
                    wifiManager.startScan();
                    return "{\"status\":\"accepted\",\"operation\":\"wifi.scan\"}";
                } catch (Exception e) {
                    return "{\"status\":\"rejected\",\"operation\":\"wifi.scan\",\"reason\":\""
                            + e.getClass().getSimpleName() + "\"}";
                }
            }
            return "{\"status\":\"unsupported\",\"operation\":\"" + method + "\"}";
        } catch (Exception e) {
            return "{\"status\":\"invalid\",\"error\":\"" + e.getClass().getSimpleName() + "\"}";
        }
    }
    public String transportCommand(String method, String params) {
        try {
            JSONObject request = new JSONObject(params == null || params.isEmpty() ? "{}" : params);
            if ("transport.status".equals(method)) {
                JSONObject status = new JSONObject();
                status.put("snapshot", snapshot());
                status.put("sta_ssid", currentStaSsid());
                status.put("ap_active", apActive());
                return status.toString();
            }
            if ("transport.apply_projection".equals(method)) {
                return applyRustProjection(request.optString("projection", ""));
            }
            if ("transport.start".equals(method)) {
                return requestNanActivation(request);
            }
            return "{\"status\":\"unsupported\",\"operation\":\"" + method + "\"}";
        } catch (Exception e) {
            return "{\"status\":\"invalid\",\"error\":\"" + e.getClass().getSimpleName() + "\"}";
        }
    }
    private String requestNanActivation(JSONObject request) {
        byte[] source = nanDeviceId;
        byte[] target;
        try {
            target = macBytes(request.optString("target_mac", ""));
        } catch (Exception e) {
            MeshNode.recordNanEvent("aware.nan_activation_rejected", "", new byte[0]);
            return "{\"status\":\"rejected\",\"operation\":\"transport.start\",\"reason\":\"invalid_target_mac\"}";
        }
        if (source == null || source.length < 6 || target.length != 6
                || baselineNanDiscoverRecord == null) {
            MeshNode.recordNanEvent("aware.nan_activation_rejected", "", new byte[0]);
            return "{\"status\":\"rejected\",\"operation\":\"transport.start\",\"reason\":\"nan_unready\"}";
        }
        byte[] activation = MeshNode.buildNanActivation(
                Arrays.copyOf(source, 6),
                target,
                nanDiscoveryRequestId,
                request.optInt("kind", 6),
                request.optInt("ap", 1),
                request.optInt("now", 1),
                request.optInt("ble", 0),
                request.optInt("nan_dw_interval", 1));
        if (activation.length == 0) {
            MeshNode.recordNanEvent("aware.nan_activation_rejected", "", new byte[0]);
            return "{\"status\":\"rejected\",\"operation\":\"transport.start\",\"reason\":\"build_failed\"}";
        }
        nanDiscoveryRequestId = (nanDiscoveryRequestId + 1) & 0xffff_ffffL;
        requestTemporaryActiveSubscribe(nanDiscoverRecord(), activation,
                "aware.nan_activation_requested");
        // Build with JSONObject: request.optString is caller-controlled and
        // string concatenation would break the response on a quote inside it.
        JSONObject accepted = new JSONObject();
        try {
            accepted.put("status", "accepted");
            accepted.put("operation", "transport.start");
            accepted.put("target_mac", request.optString("target_mac", ""));
        } catch (Exception ignored) { }
        return accepted.toString();
    }
    private static byte[] macBytes(String value) {
        StringBuilder clean = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                clean.append(c);
            }
        }
        return hex(clean.toString());
    }
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
            if ("stop".equals(operation)) {
                wifi.stopNan();
                wifi.stopP2p(() -> { });
                return "stop=accepted";
            }
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
    public void close() {
        presenceHandler.removeCallbacks(refreshNanPresence);
        presenceHandler.removeCallbacks(restoreNanDiscovery);
        ble.close();
        usb.stop();
        wifi.close();
    }
    public static void handlePendingIntent(Context context, Intent intent) { Ble.handlePendingIntentScan(context, intent); }
}
