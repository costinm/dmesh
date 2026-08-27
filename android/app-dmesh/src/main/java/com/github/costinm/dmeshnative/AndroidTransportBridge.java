package com.github.costinm.dmeshnative;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;

import com.github.costinm.dmesh.wifi.Ble;
import com.github.costinm.dmesh.wifi.TransportEventSink;
import com.github.costinm.dmesh.wifi.WifiController;
import com.github.costinm.dmesh.wifi.WifiDiscovery;
import com.github.costinm.dmesh.wifi.WifiEventSink;
import com.github.costinm.dmesh.wifi.TransportStart;

import org.json.JSONObject;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** The sole app-dmesh adapter that binds Rust messages to Android transports. */
public final class AndroidTransportBridge {
    private static AndroidTransportBridge instance;
    private final WifiController wifi;
    private final Ble ble;

    public static synchronized AndroidTransportBridge get(Context context) {
        if (instance == null) instance = new AndroidTransportBridge(context.getApplicationContext());
        return instance;
    }
    private AndroidTransportBridge(Context context) {
        wifi = WifiController.create(context, new WifiEventSink() {
            @Override public void onEvent(String event) {
                MeshNode.recordNanEvent("framework", "", event.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }

            @Override public void onDiscovered(WifiDiscovery discovery) {
                MeshNode.observeNanServiceInfo(discovery.peer, discovery.payload);
            }
        });
        ble = new Ble(context, new Handler(Looper.getMainLooper()), new TransportEventSink() {
            @Override public void onTransportEvent(String transport, String event, byte[] payload) {
                MeshNode.radioMessage("radio.transport.event",
                        "transport=" + transport + " event=" + event, payload, -1);
            }

            @Override public void onBleDiscovery(String address, int rssi, byte[] serviceData) {
                MeshNode.injectBleFrame(serviceData, rssi, address);
            }
        });
    }
    public void startBaseline() { wifi.startNanAfterP2p(); }
    public void scanBle() { ble.scan(); }
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
    public void close() { ble.close(); wifi.close(); }
    public static void handlePendingIntent(Context context, Intent intent) { Ble.handlePendingIntentScan(context, intent); }
}
