package com.github.costinm.dmesh.lm;

import android.Manifest;
import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.Window;
import android.widget.TextView;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.DMeshCompanionPrefs;
import com.github.costinm.dmesh.android.util.UiUtil;
import com.github.costinm.dmesh.lm3.Device;
import com.github.costinm.dmesh.lm3.P2P;

import java.net.InterfaceAddress;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Lightweight platform-only status shell for app-dmesh.
 *
 * The command UI lives in the ssh-mesh admin web surface. This Activity only starts
 * the foreground service, handles Android permission/VPN UI flows, shows concise
 * local status, and opens the isolated WebActivity.
 */
public class MeshActivityLight extends Activity implements MessageHandler {
    private static final String TAG = "Mesh";
    public static final String ACTION_START_VPN = "com.github.costinm.dmesh.START_VPN";
    public static final String ACTION_REQUEST_PERMISSIONS =
            "com.github.costinm.dmesh.REQUEST_PERMISSIONS";
    public static final String EXTRA_VPN_ADDRESS = "address6";
    public static final String EXTRA_PERMISSIONS = "permissions";
    private static final String ADMIN_URL = "http://127.0.0.1:18480/_m/adm/";
    private static final int MENU_OPEN_WEB = 1;
    private static final int MENU_SHOW_STATUS = 2;
    private static final int MENU_SHOW_NOTIFICATIONS = 3;
    private static final int MENU_PAIR_COMPANION = 4;
    private static final int MENU_CLEAR_COMPANION = 5;
    private static final int MENU_COMPANION_ACTIVE = 6;
    private static final int MENU_COMPANION_SLEEP = 7;
    private static final int MENU_COMPANION_LORA_LISTEN = 8;
    private static final int MENU_COMPANION_RAW_WIFI = 9;
    public static final int A_REQUEST_LOCATION = 10;
    public static final int A_REQUEST_VPN = 9;
    private static final int MAX_NOTIFICATIONS = 40;
    private static final byte[] DEFAULT_VPN_ADDRESS = new byte[] {
            (byte) 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1
    };

    private static final String[] PERMISSIONS = {
            Manifest.permission.POST_NOTIFICATIONS,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.NEARBY_WIFI_DEVICES,
    };

    private final ArrayList<String> notifications = new ArrayList<>();
    private Handler handler;
    private MsgMux mux;
    private TextView conText;
    private TextView ifText;
    private TextView msgText;
    private Bundle lastStatus;
    private Bundle lastMessage;
    private String companionStatus = "none";
    private String companionPullStatus = "";
    private long companionLastSeenMs;
    private Intent pendingStartupIntent;
    private boolean pendingVpnStart;

    static List<String> checkPermissions(Context ctx) {
        List<String> missing = new ArrayList<>();
        for (String permission : PERMISSIONS) {
            if (ctx.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                missing.add(permission);
            }
        }
        return missing;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_ACTION_BAR_OVERLAY);
        handler = new Handler(getMainLooper());
        setContentView(R.layout.main_activity);

        ActionBar actionBar = getActionBar();
        if (actionBar != null) {
            actionBar.setDisplayOptions(ActionBar.DISPLAY_SHOW_TITLE | ActionBar.DISPLAY_SHOW_HOME);
            actionBar.setHideOnContentScrollEnabled(true);
        }

        conText = findViewById(R.id.con_text);
        ifText = findViewById(R.id.if_text);
        msgText = findViewById(R.id.msg_text);
        msgText.setOnClickListener(v -> showNotifications());
        ifText.setOnClickListener(v -> showStatus());

        mux = MsgMux.get(getApplicationContext());
        mux.subscribe("net", this);
        mux.subscribe("netif", this);
        mux.subscribe("netip", this);
        mux.subscribe("wifi", this);
        mux.subscribe("BLE", this);
        mux.subscribe("COMPANION", this);
        mux.subscribe("N", this);
        mux.subscribe("messages", this);
        mux.subscribe("permission", this);

        List<String> missing = checkPermissions(getApplicationContext());
        if (!missing.isEmpty()) {
            Log.d(TAG, "Missing permissions " + missing);
            pendingStartupIntent = getIntent();
            requestPermissions(missing.toArray(new String[]{}), A_REQUEST_LOCATION);
            return;
        }

        startDMeshService();
        updateInterfaces();
        appendNotification("Activity started");
        handleIntent(getIntent());
    }

    @Override
    protected void onDestroy() {
        if (mux != null) {
            mux.unsubscribe("net", this);
            mux.unsubscribe("netif", this);
            mux.unsubscribe("netip", this);
            mux.unsubscribe("wifi", this);
            mux.unsubscribe("BLE", this);
            mux.unsubscribe("COMPANION", this);
            mux.unsubscribe("N", this);
            mux.unsubscribe("messages", this);
            mux.unsubscribe("permission", this);
        }
        super.onDestroy();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void startDMeshService() {
        try {
            startForegroundService(new Intent(this, DMService.class));
            setServiceStatus("Service requested");
        } catch (Throwable ex) {
            Log.d(TAG, "Failed to start service", ex);
            setServiceStatus("Service start failed: " + ex.getMessage());
        }
    }

    private void handleIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (ACTION_START_VPN.equals(intent.getAction())) {
            startVpnFromIntent(intent);
        } else if (ACTION_REQUEST_PERMISSIONS.equals(intent.getAction())) {
            requestPermissionsFromIntent(intent);
        }
    }

    private void requestPermissionsFromIntent(Intent intent) {
        List<String> wanted = new ArrayList<>();
        String requested = intent.getStringExtra(EXTRA_PERMISSIONS);
        if (requested != null && !requested.trim().isEmpty()) {
            for (String raw : requested.split(",")) {
                String normalized = normalizePermission(raw.trim());
                if (normalized != null
                        && checkSelfPermission(normalized) != PackageManager.PERMISSION_GRANTED) {
                    wanted.add(normalized);
                }
            }
        }
        if (wanted.isEmpty()) {
            wanted.addAll(checkPermissions(getApplicationContext()));
        }
        if (!wanted.isEmpty()) {
            requestPermissions(wanted.toArray(new String[]{}), A_REQUEST_LOCATION);
        }
    }

    private static String normalizePermission(String permission) {
        if (permission == null || permission.isEmpty()) {
            return null;
        }
        if (permission.startsWith("android.permission.")) {
            return permission;
        }
        return "android.permission." + permission;
    }

    private void startVpnFromIntent(Intent intent) {
        VpnService.address6 = vpnAddressFromIntent(intent);
        final Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent != null) {
            pendingVpnStart = true;
            startActivityForResult(prepareIntent, A_REQUEST_VPN);
            return;
        }
        startService(new Intent(this, VpnService.class));
    }

    private byte[] vpnAddressFromIntent(Intent intent) {
        byte[] address = intent.getByteArrayExtra(EXTRA_VPN_ADDRESS);
        if (address != null && address.length == 16) {
            return address;
        }
        String addressText = intent.getStringExtra(EXTRA_VPN_ADDRESS);
        if (addressText != null && !addressText.isEmpty()) {
            try {
                byte[] parsed = InetAddress.getByName(addressText).getAddress();
                if (parsed.length == 16) {
                    return parsed;
                }
                Log.w(TAG, "VPN address extra is not IPv6: " + addressText);
            } catch (Throwable t) {
                Log.w(TAG, "Invalid VPN address extra: " + addressText, t);
            }
        }
        return DEFAULT_VPN_ADDRESS.clone();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != A_REQUEST_LOCATION) {
            return;
        }
        List<String> missing = checkPermissions(getApplicationContext());
        if (!missing.isEmpty()) {
            setServiceStatus("Missing permissions: " + missing);
            return;
        }
        Intent startupIntent = pendingStartupIntent;
        pendingStartupIntent = null;
        startDMeshService();
        updateInterfaces();
        handleIntent(startupIntent != null ? startupIntent : getIntent());
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (A_REQUEST_VPN == requestCode && pendingVpnStart) {
            pendingVpnStart = false;
            startService(new Intent(this, VpnService.class));
        } else if (DMeshCompanionManager.REQUEST_ASSOCIATE == requestCode) {
            DMeshCompanionManager.handleActivityResult(this, resultCode, data);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, MENU_OPEN_WEB, 0, "Web").setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
        menu.add(0, MENU_SHOW_STATUS, 1, "Status");
        menu.add(0, MENU_SHOW_NOTIFICATIONS, 2, "Notifications");
        menu.add(0, MENU_PAIR_COMPANION, 3, "Pair companion");
        menu.add(0, MENU_CLEAR_COMPANION, 4, "Clear companion");
        menu.add(0, MENU_COMPANION_ACTIVE, 5, "Companion active 1m");
        menu.add(0, MENU_COMPANION_SLEEP, 6, "Companion sleep");
        menu.add(0, MENU_COMPANION_LORA_LISTEN, 7, "LoRa listen in sleep");
        menu.add(0, MENU_COMPANION_RAW_WIFI, 8, "Raw Wi-Fi listen");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == MENU_OPEN_WEB) {
            openWebAdmin();
            return true;
        }
        if (item.getItemId() == MENU_SHOW_STATUS) {
            showStatus();
            return true;
        }
        if (item.getItemId() == MENU_SHOW_NOTIFICATIONS) {
            showNotifications();
            return true;
        }
        if (item.getItemId() == MENU_PAIR_COMPANION) {
            DMeshCompanionManager.associate(this);
            return true;
        }
        if (item.getItemId() == MENU_CLEAR_COMPANION) {
            DMeshCompanionManager.clear(this);
            setServiceStatus("Companion cleared");
            return true;
        }
        if (item.getItemId() == MENU_COMPANION_ACTIVE) {
            sendCompanionCommand("mode active=true ms=60000");
            return true;
        }
        if (item.getItemId() == MENU_COMPANION_SLEEP) {
            sendCompanionCommand("mode sleep=true");
            return true;
        }
        if (item.getItemId() == MENU_COMPANION_LORA_LISTEN) {
            sendCompanionCommand("mode lora_sleep_listen=true save=true");
            return true;
        }
        if (item.getItemId() == MENU_COMPANION_RAW_WIFI) {
            sendCompanionCommand("mode raw_wifi=true channel=6");
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void openWebAdmin() {
        Intent intent = new Intent(this, WebActivity.class);
        intent.putExtra(WebUrls.EXTRA_URL, ADMIN_URL);
        startActivity(intent);
    }

    private void sendCompanionCommand(String command) {
        String addr = DMeshCompanionPrefs.address(this);
        if (addr == null || addr.trim().isEmpty()) {
            setServiceStatus("No companion address");
            return;
        }
        mux.publish("ble.cmd", "addr", addr.trim(), "text", command);
        setServiceStatus("Companion command: " + command);
    }

    @Override
    public void handleMessage(String topic, String msgType, Message message, MsgConn replyTo,
                              String[] args) {
        final MsgFrame frame = MsgFrame.fromMessage(message);
        final Bundle data = message.getData();
        handler.post(() -> {
            lastMessage = new Bundle(data);
            updateCompanion(frame);
            appendNotification(formatFrame(frame));
            if ("net".equals(topic) && args != null && args.length > 2
                    && "status".equals(args[2])) {
                updateStatus(data);
                return;
            }
            if ("netif".equals(topic) || "netip".equals(topic) || "wifi".equals(topic)
                    || "BLE".equals(topic) || "COMPANION".equals(topic) || "N".equals(topic)) {
                updateInterfaces();
            }
            if ("messages".equals(topic) && "status".equals(msgType)) {
                setServiceStatus("Messages: " + data.getString("events", "0") + " events");
            }
        });
    }

    private void updateStatus(Bundle data) {
        lastStatus = new Bundle(data);
        int scanCount = 0;
        int directNeighbors = 0;
        Bundle nested = data.getBundle("data");
        if (nested != null) {
            ArrayList<Bundle> scan = nested.getParcelableArrayList("scan");
            if (scan != null) {
                scanCount = scan.size();
                for (Bundle deviceBundle : scan) {
                    Device device = new Device(deviceBundle);
                    if ("1".equals(device.data.getString("gc", "0")) || device.isConnected()) {
                        directNeighbors++;
                    }
                }
            }
        }
        String visible = data.getString("visible", "0");
        String ap = data.getString("ap", "");
        String ssid = data.getString(Device.WIFISSID, data.getString("s", ""));
        StringBuilder status = new StringBuilder();
        status.append("Service active");
        status.append("\nDirect neighbors: ").append(directNeighbors);
        status.append("\nVisible: ").append(visible);
        status.append("\nScan entries: ").append(scanCount);
        appendCompanionStatus(status);
        if (!ap.isEmpty()) {
            status.append("\nAP: ").append(ap);
        }
        if (!ssid.isEmpty()) {
            status.append("\nSSID: ").append(ssid);
        }
        conText.setText(status);
        conText.setBackgroundColor(directNeighbors > 0 ? Color.rgb(209, 250, 229) : Color.TRANSPARENT);
        updateInterfaces();
    }

    private void updateInterfaces() {
        if (ifText == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                String name = ni.getName();
                if (ni.getInterfaceAddresses().isEmpty() || !ni.isUp()
                        || name.contains("dummy") || "lo".equals(name)) {
                    continue;
                }
                sb.append(name).append(": ");
                for (InterfaceAddress address : ni.getInterfaceAddresses()) {
                    sb.append(address.getAddress().getHostAddress()).append(" ");
                }
                sb.append("\n");
            }
        } catch (SocketException e) {
            sb.append("Interface error: ").append(e.getMessage()).append("\n");
        }
        if (!P2P.currentClientList.isEmpty()) {
            sb.append("P2P clients: ").append(P2P.currentClientList.size()).append("\n");
            for (WifiP2pDevice client : P2P.currentClientList) {
                sb.append(client.deviceAddress).append(" ").append(client.deviceName).append("\n");
            }
        }
        ifText.setText(sb.length() == 0 ? "No active interfaces" : sb.toString());
    }

    private void setServiceStatus(String text) {
        if (conText != null) {
            StringBuilder status = new StringBuilder(text);
            appendCompanionStatus(status);
            conText.setText(status);
        }
    }

    private void appendCompanionStatus(StringBuilder status) {
        status.append("\nCompanion advertising: ").append(companionStatus);
        if (!companionPullStatus.isEmpty()) {
            status.append("\nPull: ").append(companionPullStatus);
        }
    }

    private void updateCompanion(MsgFrame frame) {
        if (frame == null || frame.method == null) {
            return;
        }
        if ("BLE.DISC".equals(frame.method) && "dmesh".equals(frame.fields.get("proto"))) {
            String id = frame.fields.getOrDefault("id", frame.fields.getOrDefault("addr", ""));
            String event = frame.fields.getOrDefault("event", "announce");
            String pending = frame.fields.getOrDefault("pending", "");
            String payloadLen = frame.fields.getOrDefault("payload_len", "");
            String hash = frame.fields.getOrDefault("payload_hash", "");
            String rssi = frame.fields.getOrDefault("rssi", "");
            boolean advertising = isPositive(pending) || isPositive(payloadLen)
                    || "payload_pending".equals(event) || "lora_rx".equals(event);
            StringBuilder sb = new StringBuilder();
            if (advertising) {
                sb.append(id.isEmpty() ? "peer" : id);
                sb.append(' ').append(event);
                if (!pending.isEmpty() && !"0".equals(pending)) {
                    sb.append(" pending=").append(pending);
                }
                if (!payloadLen.isEmpty() && !"0".equals(payloadLen)) {
                    sb.append(' ').append(payloadLen).append("B");
                }
                if (!hash.isEmpty()) {
                    sb.append(" hash=").append(hash);
                }
                if (!rssi.isEmpty()) {
                    sb.append(" rssi=").append(rssi);
                }
            } else {
                sb.append(id.isEmpty() ? "peer" : id).append(" idle");
            }
            companionStatus = sb.toString();
            companionLastSeenMs = System.currentTimeMillis();
            return;
        }
        if ("BLE.PENDING".equals(frame.method)) {
            String id = frame.fields.getOrDefault("id", frame.fields.getOrDefault("addr", ""));
            companionPullStatus = "pending from " + (id.isEmpty() ? "peer" : id)
                    + " via " + frame.fields.getOrDefault("action", "probe");
            return;
        }
        if ("BLE.PULL".equals(frame.method)) {
            String addr = frame.fields.getOrDefault("addr", "");
            String state = frame.fields.getOrDefault("state", "");
            companionPullStatus = state + (addr.isEmpty() ? "" : " " + addr);
            return;
        }
        if ("BLE.MSG".equals(frame.method)) {
            String seq = frame.fields.getOrDefault("seq", "");
            String len = frame.fields.getOrDefault("len", "");
            companionPullStatus = "saved seq=" + seq + (len.isEmpty() ? "" : " " + len + "B");
            return;
        }
        if (frame.method.startsWith("COMPANION.")) {
            String state = frame.fields.getOrDefault("state", "");
            String addr = frame.fields.getOrDefault("addr", "");
            if ("COMPANION.CLEAR".equals(frame.method)) {
                companionStatus = "none";
                companionPullStatus = "";
            } else {
                companionStatus = state.isEmpty() ? frame.method : state
                        + (addr.isEmpty() ? "" : " " + addr);
            }
        }
    }

    private boolean isPositive(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        try {
            return Integer.parseInt(value) > 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private String formatFrame(MsgFrame frame) {
        if (frame == null || frame.method == null) {
            return "";
        }
        if ("BLE.DISC".equals(frame.method) && "dmesh".equals(frame.fields.get("proto"))) {
            String id = frame.fields.getOrDefault("id", frame.fields.getOrDefault("addr", ""));
            String event = frame.fields.getOrDefault("event", "announce");
            String len = frame.fields.getOrDefault("payload_len", "");
            String pending = frame.fields.getOrDefault("pending", "");
            String rssi = frame.fields.getOrDefault("rssi", "");
            return "BLE " + compactId(id) + " " + event
                    + fieldText("pending", pending)
                    + fieldText("len", len)
                    + fieldText("rssi", rssi);
        }
        if ("BLE.PENDING".equals(frame.method) || "BLE.PULL".equals(frame.method)) {
            return frame.method + " "
                    + frame.fields.getOrDefault("id", frame.fields.getOrDefault("addr", "peer"))
                    + fieldText("state", frame.fields.get("state"))
                    + fieldText("action", frame.fields.get("action"));
        }
        if ("BLE.MSG".equals(frame.method)) {
            return "BLE message "
                    + frame.fields.getOrDefault("seq", "")
                    + fieldText("len", frame.fields.get("len"))
                    + fieldText("hash", frame.fields.get("hash"));
        }
        if (frame.method.startsWith("COMPANION.")) {
            return frame.method
                    + fieldText("state", frame.fields.get("state"))
                    + fieldText("addr", frame.fields.get("addr"))
                    + fieldText("association", frame.fields.get("association"));
        }
        if ("net.status".equals(frame.method)) {
            return "Network status visible=" + frame.fields.getOrDefault("visible", "0")
                    + fieldText("ap", frame.fields.get("ap"))
                    + fieldText("ssid", frame.fields.get("s"));
        }
        if ("wifi.BLE.DISC".equals(frame.method)) {
            return "BLE companion " + frame.fields.getOrDefault("name", "peer");
        }
        if (frame.fields.isEmpty()) {
            return frame.method;
        }
        return frame.method + " " + frame.fields.toString();
    }

    private String compactId(String id) {
        if (id == null || id.length() <= 12) {
            return id == null ? "" : id;
        }
        return id.substring(0, 12);
    }

    private String fieldText(String key, String value) {
        if (value == null || value.isEmpty() || "0".equals(value)) {
            return "";
        }
        return " " + key + "=" + value;
    }

    private void appendNotification(String text) {
        notifications.add(0, text);
        while (notifications.size() > MAX_NOTIFICATIONS) {
            notifications.remove(notifications.size() - 1);
        }
        if (msgText != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Notifications: ").append(notifications.size()).append("\n");
            int shown = Math.min(8, notifications.size());
            for (int i = 0; i < shown; i++) {
                sb.append(notifications.get(i)).append("\n\n");
            }
            msgText.setText(sb.toString());
        }
    }

    private void showStatus() {
        new AlertDialog.Builder(this)
                .setTitle("Status")
                .setMessage(lastStatus == null ? ifText.getText() : UiUtil.toString(lastStatus, "\n"))
                .setPositiveButton("OK", null)
                .show();
    }

    private void showNotifications() {
        StringBuilder sb = new StringBuilder();
        for (String notification : notifications) {
            sb.append(notification).append("\n\n");
        }
        if (lastMessage != null) {
            sb.append("Last message\n").append(UiUtil.toString(lastMessage, "\n"));
        }
        new AlertDialog.Builder(this)
                .setTitle("Notifications")
                .setMessage(sb.length() == 0 ? "No notifications" : sb.toString())
                .setPositiveButton("OK", null)
                .show();
    }
}
