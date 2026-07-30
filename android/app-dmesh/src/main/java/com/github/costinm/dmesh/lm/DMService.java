package com.github.costinm.dmesh.lm;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Bundle;
import android.os.Message;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import android.app.RemoteInput;

import com.github.costinm.dmesh.android.msg.BaseMsgService;
import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;

import com.github.costinm.dmesh.lm3.LocalMesh;
import com.github.costinm.dmesh.lm3.Ble;
import com.github.costinm.dmeshnative.MeshNode;
import com.github.costinm.dmeshnative.Rust;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Foreground service maintaining the notification, wifi/BT/net and native code..
 *
 * This runs in a different process - to keep memory isolated (not load UI components).
 * The base class exposes a Messenger based binder interface - no extra AIDL required.
 * The protocol is based on events/messages which are forwarded in the mesh or handled locally,
 * so Messenger and binary messages (generated in native code, etc) can reduce memory use and
 * serialization overheads.
 */
public class DMService extends BaseMsgService implements MessageHandler {
    public static final String TAG = "DM-SVC";
    public static final String PREF_ENABLED = "lm_enabled";
    public static final String PREF_WIFI_ENABLED = "wifi_enabled";
    public static final String PREF_VPN_ENABLED = "vpn_enabled";
    public static final int RUST_SSH_PORT = 15022;
    public static final int RUST_HTTP_PORT = 18480;

    // Implements the Wifi, discovery messaging interface, using Android APIs.
    static LocalMesh wifi;

    // Notification bar UI - handles messages from the mux to update the bar.
    private NotificationHandler nh;

    private MeshNode meshNode;
    private static volatile DMService activeService;
    private static final int MAX_LOG_EVENTS = 512;
    private static final long DUPLICATE_EVENT_WINDOW_MS = 30000;
    private final ArrayList<MsgFrame> logEvents = new ArrayList<>();
    private final Map<String, MessageSubscriber> logSubscribers = new HashMap<>();
    private final Map<String, String> lastLogSignature = new HashMap<>();
    private final Map<String, Long> lastLogAt = new HashMap<>();
    private MsgConn historyConn;

    private SharedPreferences prefs;

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ATTESTATION_KEY_ALIAS = "attestation_key";
    private PrivateKey attestationKey;
    private Certificate[] attestationCerts;

    boolean fg = false;

    /**
     * MsgMux defines this for processing incoming messages. Binder is one of the mechanisms to
     * receive messages, but authenticated remote messages are also accepted.
     *
     * @param topic
     * @param msgType
     * @param m       the actual message. The Bundle has the parsed metadata.
     * @param replyTo null if the message was generated locally.
     * @param args
     */
    @Override
    public void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args) {
        if (args.length < 2) {
            return;
        }
        if (args[1].equals("I")) {
                // Update id4 for wifi. Will be used in announcements.
                wifi.handleMessage(topic, msgType, m, replyTo, args);
        }
    }

    public void onLowMemory() {
        Log.d(TAG, "On Low memory");
    }

    public void onTrimMemory(int level) {
        Log.d(TAG, "On Trim memory " + level);
    }

    public static class Receiver extends BroadcastReceiver {

        private CharSequence getMessageText(Intent intent) {
            Bundle remoteInput = RemoteInput.getResultsFromIntent(intent);
            if (remoteInput != null) {
                return remoteInput.getCharSequence(":uri");
            }
            return null;
        }

        @Override
        public void onReceive(Context context, Intent intent) {
            if (Ble.ACTION_SCAN_RESULT.equals(intent.getAction())) {
                Ble.handlePendingIntentScan(context, intent);
                return;
            }
            CharSequence txt = getMessageText(intent);
            Log.d(TAG, "BROADCAST MSG: " + txt + " " + intent + " " + intent.getData());

            // TODO: Add the channel

            Notification repliedNotification = new Notification.Builder(context, "dmesh")
                    .setSmallIcon(R.drawable.ic_launcher_background)
                    .setContentText("CMD HANDLED")
                    .build();

            // Re-issue the notification on the channel.
            NotificationManager notificationManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                // TODO: Consider calling
                //    ActivityCompat#requestPermissions
                // here to request the missing permissions, and then overriding
                //   public void onRequestPermissionsResult(int requestCode, String[] permissions,
                //                                          int[] grantResults)
                // to handle the case where the user grants the permission. See the documentation
                // for ActivityCompat#requestPermissions for more details.
                return;
            }
            notificationManager.notify(1, repliedNotification);
        }
    }

    static byte[] addr;

    @Override
    public void onCreate() {
        super.onCreate();
        activeService = this;

        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        // A foreground-service launch has a short system deadline.  Native
        // mesh and radio setup can take longer, so publish the notification
        // before loading Rust or constructing LocalMesh; otherwise Android
        // keeps the service pending and BLE scans never register.
        nh = new NotificationHandler(this);
        ensureForeground();

        try {
            Rust.load();
            Log.d(TAG, "Rust dmesh library loaded");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "Rust dmesh library unavailable", e);
        }
        wifi = LocalMesh.get(this.getApplicationContext());

        // Dispatching messages on this service.
        mux.subscribe("ble", wifi.ble);
        mux.subscribe("wifi", wifi);
        mux.subscribe("permission", this::handlePermissionMessage);
        mux.subscribe("messages", this::handleMessagesMessage);
        mux.subscribe("companion", this::handleCompanionMessage);
        mux.subscribe("N", nh);

        // Info from the client - currently the 64-bit node ID, other info will be added.
        // Sent on connect.
        mux.subscribe("I", this);

        // send status on connect.
        mux.subscribe(":open", new MessageHandler() {
            @Override
            public void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args) {
                wifi.sendWifiDiscoveryStatus("connect", "");
            }
        });
        historyConn = new MsgConn(mux) {
            @Override
            public boolean sendFrame(MsgFrame frame) {
                recordJsonFrame(frame);
                return true;
            }
        };
        mux.addInConnection("dmservice-history", historyConn, new MsgFrame("session.open").toMessage());

        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        Network[] nets = cm.getAllNetworks();
        for (Network n: nets) {
            // if connected, type WIFI
            LinkProperties lp = cm.getLinkProperties(n);
            try {
                NetworkInterface ni = NetworkInterface.getByName(lp.getInterfaceName());
                Log.d(TAG, "NetworkInterface: " + ni);
                mux.publish("netif." + ni.getName());
                for (InterfaceAddress nia:  ni.getInterfaceAddresses()) {
                    InetAddress ia = nia.getAddress();
                    if (ia instanceof Inet6Address) {
                        Log.d(TAG, "I6 " + ((Inet6Address)ia).getScopeId() + " " +
                                ((Inet6Address)ia).getHostAddress());
                        mux.publish("netip." + ni.getName() + "/" + nia.getAddress());
                    } else {
                        mux.publish("netip." + ni.getName() + "/" + nia.getAddress());
                    }
                }
            } catch (SocketException e) {
                e.printStackTrace();
            }
        }

        LMJob.schedule(this.getApplicationContext(), 15 * 60 * 1000);

        // MeshNode.start() enters native code and may create keys, sockets, and
        // worker threads.  Do not hold the service main thread while that
        // happens: Android delivers BLE scan and GATT callbacks there.
        new Thread(this::startRustMesh, "dmesh-rust-mesh").start();

    }

    public void onDestroy() {
        activeService = null;
        if (meshNode != null) {
            meshNode.stop();
            meshNode = null;
        }
        if (historyConn != null) {
            mux.removeInConnection("dmservice-history");
            historyConn = null;
        }
        wifi.onDestroy();
        super.onDestroy();
    }

    static DMService getActiveService() {
        return activeService;
    }

    MeshNode shellMeshNode() {
        return meshNode;
    }

    com.github.costinm.dmesh.android.msg.MsgMux shellMux() {
        return mux;
    }

    synchronized void recordJsonEvent(String source, String line) {
        if (line == null || line.isEmpty()) {
            return;
        }
        MsgFrame event = new MsgFrame("messages.event");
        event.fields.put("source", source);
        event.fields.put("json", line);
        recordJsonFrame(event);
    }

    synchronized void recordJsonFrame(MsgFrame event) {
        if (event == null || event.method == null) {
            return;
        }
        if (isDuplicateHistoryFrame(event)) {
            return;
        }
        logEvents.add(event);
        while (logEvents.size() > MAX_LOG_EVENTS) {
            logEvents.remove(0);
        }
        for (MessageSubscriber sub : new ArrayList<>(logSubscribers.values())) {
            if (!event.matchesKeys(sub.keys)) {
                continue;
            }
            if (!sub.conn.sendFrame(event)) {
                logSubscribers.remove(sub.conn.name);
            }
        }
    }

    private boolean isDuplicateHistoryFrame(MsgFrame event) {
        String key = historyDedupeKey(event);
        if (key == null) {
            return false;
        }
        String signature = historySignature(event);
        long now = android.os.SystemClock.elapsedRealtime();
        String previous = lastLogSignature.get(key);
        Long previousAt = lastLogAt.get(key);
        lastLogSignature.put(key, signature);
        lastLogAt.put(key, now);
        return signature.equals(previous) && previousAt != null
                && now - previousAt < DUPLICATE_EVENT_WINDOW_MS;
    }

    private String historyDedupeKey(MsgFrame event) {
        if ("BLE.DISC".equals(event.method)) {
            return "BLE.DISC:" + event.fields.getOrDefault("id",
                    event.fields.getOrDefault("addr", ""));
        }
        if ("BLE.PULL".equals(event.method) || "BLE.PENDING".equals(event.method)) {
            return event.method + ":" + event.fields.getOrDefault("id",
                    event.fields.getOrDefault("addr", ""));
        }
        if (event.method != null && event.method.startsWith("COMPANION.")) {
            return event.method + ":" + event.fields.getOrDefault("association",
                    event.fields.getOrDefault("addr", ""));
        }
        if ("wifi.BLE.DISC".equals(event.method)) {
            return "wifi.BLE.DISC:" + event.fields.getOrDefault("name", "");
        }
        if ("net.status".equals(event.method)) {
            return "net.status";
        }
        return null;
    }

    private String historySignature(MsgFrame event) {
        StringBuilder sb = new StringBuilder(event.method);
        appendHistoryField(sb, event, "id");
        appendHistoryField(sb, event, "addr");
        appendHistoryField(sb, event, "event");
        appendHistoryField(sb, event, "pending");
        appendHistoryField(sb, event, "payload_len");
        appendHistoryField(sb, event, "payload_hash");
        appendHistoryField(sb, event, "pull");
        appendHistoryField(sb, event, "state");
        appendHistoryField(sb, event, "association");
        appendHistoryField(sb, event, "visible");
        appendHistoryField(sb, event, "ap");
        appendHistoryField(sb, event, "s");
        return sb.toString();
    }

    private void appendHistoryField(StringBuilder sb, MsgFrame event, String key) {
        String value = event.fields.get(key);
        if (value != null && !value.isEmpty()) {
            sb.append('|').append(key).append('=').append(value);
        }
    }

    private void handleMessagesMessage(String topic, String msgType, Message m, MsgConn replyTo,
                                   String[] args) {
        MsgFrame req = MsgFrame.fromMessage(m);
        MsgFrame reply = new MsgFrame("messages." + (msgType == null ? "status" : msgType));
        reply.id = req.id;
        if ("subscribe".equals(msgType)) {
            if (replyTo == null) {
                reply.method = "messages.error";
                reply.fields.put("error", "messages subscribe requires a reply connection");
            } else {
                synchronized (this) {
                    String keys = req.fields.getOrDefault("keys", req.fields.getOrDefault("filter", "all"));
                    logSubscribers.put(replyTo.name, new MessageSubscriber(replyTo, keys));
                    reply.fields.put("ok", "true");
                    reply.fields.put("events", Integer.toString(logEvents.size()));
                    reply.fields.put("keys", keys);
                    replyTo.sendFrame(reply);
                    for (MsgFrame event : logEvents) {
                        if (event.matchesKeys(keys)) {
                            replyTo.sendFrame(event);
                        }
                    }
                    return;
                }
            }
        } else if ("snapshot".equals(msgType) || "history".equals(msgType)) {
            synchronized (this) {
                String keys = req.fields.getOrDefault("keys", req.fields.getOrDefault("filter", "all"));
                int limit = parsePositiveInt(req.fields.get("limit"), MAX_LOG_EVENTS);
                int sent = 0;
                reply.fields.put("ok", "true");
                reply.fields.put("events", Integer.toString(logEvents.size()));
                reply.fields.put("keys", keys);
                reply.fields.put("limit", Integer.toString(limit));
                if (replyTo != null) {
                    replyTo.sendFrame(reply);
                    int start = Math.max(0, logEvents.size() - limit);
                    for (int i = start; i < logEvents.size(); i++) {
                        MsgFrame event = logEvents.get(i);
                        if (event.matchesKeys(keys)) {
                            replyTo.sendFrame(event);
                            sent++;
                        }
                    }
                    MsgFrame done = new MsgFrame("messages.snapshot.done");
                    done.id = req.id;
                    done.fields.put("ok", "true");
                    done.fields.put("count", Integer.toString(sent));
                    done.fields.put("keys", keys);
                    replyTo.sendFrame(done);
                    return;
                }
            }
        } else if ("file".equals(msgType) || "list".equals(msgType) || "read".equals(msgType)) {
            fillRadioMessagesReply(reply, req, "read".equals(msgType));
        } else if ("status".equals(msgType) || msgType == null || msgType.isEmpty()) {
            synchronized (this) {
                reply.fields.put("ok", "true");
                reply.fields.put("events", Integer.toString(logEvents.size()));
                reply.fields.put("subscribers", Integer.toString(logSubscribers.size()));
            }
        } else {
            reply.method = "messages.error";
            reply.fields.put("error", "unknown messages command: " + msgType);
        }
        if (replyTo != null) {
            replyTo.sendFrame(reply);
        }
    }

    private void fillRadioMessagesReply(MsgFrame reply, MsgFrame req, boolean includePreview) {
        File file = new File(getFilesDir(), "radio/ble/messages.bin");
        reply.fields.put("ok", "true");
        reply.fields.put("file", file.getAbsolutePath());
        reply.fields.put("bytes", Long.toString(file.exists() ? file.length() : 0));
        if (!file.exists()) {
            reply.fields.put("count", "0");
            reply.fields.put("messages", "");
            return;
        }
        long wantSeq = parseLong(req.fields.get("seq"), -1);
        int limit = parsePositiveInt(req.fields.get("limit"), 40);
        int maxPreview = parsePositiveInt(req.fields.get("preview"), 96);
        if (limit > 200) {
            limit = 200;
        }
        if (maxPreview > 512) {
            maxPreview = 512;
        }
        try {
            RadioMessageList list = readRadioMessageList(file, wantSeq, limit, includePreview, maxPreview);
            reply.fields.put("count", Integer.toString(list.count));
            reply.fields.put("messages", list.text);
        } catch (IOException e) {
            reply.method = "messages.error";
            reply.fields.put("ok", "false");
            reply.fields.put("error", e.toString());
        }
    }

    private RadioMessageList readRadioMessageList(File file, long wantSeq, int limit,
                                                  boolean includePreview, int maxPreview)
            throws IOException {
        RadioMessageList out = new RadioMessageList();
        try (FileInputStream in = new FileInputStream(file)) {
            while (out.count < limit) {
                String header = readLine(in);
                if (header == null) {
                    break;
                }
                if (!header.startsWith("msg ")) {
                    continue;
                }
                int len = (int) parseLongField(header, "len", 0);
                long seq = parseLongField(header, "seq", 0);
                byte[] payload = readExact(in, len);
                if (payload.length < len) {
                    break;
                }
                in.read();
                if (wantSeq >= 0 && wantSeq != seq) {
                    continue;
                }
                if (out.text.length() > 0) {
                    out.text += "\n";
                }
                out.text += header;
                if (includePreview) {
                    out.text += " preview_hex=" + hexPreview(payload, maxPreview);
                }
                out.count++;
            }
        }
        return out;
    }

    private String readLine(FileInputStream in) throws IOException {
        byte[] buf = new byte[512];
        int pos = 0;
        while (pos < buf.length) {
            int b = in.read();
            if (b < 0) {
                return pos == 0 ? null : new String(buf, 0, pos, StandardCharsets.UTF_8);
            }
            if (b == '\n') {
                return new String(buf, 0, pos, StandardCharsets.UTF_8);
            }
            buf[pos++] = (byte) b;
        }
        return new String(buf, 0, pos, StandardCharsets.UTF_8);
    }

    private byte[] readExact(FileInputStream in, int len) throws IOException {
        if (len <= 0) {
            return new byte[0];
        }
        byte[] data = new byte[len];
        int pos = 0;
        while (pos < len) {
            int n = in.read(data, pos, len - pos);
            if (n < 0) {
                break;
            }
            pos += n;
        }
        if (pos == len) {
            return data;
        }
        byte[] shortData = new byte[pos];
        System.arraycopy(data, 0, shortData, 0, pos);
        return shortData;
    }

    private String hexPreview(byte[] payload, int maxBytes) {
        int n = Math.min(payload.length, maxBytes);
        char[] out = new char[n * 2];
        char[] hex = "0123456789abcdef".toCharArray();
        for (int i = 0; i < n; i++) {
            int v = payload[i] & 0xff;
            out[i * 2] = hex[v >>> 4];
            out[i * 2 + 1] = hex[v & 0x0f];
        }
        return new String(out);
    }

    private long parseLongField(String line, String key, long def) {
        String prefix = key + "=";
        for (String part : line.split("\\s+")) {
            if (part.startsWith(prefix)) {
                return parseLong(part.substring(prefix.length()), def);
            }
        }
        return def;
    }

    private long parseLong(String raw, long def) {
        if (raw == null || raw.isEmpty()) {
            return def;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static final class RadioMessageList {
        int count;
        String text = "";
    }

    private static int parsePositiveInt(String raw, int def) {
        if (raw == null || raw.isEmpty()) {
            return def;
        }
        try {
            int parsed = Integer.parseInt(raw);
            return parsed <= 0 ? def : parsed;
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static final class MessageSubscriber {
        final MsgConn conn;
        final String keys;

        MessageSubscriber(MsgConn conn, String keys) {
            this.conn = conn;
            this.keys = keys;
        }
    }

    private void handlePermissionMessage(String topic, String msgType, Message m, MsgConn replyTo,
                                         String[] args) {
        MsgFrame req = MsgFrame.fromMessage(m);
        MsgFrame reply = new MsgFrame("permission." + (msgType == null ? "status" : msgType));
        reply.id = req.id;

        if ("request".equals(msgType)) {
            String requested = req.fields.get("permissions");
            Intent intent = new Intent(this, MeshActivityLight.class);
            intent.setAction(MeshActivityLight.ACTION_REQUEST_PERMISSIONS);
            if (requested != null && !requested.isEmpty()) {
                intent.putExtra(MeshActivityLight.EXTRA_PERMISSIONS, requested);
            }
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try {
                startActivity(intent);
                reply.fields.put("requested", requested == null ? "" : requested);
            } catch (Throwable t) {
                reply.method = "permission.error";
                reply.fields.put("error", t.toString());
            }
        } else if (!"status".equals(msgType) && msgType != null && !msgType.isEmpty()) {
            reply.method = "permission.error";
            reply.fields.put("error", "unknown permission command: " + msgType);
        }

        List<String> missing = MeshActivityLight.checkPermissions(getApplicationContext());
        reply.fields.put("missing", String.join(",", missing));
        reply.fields.put("ok", Boolean.toString(missing.isEmpty()));
        if (replyTo != null) {
            replyTo.sendFrame(reply);
        }
    }

    private void handleCompanionMessage(String topic, String msgType, Message m, MsgConn replyTo,
                                        String[] args) {
        MsgFrame req = MsgFrame.fromMessage(m);
        MsgFrame reply = new MsgFrame("companion." + (msgType == null ? "status" : msgType));
        reply.id = req.id;
        if ("clear".equals(msgType)) {
            DMeshCompanionManager.clear(this);
            reply.fields.put("ok", "true");
        } else if ("pair".equals(msgType) || "associate".equals(msgType)) {
            String addr = req.fields.getOrDefault("addr", "");
            String name = req.fields.getOrDefault("name", "");
            if (!addr.isEmpty()) {
                DMeshCompanionManager.saveDirect(this, addr, name);
                reply.fields.put("pairing", "direct_addr");
            } else {
                boolean claimed = DMeshCompanionManager.startPairingWindow(this);
                if (wifi != null && wifi.ble != null) {
                    wifi.ble.scan();
                }
                reply.fields.put("pairing", claimed ? "recent_scan" : "direct_scan");
            }
            reply.fields.put("ok", "true");
        } else if ("status".equals(msgType) || msgType == null || msgType.isEmpty()) {
            reply.fields.put("ok", "true");
        } else {
            reply.method = "companion.error";
            reply.fields.put("error", "unknown companion command: " + msgType);
        }
        reply.fields.put("status", DMeshCompanionManager.status(this));
        if (replyTo != null) {
            replyTo.sendFrame(reply);
        }
    }

    private synchronized void startRustMesh() {
        if (meshNode != null) {
            return;
        }
        try {
            File baseDir = new File(getFilesDir(), "ssh-mesh");
            if (!baseDir.exists() && !baseDir.mkdirs()) {
                Log.w(TAG, "Failed to create Rust mesh dir: " + baseDir);
                return;
            }
            MeshNode node = new MeshNode(baseDir.getAbsolutePath());
            node.start(RUST_SSH_PORT, RUST_HTTP_PORT);
            node.setCallback(new SshJsonlMsgBridge(this, mux));
            meshNode = node;
            Log.d(TAG, "Rust mesh node started: ssh=" + RUST_SSH_PORT
                    + " http=" + RUST_HTTP_PORT
                    + " pubkey=" + meshNode.getPublicKey());
        } catch (Throwable t) {
            Log.w(TAG, "Failed to start Rust mesh node", t);
        }
    }

    public void stop() {
        VpnService.stopVpn();

        stopForeground(true);

        // Best if running as separate process...
        stopSelf();

        fg = false;
        Log.d(TAG, "Stop fg");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand" + startId + " " + flags + " " + intent);
        if (intent == null) {
            return START_STICKY;
        }

        ensureForeground();

        //VpnService.maybeStartVpn(prefs, this);

        return START_STICKY;
    }

    private void ensureForeground() {
        if (fg || nh == null) {
            return;
        }
        try {
            startForeground(5228, nh.getNotification(new Bundle()),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING
                            | ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION);
            Log.d(TAG, "Starting fg");
            fg = true;
        } catch (Throwable t) {
            Log.e(TAG, "Unable to start foreground service", t);
        }
    }


//    @RequiresApi(36)
//    void sampleRecordSystemTrace() {
//        Executor mainExecutor = Executors.newSingleThreadExecutor();
//        Consumer<ProfilingResult> resultCallback =
//                new Consumer<ProfilingResult>() {
//                    @Override
//                    public void accept(ProfilingResult profilingResult) {
//                        if (profilingResult.getErrorCode() == ProfilingResult.ERROR_NONE) {
//                            Log.d(
//                                    "ProfileTest",
//                                    "Received profiling result file=" + profilingResult.getResultFilePath());
//                        } else {
//                            Log.e(
//                                    "ProfileTest",
//                                    "Profiling failed errorcode="
//
//                                            + profilingResult.getErrorCode()
//                                            + " errormsg="
//                                            + profilingResult.getErrorMessage());
//                        }
//                    }
//                };
//        CancellationSignal stopSignal = new CancellationSignal();
//
//        SystemTraceRequestBuilder requestBuilder = new SystemTraceRequestBuilder();
//        requestBuilder.setCancellationSignal(stopSignal);
//        requestBuilder.setTag("FOO");
//        requestBuilder.setDurationMs(60000);
//        requestBuilder.setBufferFillPolicy(BufferFillPolicy.RING_BUFFER);
//        requestBuilder.setBufferSizeKb(20971520);
//        Profiling.requestProfiling(getApplicationContext(), requestBuilder.build(), mainExecutor,
//                resultCallback);
//
//        // Wait some time for profiling to start.
//
//        Trace.beginSection("MyApp:HeavyOperation");
//        //heavyOperation();
//        Trace.endSection();
//
//        // Once the interesting code section is profiled, stop profile
//        stopSignal.cancel();
//    }
    // /data/user/0/<app>/files/profiling/profile<tag><datetime>.perfetto-trace

    void generateAttestationKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);

            if (keyStore.containsAlias(ATTESTATION_KEY_ALIAS)) {
                KeyStore.Entry entry = keyStore.getEntry(ATTESTATION_KEY_ALIAS, null);
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    this.attestationKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
                    this.attestationCerts = keyStore.getCertificateChain(ATTESTATION_KEY_ALIAS);
                    Log.d(TAG, "Attestation key already exists. Loaded from Keystore.");
                    return;
                }
            }

            Log.d(TAG, "Generating new attestation key.");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC /* "EC" */ , ANDROID_KEYSTORE);

            // This is specific to android keystore - can't avoid the dependency
            // ( unless calling binder directly from native )
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    ATTESTATION_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN /* 4 */)
                    .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setUserAuthenticationRequired(false) // even if user didn't authenticate recently
                    .setDigests(KeyProperties.DIGEST_SHA256 /* SHA-256 */ )
                    .setAttestationChallenge("a_test_challenge".getBytes())
                    .build();

            keyPairGenerator.initialize(spec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            this.attestationKey = keyPair.getPrivate();
            this.attestationCerts = keyStore.getCertificateChain(ATTESTATION_KEY_ALIAS);
            KeyStore.Entry entry = keyStore.getEntry(ATTESTATION_KEY_ALIAS, null);
            for (Certificate cert : this.attestationCerts) {
                Log.d(TAG, "Got  " + cert);
            }

        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException | NoSuchProviderException |
                 UnrecoverableEntryException e) {
            Log.e(TAG, "Failed to generate or load attestation key", e);
        }
    }

}
