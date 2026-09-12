package com.github.costinm.dmesh.lm;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.LinkAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import android.app.RemoteInput;

import com.github.costinm.dmesh.MeshService;
import com.github.costinm.dmesh.MeshStream;

import com.github.costinm.dmeshnative.AndroidTransportBridge;
import com.github.costinm.dmeshnative.CborMessageCodec;
import com.github.costinm.dmeshnative.MeshNode;
import com.github.costinm.dmeshnative.Rust;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
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
import java.security.MessageDigest;
import android.os.Process;
import android.content.pm.Signature;
import com.github.costinm.dmesh.DirectBinder;
import java.util.ArrayList;
import java.util.TreeMap;


/**
 * Foreground service maintaining the notification, wifi/BT/net and native code..
 *
 * This runs in a different process - to keep memory isolated (not load UI components).
 * DirectBinder is the Android app boundary. Rust owns mesh routing, command
 * policy, histories, and subscriptions; this service only translates Android
 * framework state and explicit app Binder calls.
 */
public class DMService extends MeshService {
    public static final String TAG = "DM-SVC";
    public static final String PREF_ENABLED = "lm_enabled";
    public static final String PREF_WIFI_ENABLED = "wifi_enabled";
    public static final String PREF_VPN_ENABLED = "vpn_enabled";
    public static final int RUST_SSH_PORT = 15022;
    public static final int RUST_HTTP_PORT = 18480;

    // Implements the Wifi, discovery messaging interface, using Android APIs.
    static AndroidTransportBridge transport;

    // Notification bar UI for foreground-service lifetime only.
    private NotificationHandler nh;

    private MeshNode meshNode;
    private MessageStreamGateway messageGateway;
    private static volatile DMService activeService;
    private BatteryMonitor batteryMonitor;
    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback localNetworksCallback;

    private SharedPreferences prefs;

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ATTESTATION_KEY_ALIAS = "attestation_key";
    private PrivateKey attestationKey;
    private Certificate[] attestationCerts;

    boolean fg = false;

    public void onLowMemory() {
        Log.d(TAG, "On Low memory");
    }

    public void onTrimMemory(int level) {
        Log.d(TAG, "On Trim memory " + level);
        submitMemoryTelemetry(level);
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
            if ("com.github.costinm.dmesh.wifi.BLE_SCAN".equals(intent.getAction())) {
                AndroidTransportBridge.handlePendingIntent(context, intent);
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
        // before loading Rust or constructing the radio owner; otherwise Android
        // keeps the service pending and BLE scans never register.
        nh = new NotificationHandler(this);
        ensureForeground();

        try {
            Rust.load();
            Log.d(TAG, "Rust dmesh library loaded");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "Rust dmesh library unavailable", e);
        }
        batteryMonitor = new BatteryMonitor(this);
        submitMemoryTelemetry(0);
        transport = AndroidTransportBridge.get(this.getApplicationContext());

        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        connectivityManager = cm;
        publishLocalNetworks();
        localNetworksCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { publishLocalNetworks(); }
            @Override public void onLost(Network network) { publishLocalNetworks(); }
            @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                publishLocalNetworks();
            }
            @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                publishLocalNetworks();
            }
        };
        cm.registerNetworkCallback(new android.net.NetworkRequest.Builder().build(),
                localNetworksCallback);
        // MeshNode.start() enters native code and may create keys, sockets, and
        // worker threads.  Do not hold the service main thread while that
        // happens: Android delivers BLE scan and GATT callbacks there.
        new Thread(this::startRustMesh, "dmesh-rust-mesh").start();

    }

    public void onDestroy() {
        activeService = null;
        if (batteryMonitor != null) {
            batteryMonitor.close();
            batteryMonitor = null;
        }
        if (connectivityManager != null && localNetworksCallback != null) {
            connectivityManager.unregisterNetworkCallback(localNetworksCallback);
            localNetworksCallback = null;
        }
        if (meshNode != null) {
            meshNode.stop();
            meshNode = null;
        }
        if (transport != null) transport.close();
        super.onDestroy();
    }

    /**
     * Android is the observer of framework network state; Rust owns the
     * resulting local-networks table and makes routing/discovery decisions.
     * This deliberately sends a bounded byte snapshot rather than Java
     * network objects or framework callbacks through JNI.
     */
    private void publishLocalNetworks() {
        if (connectivityManager == null) {
            return;
        }
        try {
            TreeMap<String, LocalNetwork> networks = new TreeMap<>();
            java.util.Enumeration<NetworkInterface> all = NetworkInterface.getNetworkInterfaces();
            while (all != null && all.hasMoreElements()) {
                NetworkInterface networkInterface = all.nextElement();
                String name = networkInterface.getName();
                if (name == null || name.isEmpty() || networkInterface.isLoopback()) {
                    continue;
                }
                LocalNetwork row = new LocalNetwork(name);
                row.up = networkInterface.isUp();
                row.multicast = networkInterface.supportsMulticast();
                for (InterfaceAddress address : networkInterface.getInterfaceAddresses()) {
                    row.addresses.add(address.getAddress().getHostAddress());
                }
                networks.put(name, row);
            }
            for (Network network : connectivityManager.getAllNetworks()) {
                LinkProperties properties = connectivityManager.getLinkProperties(network);
                if (properties == null || properties.getInterfaceName() == null) {
                    continue;
                }
                String name = properties.getInterfaceName();
                LocalNetwork row = networks.get(name);
                if (row == null) {
                    row = new LocalNetwork(name);
                    networks.put(name, row);
                }
                row.active = true;
                NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
                if (capabilities != null) {
                    row.internet |= capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
                    row.validated |= capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
                    row.metered |= !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
                    addTransport(row.transports, capabilities, NetworkCapabilities.TRANSPORT_WIFI, "wifi");
                    addTransport(row.transports, capabilities, NetworkCapabilities.TRANSPORT_ETHERNET, "ethernet");
                    addTransport(row.transports, capabilities, NetworkCapabilities.TRANSPORT_CELLULAR, "cellular");
                    addTransport(row.transports, capabilities, NetworkCapabilities.TRANSPORT_VPN, "vpn");
                    addTransport(row.transports, capabilities, NetworkCapabilities.TRANSPORT_BLUETOOTH, "bluetooth");
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                            && transport != null && !transport.currentStaSsid().isEmpty()) {
                        row.ssid = transport.currentStaSsid();
                    }
                }
                for (LinkAddress address : properties.getLinkAddresses()) {
                    String text = address.getAddress().getHostAddress();
                    if (!row.addresses.contains(text)) row.addresses.add(text);
                }
                for (InetAddress server : properties.getDnsServers()) {
                    String text = server.getHostAddress();
                    if (!row.dnsServers.contains(text)) row.dnsServers.add(text);
                }
                for (RouteInfo route : properties.getRoutes()) {
                    InetAddress gateway = route.getGateway();
                    if (gateway != null && !gateway.isAnyLocalAddress()) {
                        String text = gateway.getHostAddress();
                        if (!row.gateways.contains(text)) row.gateways.add(text);
                    }
                }
            }
            Bundle snapshot = new Bundle();
            ArrayList<Bundle> rows = new ArrayList<>();
            for (LocalNetwork row : networks.values()) {
                rows.add(row.toBundle());
            }
            snapshot.putParcelableArrayList("networks", rows);
            MeshNode.radioMessage("radio.local_networks.update", "",
                    CborMessageCodec.encodeBundle(snapshot), -1);
            // The common announce carries framework-observed UDP6 endpoints.
            // Java reports facts only; Rust owns the announce and sender.
            if (transport != null) {
                String staLinkLocal = "";
                String apLinkLocal = "";
                for (LocalNetwork row : networks.values()) {
                    if (!row.active) continue;
                    String linkLocal = firstLinkLocal(row.addresses);
                    if (linkLocal.isEmpty()) continue;
                    if (row.ssid != null && !row.ssid.isEmpty()) staLinkLocal = linkLocal;
                    else if (transport.apActive() && row.transports.contains("wifi")) apLinkLocal = linkLocal;
                }
                transport.updateLinkLocalAddresses(staLinkLocal, apLinkLocal);
            }
            // Trigger the independent UDP6 multicast announce immediately on
            // each observed network change; the five-minute loop remains the
            // passive refresh, not the only chance to become visible.
            if (meshNode != null) meshNode.triggerAnnounce();
        } catch (Exception error) {
            Log.w(TAG, "Unable to snapshot local networks", error);
        }
    }

    /** Report Android memory facts to Rust; Rust applies scheduling policy. */
    private void submitMemoryTelemetry(int trimLevel) {
        try {
            ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
            ActivityManager.MemoryInfo memory = new ActivityManager.MemoryInfo();
            manager.getMemoryInfo(memory);
            String json = "{\"source\":\"android\",\"event\":\"memory\""
                    + ",\"memory_available_bytes\":" + memory.availMem
                    + ",\"memory_low\":" + memory.lowMemory
                    + ",\"memory_threshold_bytes\":" + memory.threshold
                    + ",\"trim_level\":" + trimLevel + "}";
            MeshNode.radioMessage("radio.power.status", "",
                    json.getBytes(StandardCharsets.UTF_8), -1);
        } catch (Throwable error) {
            Log.d(TAG, "Rust memory telemetry unavailable", error);
        }
    }

    private static void addTransport(ArrayList<String> transports, NetworkCapabilities capabilities,
                                     int transport, String name) {
        if (capabilities.hasTransport(transport)) transports.add(name);
    }

    private static final class LocalNetwork {
        final String name;
        final ArrayList<String> addresses = new ArrayList<>();
        final ArrayList<String> dnsServers = new ArrayList<>();
        final ArrayList<String> gateways = new ArrayList<>();
        final ArrayList<String> transports = new ArrayList<>();
        boolean up;
        boolean multicast;
        boolean active;
        boolean internet;
        boolean validated;
        boolean metered;
        String ssid;

        LocalNetwork(String name) { this.name = name; }

        Bundle toBundle() {
            Bundle row = new Bundle();
            row.putString("interface", name);
            row.putBoolean("up", up);
            row.putBoolean("multicast", multicast);
            row.putBoolean("active", active);
            row.putBoolean("internet", internet);
            row.putBoolean("validated", validated);
            row.putBoolean("metered", metered);
            row.putStringArrayList("addresses", addresses);
            row.putStringArrayList("dns_servers", dnsServers);
            row.putStringArrayList("gateways", gateways);
            row.putStringArrayList("transports", transports);
            if (ssid != null && !ssid.isEmpty()) row.putString("ssid", ssid);
            return row;
        }
    }

    private static String firstLinkLocal(ArrayList<String> addresses) {
        for (String address : addresses) {
            if (address != null && address.startsWith("fe80:")) {
                int zone = address.indexOf('%');
                return zone < 0 ? address : address.substring(0, zone);
            }
        }
        return "";
    }

    static DMService getActiveService() {
        return activeService;
    }

    MeshNode shellMeshNode() {
        return meshNode;
    }

    String applyShellTransportProjection(String projection) {
        return transport == null ? "transport_unavailable" : transport.applyRustProjection(projection);
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
            node.start(getApplicationContext(), RUST_SSH_PORT, RUST_HTTP_PORT);
            messageGateway = new MessageStreamGateway(this);
            node.setCallback(messageGateway);
            meshNode = node;
            // Start Aware only after the native event sink exists. Starting
            // it in onCreate races attach/publish/subscribe callbacks against
            // nativeStartMesh and makes a live Android NAN session look
            // inactive to the shared Rust telemetry handler.
            if (transport != null) {
                transport.configureNanIdentity(node.getPublicKey());
                transport.startBaseline();
            }
            Log.d(TAG, "Rust mesh node started: ssh=" + RUST_SSH_PORT
                    + " http=" + RUST_HTTP_PORT
                    + " pubkey=" + meshNode.getPublicKey());
        } catch (Throwable t) {
            Log.w(TAG, "Failed to start Rust mesh node", t);
        }
    }

    @Override
    protected boolean onDirectStream(DirectBinder.DirectMessage message, Parcel reply)
            throws RemoteException {
        if (message == null) return false;
        MeshStream stream = message.stream != null ? message.stream : new MeshStream(null);

        // Caller identity plumbing
        int uid = message.callingUid;
        int pid = message.callingPid;
        PackageManager pm = getPackageManager();
        String callingPkg = "";
        String certSha256 = "";
        boolean isSameSig = false;

        if (uid == Process.myUid()) {
            callingPkg = getPackageName();
            isSameSig = true;
        } else if (pm != null && uid > 0) {
            String[] packages = pm.getPackagesForUid(uid);
            if (packages != null && packages.length > 0) {
                callingPkg = packages[0];
            }
            isSameSig = (pm.checkSignatures(uid, Process.myUid()) == PackageManager.SIGNATURE_MATCH);
            try {
                if (callingPkg != null && !callingPkg.isEmpty()) {
                    android.content.pm.PackageInfo pi = pm.getPackageInfo(callingPkg, PackageManager.GET_SIGNING_CERTIFICATES);
                    if (pi != null && pi.signingInfo != null) {
                        Signature[] sigs = pi.signingInfo.getApkContentsSigners();
                        if (sigs != null && sigs.length > 0) {
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
                            byte[] digest = md.digest(sigs[0].toByteArray());
                            StringBuilder sb = new StringBuilder();
                            for (byte b : digest) {
                                sb.append(String.format("%02x", b));
                            }
                            certSha256 = sb.toString();
                        }
                    }
                }
            } catch (Throwable t) {
                Log.d(TAG, "failed to get caller signing certificate", t);
            }
        }

        stream.data.putInt("caller_uid", uid);
        stream.data.putInt("caller_pid", pid);
        stream.data.putString("caller_package", callingPkg);
        stream.data.putBoolean("caller_same_sig", isSameSig);
        stream.data.putString("caller_cert_sha256", certSha256);
        stream.fields.put("caller_uid", String.valueOf(uid));
        stream.fields.put("caller_package", callingPkg);
        stream.fields.put("caller_same_sig", String.valueOf(isSameSig));
        stream.fields.put("caller_cert_sha256", certSha256);

        // Routing: if external intent target, delegate to messageGateway
        if (stream.to != null && stream.to.startsWith("intent:")) {
            MessageStreamGateway gateway = messageGateway;
            return gateway != null && gateway.onDirectMessage(stream, message.callback);
        }

        // Local node command/query: dispatch to Rust MeshNode
        String method = stream.method;
        if (method == null || method.isEmpty()) {
            method = stream.uri;
        }
        if (method == null || method.isEmpty()) {
            method = "discovery.nodes";
        }
        if ("lmesh.nodes".equals(method) || "nodes".equals(method) || "devices".equals(method)) {
            method = "discovery.nodes";
        } else if ("lmesh.status".equals(method) || "status".equals(method)) {
            method = "discovery.status";
        }

        StringBuilder args = new StringBuilder();
        args.append("caller_uid=").append(uid);
        if (!callingPkg.isEmpty()) args.append(" caller_package=").append(callingPkg);
        args.append(" caller_same_sig=").append(isSameSig);
        if (!certSha256.isEmpty()) args.append(" caller_cert_sha256=").append(certSha256);
        for (String key : stream.fields.keySet()) {
            if (!key.startsWith("caller_")) {
                args.append(" ").append(key).append("=").append(stream.fields.get(key));
            }
        }

        byte[] respBytes = null;
        try {
            respBytes = MeshNode.radioMessage(method, args.toString(), stream.payload, -1);
        } catch (Throwable t) {
            Log.w(TAG, "MeshNode dispatch failed for " + method, t);
        }
        if (respBytes == null) {
            respBytes = new byte[0];
        }

        // Return reply: synchronous 2-way vs asynchronous 1-way
        if (!message.isOneWay() && reply != null) {
            DirectBinder.writeReply(reply, respBytes, stream.encoding, null);
            return true;
        } else if (message.callback != null) {
            DirectBinder.transact(message.callback, DirectBinder.TRANSACT_EVENT,
                    respBytes, stream.encoding, null, null, null);
            return true;
        }
        return true;
    }

    @Override
    protected boolean onDirectStream(MeshStream stream, IBinder callback, Parcel reply)
            throws RemoteException {
        MessageStreamGateway gateway = messageGateway;
        return gateway != null && gateway.onDirectMessage(stream, callback);
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
