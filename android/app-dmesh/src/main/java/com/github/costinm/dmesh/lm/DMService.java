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

import com.github.costinm.dmesh.lm3.LocalMesh;

import java.io.IOException;
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

    // Implements the Wifi, discovery messaging interface, using Android APIs.
    static LocalMesh wifi;

    // Notification bar UI - handles messages from the mux to update the bar.
    private NotificationHandler nh;

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
        Log.d(TAG, "On Trim memory");
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

        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        String dataDir = getBaseContext().getFilesDir().getAbsolutePath();

        dmjni.Dmjni.initDmesh(dataDir, new dmjni.MessageHandler() {
            @Override
            public void handle(String s, byte[] bytes, byte[] bytes1) {

                Log.d(TAG, "MESSAGE FROM NATIVE" + s);
            }
        });

        wifi = LocalMesh.get(this.getApplicationContext());

        nh = new NotificationHandler(this);

        // Dispatching messages on this service.
        mux.subscribe("ble", wifi.ble);
        mux.subscribe("wifi", wifi);
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

        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        Network[] nets = cm.getAllNetworks();
        for (Network n: nets) {
            // if connected, type WIFI
            LinkProperties lp = cm.getLinkProperties(n);
            try {
                NetworkInterface ni = NetworkInterface.getByName(lp.getInterfaceName());
                Log.d(TAG, "NetworkInterface: " + ni);
                mux.publish("/netif/" + ni.getName());
                for (InterfaceAddress nia:  ni.getInterfaceAddresses()) {
                    InetAddress ia = nia.getAddress();
                    if (ia instanceof Inet6Address) {
                        Log.d(TAG, "I6 " + ((Inet6Address)ia).getScopeId() + " " +
                                ((Inet6Address)ia).getHostAddress());
                        mux.publish("/netip/" + ni.getName() + "/" + nia.getAddress());
                    } else {
                        mux.publish("/netip/" + ni.getName() + "/" + nia.getAddress());
                    }
                }
            } catch (SocketException e) {
                e.printStackTrace();
            }
        }

        LMJob.schedule(this.getApplicationContext(), 15 * 60 * 1000);

    }

    public void onDestroy() {
        wifi.onDestroy();
        super.onDestroy();
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
            return START_NOT_STICKY;
        }

        try {
            startForeground( 5228, nh.getNotification(new Bundle()), ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING);
            Log.d(TAG, "Starting fg");
            fg = true;
        } catch (Throwable t) {
            t.printStackTrace();
        }

        //VpnService.maybeStartVpn(prefs, this);

        return super.onStartCommand(intent, flags, startId);
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
