package com.github.costinm.dmesh.lm3;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.NetworkSpecifier;
import android.net.wifi.aware.AttachCallback;
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
import android.widget.Toast;

import androidx.annotation.RequiresApi;

import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.Hex;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@TargetApi(Build.VERSION_CODES.O)
public class Nan {
    private static final String TAG = "DM/wifi/nan";
    static Map<String, Device> devices = new HashMap<>();
    public WifiAwareManager nanMgr;
    public String nanId;
    Context ctx;
    Wifi wifi;
    WifiAwareSession nanSession;
    // Not null if publish session active and nan active
    PublishDiscoverySession pubSession;
    // Not null if sub session active
    SubscribeDiscoverySession subSession;
    // Intended status of NAN subscription. subType indicates the type.
    boolean nanSub;
    int subType = SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE;
    // Intended status of NAN publishing.
    boolean nanPub;
    int pubType = PublishConfig.PUBLISH_TYPE_SOLICITED;
    // Intended status of NAN radio, based on command/setting.
    // If true, when possible radio will be started.
    boolean nanActive;
    byte[] nanMac;
    String pubServiceName = "dmesh";
    byte[] pubServiceInfo;

    // called when mgr reports 'isAvailable'. NAN may be turned off when P2P is enabled or in
    // many other cases. When it returns, if we sub or adv attach will be called again.
    int msgId;

    public Nan(Wifi wifi) {
        this.wifi = wifi;
        this.ctx = wifi.ctx;

        nanMgr = ctx.getSystemService(WifiAwareManager.class);
        if (nanMgr == null) {
            return;
        }

        if (nanMgr.getCharacteristics() != null) {
            Log.d(TAG, "/NAN/Char" + nanMgr.getCharacteristics().getMaxServiceNameLength() +
                    "/" + nanMgr.getCharacteristics().getMaxServiceSpecificInfoLength() + " " +
                    nanMgr.isAvailable());
        } else {
            Log.d(TAG, "/NAN/Avail" + nanMgr.isAvailable());
        }
    }

    boolean isAvailable() {
        return nanMac != null && nanMgr != null && nanMgr.isAvailable();
    }

    /**
     * Start the NAN radio, and after that possibly publish or subscribe, if the mode is enabled.
     * Once attach succeeds the radio will send discovery beacons and participate in NAN master.
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    private void startNanRadio() {
        if (nanMgr == null) {
            return;
        }
        nanActive = true;
        if (!nanMgr.isAvailable()) {
            return;
        }
        Log.d(TAG, "/NAN/ATTACH");
        try {
            nanMgr.attach(new AttachCallback() {
                @Override
                public void onAttached(WifiAwareSession session) {
                    super.onAttached(session);
                    nanSession = session;

                    if (nanPub) {
                        publish();
                    }

                    if (nanSub) {
                        startNanSub();
                    }

                    MsgMux.get(ctx).publish("/net/NAN/Attach");
                }

                @Override
                public void onAttachFailed() {
                    super.onAttachFailed();
                    MsgMux.get(ctx).publish("/net/NAN/AttachError");
                }
            }, new IdentityChangedListener() {
                @Override
                public void onIdentityChanged(byte[] mac) {
                    super.onIdentityChanged(mac);
                    nanMac = mac;
                    nanId = new String(Hex.encode(mac));
                    MsgMux.get(ctx).publish("/net/NAN/MAC/" + nanId);

                    wifi.sendWifiDiscoveryStatus("/nan/id", "");
                }
            }, null);
        } catch (Throwable t) {
            Log.d(TAG, "/NAN/ " + t);
            MsgMux.get(ctx).publish("/net/NAN/AttachError", "err", t.getMessage());
        }
    }

    /**
     * Set nan radio desired state.
     * <p>
     * If on - will attempt to attach, and if not possible will attach when it it becomes so.
     * <p>
     * If off, close the NAN session, will stop sending discovery beacons - and not start again.
     */
    public void nanRadio(boolean on) {
        nanActive = on;
        if (on) {
            startNanRadio();
        } else {
            nanActive = false;
            // TODO: for now auto-starts if available.
            if (nanSession == null) {
                return;
            }

            nanSession.close();
            nanSession = null;
            nanId = null; // will be reset on next start.
        }
    }

    void onDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, boolean byPublisher) {

        Device bd = new Device(peerHandle, serviceSpecificInfo);
        Device old = devices.get(bd.id);
        if (old == null) {
            onDiscovery(bd, bd.id, true);
        } else {
            // See BLE - it keeps discovering device in range.
            if (SystemClock.elapsedRealtime() - old.lastScan > 120000) {
                onDiscovery(bd, bd.id, false);
            }
        }
        devices.put(bd.id, bd);


        String info = new String(serviceSpecificInfo);

        // for debugging
        if (byPublisher) {
            // Used with active sub and passive pub
            MsgMux.get(ctx).publish("/net/NAN/PubServiceDiscovered/" + info + "/" + peerHandle);
            bd.nanSession = pubSession;
        } else {
            // Used with active pub and passive sub
            MsgMux.get(ctx).publish("/net/NAN/SubServiceDiscovered/" + info + "/" + peerHandle);
            bd.nanSession = subSession;
        }
        send(bd.id, "FOUND");

        //conNan(bd.id);
    }

    private void onDiscovery(Device bd, String id, boolean b) {
        wifi.sendWifiDiscoveryStatus("nan", "");
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void publish() {
        PublishConfig pub = new PublishConfig.Builder().setServiceName(pubServiceName)
                .setPublishType(pubType) // silent, but respond to active requests
                .setTerminateNotificationEnabled(true)
                .setServiceSpecificInfo(wifi.adv.getBytes())
                .build();
        nanSession.publish(pub, new MyNanCallback(true) {
            @Override
            public void onPublishStarted(PublishDiscoverySession session) {
                super.onPublishStarted(session);
                Log.d(TAG, "/NAN/PubStart");
                MsgMux.get(ctx).publish("/net/NAN/PubStart");
                pubSession = session;
            }

            @Override
            public void onSessionTerminated() {
                super.onSessionTerminated();
                pubSession = null;
                MsgMux.get(ctx).publish("/net/NAN/PubStop", "dev", "" + devices);
            }

            @Override
            public void onMessageReceived(PeerHandle peerHandle, byte[] message) {

                super.onMessageReceived(peerHandle, message);
                String msg = new String(message);
                if (msg.startsWith("PING")) {
                    pubSession.sendMessage(peerHandle, 1, "PONGP".getBytes());
                    Toast.makeText(wifi.ctx, "PINGP " + msg, Toast.LENGTH_SHORT);
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
                    wifi.cm.requestNetwork(nr, new Wifi.ConnectivityCallback(wifi), 10000);
                    pubSession.sendMessage(peerHandle, 1, "CONS".getBytes());

                } else {
                    Toast.makeText(wifi.ctx, "NAN: " + msg, Toast.LENGTH_SHORT);
                }
                MsgMux.get(ctx).publish("/net/NAN/TXT/" + msg + "/" + peerHandle);
            }
        }, null);
    }

    public void onWifiAwareStateChanged(Intent i) {
        i.getBooleanExtra("foo", true);
        Log.d("NAN", "State changed " + i.getAction() + " " + i.getExtras());
        if (isAvailable()) {
            if (nanActive) {
                startNanRadio();
            }
        } else {
            nanSession = null;
            MsgMux.get(ctx).publish("/net/NAN/STOP");
        }
    }

    public void pub(boolean active) {
        nanPub = true;
        pubType = active ? PublishConfig.PUBLISH_TYPE_UNSOLICITED : PublishConfig.PUBLISH_TYPE_SOLICITED;

        if (!isAvailable()) {
            nanRadio(true);
            return;
        }
        if (pubSession == null) {
            if (nanSession == null) {
                startNanRadio(); // will use nanAnnActive to activate publish when attached
            } else {
                publish();
            }
        }
    }

    public void stopPub() {
        nanPub = false;
        if (pubSession != null) {
            pubSession.close();
            pubSession = null;
        }
    }

    public void sub(Handler h, boolean active) {
        subType = active ? SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE : SubscribeConfig.SUBSCRIBE_TYPE_PASSIVE;
        nanSub = active;

        if (nanSession == null) {
            nanRadio(true); // will set sub session
        } else {
            startNanSub();
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
    private void startNanSub() {

        SubscribeConfig cfg = new SubscribeConfig.Builder()
                .setServiceName("dmesh")
                .setServiceSpecificInfo(wifi.adv.getBytes())
                .setSubscribeType(subType)
                .setTerminateNotificationEnabled(true)
                .build();
        Log.d(TAG, "/NAN/Subscribe");

        nanSession.subscribe(cfg, new MyNanCallback(false) {

            @Override
            public void onSubscribeStarted(SubscribeDiscoverySession session) {
                super.onSubscribeStarted(session);
                Log.d(TAG, "/NAN/SubStart" + session);
                MsgMux.get(ctx).publish("/net/NAN/SubStart");
                subSession = session;
            }

            @Override
            public void onSessionTerminated() {
                super.onSessionTerminated();
                subSession = null;
                MsgMux.get(ctx).publish("/net/NAN/SubStop", "dev", "" + devices);
            }


            @Override
            public void onMessageReceived(final PeerHandle peerHandle, byte[] message) {
                super.onMessageReceived(peerHandle, message);
                String msg = new String(message);
                if (msg.equals("CONS")) {
                    wifi.delayHandler.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            NetworkSpecifier ns;
                            if (Build.VERSION.SDK_INT >= 29) {
                                ns = new WifiAwareNetworkSpecifier.Builder(subSession, peerHandle).build();
                            } else {
                                ns = subSession.createNetworkSpecifierOpen(peerHandle);
                            }
                            NetworkRequest nr = new NetworkRequest.Builder()
                                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                                    .setNetworkSpecifier(ns).build();
                            wifi.cm.requestNetwork(nr, new Wifi.ConnectivityCallback(wifi), 10000);
                        }
                    }, 3000);
                } else {
                    Toast.makeText(wifi.ctx, "NAN: " + msg, Toast.LENGTH_SHORT);
                }

                MsgMux.get(ctx).publish("/net/NAN/TXT/" + msg + "/" + peerHandle);
                Log.d(TAG, "NAN received: " + msg + " " + peerHandle);
            }
        }, null);

    }

    /**
     * Connect to a NAN device.
     *
     * @param id - the primary ID, from the pub announce.
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public void conNan(String id) {
        if ("0".equals(id) || "*".equals(id)) {
            for (Device d : devices.values()) {
                subSession.sendMessage(d.nan, msgId++, "CON".getBytes());
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
            subSession.sendMessage(d.nan, msgId++, "CON".getBytes());
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void sendAll(String id) {
        if (subSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == subSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send " + d.id + " " + d.nan + " " + msgId);
                    subSession.sendMessage(d.nan, msgId++, id.getBytes());
                }
            }
        }
        if (pubSession != null) {
            for (Device d : devices.values()) {
                if (d.nan != null && d.nanSession == pubSession) {
                    // May log: DiscoverySession: called on terminated session
                    Log.d(TAG, "NAN send pub " + d.id + " " + d.nan + " " + msgId);
                    pubSession.sendMessage(d.nan, msgId++, id.getBytes());
                }
            }
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void send(String id, String msg) {
        Device d = devices.get(id);
        if (d != null && d.nan != null && d.nanSession != null) {
            d.nanSession.sendMessage(d.nan, msgId++, msg.getBytes());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    class MyNanCallback extends DiscoverySessionCallback {
        private final boolean pub;

        public MyNanCallback(boolean pub) {
            this.pub = pub;
        }

        @Override
        public void onSessionTerminated() {
            devices.clear(); // TODO: only devices of given type
            super.onSessionTerminated();
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

            onDiscovered(peerHandle, serviceSpecificInfo, pub);
        }


        @Override
        public void onSessionConfigUpdated() {
            super.onSessionConfigUpdated();
            Log.d(TAG, "/NAN/PubSessionConfigUpdated");
        }

        @Override
        public void onSessionConfigFailed() {
            super.onSessionConfigFailed();
            MsgMux.get(ctx).publish("/net/NAN/PubSessionConfigFailed");
        }

        @Override
        public void onServiceDiscoveredWithinRange(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter, int distanceMm) {
            onServiceDiscovered(peerHandle, serviceSpecificInfo, matchFilter);
        }

        @Override
        public void onMessageSendSucceeded(int messageId) {
            super.onMessageSendSucceeded(messageId);
            Log.d(TAG, "/NAN/SENT/" + messageId);
        }

        @Override
        public void onMessageSendFailed(int messageId) {
            super.onMessageSendFailed(messageId);
            MsgMux.get(ctx).publish("/net/NAN/MSGERR", "id", Integer.toString(messageId));
        }
    }


}
