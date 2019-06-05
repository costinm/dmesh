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
import android.net.wifi.aware.WifiAwareSession;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.widget.Toast;

import com.github.costinm.dmesh.android.util.Hex;
import com.github.costinm.dmesh.android.util.MsgMux;

import java.util.List;

@TargetApi(Build.VERSION_CODES.O)
public class Nan {
    Wifi wifi;
    private static final String TAG = "DM/wifi/nan";

    WifiAwareSession nanSession;
    WifiAwareManager nanMgr;
    PublishDiscoverySession pubSession;
    SubscribeDiscoverySession subSession;

    boolean nanSubActive;
    byte[] nanMac;
    String nanId;



    Context ctx;

    public Nan(Wifi wifi) {
        this.wifi = wifi;
        this.ctx = wifi.ctx;

        nanMgr = ctx.getSystemService(WifiAwareManager.class);
        if (nanMgr == null) {
            return;
        }
        Log.d(TAG, "/NAN/" + nanMgr.getCharacteristics());

        if (isAvailable()) {
            attachWifiAware();
        }
    }

    boolean isAvailable() {
        return nanMac != null && nanMgr.isAvailable();
    }

    // called when mgr reports 'isAvailable'.
    //
    @RequiresApi(api = Build.VERSION_CODES.O)
    private void attachWifiAware() {
        Log.d(TAG, "/NAN/ATTACH");
        nanMgr.attach(new AttachCallback() {
            @Override
            public void onAttached(WifiAwareSession session) {
                super.onAttached(session);
                nanSession = session;
                onNanAttach();

                startNanSub();

                MsgMux.get(ctx).broadcastTxt("/wifi/NAN/Attach");

                wifi.sendWifiDiscoveryStatus("/nan/attach");
            }

            @Override
            public void onAttachFailed() {
                super.onAttachFailed();
                MsgMux.get(ctx).broadcastTxt("/wifi/NAN/AttachError");
            }
        }, new IdentityChangedListener() {
            @Override
            public void onIdentityChanged(byte[] mac) {
                super.onIdentityChanged(mac);
                nanMac = mac;
                nanId = new String(Hex.encode(mac));
                MsgMux.get(ctx).broadcastTxt("/wifi/NAN/MAC/" + nanId);

                wifi.sendWifiDiscoveryStatus("/nan/id");
            }
        }, null);
    }

    public void updateAnnounce() {
        if (!isAvailable()) {
            return;
        }
    }


    @RequiresApi(api = Build.VERSION_CODES.O)
    class MyNanCallback extends DiscoverySessionCallback {
        private final boolean pub;

        public MyNanCallback(boolean pub) {
            this.pub = true;
        }

        @Override
        public void onSessionConfigUpdated() {
            super.onSessionConfigUpdated();
            Log.d(TAG, "/NAN/PubSessionConfigUpdated");
        }

        @Override
        public void onSessionConfigFailed() {
            super.onSessionConfigFailed();
            MsgMux.get(ctx).broadcastTxt("/wifi/NAN/PubSessionConfigFailed");
        }


        @Override
        public void onServiceDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter) {
            super.onServiceDiscovered(peerHandle, serviceSpecificInfo, matchFilter);

            MsgMux.get(ctx).broadcastTxt("/wifi/NAN/PubServiceDiscovered/" + new String(serviceSpecificInfo) + "/" + peerHandle);
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
            MsgMux.get(ctx).broadcastTxt("/wifi/NAN/MSGERR/" + messageId);
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void onNanAttach() {
        PublishConfig pub = new PublishConfig.Builder().setServiceName("dmesh")
                .setPublishType(PublishConfig.PUBLISH_TYPE_SOLICITED) // silent, but respond to active requests
                .setTerminateNotificationEnabled(true)
                .setServiceSpecificInfo(wifi.adv.getBytes())
                .build();
        nanSession.publish(pub, new MyNanCallback(true) {
            @Override
            public void onPublishStarted(PublishDiscoverySession session) {
                super.onPublishStarted(session);
                Log.d(TAG, "/NAN/PublishStart");
                pubSession = session;
            }
            @Override
            public void onSessionTerminated() {
                super.onSessionTerminated();
                pubSession = null;
                MsgMux.get(ctx).broadcastTxt("/wifi/NAN/PubSessionTerminated");
            }

            @Override
            public void onMessageReceived(PeerHandle peerHandle, byte[] message) {

                super.onMessageReceived(peerHandle, message);
                String msg = new String(message);
                if (msg.equals("PING")) {
                    pubSession.sendMessage(peerHandle, 1, "PONG".getBytes());
                    Toast.makeText(wifi.ctx, "PING " + msg, Toast.LENGTH_SHORT);
                } else if (msg.equals("CON")) {
                    NetworkSpecifier ns;
                    if (Build.VERSION.SDK_INT >= 29 && Build.VERSION.PREVIEW_SDK_INT > 0) {
                        ns = new WifiAwareManager.NetworkSpecifierBuilder().setPeerHandle(peerHandle).build();
                    } else {
                        ns = pubSession.createNetworkSpecifierOpen(peerHandle);
                    }
                    NetworkRequest nr = new NetworkRequest.Builder()
                            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                            .setNetworkSpecifier(ns).build();
                    wifi.cm.requestNetwork(nr, new Wifi.ConnectivityCallback(wifi), 10000);
                    pubSession.sendMessage(peerHandle, 1, "CONS".getBytes());

                }
                MsgMux.get(ctx).broadcastTxt("/wifi/NAN/TXT/" + msg + "/" + peerHandle);
            }
        }, null);
    }


    @RequiresApi(api = Build.VERSION_CODES.O)
    public void startNan() {
        // TODO: for now publish auto-starts if available.
        if (nanMgr == null) {
            return;
        }
        nanSubActive = true;
        if (nanSession == null) {
            attachWifiAware();
        } else {
            startNanSub();
        }
    }

    public void onWifiAwareStateChanged(Intent i) {
        if (isAvailable()) {
            MsgMux.get(ctx).broadcastTxt("/wifi/NAN/START");
            attachWifiAware();
            wifi.sendWifiDiscoveryStatus("/NAN/START");
        } else {
            nanSession = null;
            MsgMux.get(ctx).broadcastTxt("/wifi/NAN/STOP");
            wifi.sendWifiDiscoveryStatus("/NAN/STOP");
        }
    }

    public void startNanSub() {
        SubscribeConfig cfg = new SubscribeConfig.Builder()
                .setServiceName("dmesh")
                .setServiceSpecificInfo(wifi.adv.getBytes())
                .setSubscribeType(SubscribeConfig.SUBSCRIBE_TYPE_ACTIVE)
                .build();

        nanSession.subscribe(cfg, new MyNanCallback(false) {

            @Override
            public void onSubscribeStarted(SubscribeDiscoverySession session) {
                super.onSubscribeStarted(session);
                Log.d(TAG, "/NAN/SubStart");
                subSession = session;
            }
            @Override
            public void onSessionTerminated() {
                super.onSessionTerminated();
                subSession = null;
                MsgMux.get(ctx).broadcastTxt("/wifi/NAN/SubSessionTerminated");
            }

            @Override
            public void onServiceDiscovered(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter) {
                super.onServiceDiscovered(peerHandle, serviceSpecificInfo, matchFilter);
            }

            @Override
            public void onServiceDiscoveredWithinRange(PeerHandle peerHandle, byte[] serviceSpecificInfo, List<byte[]> matchFilter, int distanceMm) {
                super.onServiceDiscoveredWithinRange(peerHandle, serviceSpecificInfo, matchFilter, distanceMm);
            }

            @Override
            public void onMessageReceived(final PeerHandle peerHandle, byte[] message) {
                super.onMessageReceived(peerHandle, message);
                String msg = new String(message);
                if (msg.equals("CONS")) {
                    MsgMux.get(ctx).broadcastHandler.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            NetworkSpecifier ns;
                            if (Build.VERSION.SDK_INT >= 29) {
                                ns = new WifiAwareManager.NetworkSpecifierBuilder().setPeerHandle(peerHandle).build();
                            } else {
                                ns = pubSession.createNetworkSpecifierOpen(peerHandle);
                            }
                            NetworkRequest nr = new NetworkRequest.Builder()
                                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                                    .setNetworkSpecifier(ns).build();
                            wifi.cm.requestNetwork(nr, new Wifi.ConnectivityCallback(wifi), 10000);
                        }
                    }, 3000);
                }

            }
        }, null);

    }

    public void stopNan() {
        // TODO: for now auto-starts if available.
        if (nanSession == null) {
            return;
        }

        nanSession.close();
        nanSession = null;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void conNan(String id) {
        Device d = wifi.sdDevByAddr.get(id);
        if (d == null || subSession == null) {
            return;
        }

        if (d.nan != null) {
            subSession.sendMessage(d.nan, 1, "CON".getBytes());
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void pingNan(String id) {
        if (subSession == null) {
            return;
        }
        for (Device d: wifi.sdDevByAddr.values()) {
            if (d.nan != null) {
                subSession.sendMessage(d.nan, 1, "PING".getBytes());
            }
        }
    }



}
