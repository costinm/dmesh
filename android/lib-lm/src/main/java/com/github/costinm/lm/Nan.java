package com.github.costinm.lm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.NetworkSpecifier;
import android.net.wifi.aware.AttachCallback;
import android.net.wifi.aware.DiscoverySessionCallback;
import android.net.wifi.aware.PeerHandle;
import android.net.wifi.aware.PublishConfig;
import android.net.wifi.aware.PublishDiscoverySession;
import android.net.wifi.aware.SubscribeConfig;
import android.net.wifi.aware.SubscribeDiscoverySession;
import android.net.wifi.aware.WifiAwareManager;
import android.net.wifi.aware.WifiAwareSession;
import android.os.Build;
import android.os.Handler;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.util.List;

@RequiresApi(api = Build.VERSION_CODES.O)
public class Nan {
    static final String TAG="LM-NAN";
    Handler serviceHandler;
    Context ctx;

    public Nan(Context ctx, Handler h) {
        this.serviceHandler = h;
        this.ctx = ctx;
        Log.d(TAG, "HAS WIFI_AWARE");
    }

    void startWifiAware() {

        final WifiAwareManager mgr = ctx.getSystemService(WifiAwareManager.class);
        IntentFilter filter =
                new IntentFilter(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED);
        BroadcastReceiver myReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (mgr.isAvailable()) {
                    Log.d(TAG, "Wifi manager available");
                    attachWifiAware(mgr, ctx);
                } else {
                    Log.d(TAG, "Wifi manager not available");
                }
            }
        };
        ctx.registerReceiver(myReceiver, filter);
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void attachWifiAware(WifiAwareManager mgr, final Context ctx) {
        final ConnectivityManager cm = ctx.getSystemService(ConnectivityManager.class);
        mgr.attach(new AttachCallback() {

            @Override
            public void onAttached(WifiAwareSession session) {
                super.onAttached(session);
                Log.d(TAG, "NAN Attached");

                // service name is converted to 6byte hash
                // publishType default is passinve - i.e. will respond, but not broadcast
                // match filter not used
                PublishConfig config = new PublishConfig.Builder()
                        .setServiceName("dmesh")
                        .build();
                // TODO: set the 8-byte mesh ID into service info
                //        .setServiceSpecificInfo()
                // TODO: evaluate if setting TTL to match p2p is useful

                session.publish(config, new DiscoverySessionCallback() {
                    PublishDiscoverySession d;
                    @Override
                    public void onPublishStarted(PublishDiscoverySession session) {
                        Log.d(TAG, "publish started " + session);
                        // can update the session
                        d = session;
                    }
                    @Override
                    public void onMessageReceived(PeerHandle peerHandle, byte[] message) {
                        Log.d(TAG, "Message received " + peerHandle + " " + new String(message));
                        NetworkSpecifier networkSpecifier = d.createNetworkSpecifierOpen(peerHandle);
                        NetworkRequest nr = new NetworkRequest.Builder().setNetworkSpecifier(networkSpecifier)
                                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                                .build();

                        cm.requestNetwork(nr, new ConnectivityManager.NetworkCallback() {});
                    }}, null);

                SubscribeConfig sub = new SubscribeConfig.Builder()
                        .setServiceName("dmesh")
                        .build();

                session.subscribe(sub, new DiscoverySessionCallback() {
                    SubscribeDiscoverySession s;
                    @Override
                    public void onSubscribeStarted(SubscribeDiscoverySession session) {
                        Log.d(TAG, "NAN subscribeStarted " + session);
                        // just update subscribe
                        s = session;
                    }

                    @Override
                    public void onServiceDiscovered(PeerHandle peerHandle,
                                                    byte[] serviceSpecificInfo, List<byte[]> matchFilter) {
                        Log.d(TAG, "NAN serviceDiscoverred " + peerHandle + " " +
                                serviceSpecificInfo + " " + matchFilter);
                        s.sendMessage(peerHandle, 1, "Hello".getBytes());
                        NetworkSpecifier networkSpecifier = s.createNetworkSpecifierOpen(peerHandle);
                        NetworkRequest nr = new NetworkRequest.Builder().setNetworkSpecifier(networkSpecifier)
                                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                                .build();

                        cm.requestNetwork(nr, new ConnectivityManager.NetworkCallback() {});
                    }
                }, null);
            }

            @Override
            public void onAttachFailed() {
                super.onAttachFailed();
                Log.d(TAG, "NAN Attach failed");
            }
        }, serviceHandler);
    }


}
