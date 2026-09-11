package com.github.costinm.dmesh.lm3;

import android.content.Context;
import android.os.Handler;
import java.util.Map;

/**
 * P2P Group Owner helper managing Wi-Fi Direct operations for LocalMesh.
 */
public class P2pGroupOwner {
    private final Context ctx;
    private final Handler handler;
    private boolean radioClaimed = false;

    public interface Callback {
        void onStarted(String ssid, String passphrase);
        void onError(String error);
    }

    public interface StopCallback {
        void onStopped();
        void onError(String error);
    }

    public interface ServiceCallback {
        void onAdvertising();
        void onError(String error);
    }

    public interface DiscoveryCallback {
        void onStarted();
        void onService(String instance, String type, String device);
        void onTxt(String domain, Map<String, String> attributes, String device);
        void onError(String error);
    }

    public interface SimpleCallback {
        void onDone();
    }

    public P2pGroupOwner(Context ctx, Handler handler) {
        this.ctx = ctx.getApplicationContext();
        this.handler = handler;
    }

    public synchronized boolean isRadioClaimed() {
        return radioClaimed;
    }

    public synchronized void start(Callback cb) {
        radioClaimed = true;
        if (cb != null) {
            cb.onError("not_implemented");
        }
    }

    public synchronized void stop(StopCallback cb) {
        radioClaimed = false;
        if (cb != null) {
            cb.onStopped();
        }
    }

    public synchronized void stop(SimpleCallback cb) {
        radioClaimed = false;
        if (cb != null) {
            cb.onDone();
        }
    }

    public synchronized void stop() {
        radioClaimed = false;
    }

    public synchronized void advertiseTransportStart(byte[] data, ServiceCallback cb) {
        if (cb != null) {
            cb.onError("not_implemented");
        }
    }

    public synchronized void discoverDmesh(DiscoveryCallback cb) {
        if (cb != null) {
            cb.onError("not_implemented");
        }
    }
}
