package com.github.costinm.dmesh.web;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import com.github.costinm.dmesh.MeshService;
import com.github.costinm.dmesh.DirectBinder;
import com.github.costinm.dmesh.MeshClient;
import com.github.costinm.dmesh.MeshStream;

import java.util.ArrayList;

public class WebBridgeService extends MeshService {
    private static final String TAG = "DMeshWebSvc";
    static final String OPEN_URL_ACTION = "com.github.costinm.dmesh.web.OPEN_URL";
    static final String FORWARD_PORT_ACTION = "com.github.costinm.dmesh.web.FORWARD_PORT";
    private static final String OPEN_ACTION = "com.github.costinm.dmesh.web.OPEN";
    private final ArrayList<DirectBinder> activeEndpoints = new ArrayList<>();
    private MeshClient forwardConnection;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        String action = intent.getAction();
        if (OPEN_URL_ACTION.equals(action)) {
            openUrl(intent.getStringExtra(WebActivity.EXTRA_URL));
            return START_NOT_STICKY;
        }
        if (FORWARD_PORT_ACTION.equals(action)) {
            requestForward(intent.getExtras());
            return START_NOT_STICKY;
        }
        return super.onStartCommand(intent, flags, startId);
    }

    /** Bounded DirectBinder command used by DMesh transport conformance tests. */
    @Override
    protected boolean onDirectStream(MeshStream request, IBinder callback, Parcel reply)
            throws RemoteException {
        if (request != null && "/web/echo".equals(request.method)) {
            MeshStream response = new MeshStream("web.echo");
            response.id = request.id;
            response.replyTo = request.id;
            response.data = new Bundle(request.data);
            response.fields.putAll(request.fields);
            return callback != null && DirectBinder.transact(callback,
                    DirectBinder.TRANSACT_EVENT, response, null, null);
        }
        if (request != null && "/web/endpoint".equals(request.method)
                && request.id != null && !request.id.isEmpty() && callback != null) {
            return exerciseCallerEndpoint(request, callback);
        }
        if (request != null && "/web/open".equals(request.method)) {
            openUrl(request.data.getString(WebActivity.EXTRA_URL));
        } else if (request != null && "/web/forward".equals(request.method)) {
            requestForward(request.data);
        } else {
            return false;
        }
        if (callback != null) {
            MeshStream receipt = new MeshStream("web.received");
            receipt.replyTo = request.id;
            DirectBinder.transact(callback, DirectBinder.TRANSACT_EVENT, receipt, null, null);
        }
        return true;
    }

    /**
     * Test/proof endpoint for the common app API.  The initial Binder endpoint
     * accepts an uncorrelated app event and a correlated app request; the
     * request carries this service's Binder so its response can return here.
     */
    private boolean exerciseCallerEndpoint(MeshStream initial, IBinder routerEndpoint) {
        MeshStream oneWay = new MeshStream("web.oneway");
        oneWay.type = "event";
        oneWay.data.putString("value", "from-app-web");
        if (!DirectBinder.transact(routerEndpoint, DirectBinder.TRANSACT_EVENT,
                oneWay, null, null)) {
            return false;
        }

        String requestId = initial.id + ":app-request";
        final DirectBinder[] endpoint = new DirectBinder[1];
        endpoint[0] = new DirectBinder((code, message, parcel) -> {
            MeshStream response = message.stream;
            if (response == null || !requestId.equals(response.replyTo)) {
                return false;
            }
            synchronized (activeEndpoints) {
                activeEndpoints.remove(endpoint[0]);
            }
            MeshStream receipt = new MeshStream("web.reverse.received");
            receipt.replyTo = requestId;
            receipt.data.putString("value", response.data.getString("value"));
            return DirectBinder.transact(routerEndpoint, DirectBinder.TRANSACT_EVENT,
                    receipt, null, null);
        });
        DirectBinder appEndpoint = endpoint[0];
        synchronized (activeEndpoints) {
            activeEndpoints.add(appEndpoint);
        }
        MeshStream request = new MeshStream("web.reverse");
        request.id = requestId;
        request.type = "request";
        request.data.putString("value", "from-app-web");
        boolean sent = DirectBinder.transact(routerEndpoint, DirectBinder.TRANSACT_MESSAGE,
                request, appEndpoint, null);
        if (!sent) {
            synchronized (activeEndpoints) {
                activeEndpoints.remove(appEndpoint);
            }
        }
        return sent;
    }

    private void openUrl(String url) {
        if (url == null || url.length() == 0) {
            url = WebActivity.HOME_URL;
        }
        Intent intent = new Intent(OPEN_ACTION);
        intent.setComponent(new ComponentName(this, WebActivity.class));
        intent.putExtra(WebActivity.EXTRA_URL, url);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
    }

    private void requestForward(Bundle args) {
        MeshStream request = new MeshStream("/web/forward");
        request.id = "web-forward-" + System.nanoTime();
        request.data.putString(WebActivity.EXTRA_HOST,
                valueOrDefault(args, WebActivity.EXTRA_HOST, "127.0.0.1"));
        request.data.putString(WebActivity.EXTRA_PORT,
                valueOrDefault(args, WebActivity.EXTRA_PORT, "22"));
        request.data.putString(WebActivity.EXTRA_LOCAL_PORT,
                valueOrDefault(args, WebActivity.EXTRA_LOCAL_PORT, "10022"));
        if (forwardConnection == null) {
            forwardConnection = MeshClient.get(this);
            forwardConnection.setStreamReceiver(
                    frame -> Log.d(TAG, "Forward response " + frame.method));
        }
        if (!forwardConnection.sendStream(request)) {
            Log.w(TAG, "Unable to send DirectBinder forward request to app-dmesh");
        }
    }

    private static String valueOrDefault(Bundle args, String key, String fallback) {
        if (args == null) {
            return fallback;
        }
        String value = args.getString(key);
        return value == null || value.length() == 0 ? fallback : value;
    }
}
