package com.github.costinm.dmesh.web;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.BaseMsgService;
import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;

public class WebBridgeService extends BaseMsgService implements MessageHandler {
    private static final String TAG = "DMeshWebSvc";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        String action = intent.getAction();
        if (WebUrls.OPEN_URL_ACTION.equals(action)) {
            openUrl(intent.getStringExtra(WebUrls.EXTRA_URL));
            return START_NOT_STICKY;
        }
        if (WebUrls.FORWARD_PORT_ACTION.equals(action)) {
            requestForward(intent.getExtras());
            return START_NOT_STICKY;
        }
        return super.onStartCommand(intent, flags, startId);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        mux.subscribe("/web", this);
    }

    @Override
    protected boolean handleInMessage(Message msg) {
        Bundle data = msg.getData();
        String uri = data.getString(":uri", "");
        if ("/web/open".equals(uri)) {
            openUrl(data.getString(WebUrls.EXTRA_URL));
            return true;
        }
        if ("/web/forward".equals(uri)) {
            requestForward(data);
            return true;
        }
        return super.handleInMessage(msg);
    }

    @Override
    public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo,
                              String[] args) {
        MsgFrame frame = MsgFrame.fromMessage(msg);
        if ("/web/open".equals(frame.method)) {
            openUrl(frame.fields.get(WebUrls.EXTRA_URL));
        } else if ("/web/forward".equals(frame.method)) {
            Bundle data = msg.getData();
            requestForward(data);
        } else {
            return;
        }
        if (replyTo != null) {
            MsgFrame receipt = new MsgFrame("web.received");
            receipt.id = frame.id;
            receipt.fields.put("from", "app-web");
            receipt.fields.put("method", frame.method);
            replyTo.sendFrame(receipt);
        }
    }

    private void openUrl(String url) {
        if (url == null || url.length() == 0) {
            url = WebUrls.HOME_URL;
        }
        Intent intent = new Intent(WebUrls.OPEN_ACTION);
        intent.setComponent(new ComponentName(this, WebActivity.class));
        intent.putExtra(WebUrls.EXTRA_URL, url);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
    }

    private void requestForward(Bundle args) {
        final Message msg = Message.obtain();
        Bundle data = msg.getData();
        data.putString(":uri", "/web/forward");
        data.putString(WebUrls.EXTRA_HOST, valueOrDefault(args, WebUrls.EXTRA_HOST, "127.0.0.1"));
        data.putString(WebUrls.EXTRA_PORT, valueOrDefault(args, WebUrls.EXTRA_PORT, "22"));
        data.putString(WebUrls.EXTRA_LOCAL_PORT, valueOrDefault(args, WebUrls.EXTRA_LOCAL_PORT, "10022"));

        Intent intent = new Intent();
        intent.setComponent(new ComponentName(WebUrls.APP_D_MESH_PACKAGE, WebUrls.APP_D_MESH_SERVICE));

        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                try {
                    new Messenger(service).send(msg);
                    Log.d(TAG, "Forward request sent to app-dmesh " + data);
                } catch (RemoteException e) {
                    Log.w(TAG, "Unable to send forward request to app-dmesh", e);
                } finally {
                    unbindService(this);
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
            }
        };

        if (!bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            Log.w(TAG, "Unable to bind app-dmesh service");
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
