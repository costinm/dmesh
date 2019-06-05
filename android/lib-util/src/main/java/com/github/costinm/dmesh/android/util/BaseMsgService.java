package com.github.costinm.dmesh.android.util;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * A base service exposing a Messenger interface and accepting a Messanger callback.
 *
 * Works on GB+
 */
public class BaseMsgService extends Service {

    private static final String TAG = "MsgService";
    /**
     * Handlers for incoming messages from the Service. Must be registered with the service.
     *
     * Based on :uri - currently strings not starting with /, matching on the first part of the path.
     * May be extended with better matchers.
     *
     * In gRPC terms - would be the service name.
     */
    public Map<String, MsgMux.MessageHandler> inHandlers = new HashMap<>();

    protected MsgMux mux;

    // Main Messenger used as binder, using 'inHandler' as a handler, which delegates to the
    // Service class itself.
    private Messenger inMessenger;

    @Override
    public void onCreate() {
        super.onCreate();
        mux = MsgMux.get(getApplicationContext());
    }

    /**
     * Return a Messenger object. Clients must send Messages.
     *
     * For <LMP, the identity of the caller is no available - we are going to relax the security
     * and allow the caller.
     *
     * All received messages are processed via mux.handleInMessage
     */
    @Override
    public IBinder onBind(Intent intent) {
        Messenger out = intent.getParcelableExtra("m");
        Log.d(TAG, "BIND Intent " + intent + " " + intent.getExtras());

        if (inMessenger == null) {
            Handler inHandler = new Handler(new Handler.Callback() {
                @Override
                public boolean handleMessage(Message msg) {
                    mux.handleInMessage(BaseMsgService.this, msg);
                    return true;
                }
            });
            inMessenger = new Messenger(inHandler);
        }
        return inMessenger.getBinder();
    }

    // When all clients have been disconnected
    @Override
    public boolean onUnbind(Intent intent) {
        Log.d(TAG, "UNBIND Intent " + intent + " " + intent.getExtras());
        return super.onUnbind(intent);
    }

    /**
     * Alternative to binding to the service: will pass a Messenger ("m") and a PendingIntent ("p").
     *
     * The service will use the Messenger parameter to send back an initial Message with 'replyTo'
     * set to the service Messenger.
     *
     * At this point the communication continues just like in the case of 'bind'.
     *
     * This works in BroadcastReceivers and cases where a full bind is not needed. Note that the
     * service or the app may go away at any time.
     *
     * @return
     */
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        Messenger m = intent.getParcelableExtra("m");
        if (m != null) {
            Message msg = Message.obtain();
            msg.getData().putParcelable("m", inMessenger);
            try {
                m.send(msg);
            } catch (RemoteException e) {
                e.printStackTrace();
            }

            return START_NOT_STICKY;
        }

        // Debug only - we can't verify the caller unless a message is sent.

        Message msg = Message.obtain();
        int cmd = intent.getIntExtra("what", 0);
        msg.what = cmd;

        Bundle data = msg.getData();
        if (intent.getExtras() != null) {
            data.putAll(intent.getExtras());
        }

        mux.handleInMessage(this, msg);

        return super.onStartCommand(intent, flags, startId);
    }


}
