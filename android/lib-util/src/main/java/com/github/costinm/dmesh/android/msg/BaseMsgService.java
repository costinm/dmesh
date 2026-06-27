package com.github.costinm.dmesh.android.msg;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

/**
 * Server-side messaging mux, using Messenger. This is similar to typical HTTP - using Binder
 * but without requiring an AIDL. Parameters can be marshalled as a Bundle (like json) or
 * in byte[] - including proto, CBOR, json - as received from remote device and without
 * expensive conversions.
 * <p>
 * The base service is exposing a Messenger interface for bind, and accepting a Messenger callback.
 * <p>
 * Works on GB+, but only LMP+ has support for credential passing and can verify the identity of the
 * caller.
 * <p>
 * Client side is Mux, who handles all in/out connections and dispatching.
 */
public class BaseMsgService extends Service {

    private static final String TAG = "MsgService";

    protected MsgMux mux;

    // Main Messenger used as binder. This will also be returned to callers of onStartService
    // that pass a messenger.
    private Messenger inMessenger;

    @Override
    public void onCreate() {
        super.onCreate();

        if (mux == null) {
            mux = MsgMux.get(getApplicationContext());
        }
        HandlerThread bgT = new HandlerThread("msg-thread");
        bgT.start();

        Handler inHandler = new Handler(bgT.getLooper(), new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                return handleInMessage(msg);
            }
        });
        inMessenger = new Messenger(inHandler);
    }

    /**
     * Return a Messenger object. Clients must send Messages.
     * <p>
     * For <LMP, the identity of the caller is no available - we are going to relax the security
     * and allow the caller.
     * <p>
     * All received messages are processed via mux.handleInMessage
     */
    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "BIND Intent " + intent + " " + intent.getExtras());
        if (intent != null && "mesh.direct".equals(intent.getAction())) {
            return db;
        }
        return inMessenger.getBinder();
    }

    protected DirectBinder db = new DirectBinder(this::handleDirectMessage);

    // When all activeIn have been disconnected
    @Override
    public boolean onUnbind(Intent intent) {
        Log.d(TAG, "UNBIND Intent " + intent + " " + intent.getExtras());
        return super.onUnbind(intent);
    }

    /**
     * onTransact implements the raw binder interface - no marshalling with Parcelable is done,
     * receiver can use the Parcel directly.
     *
     * This is the most memory efficient way to use binder - call  data.readBlob();
     * reply.writeByte((byte)n), etc;
     *
     */
    protected boolean onTransact(int code, Parcel data, Parcel reply,
                                 int flags) throws RemoteException {
        return true;
    }

    protected boolean handleDirectMessage(int code, DirectBinder.DirectMessage direct,
                                          Parcel reply) throws RemoteException {
        String key = "direct:" + Binder.getCallingUid();
        MsgConn c = mux.activeIn.get(key);
        boolean open = direct.frame != null && "1".equals(direct.frame.fields.get(":open"));
        if (c == null || open) {
            c = new DirectMsgConn(mux, direct.callback, key);
            mux.addInConnection(key, c, direct.frame == null ? Message.obtain() : direct.frame.toMessage());
            Log.d(TAG, "New direct binder client " + key);
        } else if (c instanceof DirectMsgConn && direct.callback != null) {
            ((DirectMsgConn) c).out = direct.callback;
        }
        return mux.handleFrame(key, c, direct.frame == null ? new MsgFrame(null) : direct.frame);
    }

    /**
     * Message received using the Messenger interface exposed to clients (registered handlers)
     */
    protected boolean handleInMessage(Message msg) {
        // TODO: verify MsgConn first call, replyTo
        // TODO: inject debug handler
        String key = "" + msg.sendingUid;
        MsgConn c = mux.activeIn.get(key);

        if (c == null || msg.getData().getBoolean(":open", false)) {
            c = new MsgConMessengerS(mux, msg.replyTo, key);
            mux.addInConnection(key, c, msg);
            Log.d(TAG, "New Client " + msg.sendingUid);
        }

        return mux.handleMessage(key, c, msg);
    }

    /**
     * Alternative to binding to the service: will pass a Messenger ("m") and a PendingIntent ("p").
     * <p>
     * The service will use the Messenger parameter to send back an initial Message with 'replyTo'
     * set to the service Messenger.
     * <p>
     * At this point the communication continues just like in the case of 'bind'.
     * <p>
     * This works in BroadcastReceivers and cases where a full bind is not needed. Note that the
     * service or the app may go away at any time.
     */
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        // Send back our messenger. Used instead of bind.
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

        return super.onStartCommand(intent, flags, startId);
    }

    static class MsgConMessengerS extends MsgConn {
        Messenger out;

        /**
         * Server-side connection, using a Messenger and optional PendingIntent
         * <p>
         * TODO: If myPendingIntent is present, will be used as a Service (or Broadcast?), to restart the app,
         * passing a Messenger. The messages will be queued.
         */
        MsgConMessengerS(MsgMux mux, Messenger out, String name) {
            super(mux);
            this.out = out;
            this.name = name;
        }

        /**
         * Send a message to the remote side.
         * <p>
         * For server connections (DMMsgService, or internal activeIn with callbacks), it is sent to the client.
         * <p>
         * For client connections (bind to a server), it is sent to the server.
         */
        public boolean send(Message m) {
            if (out == null) {
                return false;
            }
            try {
                out.send(m);
                return true;
            } catch (RemoteException e) {
                if (name != null) {
                    Log.d(TAG, "Connection closed " + name);
                    mux.activeIn.remove(name);
                }
                out = null;
            }
            return false;
        }
    }

    static class DirectMsgConn extends MsgConn {
        IBinder out;

        DirectMsgConn(MsgMux mux, IBinder out, String name) {
            super(mux);
            this.out = out;
            this.name = name;
        }

        public boolean sendFrame(MsgFrame frame) {
            IBinder binder = out;
            if (binder == null) {
                return false;
            }
            boolean ok = DirectBinder.transact(
                    binder,
                    DirectBinder.TRANSACT_MESSAGE,
                    frame,
                    null,
                    null);
            if (!ok && name != null) {
                mux.removeInConnection(name);
                out = null;
            }
            return ok;
        }

        public boolean send(Message m) {
            return sendFrame(MsgFrame.fromMessage(m));
        }
    }
}
