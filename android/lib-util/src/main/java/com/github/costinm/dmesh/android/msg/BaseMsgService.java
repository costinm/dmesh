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
 * Server-side messaging mux, using Messenger or DirectBinder.
 * Handles both 1-way (asynchronous with callback binder) and 2-way (synchronous with reply Parcel).
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
     * Return DirectBinder for "mesh.direct" or Messenger binder.
     */
    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "BIND Intent " + intent + " " + intent.getExtras());
        if (intent != null && DirectBinder.ACTION_DIRECT.equals(intent.getAction())) {
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
     * onTransact implements the raw binder interface.
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
        boolean oneWay = direct.isOneWay();

        if (c == null || open) {
            c = new DirectMsgConn(mux, direct.callback, key);
            mux.addInConnection(key, c, direct.frame == null ? Message.obtain() : direct.frame.toMessage());
            Log.d(TAG, "New direct binder client " + key + " oneWay=" + oneWay + " hasCallback=" + direct.hasCallback());
        } else if (c instanceof DirectMsgConn && direct.callback != null) {
            ((DirectMsgConn) c).out = direct.callback;
        }

        if (oneWay) {
            if (!direct.hasCallback() && direct.frame != null && !":open".equals(direct.frame.method)) {
                Log.w(TAG, "One-way direct message received without callback binder: " + direct.frame.method);
            }
        }

        MsgFrame frame = direct.frame == null ? new MsgFrame(null) : direct.frame;

        // If 2-way call and reply parcel is provided, allow generating a direct synchronous response
        if (!oneWay && reply != null) {
            MsgFrame syncReply = handleDirectSyncRequest(key, c, frame);
            if (syncReply != null) {
                DirectBinder.writeMessage(reply, syncReply, null, null);
                return true;
            }
        }

        return mux.handleFrame(key, c, frame);
    }

    /**
     * Hook for subclasses or services to provide a synchronous response for 2-way transactions.
     * Returns null if standard asynchronous dispatch via MsgMux should occur instead.
     */
    protected MsgFrame handleDirectSyncRequest(String src, MsgConn con, MsgFrame frame) {
        return null;
    }

    /**
     * Message received using the Messenger interface exposed to clients (registered handlers)
     */
    protected boolean handleInMessage(Message msg) {
        String key = "" + msg.sendingUid;
        MsgConn c = mux.activeIn.get(key);

        if (c == null || msg.getData().getBoolean(":open", false)) {
            c = new MsgConMessengerS(mux, msg.replyTo, key);
            mux.addInConnection(key, c, msg);
            Log.d(TAG, "New Client " + msg.sendingUid);
        }

        return mux.handleMessage(key, c, msg);
    }

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

        return super.onStartCommand(intent, flags, startId);
    }

    static class MsgConMessengerS extends MsgConn {
        Messenger out;

        MsgConMessengerS(MsgMux mux, Messenger out, String name) {
            super(mux);
            this.out = out;
            this.name = name;
        }

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

    public static class DirectMsgConn extends MsgConn {
        public IBinder out;

        public DirectMsgConn(MsgMux mux, IBinder out, String name) {
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
