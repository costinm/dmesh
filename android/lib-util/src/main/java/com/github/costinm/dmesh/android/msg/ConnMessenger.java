package com.github.costinm.dmesh.android.msg;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

/**
 * A simple client using a Messenger to receive and send Message to a Binder server.
 * <p>
 * TODO: currently binds to service, but we can also use startService() with a Messenger handshake
 * for cases a long-lived binding to the service is not needed. Binding will keep the target active.
 */
class ConnMessenger extends MsgConn {

    private static String TAG = "MsgC";
    // Package name of the remote side.
    // Used as key in either activeIn or activeOut.
    public String remotePackage;
    // MsgConn messenger receiving from service. Will be passed to all the bound services, in
    // 'replyTo' field.
    protected Messenger inMessenger;
    // Used as a token to identify the client and possibly restart it on demand.
    // Only for GB to KK
    protected PendingIntent myPendingIntent;
    // exposed by the service. May be null if a binding is not active.
    // Set to null if sending a message fails.
    protected Messenger svc;
    /**
     * If set, this connection is a bind to a remote package service.
     * This is the full class name of the service, as declared in the manifest.
     */
    String svcName;
    /**
     * Set as long as an activeOut bind connection exists, if svcName is set.
     */
    ServiceConnection sc;

    /**
     * Create a client
     *
     * @param pkg Package implementing the service.
     * @param svc Class name of the service.
     */
    ConnMessenger(final MsgMux mux, String pkg, String svc) {
        super(mux);
        this.remotePackage = pkg;
        this.svcName = svc;
        Handler fromLMHandler = new Handler(mux.handlerThread.getLooper(), new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                mux.handleMessage(remotePackage, ConnMessenger.this, msg);
                return false;
            }
        });
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.LOLLIPOP) {
            Intent i = new Intent();
            i.setComponent(new ComponentName(mux.ctx.getPackageName(), mux.ctx.getPackageName() + ".DMService"));

            myPendingIntent = PendingIntent.getService(mux.ctx, 1973, i, 0);
        }
        inMessenger = new Messenger(fromLMHandler);
    }

    public void bind(final Context ctx) {
        Intent i = new Intent();
        i.setComponent(new ComponentName(remotePackage, svcName));

        // TODO: exp backoff, stop after X retries, etc.
        sc = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                svc = new Messenger(service);
                Log.d(TAG, "Connected to " + name);

                Message m = Message.obtain();
                m.getData().putBoolean(":open", true);
                send(m);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                svc = null;
                Log.d(TAG, "LM service disconnected" + name);
                mux.broadcastHandler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        bind(ctx);
                    }
                }, 1000);
            }
        };
        boolean b = ctx.bindService(i, sc, Context.BIND_AUTO_CREATE);
        if (!b) {
            mux.broadcastHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    bind(ctx);
                }
            }, 1000);
        }
    }

    public void close() {
        mux.activeOut.remove(remotePackage);
        if (sc != null) {
            try {
                mux.ctx.unbindService(sc);
            } catch (Throwable t) {
                Log.d(TAG, t.getMessage());
            }
            sc = null;
        }
    }

    boolean send(Message m) {
        Messenger mg = svc;
        if (mg == null) {
            return false;
        }
        m.replyTo = inMessenger;
        if (myPendingIntent != null) {
            m.getData().putParcelable(":p", myPendingIntent);
        }

        try {
            mg.send(m);
            return true;
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        return false;
    }

    //@Override

    public void start() {
        bind(mux.ctx);
    }
}
