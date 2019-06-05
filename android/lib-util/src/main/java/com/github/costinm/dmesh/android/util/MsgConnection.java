package com.github.costinm.dmesh.android.util;

import android.app.PendingIntent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * MsgConnection wraps the Messenger used to send messages to one client of the service.
 *
 */
public class MsgConnection { // implements Handler.Callback {
    private static final String TAG = "MsgCon";

    public Messenger out;
    // TODO: use myPendingIntent to re-activate
    public PendingIntent pi;

    // Package name of the remote side.
    // Used as key in either clients or active.
    public String remotePackage;

    /**
     * If set, this connection is a bind to a remote package service.
     * This is the full class name of the service, as declared in the manifest.
     */
    String svcName;

    /**
     * Set as long as an active bind connection exists, if svcName is set.
     */
    ServiceConnection sc;

    public Map<String, MsgMux.MessageHandler> handers = new HashMap<>();


    // callback is set for internal udsHandlers.
    Handler.Callback callback;

    MsgMux mux;

    /**
     * Server-side connection, using a Messenger and optional PendingIntent
     *
     * TODO: If myPendingIntent is present, will be used as a Service (or Broadcast?), to restart the app,
     * passing a Messenger. The messages will be queued.
     */
    public MsgConnection(MsgMux mux, Messenger out, PendingIntent pi) {
        this(mux);
        this.out = out;
        this.pi = pi;
        if (pi != null) {
            remotePackage = pi.getTargetPackage();
        }
    }

    public MsgConnection(MsgMux mux, String pkg, String svc) {
        this.mux = mux;
        this.remotePackage = pkg;
        this.svcName = svc;
    }

    public MsgConnection(MsgMux mux) {
        this.mux = mux;
    }

    public void close() {
        mux.active.remove(remotePackage);
        if (sc != null) {
            try {
                mux.ctx.unbindService(sc);
            } catch (Throwable t) {
                Log.d(TAG, t.getMessage());
            }
            sc = null;
        }
    }

    /**
     *  Send a message to the remote side.
     *
     *  For server connections (DMMsgService, or internal clients with callbacks), it is sent to the client.
     *
     *  For client connections (bind to a server), it is sent to the server.
     */
    public boolean send(Message m) {
        if (callback != null) {
            return callback.handleMessage(m);
        }
        if (out == null) {
            return false;
        }
        try {
            out.send(m);
            return true;
        } catch (RemoteException e) {
            if (remotePackage != null) {
                Log.d(TAG, "Connection closed " + remotePackage);
                mux.clients.remove(remotePackage);
            }
            out = null;
        }
        return false;
    }

    public boolean send(String uri, String... parms) {
        Message m = Message.obtain();
        m.what = 1;
        m.getData().putString(":uri", uri);
        Bundle b = m.getData();
        for (int i = 0; i < parms.length; i += 2) {
            b.putString(parms[i], parms[i + 1]);
        }
        return send(m);
    }



}
