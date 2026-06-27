package com.github.costinm.dmesh.android.msg;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import java.util.ArrayList;

public class DirectBinderConn extends MsgConn {
    private static final String TAG = "DirectBinderConn";

    private final Context ctx;
    private final String packageName;
    private final String serviceName;
    private final ArrayList<MsgFrame> pending = new ArrayList<>();
    private IBinder remote;
    private ServiceConnection connection;

    private final DirectBinder callback = new DirectBinder(new DirectBinder.Receiver() {
        @Override
        public boolean onDirectMessage(int code, DirectBinder.DirectMessage msg, Parcel reply)
                throws RemoteException {
            mux.receiveFrame(name, DirectBinderConn.this, msg.frame);
            return true;
        }
    });

    public DirectBinderConn(MsgMux mux, Context ctx, String packageName, String serviceName) {
        super(mux);
        this.ctx = ctx.getApplicationContext();
        this.packageName = packageName;
        this.serviceName = serviceName;
        this.name = "direct:" + packageName + "/" + serviceName;
    }

    @Override
    public void start() {
        bind();
    }

    @Override
    public void close() {
        if (connection != null) {
            try {
                ctx.unbindService(connection);
            } catch (Throwable t) {
                Log.d(TAG, "unbind failed", t);
            }
        }
        connection = null;
        remote = null;
        pending.clear();
    }

    @Override
    public boolean sendFrame(MsgFrame frame) {
        if (remote == null) {
            pending.add(frame);
            bind();
            return true;
        }
        return sendNow(frame);
    }

    private void bind() {
        if (connection != null) {
            return;
        }
        Intent intent = new Intent();
        intent.setAction(DirectBinder.ACTION_DIRECT);
        intent.setComponent(new ComponentName(packageName, serviceName));
        connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                remote = service;
                Log.d(TAG, "connected " + name);
                flushPending();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                Log.d(TAG, "disconnected " + name);
                remote = null;
                connection = null;
            }
        };
        if (!ctx.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            Log.d(TAG, "bind failed " + packageName + "/" + serviceName);
            connection = null;
        }
    }

    private void flushPending() {
        ArrayList<MsgFrame> copy = new ArrayList<>(pending);
        pending.clear();
        for (MsgFrame frame : copy) {
            sendNow(frame);
        }
    }

    private boolean sendNow(MsgFrame frame) {
        IBinder binder = remote;
        if (binder == null) {
            return false;
        }
        return DirectBinder.transact(
                binder,
                DirectBinder.TRANSACT_MESSAGE,
                frame,
                callback,
                null);
    }
}
