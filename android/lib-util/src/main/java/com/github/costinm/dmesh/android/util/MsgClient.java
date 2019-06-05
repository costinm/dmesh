package com.github.costinm.dmesh.android.util;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * A simple client using a Messenger to receive and send Message to a Binder server.
 *
 * Currently expects a service named ".DMService" extending BaseMsgService. May allow more
 * options in future, but simpler for now.
 *
 */
public class MsgClient extends MsgConnection implements Handler.Callback {

    protected Handler fromLMHandler;

    // MsgConnection messenger receiving from service
    protected Messenger fromLM;

    // Used as a token to identify the client and possibly restart it on demand.
    protected PendingIntent myPendingIntent;

    // exposed by the service. May be null.
    protected Messenger svc;

    private static String TAG = "MsgC";

    /**
     * Create a client
     * @param pkg Package implementing the service.
     * @param svc Class name of the service.
     * @param callback everything received from the app will invoke the callback
     */
    MsgClient(MsgMux mux, String pkg, String svc, Handler.Callback callback) {
        super(mux, pkg, svc);
        this.callback = callback;
        fromLMHandler = new Handler(mux.handlerThread.getLooper(), new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                MsgClient.this.handleMessage(msg);
                return false;
            }
        });
        fromLM = new Messenger(fromLMHandler);
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

    public boolean send(Message m) {
        Messenger mg = svc;
        if (mg == null) {
            return false;
        }
        m.replyTo = fromLM;
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

    @Override
    public boolean handleMessage(Message msg) {
        Bundle arg = msg.getData();

        final String cmd = arg.getString(":uri");
        if (cmd == null) {
            return false;
        }
        String[] args = cmd.split("/");
        if (args.length < 2) {
            return false;
        }
        Log.d(TAG, "Message from SVC " + remotePackage + " " + msg.getData() + " " + msg.what);

        MsgMux.MessageHandler open = handers.get(args[1]);
        if (open != null) {
            open.handleMessage(msg, msg.replyTo, args);
            return false;
        } else {
            return callback.handleMessage(msg);
        }
    }
}
