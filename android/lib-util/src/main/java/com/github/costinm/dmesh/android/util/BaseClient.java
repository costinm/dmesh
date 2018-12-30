package com.github.costinm.dmesh.android.util;

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

public class BaseClient {
    private final String pkg;
    private final String svcName;
    protected Handler fromLMHandler;
    protected Messenger fromLM;
    protected PendingIntent pi;

    protected Messenger svc;

    private static String TAG = "MsgC";

    public BaseClient(String pkg, String svc) {
        this.pkg = pkg;
        this.svcName = svc;

    }

    public Messenger bind(final Context ctx) {
        Intent i = new Intent();
        i.setComponent(new ComponentName(pkg, svcName));
        i.putExtra("m", fromLM);
        i.putExtra("p", pi);

        boolean b = ctx.bindService(i, new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                svc = new Messenger(service);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                svc = null;
                Log.d(TAG, "LM service disconnected" + name);
                bind(ctx);
            }
        }, Context.BIND_AUTO_CREATE);
        return null;
    }

    public void cmd(int i) {
        Messenger mg = svc;
        if (mg == null) {
            return;
        }
        Message m = Message.obtain();
        m.what = i;
        try {
            mg.send(m);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

}
