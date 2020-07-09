package com.github.costinm.dmesh;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import androidx.annotation.RequiresApi;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;

/**
 * Handles a message by updating the notification.
 * Uses the platform notification package package. An alternative using app compat in the
 * 'modern' application - this is a minimal version.
 */
public class NotificationHandler implements MessageHandler {
    Context ctx;
    protected NotificationManager nm;
    // Pending indent for main action ( show UI )
    protected PendingIntent pi;


    public NotificationHandler(Context dmService) {
        ctx = dmService;
        nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            createNotificationChannel();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public NotificationChannel createNotificationChannel() {
        // Channel visible name is "DMesh status"
        NotificationChannel nc = new NotificationChannel("dmesh", "DMesh status",
                NotificationManager.IMPORTANCE_LOW);
        NotificationChannel nc2 = new NotificationChannel("dmwifi", "DMesh Wifi",
                NotificationManager.IMPORTANCE_LOW);

        //nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        // LOW: show everywhere ( so ok for foreground services ). FG rewquires at least LOW.
        nm.createNotificationChannel(nc);
        nm.createNotificationChannel(nc2);
        return nc;
    }


    @Override
    public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo, String[] args) {
        Bundle arg = msg.getData();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            Notification n = getNotification(arg);
            if (nm != null) {
                nm.notify(1, n);
            }
        }

    }

    /**
     * Build a notification, using the bundle content.
     *
     * TODO: support messages from apps, etc.
     *
     * @return
     */
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    protected Notification getNotification(Bundle data) {
        Notification.Builder b;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel nc = createNotificationChannel();
            nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);

            b = new Notification.Builder(ctx, "dmesh");
        } else {
            b = new Notification.Builder(ctx);
            b.setDefaults(Notification.DEFAULT_LIGHTS);
        }

        b.setContentTitle(data.getString("title", "Device Mesh"));

        Intent i = new Intent();
        i.setComponent(new ComponentName(ctx.getPackageName(), ctx.getPackageName() + ".MainActivity"));
        pi = PendingIntent.getActivity(ctx, 1, i, 0);

        String txt = data.getString("text", "Starting");
        b.setContentText(txt);
        b.setContentIntent(pi);

        if (Build.VERSION.SDK_INT < 26) {
            b.setPriority(Notification.PRIORITY_MIN);
        }

        return b.build();
    }

}
