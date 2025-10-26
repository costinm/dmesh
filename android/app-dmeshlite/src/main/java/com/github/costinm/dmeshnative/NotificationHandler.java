package com.github.costinm.dmeshnative;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import androidx.annotation.RequiresApi;

/**
 * Handles a message by updating the notification.
 * Uses the platform notification package package. An alternative using app compat in the
 * 'modern' application - this is a minimal version.
 */
public class NotificationHandler {
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


    public void handleMessage(String msg) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            Notification n = getNotification(msg);
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
    protected Notification getNotification(String data) {
        Notification.Builder b;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel nc = createNotificationChannel();
            nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);

            b = new Notification.Builder(ctx, "dmesh");
        } else {
            b = new Notification.Builder(ctx);
            b.setDefaults(Notification.DEFAULT_LIGHTS);
        }

        b.setContentTitle("DMesh");

        Intent i = new Intent();
        i.setComponent(new ComponentName(ctx.getPackageName(), ctx.getPackageName() + ".MainActivity"));
        pi = PendingIntent.getActivity(ctx, 1, i, 0);

        if (data.equals("")) {
            data = "Active";
        }
        String txt = data;
        b.setContentText(txt);
        b.setContentIntent(pi);

        if (Build.VERSION.SDK_INT < 26) {
            b.setPriority(Notification.PRIORITY_MIN);
        }

        return b.build();
    }

}
