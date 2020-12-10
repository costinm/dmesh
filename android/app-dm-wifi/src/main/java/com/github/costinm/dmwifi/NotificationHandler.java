package com.github.costinm.dmwifi;

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
import androidx.core.app.NotificationCompat;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;

public class NotificationHandler implements MessageHandler {
    Context ctx;
    protected NotificationManager nm;
    // Pending indent for main action ( show UI )
    protected PendingIntent pi;

    /**
     *  Recent messages notification
     *
     */
    static final int NID_MSG = 1;

    // Wifi info - including visible BLE or Wifi neighbors
    static final int NID_WIFI = 2;


    public NotificationHandler(Context dmService) {
        ctx = dmService;
        nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            createNotificationChannel();
        }
        Intent i = new Intent();
        i.setComponent(new ComponentName(ctx.getPackageName(), ctx.getPackageName() + ".WifiActivity"));
        pi = PendingIntent.getActivity(ctx, 1, i, 0);

    }
    @RequiresApi(api = Build.VERSION_CODES.O)
    public void createNotificationChannel() {
        // Channel visible name is "DMesh status"
        NotificationChannel nc = new NotificationChannel("dmesh", "DMesh status",
                NotificationManager.IMPORTANCE_LOW);
        NotificationChannel nc2 = new NotificationChannel("dmwifi", "DMesh Wifi",
                NotificationManager.IMPORTANCE_LOW);

        //nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        // LOW: show everywhere ( so ok for foreground services ). FG rewquires at least LOW.
        nm.createNotificationChannel(nc);
        nm.createNotificationChannel(nc2);
        nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        nc2.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
    }

    @Override
    public void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args) {
        Bundle arg = m.getData();

        Notification n = getNotification(arg);
        if (nm != null) {
            nm.notify(1, n);
        }
    }

    /**
     *  Main notification.
     * @param data
     * @return
     */
    protected Notification getNotification(Bundle data) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, "dmesh");
        b.setDefaults(Notification.DEFAULT_LIGHTS);

        b.setShowWhen(true);
        b.setContentTitle(data.getString("title", "Device Mesh"));

//        String iconId = data.getString("icon", "0");
//        switch (iconId) {
//            case "0":
//                b.setColor(0xFFDE03); // yellow
//                b.setSmallIcon(com.github.costinm.dmesh.libdm.R.drawable.ic_router_yellow_900_24dp);
//                break;
//            case "red":
//                b.setColor(0xd602ee); // redish
//                b.setSmallIcon(com.github.costinm.dmesh.libdm.R.drawable.ic_router_red_900_24dp);
//                break;
//            case "green":
//                b.setColor(0xAAF255); // light green
//                b.setSmallIcon(com.github.costinm.dmesh.libdm.R.drawable.ic_router_green_900_24dp);
//                break;
//            case "blue":
//                b.setColor(0x6002ee); // blue
//                b.setSmallIcon(com.github.costinm.dmesh.libdm.R.drawable.ic_router_blue_900_24dp);
//                break;
//        }

        // TODO: header text customization (after app name)

        // third row of text
        //b.setSubText()

        // TODO: recent messages and events
//        b.setStyle(new Notification.InboxStyle()
//                .addLine("Line1")
//                .addLine("Line2")
//        );

//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
//            b.setStyle(new Notification.MessagingStyle("R")
//                    .addMessage(new Notification.MessagingStyle.Message("test", 0, "sender"))
//            );
//        }


        String txt = data.getString("text", "Starting");
        b.setContentText(txt);
        b.setContentIntent(pi);
        //b.setStyle()
        //b.addAction()
        b.setPriority(Notification.PRIORITY_MIN);

//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) {
//            b.addAction(new Notification.Action(1, "Sync", syncPI));
//        }

        return b.build();
    }
}
