package com.github.costinm.dmesh.lm;

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
import androidx.core.app.RemoteInput;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;

public class NotificationHandler implements MessageHandler {
    public static final String CHANNEL_STATUS = "dmesh";
    public static final String CHANNEL_WIFI = "dmwifi";
    public static final String CHANNEL_MSG = "dmmsg";
    Context ctx;
    protected NotificationManager nm;

    // Pending indent for main action ( show UI )
    protected PendingIntent pi;
    protected PendingIntent syncPI;

    /**
     *  Recent messages notification
     *
     */
    static final int NID_MSG = 1;

    // Wifi info - including visible BLE or Wifi neighbors
    static final int NID_WIFI = 2;
    private Intent brIntent;


    public NotificationHandler(Context dmService) {
        ctx = dmService;
        nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            createNotificationChannel();
        }
        Intent i = new Intent();
        i.setComponent(new ComponentName(ctx.getPackageName(), ctx.getPackageName() + ".SetupActivity"));
        pi = PendingIntent.getActivity(ctx, 1, i, PendingIntent.FLAG_MUTABLE);

        brIntent = new Intent();
        brIntent.setComponent(new ComponentName(ctx.getPackageName(), ctx.getPackageName() + ".DMService$Receiver"));

        i = new Intent();
        i.setComponent(new ComponentName(ctx.getPackageName(), ctx.getPackageName() + ".DMService"))
                .putExtra(":uri", "/sync");
        syncPI = PendingIntent.getService(ctx, 1, i, PendingIntent.FLAG_MUTABLE);

    }


    @RequiresApi(api = Build.VERSION_CODES.O)
    public void createNotificationChannel() {
        // Channel visible name is "DMesh status"
        NotificationChannel nc = new NotificationChannel(CHANNEL_STATUS, "DMesh status",
                NotificationManager.IMPORTANCE_LOW);
        NotificationChannel nc2 = new NotificationChannel(CHANNEL_WIFI, "DMesh Wifi",
                NotificationManager.IMPORTANCE_LOW);
        NotificationChannel nc3 = new NotificationChannel(CHANNEL_MSG, "DMesh Messages",
                NotificationManager.IMPORTANCE_LOW);

        //nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        // LOW: show everywhere ( so ok for foreground services ). FG rewquires at least LOW.
        nm.createNotificationChannel(nc);
        nm.createNotificationChannel(nc2);
        nm.createNotificationChannel(nc3);
        nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        nc2.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        nc3.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
    }

    @Override
    public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo, String[] args) {
        Bundle arg = msg.getData();

        String type = arg.getString("type", "status");
        switch (type) {
            case "status": {
                Notification n = getNotification(arg);
                if (nm != null) {
                    nm.notify(1, n);
                }
                break;
            }
            case "disc": {
                Notification n = getNeighborNotification(arg);
                if (nm != null) {
                    nm.notify(2, n);
                }
                break;
            }
            case "msg": {
                Notification n = getMsgNotification(arg);
                if (nm != null) {
                    nm.notify(3, n);
                }
                break;
            }
        }

    }

    /**
     * Notification shown when a BLE or Wifi DMESH or similar network is detected.
     *
     * Action is to create a mesh with the neighbor device.
     * TODO
     */
    protected Notification getNeighborNotification(Bundle data) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, CHANNEL_WIFI);
        b.setDefaults(Notification.DEFAULT_LIGHTS);
        b.setShowWhen(true);
        b.setContentIntent(pi);

        String title = data.getString("title", "Device Mesh");
        b.setContentTitle(title);
        String txt = data.getString("text", "Starting");
        b.setContentText(txt);

        b.setPriority(Notification.PRIORITY_MIN);


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            b.setStyle(new NotificationCompat.BigTextStyle()
                    .setBigContentTitle(title).setSummaryText(txt).bigText(txt));


            b.addAction(new NotificationCompat.Action(1, "Sync", syncPI));
            RemoteInput remoteInput = new RemoteInput.Builder("cmd")
                    .setLabel("Cmd")
                    .build();

            PendingIntent replyPendingIntent =
                    PendingIntent.getBroadcast(ctx,
                            1, // request code
                            brIntent,
                            PendingIntent.FLAG_UPDATE_CURRENT);
            NotificationCompat.Action action =
                    new NotificationCompat.Action.Builder(R.drawable.ic_action_dbg,
                            "Cmd", replyPendingIntent)
                            .addRemoteInput(remoteInput)
                            .build();

            b.addAction(action);
        }
        b.setOnlyAlertOnce(true);

        return b.build();
    }

    /**
     * Broadcast or direct message.
     *
     * Action is to reply.
     * TODO
     */
    protected Notification getMsgNotification(Bundle data) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, CHANNEL_MSG);
        b.setDefaults(Notification.DEFAULT_LIGHTS);

        b.setShowWhen(true);

//        b.setStyle(new NotificationCompat.MessagingStyle("R")
//                .addMessage(new NotificationCompat.MessagingStyle.Message("test", 0, "sender"))
//        );

        b.setContentIntent(pi);

        String title = data.getString("title", "Device Mesh");
        b.setContentTitle(title);
        String txt = data.getString("text", "Starting");
        b.setContentText(txt);


        b.setPriority(Notification.PRIORITY_MIN);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {

            b.setStyle(new NotificationCompat.BigTextStyle()
                    .setBigContentTitle(title).setSummaryText(txt).bigText(txt));
            b.addAction(new NotificationCompat.Action(1, "Sync", syncPI));
            RemoteInput remoteInput = new RemoteInput.Builder("cmd")
                    .setLabel("Cmd")
                    .build();

            PendingIntent replyPendingIntent =
                    PendingIntent.getBroadcast(ctx,
                            1, // request code
                            brIntent,
                            PendingIntent.FLAG_UPDATE_CURRENT);
            NotificationCompat.Action action =
                    new NotificationCompat.Action.Builder(R.drawable.ic_action_dbg,
                            "Cmd", replyPendingIntent)
                            .addRemoteInput(remoteInput)
                            .build();

            b.addAction(action);
        }

        b.setOnlyAlertOnce(true);

        return b.build();
    }

    /**
     *  Main notification.
     * @param data
     * @return
     */
    protected Notification getNotification(Bundle data) {
        NotificationCompat.Builder b = new NotificationCompat.Builder(ctx, CHANNEL_STATUS);
        b.setDefaults(Notification.DEFAULT_LIGHTS);

        b.setShowWhen(true);

        String iconId = data.getString("icon", "0");
        switch (iconId) {
            case "0":
                b.setColor(0xFFDE03); // yellow
                b.setSmallIcon(R.drawable.ic_router_yellow_900_24dp);
                break;
            case "red":
                b.setColor(0xd602ee); // redish
                b.setSmallIcon(R.drawable.ic_router_red_900_24dp);
                break;
            case "green":
                b.setColor(0xAAF255); // light green
                b.setSmallIcon(R.drawable.ic_router_green_900_24dp);
                break;
            case "blue":
                b.setColor(0x6002ee); // blue
                b.setSmallIcon(R.drawable.ic_router_blue_900_24dp);
                break;
        }

        // TODO: header text customization (after app name)

        // third row of text
        //b.setSubText()


//        b.setStyle(new NotificationCompat.MessagingStyle("R")
//                .addMessage(new NotificationCompat.MessagingStyle.Message("test", 0, "sender"))
//        );

        //StatusBarNotification(pkg=com.github.costinm.dmwifi user=UserHandle{0} id=1 tag=null score=-20
        // key=0|com.github.costinm.dmwifi|1|null|10023: Notification(pri=-2
        // contentView=com.github.costinm.dmwifi/0x1090188
        // vibrate=null sound=null defaults=0x4 flags=0x63 color=0xffffde03 actions=1 vis=PRIVATE))



        b.setContentIntent(pi);

        String title = data.getString("title", "Device Mesh");
        b.setContentTitle(title);
        String txt = data.getString("text", "Starting");
        b.setContentText(txt);


        b.setStyle(new NotificationCompat.BigTextStyle()
            .setBigContentTitle(title).setSummaryText(txt).bigText(txt));

        b.setPriority(Notification.PRIORITY_MIN);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {

            b.addAction(new NotificationCompat.Action(1, "Sync", syncPI));
            RemoteInput remoteInput = new RemoteInput.Builder("cmd")
                    .setLabel("Cmd")
                    .build();
            PendingIntent replyPendingIntent =
                    PendingIntent.getBroadcast(ctx,
                            1, // request code
                            brIntent,
                            PendingIntent.FLAG_MUTABLE
                    );
            NotificationCompat.Action action =
                    new NotificationCompat.Action.Builder(R.drawable.ic_action_dbg,
                            "Cmd", replyPendingIntent)
                            .addRemoteInput(remoteInput)
                            .build();

            b.addAction(action);
        }

        b.setOnlyAlertOnce(true);

        return b.build();
    }
}
