package com.github.costinm.lm;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.Messenger;
import android.support.annotation.RequiresApi;
import android.util.Log;

public class LMService extends Service {
    public static final String TAG = "LM-SVC";
    static final String NOTIFICATION_TAG = "Fg";
    public static final int NOTIFICATION_ID = 1;

    public static String title;
    public static String text;
    public static PendingIntent notIntent;

    protected LMesh lm;

    PendingIntent pi;

    @RequiresApi(api = Build.VERSION_CODES.O)
    NotificationChannel createNotificationChannel() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel nc = new NotificationChannel("dmesh", "DMesh",
                NotificationManager.IMPORTANCE_NONE);
        nm.createNotificationChannel(nc);
        return nc;
    }

    /**
     * Update the notification.
     *
     * Title and text are received from the native app.
     */
    void setNotification(String title, String text) {
        this.title = title;
        this.text = text;
        //updateNotification();
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.notify(NOTIFICATION_ID, getNotification());
    }

    void updateNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            startForeground(NOTIFICATION_ID, getNotification());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    Notification getNotification() {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel nc = createNotificationChannel();
            b = new Notification.Builder(this, "dmesh");
            nc.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);

            //nc.setImportance(NotificationManager.);
        } else {
            b = new Notification.Builder(this);
            b.setDefaults(Notification.DEFAULT_LIGHTS);
        }

        StringBuilder titleSB = new StringBuilder().append("LM ");
        if (lm.apRunning) {
            titleSB.append("*");
            b.setSmallIcon(R.mipmap.ic_launcher_red);
        } else {
            b.setSmallIcon(R.drawable.ic_stat_fg);
        }


        String ssid = lm.con.getCurrentWifiSSID();
        if (ssid != null) {
            titleSB.append(" Wifi:").append(ssid);
        }
        if (title != null) {
            titleSB.append(" ").append(title);
        }

        StringBuilder txtSB = new StringBuilder();
        txtSB.append("Nodes:").append(LMesh.connectable.size())
                .append("/").append(lm.visible());
        if (text != null) {
            txtSB.append(" ").append(text);
        }

        Intent i = new Intent(this, LMSettingsActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 1, i, 0);

        if (lm.hasDMeshConnection()) {
            if (lm.apRunning) {
                b.setColor(0xd602ee); // redish
                b.setSmallIcon(R.drawable.ic_router_red_900_24dp);
            } else {
                b.setColor(0xAAF255); // light green
                b.setSmallIcon(R.drawable.ic_router_green_900_24dp);
            }
        } else if (lm.apRunning) {
            b.setColor(0x6002ee); // blue
            b.setSmallIcon(R.drawable.ic_router_blue_900_24dp);
        } else {
            // nothing
            b.setColor(0xFFDE03); // yellow
            b.setSmallIcon(R.drawable.ic_router_yellow_900_24dp);
        }

        b.setContentTitle(titleSB)
                .setContentText(txtSB)
                .setContentIntent(pi);
        //b.setStyle()
        //b.addAction()
        return b.build();
    }

    @Override
    public boolean onUnbind(Intent intent) {
        lm.observer = null;
        pi = null;
        return super.onUnbind(intent);
    }

    @Override
    public IBinder onBind(Intent intent) {
        Messenger m = intent.getParcelableExtra("m");
        pi = intent.getParcelableExtra("p");

        lm.observer = m;
        return lm.serviceHandlerMsg.getBinder();
    }

    @Override
    public void onCreate() {
        super.onCreate();

        lm = LMesh.get(this);

        // Will unregisterReceiver the AP if running from previous instance.
        lm.onStart(this);

        Log.d(TAG, "Starting");
        // What happens if we're not in foreground ? Networking (sockets) won't work,
        // DHCP is likely to fail too.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                startForeground(1, getNotification());
        }
        lm.service = this;
    }

    /**
     * Debug:
     * adb shell am startservice --ei what 2 com.github.costinm.dmesh.lm/.LMService
     */
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        String cmd = intent.getStringExtra("cmd");
        if (cmd != null) {
            lm.handleCmd(cmd, intent);
        }
        lm.updateCycle();
        return super.onStartCommand(intent, flags, startId);
    }
}
