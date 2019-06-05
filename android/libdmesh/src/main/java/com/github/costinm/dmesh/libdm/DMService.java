package com.github.costinm.dmesh.libdm;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.github.costinm.dmesh.android.util.BaseMsgService;

/**
 * Basic service starting and maintaining the native process.
 */
public class DMService extends BaseMsgService {
    public static final String TAG = "LM-SVC";

    public static String title;
    public static String text;
    public static final int NOTIFICATION_ID = 1;
    public PendingIntent pi;

    protected DMesh dmUDS;

    private SharedPreferences prefs;

    /**
     * Update the notification.
     *
     * Title and text are received from the native app.
     */
    public void setNotification(String title, String text) {
        this.title = title;
        this.text = text;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            nm.notify(NOTIFICATION_ID, getNotification());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public NotificationChannel createNotificationChannel() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel nc = new NotificationChannel("dmesh", "DMesh",
                NotificationManager.IMPORTANCE_NONE);
        nm.createNotificationChannel(nc);
        return nc;
    }

    public void updateNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            // TODO: update notification on significant changes (connect, lost, size changes)
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
        if (dmUDS.apRunning) {
            titleSB.append("*");
            b.setSmallIcon(R.mipmap.ic_launcher_red);
        } else {
            b.setSmallIcon(R.drawable.ic_stat_fg);
        }
        String ssid = dmUDS.getCurrentSSID();
        if (ssid != null) {
            titleSB.append(" Wifi:").append(ssid);
        }
        if (title != null) {
            titleSB.append(" ").append(title);
        }
        if (title != null) {
            titleSB.append(" ").append(title);
        }

        StringBuilder txtSB = new StringBuilder();
        if (text != null) {
            txtSB.append(" ").append(text);
        }

        Intent i = new Intent();
        i.setComponent(
                new ComponentName("com.github.costinm.dmesh.lm",
                        "com.github.costinm.dmesh.lm.DMSettingsActivity"));
        pi = PendingIntent.getActivity(this, 1, i, 0);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            if (hasDMeshConnection()) {
                if (dmUDS.apRunning) {
                    b.setColor(0xd602ee); // redish
                    b.setSmallIcon(R.drawable.ic_router_red_900_24dp);
                } else {
                    b.setColor(0xAAF255); // light green
                    b.setSmallIcon(R.drawable.ic_router_green_900_24dp);
                }
            } else if (dmUDS.apRunning) {
                b.setColor(0x6002ee); // blue
                b.setSmallIcon(R.drawable.ic_router_blue_900_24dp);
            } else {
                // nothing
                    b.setColor(0xFFDE03); // yellow
                b.setSmallIcon(R.drawable.ic_router_yellow_900_24dp);
            }
        }

        b.setContentTitle(titleSB)
                .setContentText(txtSB)
                .setContentIntent(pi);
        //b.setStyle()
        //b.addAction()
        return b.build();
    }

    boolean hasDMeshConnection() {
        String ssid = dmUDS.getCurrentSSID();
        return ssid != null && ssid.startsWith("DIRECT-") && ssid.startsWith("DM-");
    }

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // The native implementation the service.
        dmUDS = new DMesh(this, "dmesh");

        // TODO: interface for clients

        Log.d(TAG, "Starting1");
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
        if (!prefs.getBoolean("lm_enabled", true)) {
            dmUDS.send("/KILL", null, null);

            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            startForeground(1, getNotification());
            Log.d(TAG, "Starting fg");
        }

        return super.onStartCommand(intent, flags, startId);
    }
}
