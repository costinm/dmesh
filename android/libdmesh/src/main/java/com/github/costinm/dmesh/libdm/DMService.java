package com.github.costinm.dmesh.libdm;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.github.costinm.dmesh.android.util.BaseMsgService;

/**
 * Basic service starting and maintaining the native process.
 * Can be used on Gingerbread(10) to KitKat - for LMP use the full version
 * that includes wifi.
 */
public class DMService extends BaseMsgService {
    public static final String TAG = "LM-SVC";
    public static String title;
    public static String text;
    public static PendingIntent notIntent;
    static boolean fg = false;
    DMUDS dmUDS;
    public static final int EV_PREF = 60;

    void setNotification(String title, String text) {
        this.title = title;
        this.text = text;
        updateNotification();
    }

    void updateNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            // TODO: update notification on significant changes (connect, lost, size changes)
            startForeground(1, getNotification());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    Notification getNotification() {
        Notification.Builder b;
        b = new Notification.Builder(this);
        StringBuilder titleSB = new StringBuilder().append("LM ");
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
        PendingIntent pi = PendingIntent.getActivity(this, 1, i, 0);

        b.setContentTitle(titleSB)
                .setContentText(txtSB)
                .setContentIntent(pi);
        return b.build();
    }


    @Override
    public void onCreate() {
        super.onCreate();
        dmUDS = new DMUDS(this, mHandler, "dmesh");

        Log.d(TAG, "Starting");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            startForeground(1, getNotification());
            fg = true;
            Log.d(TAG, "Starting fg");
        }
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
        // What happens if we're not in foreground ? Networking (sockets) won't work,
        // DHCP is likely to fail too.
        if (intent.getBooleanExtra("lm_fg", false)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                if (!fg) {
                    startForeground(1, getNotification());
                    fg = true;
                    Log.d(TAG, "Starting fg");
                } else {

                }
            }
        } else if (intent.getBooleanExtra("lm_bg", false)) {
            if (fg) {
                stopForeground(true);
                stopSelf();
            }
        }
        //lm.updateCycle();
        return super.onStartCommand(intent, flags, startId);
    }
}
