package com.github.costinm.dmwifi;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.preference.PreferenceManager;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationCompat;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.BaseMsgService;
import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;

public class DMService extends BaseMsgService {
    public static final String TAG = "DM-SVC";

    private NotificationHandler nh;
    // The actual communication handlers
    private SharedPreferences prefs;

    boolean fg = false;

    @Override
    public void onCreate() {
        super.onCreate();

        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        nh = new NotificationHandler(this);
        mux.subscribe("N", nh);
    }

    public void onDestroy() {
        super.onDestroy();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }

        if (!prefs.getBoolean("lm_enabled", true)) {

            stopForeground(true);
            stopSelf();
            fg = false;
            return START_NOT_STICKY;
        }

        if (!fg) {
            startForeground(1, nh.getNotification(new Bundle()));
            Log.d(TAG, "Starting fg");
            fg = true;
        }

        return super.onStartCommand(intent, flags, startId);
    }

}
