package com.github.costinm.dmesh.transport;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.IBinder;

/**
 * Keeps the standalone regression harness alive while a shell-controlled
 * P2P/NAN callback sequence is running with the screen off. It intentionally
 * has the public {@code connectedDevice} type, never the {@code location}
 * type: the harness uses NEARBY_WIFI_DEVICES and declares neverForLocation.
 */
public final class ReproForegroundService extends Service {
    private static final String CHANNEL = "dmesh_transport";
    private static final int NOTIFICATION_ID = 1;

    @Override public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL,
                "P2P/NAN repro", NotificationManager.IMPORTANCE_LOW));
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("P2P/NAN reproduction active")
                .setContentText("Platform Wi-Fi test harness")
                .setOngoing(true)
                .build();
        startForeground(NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
