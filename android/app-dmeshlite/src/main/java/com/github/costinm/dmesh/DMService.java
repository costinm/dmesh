package com.github.costinm.dmesh;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.BaseMsgService;
import com.github.costinm.dmesh.libdm.DMesh;
import com.github.costinm.dmesh.libdm.vpn.VpnService;

/**
 * Mesh service, starting and maintaining the native process and handling the communication with
 * Android services.
 * <p>
 * As required, will maintain a notification so user is aware the service is running, which will
 * include the status of the service.
 * <p>
 * Most of the logic is in the native process - which can also run on servers and non-android
 * IOT devices, using similar adapters to the native platform.
 * <p>
 * TODO: setup_menu a job to do the periodic sync and automatic startup
 * TODO: move to the application + notification helper.
 */
public class DMService extends BaseMsgService {
    public static final String TAG = "DM-SVC";

    // The actual communication handlers
    public static DMesh dmUDS;

    // Pending indent for the sync action.
    public PendingIntent syncPI;

    private SharedPreferences prefs;
    private NotificationHandler nh;


    @Override
    public void onCreate() {
        super.onCreate();
        // The native implementation the service.
        prefs = PreferenceManager.getDefaultSharedPreferences(this);


        if (dmUDS == null) {
            dmUDS = DMesh.get(this);
        }

        // TODO: interface for clients
        nh = new NotificationHandler(this);
        mux.subscribe("N", nh);

        Log.d(TAG, "Starting1");
    }

    boolean fg = false;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        if (!prefs.getBoolean("lm_enabled", true)) {
            dmUDS.closeNative();
            stopForeground(true);
            stopSelf();
            fg = false;
            return START_NOT_STICKY;
        }

        // If not started, make sure it runs
        dmUDS.openNative();

        if (!fg && Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            startForeground(1, nh.getNotification(new Bundle()));
            Log.d(TAG, "Starting fg");
            fg = true;
        }

        return super.onStartCommand(intent, flags, startId);
    }
}
