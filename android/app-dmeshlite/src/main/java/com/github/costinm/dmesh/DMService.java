package com.github.costinm.dmesh;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.preference.PreferenceManager;
import android.util.Log;

import wpgate.Wpgate;

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
public class DMService extends Service {
    public static final String TAG = "DM-SVC";

    private SharedPreferences prefs;
    private NotificationHandler nh;

    // Main Messenger used as binder. This will also be returned to callers of onStartService
    // that pass a messenger.
    private Messenger inMessenger;

    public IBinder onBind(Intent intent) {
        Log.d(TAG, "BIND Intent " + intent + " " + intent.getExtras());
        return inMessenger.getBinder();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        // The native implementation the service.
        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        Handler inHandler = new Handler(new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                // Mot used.
                return false; // handleInMessage(msg);
            }
        });
        inMessenger = new Messenger(inHandler);

        // TODO: interface for clients
        nh = new NotificationHandler(this);

        Log.d(TAG, "Starting1");
    }

    boolean fg = false;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        if (!prefs.getBoolean("lm_enabled", true)) {
            //dmUDS.closeNative();
            stopForeground(true);
            stopSelf();
            fg = false;
            return START_NOT_STICKY;
        }

        Wpgate.initDmesh(new wpgate.MessageHandler() {
            @Override
            public void handle(String topic, byte[] data) {
                Log.d(TAG, "GO MSG " + topic + " " + new String(data));
                if ("N".equals(topic)) {
                    nh.handleMessage(new String(data));
                }
            }
        });


        if (!fg && Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            startForeground(1, nh.getNotification("Starting"));
            Log.d(TAG, "Starting fg");
            fg = true;
        }

        return super.onStartCommand(intent, flags, startId);
    }
}
