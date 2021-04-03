package com.github.costinm.dmesh.lm;

import android.app.Notification;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.app.RemoteInput;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.BaseMsgService;
import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.lm3.Wifi;


import wpgate.Wpgate;

/**
 * Foreground service maintaining the notification, wifi, native process.
 */
public class DMService extends BaseMsgService implements MessageHandler {
    public static final String TAG = "DM-SVC";
    public static final String PREF_ENABLED = "lm_enabled";
    public static final String PREF_WIFI_ENABLED = "wifi_enabled";
    public static final String PREF_VPN_ENABLED = "vpn_enabled";

    // Implements the Wifi, discovery messaging interface, using Android APIs.
    static Wifi wifi;

    // Notification bar UI - handles messages from the mux to update the bar.
    private NotificationHandler nh;

    private SharedPreferences prefs;

    Handler delayHandler = new Handler();

    boolean fg = false;

    @Override
    public void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args) {
        if (args.length < 2) {
            return;
        }
        switch (args[1]) {
            case "I":
                // Update id4 for wifi. Will be used in announcements.
                wifi.handleMessage(topic, msgType, m, replyTo, args);
                break;
        }
    }

    public static class Receiver extends BroadcastReceiver {

        private CharSequence getMessageText(Intent intent) {
            Bundle remoteInput = RemoteInput.getResultsFromIntent(intent);
            if (remoteInput != null) {
                return remoteInput.getCharSequence(":uri");
            }
            return null;
        }

        @Override
        public void onReceive(Context context, Intent intent) {
            CharSequence txt = getMessageText(intent);
            Log.d(TAG, "BROADCAST MSG: " + txt + " " + intent + " " + intent.getData());

            // TODO: Add the channel

            Notification repliedNotification = new NotificationCompat.Builder(context, "dmesh")
                    .setSmallIcon(R.drawable.ic_launcher_background)
                    .setContentText("CMD HANDLED")
                    .build();

            // Re-issue the notification on the channel.
            NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
            notificationManager.notify(1, repliedNotification);
        }
    }

    static byte[] addr;

    @Override
    public void onCreate() {
        super.onCreate();

        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        wifi = Wifi.get(this.getApplicationContext());

        addr = Wpgate.initDmesh(new wpgate.MessageHandler() {
            @Override
            public void handle(String topic, byte[] data) {
                Log.d(TAG, "GO MSG " + topic + " " + new String(data));
            }
        });

        nh = new NotificationHandler(this);

        // Dispatching messages on this service.
        mux.subscribe("ble", wifi.ble);
        mux.subscribe("bt", wifi.bt);
        mux.subscribe("wifi", wifi);
        mux.subscribe("N", nh);

        // Info from the client - currently the 64-bit node ID, other info will be added.
        // Sent on connect.
        mux.subscribe("I", this);

        // send status on connect.
        mux.subscribe(":open", new MessageHandler() {
            @Override
            public void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args) {
                wifi.sendWifiDiscoveryStatus("connect", "");
            }
        });


        LMJob.schedule(this.getApplicationContext(), 15 * 60 * 1000);

    }

    public void onDestroy() {
        wifi.onDestroy();
        super.onDestroy();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }

        if (!prefs.getBoolean(PREF_ENABLED, true)) {
            // TODO: implement a stop ? dmUDS.closeNative();

            VpnService.stopVpn();

            stopForeground(true);
            stopSelf();
            fg = false;
            Log.d(TAG, "Stop fg");

            return START_NOT_STICKY;
        }

        if (!fg) {
            startForeground(1, nh.getNotification(new Bundle()));
            Log.d(TAG, "Starting fg");
            fg = true;
        }

        VpnService.maybeStartVpn(prefs, this);

        return super.onStartCommand(intent, flags, startId);
    }

}
