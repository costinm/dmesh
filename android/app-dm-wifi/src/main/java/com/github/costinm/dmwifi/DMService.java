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
import com.github.costinm.dmesh.android.msg.MsgCon;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.libdm.DMesh;
import com.github.costinm.dmesh.libdm.vpn.VpnService;
import com.github.costinm.dmesh.lm3.Ble;
import com.github.costinm.dmesh.lm3.Bt2;
import com.github.costinm.dmesh.lm3.Wifi;

public class DMService extends BaseMsgService {
    public static final String TAG = "DM-SVC";

    static Wifi wifi;
    private NotificationHandler nh;
    // The actual communication handlers
    public static DMesh dmUDS;
    private SharedPreferences prefs;

    boolean fg = false;

    @Override
    public void onCreate() {
        super.onCreate();

        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        wifi = new Wifi(this.getApplicationContext(), mux.broadcastHandler, getMainLooper());
        dmUDS = new DMesh(this.getApplicationContext(), "dmesh");

        mux.addHandler("ble", wifi.ble);
        mux.addHandler("bt", wifi.bt);
        mux.addHandler("wifi", wifi);

        nh = new NotificationHandler(this);
        mux.addHandler("N", nh);

        // send status on connect.
        mux.addHandler(":open", new MsgMux.MessageHandler() {
            @Override
            public void handleMessage(Message m, MsgCon replyTo, String[] args) {
                wifi.sendWifiDiscoveryStatus("connect");
            }
        });
    }

    public void onDestroy() {
        wifi.onDestroy();
        dmUDS.closeNative();
        super.onDestroy();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }

        if (!prefs.getBoolean("lm_enabled", true)) {
            dmUDS.closeNative();

            VpnService.stopVpn();

            stopForeground(true);
            stopSelf();
            fg = false;
            return START_NOT_STICKY;
        }

        // If not started, make sure it runs
        DMesh.get().openNative();

        if (!fg) {
            startForeground(1, nh.getNotification(new Bundle()));
            Log.d(TAG, "Starting fg");
            fg = true;
        }

        VpnService.maybeStartVpn(prefs, this, DMesh.get());

        return super.onStartCommand(intent, flags, startId);
    }

}
