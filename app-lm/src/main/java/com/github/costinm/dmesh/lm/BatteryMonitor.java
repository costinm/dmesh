package com.github.costinm.dmesh.lm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;

public class BatteryMonitor extends BroadcastReceiver {
    private static final String TAG = "Bat";

    public long chargingStart = 0;
    public long idleStart = 0;
    public long idleTime = 0;
    public boolean isPowerSave = false;
    PowerManager pm;
    int status;

    public BatteryMonitor(Context ctx) {
        pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
        IntentFilter mIntentFilter = new IntentFilter();

        // Battery control - DHCP doesn't work for AP in power save.
        mIntentFilter.addAction(Intent.ACTION_BATTERY_CHANGED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mIntentFilter.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            mIntentFilter.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);
        }
        ctx.registerReceiver(this, mIntentFilter);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        long now = SystemClock.elapsedRealtime();
        intent.getStringExtra("");
        if (PowerManager.ACTION_POWER_SAVE_MODE_CHANGED.equals(action)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                isPowerSave = pm.isPowerSaveMode();
                //event("lm", "PowerSave=" + isPowerSave);
            }
        } else if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(action)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                boolean isIdle = pm.isDeviceIdleMode();
                if (isIdle) {
                    if (idleStart == 0) {
                        //event("lm", "Starting IDLE/DOZE");
                        idleStart = SystemClock.elapsedRealtime();
                    }
                } else {
                    if (idleStart == 0) {
                        idleTime += (now - idleStart);
                        //event("lm", "Exit IDLE/DOZE " + (now - idleStart));
                        idleStart = 0;
                    }
                }
            }
        } else if (Intent.ACTION_BATTERY_CHANGED.equals(action)) {
            //IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            //Intent batteryStatus = registerReceiver(null, ifilter);
            status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
//                boolean isChargingNow = status == BatteryManager.BATTERY_STATUS_CHARGING ||
//                        status == BatteryManager.BATTERY_STATUS_FULL;

            int chargePlug = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
            boolean usbCharge = chargePlug == BatteryManager.BATTERY_PLUGGED_USB;
            boolean acCharge = chargePlug == BatteryManager.BATTERY_PLUGGED_AC;
            int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);

            float batteryPct = level / (float) scale;

            if (usbCharge || acCharge) {
                if (chargingStart == 0) {
                    Log.d(TAG, "charging " + (acCharge ? "AC " : "USB ") + batteryPct);
                    chargingStart = now;
                }
            } else {
                if (chargingStart > 0) {
                    Log.d(TAG, "not charging " + batteryPct);
                    chargingStart = 0;
                }
            }
        }
    }

    public StringBuilder dump(Bundle b, StringBuilder sb) {
        long now = SystemClock.elapsedRealtime();
        if (idleStart > 0) {
            b.putLong("lm.idle", now - idleStart);
        }

        if (chargingStart > 0) {
            b.putLong("lm.charging", now - chargingStart);
        }
        return sb;
    }
}
