package com.github.costinm.dmesh.libdm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.logs.Events;

/**
 * Watch battery state.
 */
public class BatteryMonitor extends BroadcastReceiver {


    public static final int EV_BATTERY = 50;
    public static final int EV_BATTERY_PS_ON = 51;
    public static final int EV_BATTERY_PS_OFF = 52;
    public static final int EV_BATTERY_IDLE_ON = 53;
    public static final int EV_BATTERY_IDLE_OFF = 54;

    private static final String TAG = "LM-BM";
    public final PowerManager pm;
    final Context ctx;
    final Handler ctl;
    public long chargingStart = 0;
    public long idleStart = 0;
    public long idleStop = 0;
    public long totalIdleTime = 0;
    public boolean isPowerSave = false;
    public BatteryManager bm;
    public float batteryPct;
    int status = -1;
    private int chargePlugExtraPlugged;

    public BatteryMonitor(Context ctx, Handler ctl) {
        this.ctx = ctx;
        this.ctl = ctl;

        pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);

        IntentFilter mIntentFilter = new IntentFilter();
        mIntentFilter.addAction(Intent.ACTION_BATTERY_CHANGED);
        // Battery control - DHCP doesn't work for AP in power save.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mIntentFilter.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            mIntentFilter.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);
        }
        ctx.registerReceiver(this, mIntentFilter);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            bm = (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
        }
        idleStop = SystemClock.elapsedRealtime();
    }

    @SuppressWarnings("unused")
    void close() {
        ctx.unregisterReceiver(this);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        long now = SystemClock.elapsedRealtime();
        intent.getStringExtra("");

        if (PowerManager.ACTION_POWER_SAVE_MODE_CHANGED.equals(action)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                isPowerSave = pm.isPowerSaveMode();
                Log.d(TAG, "PowerSave:" + isPowerSave);
                if (isPowerSave) {
                    ctl.obtainMessage(EV_BATTERY_PS_ON).sendToTarget();
                    Events.get().add("BM", "PSON", "Power save on");
                } else {
                    ctl.obtainMessage(EV_BATTERY_PS_OFF).sendToTarget();
                    Events.get().add("BM", "PSOFF", "Power save off");
                }
            }
        } else if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(action)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                boolean isIdle = pm.isDeviceIdleMode();
                if (isIdle) {
                    if (idleStart == 0) {
                        //event("lm", "Starting IDLE/DOZE");
                        idleStart = SystemClock.elapsedRealtime();
                        ctl.obtainMessage(EV_BATTERY_IDLE_ON).sendToTarget();
                        Log.d(TAG, "Idle: " + (idleStop - idleStart));
                        Events.get().add("BM", "ION", "" + (idleStop - idleStart));
                    }
                } else {
                    if (idleStart == 0) {
                        long thisIdle = now - idleStart;
                        idleStop = SystemClock.elapsedRealtime();
                        totalIdleTime += thisIdle;
                        //event("lm", "Exit IDLE/DOZE " + (now - idleStart));
                        idleStart = 0;
                        ctl.obtainMessage(EV_BATTERY_IDLE_OFF, thisIdle).sendToTarget();
                        Log.d(TAG, "IdleOff:" + thisIdle + " " + totalIdleTime);
                        Events.get().add("BM", "IOFF", thisIdle + " " + totalIdleTime);
                    }
                }
            }
        } else if (Intent.ACTION_BATTERY_CHANGED.equals(action)) {
            status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
//            boolean isChargingNow = status == BatteryManager.BATTERY_STATUS_CHARGING ||
//                    status == BatteryManager.BATTERY_STATUS_FULL;

            int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);

            batteryPct = level / (float) scale;

            chargePlugExtraPlugged = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
            boolean usbCharge = chargePlugExtraPlugged == BatteryManager.BATTERY_PLUGGED_USB;
            boolean acCharge = chargePlugExtraPlugged == BatteryManager.BATTERY_PLUGGED_AC;

            String m = "";
            if (usbCharge || acCharge) {
                if (chargingStart == 0) {
                    m = "charging " + (acCharge ? "AC " : "USB ") + level + "/" + scale;
                    chargingStart = now;
                    Events.get().add("BM", "BC", m);
                }
            } else {
                if (chargingStart > 0) {
                    m = "not charging " + batteryPct;
                    chargingStart = 0;
                    Events.get().add("BM", "BNC", m);
                }
            }
            Message msg = ctl.obtainMessage(EV_BATTERY);
            msg.arg1 = chargePlugExtraPlugged;
            msg.arg2 = (int) (10000 * batteryPct);
            msg.sendToTarget();

            Log.d(TAG, m);
        }
    }

    public void dump(Bundle b) {
        long now = SystemClock.elapsedRealtime();
        if (idleStart > 0) {
            b.putLong("b.idle", now - idleStart);
        }
        if (totalIdleTime > 0) {
            b.putLong("b.totalIdle", totalIdleTime);
        }
        if (chargingStart > 0) {
            b.putLong("b.charging", now - chargingStart);
        }
        if (status != -1) {
            b.putLong("b.status", status);
        }
        if (isPowerSave) {
            b.putLong("b.isPowerSave", 1);
        }
        if (chargePlugExtraPlugged != 0) {
            b.putLong("b.plugged", chargePlugExtraPlugged);
        }
        if (batteryPct != 0) {
            b.putLong("b.charge", (long) (batteryPct * 100));
        }
    }

    public boolean isCharging() {
        return chargingStart > 0;
    }
}
