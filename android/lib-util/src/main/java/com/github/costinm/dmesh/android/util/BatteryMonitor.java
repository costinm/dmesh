package com.github.costinm.dmesh.android.util;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.MsgMux;

/**
 * Watch battery state.
 * <p>
 * Will broadcast the battery state, on "/BM" topic.
 * <p>
 * Content:
 * batteryPct: battery percent ( number, but as string)
 * charging: 0|usb|ac|other
 * ps: 0|1 - power save mode
 * idle: 0|1 - idle mode
 * event: last event that caused batter status to be sent.
 * bc - battery charging
 * bnc - battery not charging
 * PSON|PSOFF - power save state changed
 * ION|IOFF - idle state changed
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
    public long chargingStart = 0;
    public long idleStart = 0;
    public long idleStop = 0;
    public long totalIdleTime = 0;
    public boolean isPowerSave = false;
    public BatteryManager bm;
    public float batteryPct;
    int status = -1;
    MsgMux mux;
    boolean reg = false;
    private int chargePlugExtraPlugged;

    /**
     * Ctl will receive Messages with what EV_ about battery changes.
     */
    public BatteryMonitor(Context ctx, MsgMux mux) {
        this.ctx = ctx;
        this.mux = mux;
        pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);

        IntentFilter mIntentFilter = new IntentFilter();
        mIntentFilter.addAction(Intent.ACTION_BATTERY_CHANGED);

        // Battery control - DHCP doesn't work for AP in power save.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mIntentFilter.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        }
        mIntentFilter.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);
        ctx.registerReceiver(this, mIntentFilter);
        reg = true;
        bm = (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
        idleStop = SystemClock.elapsedRealtime();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (pm.isDeviceIdleMode()) {
                idleStart = SystemClock.elapsedRealtime();
            }
        }

        isPowerSave = pm.isPowerSaveMode();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (bm.isCharging()) {
                chargingStart = SystemClock.elapsedRealtime();
            }
        }

        // TODO: battery pct.
    }

    public void close() {
        try {
            if (reg) {
                ctx.unregisterReceiver(this);
            }
        } catch (Throwable t) {

        }
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        long now = SystemClock.elapsedRealtime();
        intent.getStringExtra("");

        if (PowerManager.ACTION_POWER_SAVE_MODE_CHANGED.equals(action)) {
            isPowerSave = pm.isPowerSaveMode();
            if (isPowerSave) {
                sendStatus("PSON");
            } else {
                sendStatus("PSOFF");
            }
        } else if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(action)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                boolean isIdle = pm.isDeviceIdleMode();
                if (isIdle) {
                    //event("lm", "Starting IDLE/DOZE");
                    if (idleStart == 0) {
                        idleStart = SystemClock.elapsedRealtime();
                        if (idleStop == 0) {
                            sendStatus("ION");
                        } else {
                            mux.publish("/BM/ION", "timeOn", Long.toString(idleStop - idleStart));
                        }
                    }
                    Log.d(TAG, "Idle: " + (idleStop - idleStart));
                } else {
                    if (idleStart != 0) {
                        long thisIdle = now - idleStart;
                        idleStop = SystemClock.elapsedRealtime();
                        totalIdleTime += thisIdle;
                        idleStart = 0;
                        Log.d(TAG, "IdleOff:" + thisIdle + " " + totalIdleTime);
                        sendStatus("IOFF");
                        mux.publish("/BM/IOFF",
                                "timeOff", thisIdle + "",
                                "totalOff", "" + totalIdleTime);
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
                    m = "charging " + +level + "/" + scale;
                    chargingStart = now;
                    sendStatus("bc");
                }
            } else {
                if (chargingStart > 0) {
                    m = "not charging " + batteryPct;
                    chargingStart = 0;
                    sendStatus("bnc");
                }
            }

            Log.d(TAG, m);
        }
    }

    public void sendStatus(String event) {

        String chState = "0";
        if (chargePlugExtraPlugged == BatteryManager.BATTERY_PLUGGED_USB) {
            chState = "usb";
        }
        if (chargePlugExtraPlugged == BatteryManager.BATTERY_PLUGGED_AC) {
            chState = "ac";
        }
        if (chargePlugExtraPlugged != 0) {
            chState = "" + chargePlugExtraPlugged;
        }

        mux.publish("/BM/status",
                "batteryPct", (int) (batteryPct * 100) + "",
                "charging", chState,
                "ps", isPowerSave ? "1" : "0",
                "status", "" + status,
                "idle", (idleStart != 0) ? "1" : "0",
                "event", event);
//        long now = SystemClock.elapsedRealtime();
//        if (idleStart > 0) {
//            b.putLong("b.idle", now - idleStart);
//        }
//        if (totalIdleTime > 0) {
//            b.putLong("b.totalIdle", totalIdleTime);
//        }
//        if (chargingStart > 0) {
//            b.putLong("b.charging", now - chargingStart);
//        }
    }
}
