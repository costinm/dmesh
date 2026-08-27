package com.github.costinm.dmesh.lm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmeshnative.MeshNode;

import java.nio.charset.StandardCharsets;

/**
 * Android battery/Doze observer. It translates framework state into bounded
 * telemetry bytes; Rust owns retention and scheduling decisions.
 */
final class BatteryMonitor extends BroadcastReceiver {
    private static final String TAG = "DM-Battery";

    private final Context context;
    private final PowerManager powerManager;
    private final BatteryManager batteryManager;
    private boolean registered;
    private long chargingStart;
    private long idleStart;
    private long totalIdleTime;
    private boolean powerSave;
    private int status = -1;
    private int plugged;
    private int batteryPercent = -1;

    BatteryMonitor(Context context) {
        this.context = context.getApplicationContext();
        powerManager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        batteryManager = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
        powerSave = powerManager.isPowerSaveMode();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && powerManager.isDeviceIdleMode()) {
            idleStart = SystemClock.elapsedRealtime();
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && batteryManager.isCharging()) {
            chargingStart = SystemClock.elapsedRealtime();
        }
        IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        filter.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            filter.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        }
        Intent sticky = this.context.registerReceiver(this, filter);
        registered = true;
        if (sticky != null) onReceive(this.context, sticky);
        submit("initial");
    }

    void close() {
        if (!registered) return;
        registered = false;
        try {
            context.unregisterReceiver(this);
        } catch (Throwable error) {
            Log.w(TAG, "battery receiver unregister failed", error);
        }
    }

    @Override
    public void onReceive(Context ignored, Intent intent) {
        String action = intent.getAction();
        long now = SystemClock.elapsedRealtime();
        if (Intent.ACTION_BATTERY_CHANGED.equals(action)) {
            status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
            int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            batteryPercent = level >= 0 && scale > 0 ? (level * 100 / scale) : -1;
            plugged = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
            boolean charging = status == BatteryManager.BATTERY_STATUS_CHARGING
                    || status == BatteryManager.BATTERY_STATUS_FULL;
            if (charging && chargingStart == 0) chargingStart = now;
            if (!charging) chargingStart = 0;
            submit(charging ? "battery_charging" : "battery");
        } else if (PowerManager.ACTION_POWER_SAVE_MODE_CHANGED.equals(action)) {
            powerSave = powerManager.isPowerSaveMode();
            submit(powerSave ? "power_save_on" : "power_save_off");
        } else if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(action)
                && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (powerManager.isDeviceIdleMode()) {
                idleStart = now;
                submit("idle_on");
            } else {
                if (idleStart != 0) totalIdleTime += now - idleStart;
                idleStart = 0;
                submit("idle_off");
            }
        }
    }

    private void submit(String event) {
        long now = SystemClock.elapsedRealtime();
        long idleMs = idleStart == 0 ? 0 : now - idleStart;
        long chargingMs = chargingStart == 0 ? 0 : now - chargingStart;
        String json = "{\"source\":\"android\",\"event\":\"" + json(event)
                + "\",\"battery_percent\":" + batteryPercent
                + ",\"status\":" + status
                + ",\"plugged\":" + plugged
                + ",\"charging\":" + (chargingStart != 0)
                + ",\"power_save\":" + powerSave
                + ",\"idle\":" + (idleStart != 0)
                + ",\"idle_ms\":" + idleMs
                + ",\"total_idle_ms\":" + totalIdleTime
                + ",\"charging_ms\":" + chargingMs + "}";
        try {
            MeshNode.radioMessage("radio.power.status", "",
                    json.getBytes(StandardCharsets.UTF_8), -1);
        } catch (Throwable error) {
            Log.d(TAG, "Rust power telemetry unavailable", error);
        }
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
