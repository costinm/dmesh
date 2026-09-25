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

import com.github.costinm.dmesh.CborMessageCodec;
import com.github.costinm.dmesh.MeshClient;
import com.github.costinm.dmesh.MeshStream;

/**
 * Android battery/Doze observer. It sends bounded CBOR facts as a MeshStream;
 * Rust owns the shared battery state and scheduling decisions.
 */
final class BatteryMonitor extends BroadcastReceiver {
    private static final String TAG = "DM-Battery";

    private final Context context;
    private final PowerManager powerManager;
    private final BatteryManager batteryManager;
    private final MeshClient meshClient;
    private boolean registered;
    private long chargingStart;
    private long idleStart;
    private long totalIdleTime;
    private boolean powerSave;
    private int batteryPercent = -1;

    BatteryMonitor(Context context) {
        this.context = context.getApplicationContext();
        powerManager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        batteryManager = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
        meshClient = MeshClient.get(this.context);
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
        submit();
    }

    void close() {
        if (!registered) return;
        registered = false;
        try {
            context.unregisterReceiver(this);
        } catch (Throwable error) {
            Log.w(TAG, "battery receiver unregister failed", error);
        }
        meshClient.close();
    }

    @Override
    public void onReceive(Context ignored, Intent intent) {
        String action = intent.getAction();
        long now = SystemClock.elapsedRealtime();
        if (Intent.ACTION_BATTERY_CHANGED.equals(action)) {
            int status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
            int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            batteryPercent = level >= 0 && scale > 0 ? (level * 100 / scale) : -1;
            boolean charging = status == BatteryManager.BATTERY_STATUS_CHARGING
                    || status == BatteryManager.BATTERY_STATUS_FULL;
            if (charging && chargingStart == 0) chargingStart = now;
            if (!charging) chargingStart = 0;
            submit();
        } else if (PowerManager.ACTION_POWER_SAVE_MODE_CHANGED.equals(action)) {
            powerSave = powerManager.isPowerSaveMode();
            submit();
        } else if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(action)
                && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (powerManager.isDeviceIdleMode()) {
                idleStart = now;
                submit();
            } else {
                if (idleStart != 0) totalIdleTime += now - idleStart;
                idleStart = 0;
                submit();
            }
        }
    }

    private void submit() {
        long now = SystemClock.elapsedRealtime();
        long idleMs = idleStart == 0 ? 0 : now - idleStart;
        long chargingMs = chargingStart == 0 ? 0 : now - chargingStart;
        Bundle state = new Bundle();
        if (batteryPercent >= 0) state.putInt("battery_percent", batteryPercent);
        state.putBoolean("charging", chargingStart != 0);
        state.putBoolean("power_save", powerSave);
        state.putBoolean("idle", idleStart != 0);
        state.putLong("idle_ms", idleMs);
        state.putLong("total_idle_ms", totalIdleTime + idleMs);
        state.putLong("charging_ms", chargingMs);
        MeshStream request = new MeshStream("battery.state.update");
        request.payload = CborMessageCodec.encodeBundle(state);
        try {
            if (!meshClient.sendStream(request)) {
                Log.d(TAG, "Rust battery stream unavailable");
            }
        } catch (Throwable error) {
            Log.d(TAG, "Rust battery stream unavailable", error);
        }
    }
}
