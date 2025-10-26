package com.github.costinm.dmeshnative;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

// Pre LMP starter
public class Starter extends BroadcastReceiver {

    public Starter() {
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        Context ctx = context.getApplicationContext();
        Log.d("LM-Start", "Starting " + action);
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);

        if (!prefs.getBoolean("lm_enabled", true)) {
            return;
        }
        switch (action) {
            case "com.github.costinm.dmesh.update":
            case "android.intent.action.BOOT_COMPLETED":
            case "android.intent.action.MY_PACKAGE_REPLACED":
            case "android.intent.action.ACTION_POWER_CONNECTED":
            case "android.intent.action.ACTION_POWER_DISCONNECTED":
                // Just make sure it is running.

                Log.d(DMService.TAG, "Starter / " + action);
                Intent i = new Intent(ctx, DMService.class);
                ctx.startService(i);

        }
    }
}
