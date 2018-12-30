package com.github.costinm.dmesh.lm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.preference.PreferenceManager;
import android.util.Log;

public class Starter extends BroadcastReceiver {

    static final String LM_ENABLED = "lm_enabled";

    public Starter() {
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        Context ctx = context.getApplicationContext();
        // Default to true for test app - the 'production' version
        // should be false, allow user to decide.
        if (!PreferenceManager.getDefaultSharedPreferences(ctx)
                .getBoolean(LM_ENABLED, true)) {
            Log.d(LMService.TAG, "Disabled / " + action);
            return;
        }
        // TODO: bind, send the data to the service
        switch (action) {
            case "com.github.costinm.dmesh.update":
            case "android.intent.action.BOOT_COMPLETED":
            case "android.intent.action.MY_PACKAGE_REPLACED":
            case "android.intent.action.ACTION_POWER_CONNECTED":
            case "android.intent.action.ACTION_POWER_DISCONNECTED":
                // Just make sure it is running.
                Log.d(LMService.TAG, "Starter / " + action);
                Intent i = new Intent(ctx, LMService.class);
                ctx.startService(i);
        }
    }
}
