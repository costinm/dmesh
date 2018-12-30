package com.github.costinm.dmesh.lm;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.util.Log;

import com.github.costinm.lm.WifiMesh;


@SuppressWarnings("deprecation")
public class WifiSettingsActivity extends PreferenceActivity
        implements SharedPreferences.OnSharedPreferenceChangeListener, Handler.Callback {

    public static final String TAG = "WifiDMPref";

    WifiMesh lm;
    private SharedPreferences prefs;

    @SuppressWarnings("deprecation")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        lm = WifiMesh.get(this);

        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        addPreferencesFromResource(R.xml.ap_preferences);

    }

    /**
     * Called after the preference was saved (?)
     */
    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        if (Starter.LM_ENABLED.equals(key)) {
            if (!sharedPreferences.getBoolean(key, false)) {
                lm.ap.stop(null);
            }
        } else {
            Log.d(TAG, key);
        }

        Intent i = new Intent(this, LMService.class);
        startService(i);
    }

    @Override
    protected void onResume() {
        super.onResume();

        getPreferenceScreen().getSharedPreferences()
                .registerOnSharedPreferenceChangeListener(this);

    }

    @Override
    protected void onPause() {
        super.onPause();
        getPreferenceScreen().getSharedPreferences()
                .unregisterOnSharedPreferenceChangeListener(this);

    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

    @Override
    public boolean handleMessage(Message m) {
        switch (m.what) {
            default:
                // Should get all events from service
                Log.d("DmeshC", "Msg " + m.what + " " + m.getData());
        }
        return false;
    }

}
