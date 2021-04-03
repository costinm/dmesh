package com.github.costinm.dmesh;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

/**
 * Base settings, for GB-KitKat without WifiDirect.
 * Doesn't include power or special permissions - only needed on L/5.0/21+.
 */
@SuppressWarnings("deprecation")
public class DMSettingsActivity extends PreferenceActivity
        implements SharedPreferences.OnSharedPreferenceChangeListener, Handler.Callback {

    private static final String TAG = "DM";
    boolean active = false;

    Handler h;

    private SharedPreferences prefs;

    Bt2ProvServer bt2;

    @SuppressWarnings("deprecation")

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.dm_preferences);
        initScreen();

        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        active = true;
        h = new Handler(this);

        bt2 = new Bt2ProvServer(this, h);
    }

    protected void initScreen() {
        Intent i = new Intent(this, DMService.class);
        startService(i);
    }

    void refresh() {
        if (!active) {
            return;
        }
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                refreshUI();
            }
        });
    }

    void refreshUI() {
        // Update any preference based on changes
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

    /**
     * Called after the preference was saved (?)
     */
    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        String val = sharedPreferences.getAll().get(key).toString();
        if ("lm_enabled".equals(key)) {
            Intent i = new Intent(this, DMService.class);
            startService(i);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        active = true;
        refresh();
        getPreferenceScreen().getSharedPreferences()
                .registerOnSharedPreferenceChangeListener(this);
    }

    @Override
    protected void onPause() {
        super.onPause();
        active = false;
        getPreferenceScreen().getSharedPreferences()
                .unregisterOnSharedPreferenceChangeListener(this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.dm, menu);
        return true;
    }

    @Override
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        int id = item.getItemId();
        int what = 0;
        if (id == R.id.wifi) {
            bt2.makeDiscoverable();
            return super.onMenuItemSelected(featureId, item);
        } else if (id == R.id.view) {
            // TODO: use WebView instead
            String url = "http://localhost:5227/status";
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse(url));
            startActivityForResult(i, 5);
            return super.onMenuItemSelected(featureId, item);
        }

        return super.onMenuItemSelected(featureId, item);
    }


    @Override
    public boolean handleMessage(Message m) {
        switch (m.what) {
            default:
                refresh();
                // Should dial all events from service
                Log.d("DmeshC", "MsgMux " + m.what + " " + m.getData());
        }
        return false;
    }


}
