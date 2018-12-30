package com.github.costinm.lm;

import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceCategory;
import android.preference.PreferenceScreen;
import android.provider.Settings;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import com.github.costinm.dmesh.libdm.DMUDS;
import com.github.costinm.dmesh.vpn.VpnService;

import static com.github.costinm.lm.LMesh.TAG;


@SuppressWarnings("deprecation")
public class LMSettingsActivity extends PreferenceActivity
        implements SharedPreferences.OnSharedPreferenceChangeListener {
    PowerManager pm;

    public static final int A_REQUEST_VPN = 9;

    PreferenceCategory permissions;
    boolean needsPower;
    boolean needsLocation;

    static boolean basicSettings = true;

    @SuppressWarnings("deprecation")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.ap_preferences);

        Intent i = new Intent(this, LMService.class);
        startService(i);

        permissions = (PreferenceCategory) findPreference("permissions");
        Preference pmenable = findPreference("power");
        pm = (PowerManager) getSystemService(POWER_SERVICE);
        needsPower = false;
        needsLocation = false;
        LMesh lm = LMesh.get(this);
        getActionBar().setTitle(lm.getMeshName());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // To start AP legacy
//            if (!Settings.System.canWrite(this)) {
//                Intent intent = new Intent(android.provider.Settings.ACTION_MANAGE_WRITE_SETTINGS);
//                intent.setData(Uri.parse("package:" + this.getPackageName()));
//                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
//                startActivityForResult(intent, 2);
//                return;
//            }
            if (!pm.isIgnoringBatteryOptimizations(getPackageName())) {
                needsPower = true;
                pmenable.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                    @RequiresApi(api = Build.VERSION_CODES.M)
                    @Override
                    public boolean onPreferenceClick(Preference preference) {
                        try {
                            Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                            i.setData(Uri.parse("package:" + LMSettingsActivity.this.getPackageName()));
                            startActivityForResult(i, 101);
                        } catch (Throwable t) {
                            // That includes all apps, hard to set. Works without the manifest perm.
                            try {
                                startActivityForResult(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS), 101);
                            } catch (Throwable t2) {
                            }
                        }
                        return false;
                    }
                });
            } else {
                permissions.removePreference(pmenable);
            }
        } else {
            permissions.removePreference(pmenable);
        }

        Preference lenable = findPreference("location");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                needsLocation = true;
                lenable.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                    @RequiresApi(api = Build.VERSION_CODES.M)
                    @Override
                    public boolean onPreferenceClick(Preference preference) {
                        try {
                            requestPermissions(new String[]{
                                    Manifest.permission.ACCESS_FINE_LOCATION,
                                    Manifest.permission.ACCESS_COARSE_LOCATION,
                                    Manifest.permission.ACCESS_WIFI_STATE,
                                    Manifest.permission.CHANGE_WIFI_STATE
                            }, 102);
                        } catch (Throwable t) {
                            t.printStackTrace();
                        }
                        return false;
                    }
                });
            } else {
                permissions.removePreference(lenable);
            }
        } else {
            permissions.removePreference(lenable);
        }

        if (!needsPower && !needsLocation) {
            getPreferenceScreen().removePreference(permissions);
        }

        if (Build.VERSION.SDK_INT >= 21) {
            // 15 min interval for discovery (min) - it means AP must run for >5 min for an
            // initiating device to be found. Setting this too long would cause battery use
            // on the more expensive AP mode.
            LMJob.schedule(this, 5 * 60 * 1000);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           String permissiona[], int[] grantResults) {
        Preference lenable = (Preference) findPreference("location");
        permissions.removePreference(lenable);
        Log.d(TAG, "Perm: " + permissiona + " " + grantResults);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == 101) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (pm.isIgnoringBatteryOptimizations(getPackageName())) {
                    Preference srv = findPreference("power");
                    if (permissions != null && srv != null) {
                        permissions.removePreference(srv);
                    }
                }
            }
        }
        if (A_REQUEST_VPN == requestCode) {
            // return from vpn permission - update
            LMesh.get(this).maybeStartVpn();
        }
        super.onActivityResult(requestCode, resultCode, data);
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
        // Cause an 'updateCycle' loop, will update state.
        if ("vpn_enabled".equals(key)) {
            // if needed
            Intent i = VpnService.prepare(this);
            if (i != null) {
                startActivityForResult(i, A_REQUEST_VPN);
                return;
            }
        }
        LMesh.get(this).updateCycle();
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
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.prefs_menu, menu);
        return true;
    }

    @Override
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.debug) {
            Intent i = new Intent(this, LMDevicesActivity.class);
            startActivityForResult(i, 101);
        } else if (id == R.id.refresh) {
            Intent i = new Intent(this, LMService.class).putExtra("cmd", "refresh");
            startService(i);
        } else if (id == R.id.mesh_start) {
            Intent i = new Intent(this, LMService.class).putExtra("cmd", "mesh_start");
            startService(i);
        } else if (id == R.id.view) {
            String url = "http://localhost:5227/status";
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse(url));
            startActivityForResult(i, 5);
        } else if (id == R.id.adv_settings) {
            PreferenceScreen ps  = (PreferenceScreen) findPreference("advanced");
            ps.setEnabled(true);
        }
        return super.onMenuItemSelected(featureId, item);
    }

}