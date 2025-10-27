package com.github.costinm.dmesh.lm;

import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.preference.PreferenceManager;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.google.android.material.navigation.NavigationView;

/**
 * Shown if DMesh is disabled. Info about app and button to enable it.
 */
public class SetupActivity extends AppCompatActivity implements MessageHandler, NavigationView.OnNavigationItemSelectedListener {

    public static final int A_REQUEST_VPN = 9;
    public static final int A_REQUEST_LOCATION = 10;
    private static final String TAG = "DMSetupActivity";

    // UI elements
    private SharedPreferences prefs;

    private Switch vpnSwitch;
    private Switch wifiSwitch;
    Toolbar toolbar;

    MsgMux mux;

    @Override
    protected void onDestroy() {
        mux.unsubscribe("net", this);
        super.onDestroy();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        setContentView(R.layout.setup);

        mux = MsgMux.get(this.getApplication());

        toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        NavigationView nav = findViewById(R.id.nav_view);
        nav.setNavigationItemSelectedListener(this);

        // TODO: show 'location enabled' and why, hide btn
        vpnSwitch = findViewById(R.id.vpn_switch);
        wifiSwitch = findViewById(R.id.wifi_switch);

        setupUI();

        mux.subscribe("net", this);
    }

    public void setupUI() {
        final Intent svcI = new Intent(this, DMService.class);

        boolean hasLocation = true;
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            hasLocation = false;
        }

        wifiSwitch.setChecked(prefs.getBoolean(DMService.PREF_WIFI_ENABLED, false) && hasLocation);
        final boolean hasLocationF = hasLocation;

        wifiSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                prefs.edit().putBoolean(DMService.PREF_WIFI_ENABLED, b).commit();
                if (!hasLocationF) {
                    try {
                        requestPermissions(new String[]{
                                Manifest.permission.ACCESS_FINE_LOCATION,
                                Manifest.permission.ACCESS_COARSE_LOCATION,
                                Manifest.permission.ACCESS_WIFI_STATE,
                                Manifest.permission.CHANGE_WIFI_STATE
                        }, A_REQUEST_LOCATION);
                    } catch (Throwable t) {
                        t.printStackTrace();
                    }
                }
                startService(svcI);
            }
        });

        final Intent i = VpnService.prepare(this);

        vpnSwitch.setChecked(prefs.getBoolean(DMService.PREF_VPN_ENABLED, false) && i == null);
        vpnSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                if (b && i != null) {
                    startActivityForResult(i, A_REQUEST_VPN);
                    // on return - will continue setup_menu of the VPN
                    return;
                }
                prefs.edit().putBoolean(DMService.PREF_VPN_ENABLED, b).commit();
                startService(svcI);
            }
        });

        setSwitch(R.id.dm_switch, DMService.PREF_ENABLED, false, svcI);
        setSwitch(R.id.vpn_ext_switch, "vpn_ext", false, svcI);

        if (prefs.getBoolean(DMService.PREF_ENABLED, true)) {
                try {
                    startForegroundService(svcI);
                } catch (Exception ex) {
                    Log.d(TAG, ex.getMessage());
                }
        }
    }

    void setSwitch(int id, final String name, boolean def, final Intent svcI) {
        boolean svcEnabed = prefs.getBoolean(name, def);
        Switch svcSwitch = findViewById(id);
        svcSwitch.setChecked(svcEnabed);
        svcSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                prefs.edit().putBoolean(name, b).commit();
                startService(svcI);
            }
        });
    }

    /**
     * Handles the permission screens.
     */
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (A_REQUEST_VPN == requestCode || A_REQUEST_LOCATION == requestCode) {
        }
        setupUI();
        super.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.setup_menu, menu);
        return true;
    }
    @Override
    public boolean onNavigationItemSelected(@NonNull MenuItem menuItem) {
        return onOptionsItemSelected(menuItem);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        String url;
        Intent i;
        // ...
        int itemId = item.getItemId();
        if (itemId == R.id.wifiAct) {
            startActivityForResult(new Intent(this, WifiActivity.class), 6);
        } else if (itemId == R.id.view) {
            urlOpen("http://localhost:5227/status");
        } else if (itemId == R.id.nav_active) {
            urlOpen("http://localhost:5227/active");
        }
        return super.onOptionsItemSelected(item);
    }

    private void urlOpen(String url) {
        Intent i = new Intent(Intent.ACTION_VIEW);
        i.setData(Uri.parse(url));
        startActivityForResult(i, 5);
    }

    @Override
    public void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args) {

    }

}
