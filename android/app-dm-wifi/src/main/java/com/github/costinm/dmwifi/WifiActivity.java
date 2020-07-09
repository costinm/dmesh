package com.github.costinm.dmwifi;

import android.Manifest;
import android.app.AlertDialog;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;
import com.google.android.material.snackbar.Snackbar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.webkit.WebView;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;

import com.github.costinm.dmesh.android.msg.MsgCon;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.msg.UiUtil;
import com.github.costinm.dmesh.libdm.vpn.VpnService;
import com.github.costinm.dmesh.lm3.Bt2;
import com.github.costinm.dmesh.lm3.Device;
import com.github.costinm.dmesh.lm3.Wifi;

import java.util.ArrayList;

import static android.graphics.Color.GREEN;

public class WifiActivity extends AppCompatActivity {

    public static final int A_REQUEST_VPN = 9;
    private static final String TAG = "P2PTest";
    private static final String STATUS_URL = "http://127.0.0.1:5227/status";

    // Interacts with the wifi service, using messages.
    //MsgCon wifi;

    MsgCon wifi;

    boolean started = false;
    Handler h = new Handler();

    // UI elements
    TextView infoText;
    TextView conText;
    TextView msgText;

    Toolbar toolbar;
    Switch apSwitch;
    Switch discSwitch;
    // If enabled, VPN will also be enabled. Little value of running the mesh without
    // at least local capture.
    Switch dmSwitch;

    boolean initialState = false;
    String visible = "0";
    Bundle lastStatus;
    String apSsid;
    String apPsk;
    Bundle msgTxtDetails;
    Bt2 bt2;
    private SharedPreferences prefs;

    String id4 = "0000";

    @Override
    protected void onDestroy() {
        wifi.close();
        //vpn.close();
        super.onDestroy();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // TODO: show intro page, dialog for permissions
        // TODO: do it only when user first does a discovery.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
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
            }
        }

        setContentView(R.layout.activity_main);

        toolbar = findViewById(R.id.toolbar);

        initialState = false;

        apSwitch = findViewById(R.id.ap_switch);
        if (savedInstanceState != null && savedInstanceState.getBoolean("ap", false)) {
            apSwitch.setChecked(true);
        }

        discSwitch = findViewById(R.id.disc_switch);
        if (savedInstanceState != null && savedInstanceState.getBoolean("disc", false)) {
            discSwitch.setChecked(true);
        }

        dmSwitch = findViewById(R.id.dm_switch);

        if (prefs.getBoolean("lm_enabled", false)) {
            Intent i = new Intent(WifiActivity.this, DMService.class);
            startService(i);
            dmSwitch.setChecked(true);
        }

        // Enabling DMesh also enables VPN - simpler UI and documentation...
        // It is very easy to decouple and use it only as SOCKS/HTTP proxy via a setting.
        dmSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                prefs.edit().putBoolean("lm_enabled", b).apply();
                prefs.edit().putBoolean("vpn_enabled", b).apply();
                Intent i = VpnService.prepare(WifiActivity.this);
                if (i != null) {
                    startActivityForResult(i, A_REQUEST_VPN);
                    // on return - will continue setup_menu of the VPN
                    return;
                }

                Intent i2 = new Intent(WifiActivity.this, DMService.class);
                startService(i2);
            }
        });


        setSupportActionBar(toolbar);

        conText = findViewById(R.id.con_text);
        infoText = findViewById(R.id.info_text);

        msgText = findViewById(R.id.msg_text);
        msgText.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AlertDialog ad = new AlertDialog.Builder(WifiActivity.this)
                        .setTitle("Last intent data")
                        .setMessage(UiUtil.toString(msgTxtDetails))
                        .create();
                ad.show();
            }
        });

        MsgMux.get(getApplicationContext()).addHandler("wifi", new MsgMux.MessageHandler() {
            @Override
            public void handleMessage(Message m, MsgCon replyTo, String[] args) {
                messageFromWifi(m);
            }
        });

        wifi = MsgMux.get(getApplicationContext()).dial(getPackageName());
        wifi.start();

        wv = findViewById(R.id.wv);

        refreshVisible();
    }
    WebView wv;

    // Called after the first 'status' update from the service.
    void initSwitches() {
        if (initialState) {
            return;
        }

        apSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                wifi.send("/wifi/p2p", "ap", b ? "1" : "0");
            }
        });
        discSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                if (b) {
                    wifi.send("/wifi/con/start");
                } else {
                    wifi.send("/wifi/con/stop");
                }
            }
        });

        initialState = true;
    }

    protected void onSaveInstanceState(Bundle icicle) {
        super.onSaveInstanceState(icicle);
        icicle.putBoolean("ap", apSwitch.isChecked());
        icicle.putBoolean("disc", discSwitch.isChecked());
    }

    private void updateStatus(Bundle data) {
        lastStatus = data;

        int gc = 0;
        Bundle data1 = data.getBundle("data");
        if (data1 != null) {
            ArrayList<Bundle> b = data1.getParcelableArrayList("scan");
            if (b != null) {
                for (Bundle bb: b) {
                    Device d = new Device(bb);

                    if (d.data.getString("gc","0").equals("1")) {
                        gc++;
                    }
                }
            }
        }
        if (gc > 0) {
            infoText.setBackgroundColor(GREEN);
        } else {
            infoText.setBackgroundColor(Color.YELLOW);
        }

        visible = data.getString("visible", "0");

        String ssid = data.getString(Device.WIFISSID);
        if (ssid == null) {
            conText.setText("Wifi disconnected");
        } else {
            final StringBuilder sb = new StringBuilder();
            sb.append("SSID: ").append(ssid).append(" ").append(data.getString(Device.LEVEL))
                    .append("/").append(data.getString(Device.FREQ));
            sb.append("\n");
            conText.setText(sb.toString());
        }

        String apStatus = data.getString("ap", "");
        if (apStatus.equals("1")) {
            started = true;
            apSwitch.setChecked(true);
            apSsid = data.getString("s");
            apPsk = data.getString("p");
            apSwitch.setText("PSK: " + apPsk);
            toolbar.setTitle("* " + apSsid.substring("DIRECT-xx-".length()));
        } else if (apStatus.equals("0")){
            started = false;
            if (apSsid != null) {
                toolbar.setTitle(" " + apSsid.substring("DIRECT-xx-".length()));
            } else {
                toolbar.setTitle("AP: Off");
            }
            apSwitch.setChecked(false);
        }

        initSwitches();

        refreshVisible();
    }

    /**
     * Handles messages from the wifi service.
     */
    public boolean messageFromWifi(Message message) {
        final Bundle d = message.getData();
        runOnUiThread(new Runnable() {
            @Override
            public void run() {

                String uri = d.getString(":uri");
                if (uri == null) {
                    return;
                }

                String[] parts = uri.split("/");
                if (parts.length < 3) {
                    return;
                }

                //  /wifi/AP/ ...
                switch (parts[2]) {
                    case "status":
                        updateStatus(d);
                        break;

                    case "p2p":
                        if (parts.length > 3 && "discState".equals(parts[3])) {
                            // TODO: UI to show P2P discovery in progress.
                            discSwitch.setChecked(d.getString("on", "0").equals("1"));
                        }
                        break;

                    case "INTENT":
                        // all other updates that are not translated to MSG
                        final Bundle i = (Bundle) d.getParcelable("data");
                        msgTxtDetails = i;
                        if (i != null) {
                            msgText.setText(parts[3]);
                        }
                        break;

                    case "AP":
                        if (d.getString("on", "0").equals("1")) {
                            started = true;
                            apSwitch.setChecked(true);
                            //toolbar.setTitle(apInfo);
                            apSwitch.setText(d.getString("s") + "/" + d.getString("p"));

                            if (Wifi.currentClientList.size() > 0) {
                                StringBuilder sb = new StringBuilder();
                                for (WifiP2pDevice c : Wifi.currentClientList) {
                                    sb.append("C: ").append(c.deviceAddress).append(" ").append(c.deviceName).append("\n");
                                }

                                infoText.setText(sb.toString());
                            }
                        } else {
                            started = false;

                            toolbar.setTitle("AP: Off");

                            infoText.setText("");
                            apSwitch.setChecked(false);
                        }

                        refreshVisible();
                        break;


                    default:
                        Snackbar.make(infoText, uri, 2000).show();
            }
        }});

        return false;
    }


    private void refreshVisible() {
        wv.loadUrl(STATUS_URL);
    }

    /**
     * Handles the permission screens.
     */
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (A_REQUEST_VPN == requestCode) {
            // return from vpn permission - update
            Intent i2 = new Intent(WifiActivity.this, DMService.class);
            startService(i2);
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.p2p, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.mdnssdon:
                wifi.send("/wifi/adv", "p2p", "1");
                break;
            case R.id.mdnssdoff:
                wifi.send("/wifi/adv","p2p", "0");
                break;
            case R.id.sddisc:
                wifi.send("/wifi/disc");
                break;
            case R.id.btlegacy:
                btlegacy();
                break;
            case R.id.scan:
                wifi.send("/wifi/scan");
                break;
            case R.id.nanstart:
                wifi.send("/wifi/adv", "on", "1");
                break;
            case R.id.nanstop:
                wifi.send("/wifi/adv", "on", "0");
                break;
            case R.id.nanping:
                wifi.send("/wifi/nan/ping");
                break;
            case R.id.disc:
                //disc.clear();
                wifi.send("/wifi/con/start", "sd", "0", "wait", "0");
                break;
            case R.id.discoff:
                wifi.send("/wifi/con/stop");
                break;
            case R.id.wificaps:
                showWifiCaps();
                break;

            case R.id.lastStatus:
                    AlertDialog ad = new AlertDialog.Builder(WifiActivity.this)
                            .setTitle("Last status")
                            .setMessage(UiUtil.toString(lastStatus, "\n"))
                            .create();
                    ad.show();
            case R.id.view:
                String url = "http://localhost:5227/status";
                Intent i = new Intent(Intent.ACTION_VIEW);
                i.setData(Uri.parse(url));
                startActivityForResult(i, 5);
                break;

            case R.id.listAct:
                startActivityForResult(new Intent(this, ListActivity.class), 6);
                break;

        }
        return super.onOptionsItemSelected(item);
    }

    /**
     * Provision legacy BT devices.
     *
     * TODO: replace with a messaging channel, connect to multiple BT if possible.
     */
    private void btlegacy() {
        if (bt2 == null) {
            bt2 = new Bt2(this, h);
        }

        bt2.scan();
        h.postDelayed(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        for (BluetoothDevice d: bt2.devices.values()) {
                            bt2.connect(d.getAddress(), "WIFI\n" + apSsid + "\n" + apPsk + "\n");
                        }
                    }
                }).start();
            }
        }, 10000);
    }

    /**
     * Details about the device
     *  - RTT - distance to AP
     *  - TDLS - direct sta to sta
     *
     * Pixel1: RTT, PowerReport, TDLS
     * Nexus6: RTT, PowerReport, TDLS, OffloadScan
     *
     */
    private void showWifiCaps() {
        // Nexus 6: all capabilities bellow.
        if (Build.VERSION.SDK_INT >= 21) {
            WifiManager mWifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            StringBuilder title = new StringBuilder();
            // May be used to reduce scans
            if (mWifiManager.isPreferredNetworkOffloadSupported()) {
                title.append("Offload Scan, ");
            }
            // Can be used to decide when to switch
            if (mWifiManager.isDeviceToApRttSupported()) {
                title.append("RTT, ");
            }
            if (mWifiManager.isEnhancedPowerReportingSupported()) {
                title.append("PowerReport, ");
            }
            // It might help reduce battery on the AP, but not sure yet how to use it.
            if (mWifiManager.isTdlsSupported()) {
                // setTdls(ip, true)
                // Tunnel direct
                title.append("TDLS, ");
            }
            if (mWifiManager.is5GHzBandSupported()) {
                title.append("5G, ");
            }
            if (!mWifiManager.isP2pSupported()) {
                title.append("!P2P, ");
            }
            if (Build.VERSION.SDK_INT >= 29) {
                if (mWifiManager.isEasyConnectSupported()) {
                    title.append("EC, ");
                }
            }
            AlertDialog ad = new AlertDialog.Builder(WifiActivity.this)
                    .setTitle("Wifi capabilities")
                    .setMessage(title.toString())
                    .create();
            ad.show();
        }
    }
}
