package com.github.costinm.dmesh.lm;

import android.app.AlertDialog;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;

import androidx.annotation.NonNull;

import com.google.android.material.navigation.NavigationView;
import com.google.android.material.snackbar.Snackbar;

import androidx.core.view.GravityCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.util.Log;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.UiUtil;
import com.github.costinm.dmesh.lm3.Bt2;
import com.github.costinm.dmesh.lm3.Device;
import com.github.costinm.dmesh.lm3.Wifi;

import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;

import static android.graphics.Color.GREEN;

/**
 * Manual connection to Wifi - with debug menu.
 */
public class WifiActivity extends AppCompatActivity implements MessageHandler {

    public static final int A_REQUEST_VPN = 9;
    private static final String TAG = "Wifi";

    // wifi is a Messenger-based connection to DMService mux, which dispatches to the native
    // process.
    //
    // SetupActivity uses the in-process mux directly - this is here to test the client code.
    Wifi wifi;

    private MsgMux mux;

    boolean apStarted = false;
    Handler h = new Handler();

    // UI elements
    ListView discList;
    //TextView infoText;
    TextView conText;
    TextView msgText;
    TextView ifText;
    ArrayList<Device> disc = new ArrayList<>();
    ArrayAdapter<Device> discListAdapter;
    Toolbar toolbar;

    String visible = "0";
    Bundle lastStatus;

    String apSsid;
    String apPsk;
    Bundle msgTxtDetails;

    Bt2 bt2;
    String id4 = "0000";
    //WebView wv;
    private SharedPreferences prefs;

    @Override
    protected void onDestroy() {
        mux.unsubscribe("net", this);
        super.onDestroy();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        setContentView(R.layout.debug_activity);


        NavigationView nav = findViewById(R.id.nav_view);
        nav.setNavigationItemSelectedListener(new NavigationView.OnNavigationItemSelectedListener() {
            @Override
            public boolean onNavigationItemSelected(@NonNull MenuItem menuItem) {
                DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
                drawer.closeDrawer(GravityCompat.START);
                return false;
            }
        });

        // can addMap2Bundle multiple header views !
        toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        View header = nav.getHeaderView(0);
        //infoText = header.findViewById(R.id.info_text);

        msgText = header.findViewById(R.id.msg_text);

        setSupportActionBar(toolbar);

        mux = MsgMux.get(getApplicationContext());
        mux.subscribe("net", this);

        wifi = Wifi.get(this);

        setupUI();
    }

    public void setupUI() {
        final Intent svcI = new Intent(this, DMService.class);


//        if (false) {
//            wv = findViewById(R.id.wv);
//            wv.setNetworkAvailable(true);
//            //wv.addJavascriptInterface();
//            //wv.autofill();
//            wv.canGoBackOrForward(10);
//            wv.getSettings().setJavaScriptEnabled(true);
//            wv.setWebViewClient(new WebViewClient() {
//                public boolean shouldOverrideUrlLoading(WebView view, String url) {
////                if (url != null && (url.startsWith("http://") || url.startsWith("https://"))) {
////                    view.getContext().startActivity(
////                            new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
////                    return true;
////                } else {
//                    return false;
////                }
//                }
//            });
//        }


        discList = findViewById(R.id.disclist);
        if (discList != null) {
            discListAdapter = new ArrayAdapter<Device>(this, android.R.layout.two_line_list_item,
                    android.R.id.text1, disc) {
                @Override
                public View getView(int position, View convertView,
                                    @NonNull ViewGroup parent) {
                    return getDeviceView(this, position, convertView, parent);
                }
            };
            discList.setAdapter(discListAdapter);
            discList.setOnCreateContextMenuListener(new View.OnCreateContextMenuListener() {
                @Override
                public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo contextMenuInfo) {

                    deviceMenu(menu, v, (AdapterView.AdapterContextMenuInfo) contextMenuInfo);

                }
            });
            discList.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                @Override
                public void onItemClick(AdapterView<?> adapterView, View view, int i, long l) {
                    Device d = (Device) adapterView.getItemAtPosition(i);
                    Log.d(TAG, "Selected " + i);
                    AlertDialog ad = new AlertDialog.Builder(WifiActivity.this)
                            .setTitle("Wifi " + i)
                            .setMessage(UiUtil.toString(d.data)) //  + "\n" + d.wifi)
                            .create();
                    ad.show();

                }
            });
        }

        conText = findViewById(R.id.con_text);
        //infoText = findViewById(R.id.info_text);

        //msgText = findViewById(R.id.msg_text);
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
        ifText = findViewById(R.id.if_text);
        ifText.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AlertDialog ad = new AlertDialog.Builder(WifiActivity.this)
                        .setTitle("Last status")
                        .setMessage(UiUtil.toString(lastStatus, "\n"))
                        .create();
                ad.show();
            }
        });

        updateInterfaces();
        refreshVisible();

        startService(svcI);

    }

    protected void onSaveInstanceState(Bundle icicle) {
        super.onSaveInstanceState(icicle);
//        icicle.putBoolean("ap", apSwitch.isChecked());
//        icicle.putBoolean("disc", discSwitch.isChecked());
    }

    /**
     * View for Device in the list.
     * - ID - if it is known ( DNS-SD, BLE, NAN as well as Wifi scan for Q)
     * If device has AP active, freq/level and SSID are also shown
     * - SSID - if device was found via Wifi scan and failed in DNS-SD.
     * - P2P Name or MAC - if found via peer discovery, but failed in DNS-SD ( may not be active ).
     * <p>
     * Connected devices are also shown - the wifi layer doesn't know the ID.
     */
    private View getDeviceView(ArrayAdapter<Device> deviceArrayAdapter, int position, View convertView, ViewGroup parent) {
        View view;
        if (convertView == null) {
            view = getLayoutInflater().inflate(R.layout.device_line, parent, false);
        } else {
            view = convertView;
        }
        TextView text = (TextView) view.findViewById(android.R.id.text1);
        TextView text2 = (TextView) view.findViewById(android.R.id.text2);

        Device d = deviceArrayAdapter.getItem(position);

        StringBuilder sb = new StringBuilder();
        appendIfSet(sb, d.data, "SSID", Device.SSID, " ");

        sb.append(d.data);

        // If wifi scan found the device - it means it's active and connectable
        int level = d.getLevel();
        if (level != 0) {
            sb.append(level).append("/").append(d.getFreq());
            text.setBackgroundColor(GREEN);
        }
        text.setText(sb);

        sb.setLength(0);

        // This also means a device address is set
        // not very useful, maybe remove
        appendIfSet(sb, d.data, "P2PN", Device.P2PName);

        // Implies SD, will have PSK as well
        appendIfSet(sb, d.data, "Net", Device.NET);

        if (d.isConnected()) {
            text2.setBackgroundColor(GREEN);
        }
        //sb.append(UiUtil.toString(d.data, "\n"));

        text2.setText(sb);

        return view;
    }

    private void appendIfSet(StringBuilder sb, Bundle data, String label, String key) {
        String s = data.getString(key);
        if (s == null) {
            return;
        }
        sb.append(label).append(":").append(s).append("\n");
    }

    private void appendIfSet(StringBuilder sb, Bundle data, String label, String key, String delim) {
        String s = data.getString(key);
        if (s == null) {
            return;
        }
        sb.append(label).append(":").append(s).append(delim);
    }

    private void deviceMenu(ContextMenu menu, View v, AdapterView.AdapterContextMenuInfo contextMenuInfo) {
        final ListView lv = (ListView) v;
        final AdapterView.AdapterContextMenuInfo acmi = contextMenuInfo;

        final Device d = discListAdapter.getItem(acmi.position);

        int i = 1;
        menu.add(i++, v.getId(), 0, "Details")
                .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                    @Override
                    public boolean onMenuItemClick(MenuItem menuItem) {
                        AlertDialog ad = new AlertDialog.Builder(WifiActivity.this)
                                .setTitle("Device details")
                                .setMessage(UiUtil.toString(d.data, "\n"))
                                .create();
                        ad.show();
                        return false;
                    }
                });
        if (d.data.get(Device.PSK) != null && d.data.get(Device.SSID) != null &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            menu.add(i++, v.getId(), 0, "ConnectQ")
                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            final Device d = discListAdapter.getItem(acmi.position);
                            wifi.send("/wifi/con/peer/" + d.id + "/Q",
                                    Device.PSK, d.data.getString(Device.PSK, ""),
                                    Device.SSID, d.data.getString(Device.SSID, "")
                            );
                            return false;
                        }
                    });
        }

        if (d.id != null) {
            menu.add(i++, v.getId(), 0, "Connect PBC")
                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            final Device d = discListAdapter.getItem(acmi.position);
                            wifi.send("/wifi/con/peer/" + d.id + "/PBC",
                                    Device.P2PAddr, d.id);
                            return false;
                        }
                    });

            // Shows a PIN on local, needs to be typed in the remote device.
//            menu.addMap2Bundle(i++, v.getId(), 0, "Connect DISPLAY")
//                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
//                        @Override
//                        public boolean onMenuItemClick(MenuItem menuItem) {
//                            final Device d = discListAdapter.getItem(acmi.position);
//                            wifi.send("/wifi/con/peer/" + d.id + "/DISPLAY",
//                                    Device.P2PAddr, d.id);
//
//                            return false;
//                        }
//                    });

            // Show a PIN on remote, has to be typed on local. Remote also needs to accept.
//            menu.addMap2Bundle(i++, v.getId(), 0, "Connect KEYPAD")
//                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
//                        @Override
//                        public boolean onMenuItemClick(MenuItem menuItem) {
//                            final Device d = discListAdapter.getItem(acmi.position);
//                            wifi.send("/wifi/con/peer/" + d.id + "/KEYPAD",
//                                    Device.P2PAddr, d.id);
//                            return false;
//                        }
//                    });

            // Almost same as PBC - shows pin on the display.
            menu.add(i++, v.getId(), 0, "Connect LABEL")
                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            final Device d = discListAdapter.getItem(acmi.position);
                            wifi.send("/wifi/con/peer/" + d.id + "/LABEL",
                                    Device.P2PAddr, d.id);
                            return false;
                        }
                    });
        }

        if (d.data.get(Device.PSK) != null && d.data.get(Device.SSID) != null) {
            menu.add(i++, v.getId(), 0, "Connect Reflect")
                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            final Device d = discListAdapter.getItem(acmi.position);
                            wifi.send("/wifi/con/peer/" + d.data.getString(Device.SSID, "") + "/REFLECT",
                                    Device.PSK, d.data.getString(Device.PSK, ""),
                                    Device.SSID, d.data.getString(Device.SSID, ""));
                            return false;
                        }
                    });
        }

        menu.add(i++, v.getId(), 0, "Disconnect P2P")
                .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                    @Override
                    public boolean onMenuItemClick(MenuItem menuItem) {
                        wifi.send("/wifi/con/cancel");
                        return false;
                    }
                });
    }

    // internal debugging - not used in dmesh
    // Handle /net/status - normally the native app takes care of this.
    private void updateStatus(Bundle data) {
        if (msgText == null) {
            return;
        }
        disc.clear();
        lastStatus = data;

        int gc = 0;
        Bundle data1 = data.getBundle("data");
        if (data1 != null) {
            ArrayList<Bundle> b = data1.getParcelableArrayList("scan");
            if (b != null) {
                for (Bundle bb : b) {
                    Device d = new Device(bb);
                    disc.add(d);

                    if (d.data.getString("gc", "0").equals("1")) {
                        gc++;
                    }
                }
            }
        }
        if (gc > 0) {
            msgText.setBackgroundColor(GREEN);
        } else {
            msgText.setBackgroundColor(Color.YELLOW);
        }

        visible = data.getString("visible", "0");

        String ssid = data.getString(Device.WIFISSID);
        if (ssid == null) {
            toolbar.setSubtitle("");
        } else {
            final StringBuilder sb = new StringBuilder();
            sb.append(ssid).append(" ").append(data.getString(Device.LEVEL))
                    .append("/").append(data.getString(Device.FREQ));
            toolbar.setSubtitle(sb.toString());
        }

        String apStatus = data.getString("ap", "");

        StringBuilder title = new StringBuilder();
        if (apStatus.equals("1")) {
            apStarted = true;
            apSsid = data.getString("s");
            apPsk = data.getString("p");
            title.append("* ");
        } else if (apStatus.equals("0")) {
            apStarted = false;
        }
        title.append(apSSID());
        title.append(" " + disc.size() + "/" + visible);
        if (gc > 0) {
            title.append("/").append(gc);
        }
        toolbar.setTitle(title);

        updateInterfaces();
        refreshVisible();
    }

    String apSSID() {
        if (apSsid == null) {
            return "none";
        }
        if (apSsid.startsWith("DIRECT-")) {
            return apSsid.substring("DIRECT-".length());
        }
        return apSsid;
    }

    /**
     * Handles messages from the wifi service. Uses normal subscribe().
     */
    public void handleMessage(String topic, String msgType, Message message, MsgConn replyTo, final String[] args) {
        final Bundle data = message.getData();
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                String[] parts = args;
                if (parts.length < 3) {
                    return;
                }

                //  /wifi/AP/ ...
                switch (parts[2]) {
                    case "status":
                        updateStatus(data);
                        break;

                    case "p2p":
                        if (parts.length > 3 && "discState".equals(parts[3])) {
                            // TODO: UI to show P2P discovery in progress.
                            //discSwitch.setChecked(data.getString("on", "0").equals("1"));
                        }
                        break;

                    case "broadcast":
                        // all other updates that are not translated to MSG
                        updateInterfaces();
                        final Bundle i = (Bundle) data.getParcelable("data");
                        msgTxtDetails = i;
                        if (i != null) {
                            msgText.setText(data.getString("a", ""));
                        }
                        break;

                    case "AP":
                        if (data.getString("on", "0").equals("1")) {
                            apStarted = true;
                            //toolbar.setTitle(apInfo);

                            StringBuilder sb = new StringBuilder();
                            sb.append(data.getString("s") + "/" + data.getString("p"));
                            if (Wifi.currentClientList.size() > 0) {
                                for (WifiP2pDevice c : Wifi.currentClientList) {
                                    sb.append("C: ").append(c.deviceAddress).append(" ").append(c.deviceName).append("\n");
                                }

                            }
                            //infoText.setText(sb.toString());
                        } else {
                            apStarted = false;

                            toolbar.setTitle("AP: Off");

                            //infoText.setText("");
                        }

                        updateInterfaces();
                        break;


                    default:
                        if (msgText != null) {
                            Snackbar.make(msgText, "" + Arrays.toString(args) + " " + data, 3000).show();
                        }
                }
            }
        });

    }

    private void updateInterfaces() {
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> nE = NetworkInterface.getNetworkInterfaces();
            while (nE != null && nE.hasMoreElements()) {
                NetworkInterface ni = nE.nextElement();
                String name = ni.getName();
                if (ni.getInterfaceAddresses().size() == 0 ||
                        !ni.isUp() ||
                        name.contains("dummy") ||
                        name.equals("lo")) {
                    continue;
                }
                sb.append(ni.getDisplayName()).append(" ");
                for (InterfaceAddress nii : ni.getInterfaceAddresses()) {
                    sb.append(nii.getAddress()).append(" ");
                }
                sb.append("\n");

            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (wifi.nan != null && wifi.nan.nanMgr != null && wifi.nan.nanMgr.isAvailable()) {
                    if (wifi.nan.nanId == null) {
                        sb.append("NAN: Avail,OFF\n");
                    } else {
                        sb.append("NAN: ").append(wifi.nan.nanId).append("\n");
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        ifText.setText(sb);
    }

    private void refreshVisible() {
        //wv.loadUrl(STATUS_URL);
        Collections.sort(disc, new Comparator<Device>() {
            @Override
            public int compare(Device d1, Device d2) {
                if (d1.isConnected() && !d2.isConnected()) {
                    return 1;
                }
                if (d2.isConnected() && !d1.isConnected()) {
                    return -1;
                }
                if (d1.getLevel() == 0 && d2.getLevel() != 0) {
                    return 1;
                }
                if (d2.getLevel() == 0 && d1.getLevel() != 0) {
                    return -1;
                }

                return d2.getLevel() - d1.getLevel();
            }
        });
        if (discListAdapter != null) {
            discListAdapter.notifyDataSetChanged();
            UiUtil.setListViewHeightBasedOnChildren(discList);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.p2p, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        MenuItem apSwitch = menu.findItem(R.id.dm_switch2);
        if (apSwitch != null) {
            apSwitch.setChecked(wifi.p2pGroupStarted);
        }
        MenuItem discSwitch = menu.findItem(R.id.sddisc);
        if (discSwitch != null) {
            discSwitch.setChecked(wifi.discoveryState == 1);
        }

        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {

            case R.id.settings: {
                startActivity(new Intent(this, SetupActivity.class));
                break;
            }
            case R.id.dm_switch2:
                item.setChecked(!item.isChecked());
                if (item.isChecked()) {
                    wifi.send("/wifi/p2p", "ap", "1");
                } else {
                    wifi.send("/wifi/p2p", "ap", "0");
                }
                break;


            case R.id.sddisc:
                item.setChecked(!item.isChecked());
                if (item.isChecked()) {
                    wifi.send("/wifi/con/start");
                } else {
                    wifi.send("/wifi/con/stop");
                }
                break;

            case R.id.mdnssdon:
                wifi.send("/wifi/adv", "p2p", "1");
                break;
            case R.id.mdnssdoff:
                wifi.send("/wifi/adv", "p2p", "0");
                break;
            case R.id.sddisc2:
                wifi.send("/wifi/disc");
                break;

            // BT
            case R.id.btscan:
                bt().scan();
                break;
            case R.id.btdsc:
                bt().makeDiscoverable();
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
            case R.id.nanAttach:
                wifi.send("/wifi/nan/start");
                break;
            case R.id.nanDetach:
                wifi.send("/wifi/nan/stop");
                break;
            case R.id.nanSub:
                wifi.send("/wifi/nan/sub/pass");
                break;
            case R.id.nanSubStop:
                wifi.send("/wifi/nan/sub/stop");
                break;
            case R.id.nanSubAct:
                wifi.send("/wifi/nan/sub");
                break;
            case R.id.nanPub:
                wifi.send("/wifi/nan/adv");
                break;
            case R.id.nanPubStop:
                wifi.send("/wifi/nan/adv/stop");
                break;
            case R.id.nanPubAct:
                wifi.send("/wifi/nan/adv/act");
                break;
            case R.id.nanCon:
                wifi.send("/wifi/nan/con/0");
                break;

            case R.id.disc:
                //disc.clear();
                discListAdapter.notifyDataSetChanged();
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
                break;
            case R.id.lastIntent:
                ad = new AlertDialog.Builder(WifiActivity.this)
                        .setTitle("Last intent data")
                        .setMessage(UiUtil.toString(msgTxtDetails))
                        .create();
                ad.show();
                break;

            case R.id.view:
                String url = "http://localhost:5227/status";
                Intent i = new Intent(Intent.ACTION_VIEW);
                i.setData(Uri.parse(url));
                startActivityForResult(i, 5);
                break;

        }
        return super.onOptionsItemSelected(item);
    }

    // Debugging and experimental stuff

    private Bt2 bt() {
        if (bt2 == null) {
            bt2 = new Bt2(this, h);
        }
        return bt2;
    }

    /**
     * Connect using BT SPP.
     * ESP32, pre-JB Android devices, etc.
     * <p>
     * Protocol is a multiplexed channel.
     * <p>
     * Android JB+ only acts as client, i.e. discovers other devices but doesn't adertise the server.
     * Advertising requires user interaction.
     * <p>
     * ESP32 and old devices implement SPP server.
     */
    private void btlegacy() {
        bt().scan();
        h.postDelayed(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        for (BluetoothDevice d : bt().devices.values()) {
                            bt2.connect(d.getAddress(), "WIFI\n" + apSsid + "\n" + apPsk + "\n");
                        }
                    }
                }).start();
            }
        }, 10000);
    }

    /**
     * Details about the node (dialog or hide/show?)
     * - RTT - distance to AP
     * - TDLS - direct sta to sta
     * <p>
     * Pixel1: RTT, PowerReport, TDLS
     * Nexus6: RTT, PowerReport, TDLS, OffloadScan
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
