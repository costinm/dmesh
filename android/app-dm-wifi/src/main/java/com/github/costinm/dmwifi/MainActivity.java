package com.github.costinm.dmwifi;

import android.Manifest;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.CompoundButton;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;

import com.github.costinm.dmesh.android.util.MsgMux;
import com.github.costinm.dmesh.android.util.MsgClient;
import com.github.costinm.dmesh.android.util.UiUtil;
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

public class MainActivity extends AppCompatActivity implements Handler.Callback {

    private static final String TAG = "P2PTest";

    MsgClient wifi;

    boolean started = false;

    Handler h;

    ListView discList;
    TextView infoText;
    TextView conText;
    TextView msgText;
    TextView ifText;
    ArrayList<Device> disc = new ArrayList<>();
    ArrayAdapter<Device> discListAdapter;
    Toolbar toolbar;

    Switch apSwitch;
    Switch discSwitch;

    private SharedPreferences prefs;


    @Override
    protected void onDestroy() {
        wifi.close();
        super.onDestroy();
    }

    boolean initialState = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        h = new Handler(this);

        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // TODO: show intro page, dialog for permissions
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
        apSwitch = findViewById(R.id.ap_switch);
        initialState = false;

        if (savedInstanceState != null && savedInstanceState.getBoolean("ap", false)) {
            apSwitch.setChecked(true);
        }
        discSwitch = findViewById(R.id.disc_switch);
        if (savedInstanceState != null && savedInstanceState.getBoolean("disc", false)) {
            discSwitch.setChecked(true);
        }
        setSupportActionBar(toolbar);

        //Toolbar aptoolbar = findViewById(R.id.ap_card_toolbar);
        //aptoolbar.inflateMenu(R.menu.ap);
        //aptoolbar.setOnMenuItemClickListener(new Toolbar.OnMenuItemClickListener(){
        //   @Override
        //    public boolean onMenuItemClick(MenuItem item) {
        //        switch (item.getItemId()) {
                //       return false;
        //    }});

        discList = findViewById(R.id.disclist);
        discListAdapter = new ArrayAdapter<Device>(this,  android.R.layout.two_line_list_item,
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
                AlertDialog ad = new AlertDialog.Builder(MainActivity.this)
                        .setTitle("Wifi " + i)
                        .setMessage(UiUtil.toString(d.data)) //  + "\n" + d.wifi)
                        .create();
                ad.show();

            }
        });

        conText = findViewById(R.id.con_text);
        infoText = findViewById(R.id.info_text);
        msgText = findViewById(R.id.msg_text);
        msgText.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AlertDialog ad = new AlertDialog.Builder(MainActivity.this)
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
                AlertDialog ad = new AlertDialog.Builder(MainActivity.this)
                        .setTitle("Last status")
                        .setMessage(UiUtil.toString(lastStatus, "\n"))
                        .create();
                ad.show();
            }
        });

        wifi = MsgMux.get(getApplicationContext()).dial(getPackageName(), new Handler.Callback() {

            @Override
            public boolean handleMessage(Message message) {
                MainActivity.this.handleMessage(message);
                return false;
            }
        });
        wifi.bind(getApplicationContext());

        updateInterfaces();
        refreshVisible();
    }

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
        sb.append(d.data.getString(Device.SSID)).append(" ");
        int level = d.getLevel();
        if (level != 0) {
            sb.append(level).append("/").append(d.getFreq());
            text.setBackgroundColor(GREEN);
        }
        text.setText(sb);

        sb.setLength(0);

        // This also means a device address is set - not very useful
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

    private void deviceMenu(ContextMenu menu, View v, AdapterView.AdapterContextMenuInfo contextMenuInfo) {
        final ListView lv = (ListView) v;
        final AdapterView.AdapterContextMenuInfo acmi = contextMenuInfo;

        final Device d = discListAdapter.getItem(acmi.position);

        final Context ctx = v.getContext();
        int i = 1;
        menu.add(i++, v.getId(), 0, "Details")
                .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                    @Override
                    public boolean onMenuItemClick(MenuItem menuItem) {
                        AlertDialog ad = new AlertDialog.Builder(MainActivity.this)
                                .setTitle("Device details")
                                .setMessage(UiUtil.toString(d.data, "\n"))
                                .create();
                        ad.show();
                        return false;
                    }
                });
        if (d.data.get(Device.PSK) != null && d.data.get(Device.SSID) != null &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && Build.VERSION.PREVIEW_SDK_INT > 0) {
            menu.add(i++, v.getId(), 0, "ConnectQ")
                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            final Device d = discListAdapter.getItem(acmi.position);
                            wifi.send("/wifi/con/peer/" + d.discAddr + "/Q",
                                    Device.PSK, d.data.getString(Device.PSK, ""),
                                    Device.SSID, d.data.getString(Device.SSID, "")
                            );
                            return false;
                        }
                    });
        }

        if (d.discAddr != null) {
            menu.add(i++, v.getId(), 0, "Connect PBC")
                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            final Device d = discListAdapter.getItem(acmi.position);
                            wifi.send("/wifi/con/peer/" + d.discAddr + "/PBC",
                                    Device.P2PAddr, d.discAddr);
                            return false;
                        }
                    });

            // Shows a PIN on local, needs to be typed in the remote device.
//            menu.add(i++, v.getId(), 0, "Connect DISPLAY")
//                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
//                        @Override
//                        public boolean onMenuItemClick(MenuItem menuItem) {
//                            final Device d = discListAdapter.getItem(acmi.position);
//                            wifi.send("/wifi/con/peer/" + d.discAddr + "/DISPLAY",
//                                    Device.P2PAddr, d.discAddr);
//
//                            return false;
//                        }
//                    });

            // Show a PIN on remote, has to be typed on local. Remote also needs to accept.
//            menu.add(i++, v.getId(), 0, "Connect KEYPAD")
//                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
//                        @Override
//                        public boolean onMenuItemClick(MenuItem menuItem) {
//                            final Device d = discListAdapter.getItem(acmi.position);
//                            wifi.send("/wifi/con/peer/" + d.discAddr + "/KEYPAD",
//                                    Device.P2PAddr, d.discAddr);
//                            return false;
//                        }
//                    });

            // Almost same as PBC - shows pin on the display.
            menu.add(i++, v.getId(), 0, "Connect LABEL")
                    .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            final Device d = discListAdapter.getItem(acmi.position);
                            wifi.send("/wifi/con/peer/" + d.discAddr + "/LABEL",
                                    Device.P2PAddr, d.discAddr);
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
                            wifi.send("/wifi/con/peer/" + d.data.getString(Device.SSID, "") + "/CompileREFLECT",
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

    String visible = "0";
    Bundle lastStatus;

    // internal debugging - not used in dmesh
    private void updateStatus(Bundle data) {
        disc.clear();
        lastStatus = data;

        int gc = 0;
        Bundle data1 = data.getBundle("data");
        if (data1 != null) {
            ArrayList<Bundle> b = data1.getParcelableArrayList("scan");
            if (b != null) {
                for (Bundle bb: b) {
                    Device d = new Device(bb);
                    disc.add(d);

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
        discSwitch.setText("Visible APs devices: " + disc.size() + "/" + visible);

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

        if (data.getString("ap", "0").equals("1")) {
            started = true;
            apSwitch.setChecked(true);
            apSsid = data.getString("s");
            apPsk = data.getString("p");
            apSwitch.setText("PSK: " + apPsk);
            toolbar.setTitle("* " + apSsid.substring("DIRECT-xx-".length()));
        } else {
            started = false;
            if (apSsid != null) {
                toolbar.setTitle(" " + apSsid.substring("DIRECT-xx-".length()));
            }
            toolbar.setTitle("AP: Off");

            infoText.setText("");
            apSwitch.setChecked(false);
        }

        initSwitches();

        updateInterfaces();
        refreshVisible();
    }

    String apSsid;
    String apPsk;

    @Override
    public boolean handleMessage(Message message) {
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
                        if ("discState".equals(parts[3])) {
                            // TODO: UI to show P2P discovery in progress.
                            discSwitch.setChecked(d.getString("on", "0").equals("1"));
                        }
                        break;

                    case "INTENT":
                        // all other updates that are not translated to MSG
                        updateInterfaces();
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

                        updateInterfaces();
                        break;


                    default:
                        Snackbar.make(infoText, uri, 2000).show();
            }
        }});

        return false;
    }

    Bundle msgTxtDetails;

    private void updateInterfaces() {
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> nE = NetworkInterface.getNetworkInterfaces();
            while(nE != null && nE.hasMoreElements()) {
                NetworkInterface ni = nE.nextElement();
                String name = ni.getName();
                if (ni.getInterfaceAddresses().size() == 0 ||
                        !ni.isUp() ||
                        name.contains("dummy") ||
                        name.equals("lo")) {
                    continue;
                }
                sb.append( ni.getDisplayName()).append(" ");
                for (InterfaceAddress nii : ni.getInterfaceAddresses()) {
                    sb.append(nii.getAddress()).append(" ");
                }
                sb.append("\n");
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        ifText.setText(sb);
    }

    private void refreshVisible() {

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
        discListAdapter.notifyDataSetChanged();
        setListViewHeightBasedOnChildren(discList);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
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
                wifi.send("/wifi/adv/start");
                break;
            case R.id.mdnssdoff:
                wifi.send("/wifi/adv/stop");
                break;
            case R.id.sddisc:
                wifi.send("/wifi/disc");
                break;
            case R.id.scan:
                wifi.send("/wifi/scan");
                break;
            case R.id.nanstart:
                wifi.send("/wifi/start");
                break;
            case R.id.nanstop:
                wifi.send("/wifi/stop");
                break;
            case R.id.nanping:
                wifi.send("/wifi/ping");
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

        }
        return super.onOptionsItemSelected(item);
    }


    /**
     * Details about the node (dialog or hide/show?)
     *  - RTT - distance to AP
     *  - TDLS - direct sta to sta
     *
     *
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
            AlertDialog ad = new AlertDialog.Builder(MainActivity.this)
                    .setTitle("Wifi capabilities")
                    .setMessage(title.toString())
                    .create();
            ad.show();
        }

    }



    /**** Method for Setting the Height of the ListView dynamically.
     **** Hack to fix the issue of not showing all the items of the ListView
     **** when placed inside a ScrollView  ****/
    public static void setListViewHeightBasedOnChildren(ListView listView) {
        ListAdapter listAdapter = listView.getAdapter();
        if (listAdapter == null)
            return;

        int desiredWidth = View.MeasureSpec.makeMeasureSpec(listView.getWidth(), View.MeasureSpec.UNSPECIFIED);
        int totalHeight = 0;
        View view = null;
        for (int i = 0; i < listAdapter.getCount(); i++) {
            view = listAdapter.getView(i, view, listView);
            if (i == 0)
                view.setLayoutParams(new ViewGroup.LayoutParams(desiredWidth, ViewGroup.LayoutParams.WRAP_CONTENT));

            view.measure(desiredWidth, View.MeasureSpec.UNSPECIFIED);
            totalHeight += view.getMeasuredHeight();
        }
        ViewGroup.LayoutParams params = listView.getLayoutParams();
        params.height = totalHeight +
                (listView.getDividerHeight() * (listAdapter.getCount() - 1));
        listView.setLayoutParams(params);
    }

}
