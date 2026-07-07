package com.github.costinm.dmesh.lm;

import static android.graphics.Color.GREEN;

import android.Manifest;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorDescription;
import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.ContextMenu;
import android.view.GestureDetector;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.inputmethod.InputMethodManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import android.text.InputType;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.UiUtil;
import com.github.costinm.dmesh.lm3.Bt2;
import com.github.costinm.dmesh.lm3.Device;
import com.github.costinm.dmesh.lm3.LocalMesh;
import com.github.costinm.dmesh.lm3.P2P;

import java.net.InterfaceAddress;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;

/**
 * Mesh activity role is to get the permissions required and show a basic static
 * screen.
 * <p>
 * The background service will run all logic, and the notification will provide
 * status and updates.
 * <p>
 * A menu for debugging and manual controls are provided, but with minimal deps and
 * UI - this only uses SDK views, no deps on other libs.
 */
public class MeshActivityLight extends Activity implements MessageHandler {

    private static final String TAG = "Mesh";
    public static final String ACTION_START_VPN = "com.github.costinm.dmesh.START_VPN";
    public static final String EXTRA_VPN_ADDRESS = "address6";
    private static final byte[] DEFAULT_VPN_ADDRESS = new byte[] {
            (byte) 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1
    };
    private boolean pendingVpnStart;
    private Intent pendingStartupIntent;

    // WIP: remove, all comms must be via mux so the service can be separate
    // process and to allow mesh control plane to control all devices in same
    // admin domain.
    LocalMesh localMesh;

    // Wraps Messenger-based IPC and webpush/native for remote.
    private MsgMux mux;

    Handler h;
    // UI elements

    // The list - shows discovered devices, messages, other things
    ArrayList<Device> disc = new ArrayList<>();

    ArrayAdapter<Device> discListAdapter;
    ListView discList;

    // 3 Info boxes - about connectivity/interfaces and a message.
    TextView conText;

    TextView msgText;

    TextView ifText;


    // This is the action bar with custom action view.
    // There are 2 implementations - ToolbarActionBar and WindowDecoratorActionBar.
    // The later has a hidden bottom bar as well. It is default if
    // android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT feature or them with action
    // bar is used. It is what current implementation is using, with a custom view.
    //
    // Calling setActionBar(Toolbar) will activate the first - fully customizable.
    ActionBar toolbar;

    String visible = "0";
    Bundle lastStatus;

    String apSsid;
    String apPsk;
    Bundle msgTxtDetails;

    Bt2 bt2;
    String id4 = "0000";
    private SharedPreferences prefs;

    private AccountManager accountManager;


    static String[] permissions = {
            Manifest.permission.POST_NOTIFICATIONS,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.NEARBY_WIFI_DEVICES,
    };

    static List<String> checkPermissions(Context ctx) {
        List<String> missing = new ArrayList<>();
        for (String p : permissions) {
            if (ctx.checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED) {
                missing.add(p);
            }
        }
        return missing;
    }

    public static final int A_REQUEST_LOCATION = 10;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_ACTION_BAR_OVERLAY);
        h = new Handler(getMainLooper());

        setContentView(R.layout.main_activity);

        msgText = findViewById(R.id.msg_text);

        toolbar = getActionBar();

        if (false) {
            toolbar.setDisplayOptions(ActionBar.DISPLAY_SHOW_CUSTOM);
            toolbar.setCustomView(R.layout.tools);
        } else {
            // TITLE, home, home-as-up, logo
            toolbar.setDisplayOptions(ActionBar.DISPLAY_SHOW_TITLE | ActionBar.DISPLAY_SHOW_HOME);
            // has methods for individual control
            //toolbar.setDisplayShowTitleEnabled(false);
        }
        // Requires OVERLAY_ACTION_BAR
        toolbar.setHideOnContentScrollEnabled(true);

        mux = MsgMux.get(getApplicationContext());
        mux.subscribe("net", this);

        localMesh = LocalMesh.get(this);

        List<String> missing = checkPermissions(getApplicationContext());
        if (missing.size() > 0) {
            Log.d(TAG, "Missing permissions " + missing);
            pendingStartupIntent = getIntent();
            requestPermissions(missing.toArray(new String[]{}), A_REQUEST_LOCATION);
            return;
        }

        startDMeshService();
        setupUI();
        handleIntent(getIntent());
    }

    private void startDMeshService() {
        final Intent svcI = new Intent(this, DMService.class);
        try {
            startForegroundService(svcI);
        } catch (Throwable ex) {
            Log.d(TAG, ex.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        mux.unsubscribe("net", this);
        super.onDestroy();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (ACTION_START_VPN.equals(intent.getAction())) {
            startVpnFromIntent(intent);
        }
    }

    private void startVpnFromIntent(Intent intent) {
        VpnService.address6 = vpnAddressFromIntent(intent);
        final Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent != null) {
            pendingVpnStart = true;
            startActivityForResult(prepareIntent, A_REQUEST_VPN);
            return;
        }
        startService(new Intent(this, VpnService.class));
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != A_REQUEST_LOCATION) {
            return;
        }

        List<String> missing = checkPermissions(getApplicationContext());
        if (missing.size() > 0) {
            Log.w(TAG, "Still missing permissions " + missing);
            return;
        }

        Intent startupIntent = pendingStartupIntent;
        pendingStartupIntent = null;
        startDMeshService();
        setupUI();
        handleIntent(startupIntent != null ? startupIntent : getIntent());
    }

    private byte[] vpnAddressFromIntent(Intent intent) {
        byte[] address = intent.getByteArrayExtra(EXTRA_VPN_ADDRESS);
        if (address != null && address.length == 16) {
            return address;
        }
        String addressText = intent.getStringExtra(EXTRA_VPN_ADDRESS);
        if (addressText != null && !addressText.isEmpty()) {
            try {
                byte[] parsed = InetAddress.getByName(addressText).getAddress();
                if (parsed.length == 16) {
                    return parsed;
                }
                Log.w(TAG, "VPN address extra is not IPv6: " + addressText);
            } catch (Throwable t) {
                Log.w(TAG, "Invalid VPN address extra: " + addressText, t);
            }
        }
        return DEFAULT_VPN_ADDRESS.clone();
    }

    public void setWebUi() {
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
    }

    public void setupList() {
        discList = findViewById(R.id.disclist);
        if (disc.size() == 0) {
            for (int i = 0; i < 30; i++) {
                disc.add(new Device("dev" + i, "content for\ndevice"));
            }
        }
        if (discList != null) {
            discListAdapter = new ArrayAdapter<Device>(this, android.R.layout.two_line_list_item,
                    android.R.id.text1, disc) {
                @Override
                public View getView(int position, View convertView,
                                    ViewGroup parent) {
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
                    AlertDialog ad = new AlertDialog.Builder(MeshActivityLight.this)
                            .setTitle("Wifi " + i)
                            .setMessage(UiUtil.toString(d.data)) //  + "\n" + d.wifi)
                            .create();
                    ad.show();

                }
            });
        }
    }

    public void setupUI() {
        final Intent svcI = new Intent(this, DMService.class);

        setupList();

        conText = findViewById(R.id.con_text);
        //infoText = findViewById(R.id.info_text);

        //msgText = findViewById(R.id.msg_text);
        msgText.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AlertDialog ad = new AlertDialog.Builder(MeshActivityLight.this)
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
                AlertDialog ad = new AlertDialog.Builder(MeshActivityLight.this)
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

        if (d.desc != null) {
            text.setText(d.desc);
            text2.setText("Hello world");
        } else {

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
        }

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
                        AlertDialog ad = new AlertDialog.Builder(MeshActivityLight.this)
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
                            localMesh.send("/wifi/con/peer/" + d.id + "/Q",
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
                            localMesh.send("/wifi/con/peer/" + d.id + "/PBC",
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
                            localMesh.send("/wifi/con/peer/" + d.id + "/LABEL",
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
                            localMesh.send("/wifi/con/peer/" + d.data.getString(Device.SSID, "") + "/REFLECT",
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
                        localMesh.send("/wifi/con/cancel");
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
            //toolbar.setSubtitle(sb.toString());
        }

        String apStatus = data.getString("ap", "");

        StringBuilder title = new StringBuilder();
        if (apStatus.equals("1")) {
            apSsid = data.getString("s");
            apPsk = data.getString("p");
            title.append("* ");
        } else if (apStatus.equals("0")) {
            //apStarted = false;
        }
        title.append(apSSID());
        title.append(" " + disc.size() + "/" + visible);
        if (gc > 0) {
            title.append("/").append(gc);
        }
        //toolbar.setTitle(title);

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
                            //apStarted = true;
                            //toolbar.setTitle(apInfo);

                            StringBuilder sb = new StringBuilder();
                            sb.append(data.getString("s") + "/" + data.getString("p"));
                            if (P2P.currentClientList.size() > 0) {
                                for (WifiP2pDevice c : P2P.currentClientList) {
                                    sb.append("C: ").append(c.deviceAddress).append(" ").append(c.deviceName).append("\n");
                                }

                            }
                            //infoText.setText(sb.toString());
                        } else {
                            //apStarted = false;

                            //toolbar.setTitle("AP: Off");

                            //infoText.setText("");
                        }

                        updateInterfaces();
                        break;

                }
            }
        });

    }

    private void updateInterfaces() {
        if (ifText == null) {
            return;
        }
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
                if (localMesh.nan != null && localMesh.nan.nanMgr != null && localMesh.nan.nanMgr.isAvailable()) {
                    if (localMesh.nan.nanId == null) {
                        sb.append("NAN: Avail,OFF\n");
                    } else {
                        sb.append("NAN: ").append(localMesh.nan.nanId).append("\n");
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
        // The code uses action bare theme context
        // toolbar.getThemedContext();

        getMenuInflater().inflate(R.menu.p2p, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        MenuItem apSwitch = menu.findItem(R.id.dm_switch2);
        if (apSwitch != null) {
            apSwitch.setChecked(localMesh.p2p.p2pGroupStarted);
        }
        MenuItem discSwitch = menu.findItem(R.id.sddisc);
        if (discSwitch != null) {
            discSwitch.setChecked(localMesh.p2p.discoveryState == 1);
        }

        return true;
    }

    public static final int A_REQUEST_VPN = 9;

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.dm_switch2) {
            item.setChecked(!item.isChecked());
            if (item.isChecked()) {
                localMesh.send("/wifi/p2p", "ap", "1");
            } else {
                localMesh.send("/wifi/p2p", "ap", "0");
            }

        } else if (id == R.id.vpnstart) {
            final Intent i = VpnService.prepare(this);
            startActivityForResult(i, A_REQUEST_VPN);

        } else if (id == R.id.sddisc) {
            item.setChecked(!item.isChecked());
            if (item.isChecked()) {
                localMesh.send("/wifi/con/start");
            } else {
                localMesh.send("/wifi/con/stop");
            }


        } else if (id == R.id.mdnssdon) {
            localMesh.send("/wifi/adv", "p2p", "1");

        } else if (id == R.id.mdnssdoff) {
            localMesh.send("/wifi/adv", "p2p", "0");

        } else if (id == R.id.sddisc2) {
            localMesh.send("/wifi/disc");


            // BT
        } else if (id == R.id.btscan) {
            bt().scan();
        } else if (id == R.id.btdsc) {
            bt().makeDiscoverable();


        } else if (id == R.id.btlegacy) {
            btlegacy();


        } else if (id == R.id.scan) {
            localMesh.send("/wifi/scan");

        } else if (id == R.id.nanstart) {
            localMesh.send("/wifi/adv", "on", "1");

        } else if (id == R.id.nanstop) {
            localMesh.send("/wifi/adv", "on", "0");

        } else if (id == R.id.nanping) {
            localMesh.send("/wifi/nan/ping");

        } else if (id == R.id.nanAttach) {
            localMesh.send("/wifi/nan/start");

        } else if (id == R.id.nanDetach) {
            localMesh.send("/wifi/nan/stop");

        } else if (id == R.id.nanSub) {
            localMesh.send("/wifi/nan/sub/pass");

        } else if (id == R.id.nanSubStop) {
            localMesh.send("/wifi/nan/sub/stop");

        } else if (id == R.id.nanSubAct) {
            localMesh.send("/wifi/nan/sub");

        } else if (id == R.id.nanPub) {
            localMesh.send("/wifi/nan/adv");

        } else if (id == R.id.nanPubStop) {
            localMesh.send("/wifi/nan/adv/stop");

        } else if (id == R.id.nanPubAct) {
            localMesh.send("/wifi/nan/adv/act");

        } else if (id == R.id.nanCon) {
            localMesh.send("/wifi/nan/con/0");


        } else if (id == R.id.disc) {
            //disc.clear();
            discListAdapter.notifyDataSetChanged();
            localMesh.send("/wifi/con/start", "sd", "0", "wait", "0");

        } else if (id == R.id.discoff) {
            localMesh.send("/wifi/con/stop");

        } else if (id == R.id.wificaps) {
            showWifiCaps();

        } else if (id == R.id.addRootKeyUrl) {
            showAddRootKeyUrl();

        } else if (id == R.id.lastStatus) {
            AlertDialog ad = new AlertDialog.Builder(MeshActivityLight.this)
                    .setTitle("Last status")
                    .setMessage(UiUtil.toString(lastStatus, "\n"))
                    .create();
            ad.show();

        } else if (id == R.id.lastIntent) {
            new AlertDialog.Builder(MeshActivityLight.this)
                    .setTitle("Last intent data")
                    .setMessage(UiUtil.toString(msgTxtDetails))
                    .create().show();


        } else if (id == R.id.view) {
            String url = "http://localhost:5227/status";
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse(url));
            startActivityForResult(i, 5);


        }
        return super.onOptionsItemSelected(item);
    }

    private void showAddRootKeyUrl() {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        input.setSingleLine(true);
        input.setHint("https://example/ca.pub");
        new AlertDialog.Builder(this)
                .setTitle("Add root key")
                .setView(input)
                .setPositiveButton("Add", (dialog, which) -> {
                    String url = input.getText().toString().trim();
                    new Thread(() -> {
                        try {
                            String path = DMeshKeys.downloadAndInstallRootPublicKey(
                                    MeshActivityLight.this, url, true);
                            runOnUiThread(() -> Toast.makeText(
                                    MeshActivityLight.this,
                                    "Installed root key: " + path,
                                    Toast.LENGTH_LONG).show());
                        } catch (Exception e) {
                            Log.w(TAG, "Failed to add root key from " + url, e);
                            runOnUiThread(() -> Toast.makeText(
                                    MeshActivityLight.this,
                                    "Failed to install key: " + e.getMessage(),
                                    Toast.LENGTH_LONG).show());
                        }
                    }, "dmesh-key-download").start();
                })
                .setNegativeButton("Cancel", null)
                .show();
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
        AlertDialog ad = new AlertDialog.Builder(MeshActivityLight.this)
                .setTitle("Wifi capabilities")
                .setMessage(localMesh.nan.info())
                .create();
        ad.show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (A_REQUEST_VPN == requestCode || A_REQUEST_LOCATION == requestCode) {
            setupUI();
            if (A_REQUEST_VPN == requestCode && pendingVpnStart) {
                pendingVpnStart = false;
                startService(new Intent(this, VpnService.class));
            }
            super.onActivityResult(requestCode, resultCode, data);
            return;
        }
    }

    // ---------- UI ---------------


    // TODO: can it use swipe events ? Show keyboard consistently ?
    private GestureDetector gestureDetector;

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        if (gestureDetector == null) {
            gestureDetector = new GestureDetector(this, new SwipeListener());
        }
        return gestureDetector.onTouchEvent(event) || super.onTouchEvent(event);
    }

    private class SwipeListener extends GestureDetector.SimpleOnGestureListener {
        private static final int SWIPE_THRESHOLD = 100;
        private static final int SWIPE_VELOCITY_THRESHOLD = 100;

        @Override
        public boolean onDown(MotionEvent e) {
            return true;
        }

        @Override
        public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {
            boolean result = false;
            try {
                float diffY = e2.getY() - e1.getY();
                float diffX = e2.getX() - e1.getX();
                if (Math.abs(diffX) > Math.abs(diffY)) {
                    if (Math.abs(diffX) > SWIPE_THRESHOLD && Math.abs(velocityX) > SWIPE_VELOCITY_THRESHOLD) {
                        if (diffX > 0) {
                            onSwipeRight();
                        } else {
                            onSwipeLeft();
                        }
                        result = true;
                    }
                } else if (Math.abs(diffY) > SWIPE_THRESHOLD && Math.abs(velocityY) > SWIPE_VELOCITY_THRESHOLD) {
                    if (diffY > 0) {
                        onSwipeDown();
                    } else {
                        onSwipeUp();
                    }
                    result = true;
                }
            } catch (Exception exception) {
                exception.printStackTrace();
            }
            return result;
        }
    }

    public void onSwipeRight() {
        Toast.makeText(this, "Swipe Right", Toast.LENGTH_SHORT).show();
    }

    public void onSwipeLeft() {
        Toast.makeText(this, "Swipe Left", Toast.LENGTH_SHORT).show();
    }

    public void onSwipeUp() {
        Toast.makeText(this, "Swipe Up", Toast.LENGTH_SHORT).show();
        // Needs a view to have focus - using the root content view or a specific EditText
        View view = getCurrentFocus();
        if (view == null) {
            view = new View(this);
        }

        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);

        imm.showSoftInput(view, InputMethodManager.SHOW_IMPLICIT);

        // OR if you have a specific EditText (e.g. 'msgText') you want to type into:
        // msgText.requestFocus();
        // imm.showSoftInput(msgText, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);
    }

    public void onSwipeDown() {
        Toast.makeText(this, "Swipe Down", Toast.LENGTH_SHORT).show();
    }


}
