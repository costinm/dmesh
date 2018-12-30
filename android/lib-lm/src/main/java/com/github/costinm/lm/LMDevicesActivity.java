package com.github.costinm.lm;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.os.SystemClock;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.SubMenu;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import com.github.costinm.dmesh.android.util.Utils;
import com.github.costinm.dmesh.libdm.DMUDS;
import com.github.costinm.dmesh.logs.CommandListActivity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import static com.github.costinm.lm.LMAPI.CMD_UPDATE_CYCLE;
import static com.github.costinm.lm.LMesh.PREF_FIXED_SSID;
import static com.github.costinm.lm.LMesh.STATE_IDLE;
import static com.github.costinm.lm.LMesh.toFind;

/**
 * List of visible DMesh connections.
 * <p>
 * Click on item to connect. Long click to disable or show details for each net.
 */
@RequiresApi(api = Build.VERSION_CODES.ICE_CREAM_SANDWICH)
public class LMDevicesActivity extends CommandListActivity {

    static List visibleDMAPs = new ArrayList<>();
    LMesh lm;
    boolean showForeign = false;
    private ListView mListView;
    // TODO: replace with layout

    public static int f2c(int freq) {
        if (freq >= 2412 && freq <= 2484) {
            return (freq - 2412) / 5 + 1;
        } else if (freq >= 5170 && freq <= 5825) {
            return (freq - 5170) / 5 + 34;
        } else {
            return -1;
        }
    }

    protected void onMessage(Message msg) {
       super.onMessage(msg);

        final int what = msg.what;
        switch (what) {
            case LMesh.AP_STATE_CHANGED:
            case LMesh.START:
            case LMesh.CONNECT:
            case LMesh.UPDATE:
                break;
            case LMesh.SCAN:
                break;
        }
        updateList();
        updateStatus(msg);
        updateLogList();
    }

    void refresh() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                updateStatus(null);
            }
        });
    }

    // Update list of APs
    void updateList() {
        visibleDMAPs.clear();
        long now = SystemClock.elapsedRealtime();

        for (LNode n: lm.devices) {
            // 5m since it was found
            if (now - n.lastScan > 300 * 1000) {
                continue;
            }

            // Will be set when discovered via P2P or BLE or BT.
            if (n.meshName == null && !lm.connectable.contains(n)) {
                continue;
            }

            visibleDMAPs.add(n);
        }

        Collections.sort(visibleDMAPs, new Comparator<LNode>() {
            @Override
            public int compare(LNode o1, LNode o2) {
                if (!lm.connectable.contains(o1) && lm.connectable.contains(o2)) {
                    return 1;
                }
                if (lm.connectable.contains(o1) && !lm.connectable.contains(o2)) {
                    return -1;
                }
                if (lm.connectable.contains(o1) && lm.connectable.contains(o2) &&
                        o1.scan != null && o2.scan != null) {
                    return (int)(o2.scan.level - o1.scan.level);
                }

                return (int)(o1.lastChange - o2.lastChange);
            }
        });
        if (mAdapter != null) {
            mAdapter.notifyDataSetChanged();
            setListViewHeightBasedOnChildren(mListView);
        }
    }

    void updateStatus(Message msg) {
        if (mAPStatusView == null) {
            return;
        }
        StringBuilder status = new StringBuilder();

        getActionBar().setTitle(lm.getMeshName());

        // Wifi SSID
        String ssid = lm.con.getCurrentWifiSSID();
        String net = lm.getNet();
        if (ssid != null) {
            if (ssid.startsWith("DIRECT-")) {
                String shortn = LMesh.ssidShortName(ssid);
                status.append("LMESH: ").append(shortn);
                if (net != null && !net.equals(ssid)) {
                    status.append(" ").append(net);
                }
            } else {
                status.append("Wifi: ").append(ssid);
            }
        }
        if (lm.lmon != null) {
            if (lm.hasMobileInternet()) {
                status.append("\nMobile:").append(lm.lmon.mobileAddress);
            }
            if (lm.hasWifiInternet()) {
                status.append("\nWifi:").append(lm.lmon.wifi4Address);
            }
            //status.append("\nLocal:" + lm.lmon.wifi6LocalAddress);
        }
        status.append("\nVisible: ")
                .append(lm.visible())
                .append("/")
                .append(lm.connectable.size());

        // AP status - 2 lines
        if (lm.ssid != null) {
            // TODO: save to prefs, get it from prefs
            status.append("\nAP: ");
            if (lm.apRunning) {
                if (lm.keepApOn) {
                    status.append(" [*] ");
                } else {
                    status.append(" * ");
                }
            }
            status.append(lm.ssid).append(" ");
        }
        if (lm.hasDMeshConnection()) {
            // nothing
            mAPStatusView.setBackgroundColor(Color.parseColor("#fff59d")); // yellow
        } else {
            mAPStatusView.setBackgroundColor(Color.parseColor("#FFAB91")); // blue
        }

        if (lm.hasDMeshConnection()) {
            if (lm.apRunning) {
                getActionBar().setIcon(R.drawable.ic_router_red_900_24dp);
            } else {
                getActionBar().setIcon(R.drawable.ic_router_green_900_24dp);
            }
        } else if (lm.apRunning) {
            getActionBar().setIcon(R.drawable.ic_router_blue_900_24dp);
        } else {
            // nothing
            getActionBar().setIcon(R.drawable.ic_router_yellow_900_24dp);
        }

        if (lm.state < lm.states.length) {
            status.append("\nstate: ").append(lm.states[lm.state]).append(" ");
        } else {
            status.append("\nstate: ").append(lm.state).append(" ");
        }
        if (lm.bm != null && lm.bm.bm != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                int cAStart = lm.bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE);
                int cStart = lm.bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW);
                if (cAStart == -1) {
                    cAStart = 0;
                }
                if (cStart == -1) {
                    cStart = 0;
                }
                if (cAStart != 0 || cStart != 0) {
                    status.append("\nBattery: ").append(cStart / 1000).append("/").append(cAStart / 1000);
                }
            }
        }

        if (msg != null) {
            String err = msg.getData().getString("err");
            if (err != null) {
                status.append("\nERROOR:" + err);
            }
            String msgTxt = msg.getData().getString("msg");
            if (msgTxt != null) {
                status.append(msgTxt);
            }

        }


        if (mAPStatusView != null) {
            mAPStatusView.setText(status);
        }
    }

    private void showAPWifiStatus() {
        StringBuilder status = new StringBuilder();
        long now = SystemClock.elapsedRealtime();

        if (lm.ssid == null) {

        } else {
            status.append("SSID=").append(lm.ssid);
            status.append("\nPSK=").append(lm.pass);
            if (lm.apRunning) {
                status.append("\non_since: ").append((now - lm.ap.lastStart) / 1000);
                status.append("\nap6:").append(lm.lmon.ap6Address);
            } else {
                status.append("\noff_since: ").append((now - lm.ap.lastStop) / 1000)
                        .append(" last: ").append(lm.ap.lastDuration / 1000);
            }
            status.append(" starts: ").append(lm.ap.apStartTimes).append(" run:").
                    append(lm.ap.apRunTime / 1000).
                    append(" ratio: ").append((int) ((100 * lm.ap.apRunTime) / (now - lm.ap.first)));
            if (Connect.lastSuccess != 0) {
                status.append("\nLast connect:").append(timeOfDayShort(e2s(Connect.lastSuccess)));
            }
        }

        AlertDialog ad = new AlertDialog.Builder(this)
                .setTitle("Status details")
                .setMessage(status)
                .create();
        ad.show();

    }

    protected void updateStatus() {
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        lm = LMesh.get(this);

        Intent i = new Intent(this, LMService.class);
        startService(i);

        getActionBar().setTitle(lm.getMeshName());

        mAPStatusView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showAPWifiStatus();
            }
        });
        mListView = (ListView) findViewById(R.id.connections_list);

        //https://stackoverflow.com/questions/18367522/android-list-view-inside-a-scroll-view
        mListView.setOnTouchListener(new View.OnTouchListener() {
            // Setting on Touch Listener for handling the touch inside ScrollView
            @Override
            public boolean onTouch(View v, MotionEvent event) {
                // Disallow the touch request for parent scroll on touch of child view
                v.getParent().requestDisallowInterceptTouchEvent(true);
                return false;
            }
        });
        mListView.setOnItemClickListener(this);
        mListView.setOnCreateContextMenuListener(this);

        mAdapter = new ArrayAdapter<Object>(
                this,
                android.R.layout.two_line_list_item,
                android.R.id.text1,
                visibleDMAPs) {
            @NonNull
            @Override
            public View getView(int position, View convertView,
                                @NonNull ViewGroup parent) {
                return getNodeView(this, position, convertView, parent);
            }

        };
        mListView.setAdapter(mAdapter);

        setListViewHeightBasedOnChildren(mListView);

        lm.debugobserver = h;
        if (Build.VERSION.SDK_INT >= 21) {
            // 15 min interval for discovery (min) - it means AP must run for >5 min for an
            // initiating device to be found. Setting this too long would cause battery use
            // on the more expensive AP mode.
            LMJob.schedule(this, 5 * 60 * 1000);
        }
        updateList();
        updateStatus(null);
    }


    @Override
    public boolean onContextItemSelected(MenuItem item) {
        return super.onContextItemSelected(item);
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, final View v, ContextMenu.ContextMenuInfo menuInfo) {
        final ListView lv = (ListView) v;
        final AdapterView.AdapterContextMenuInfo acmi = (AdapterView.AdapterContextMenuInfo) menuInfo;

        final Context ctx = v.getContext();
        menu.add(3, v.getId(), 0, "Connect").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                final LNode mItem = (LNode) mAdapter.getItem(acmi.position);
                // will be sticky, but only used if mode is fixed
                if (mItem != null) {
                    lm.con.connectToAP(mItem, true, h.obtainMessage(LMesh.CONNECT));
                    prefs.edit().putString(PREF_FIXED_SSID, mItem.ssid).apply();
                }
                return false;
            }
        });

        menu.add(3, v.getId(), 0, "Details").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                final LNode mItem = (LNode) mAdapter.getItem(acmi.position);
                showDStatus(mItem);
                return false;
            }
        });
    }

    private String ssid(String ssid) {
        if (ssid.startsWith("DIRECT-")) {
            return ssid.substring(10);
        }
        return ssid;
    }

    @NonNull
    private View getNodeView(ArrayAdapter<Object> arrayAdapter, int position, View convertView, @NonNull ViewGroup parent) {
        View view;
        if (convertView == null) {
            view = getLayoutInflater().inflate(android.R.layout.two_line_list_item, parent, false);
        } else {
            view = convertView;
        }

        long now = SystemClock.elapsedRealtime();

        final LNode n = (LNode) arrayAdapter.getItem(position);
        if (n != null) {
            TextView text = (TextView) view.findViewById(android.R.id.text2);

            StringBuilder sb = new StringBuilder();

            boolean visible = false;

            TextView text1 = (TextView) view.findViewById(android.R.id.text1);
            sb = new StringBuilder();
            sb.append(timeOfDayShort(e2s(n.lastScan))).append(" ");

            if (lm.connectable.contains(n)) {
                text.setBackgroundColor(Color.GREEN);
                sb.append("*");
                visible = true;
            } else {
                text.setBackgroundColor(Color.YELLOW);
            }

            if (n.meshName != null) {
                sb.append(n.meshName.trim()).append(" ");
            }
            if (n.name != null) {
                sb.append(n.name).append(" ");
            }
            if (n.ssid != null) {
                if (n.name == null || !n.ssid.endsWith(n.name)) {
                    sb.append(ssid(n.ssid));
                }
            }

            if (n.build != null) {
                sb.append(" ").append(n.build);
            }

            text1.setText(sb.toString());

            sb = new StringBuilder();
            //sb.append(timeOfDayShort(e2s(n.p2pLastDiscoveredE))).append(" ");

            if (n.scan != null) {
                if (visible) {
                    sb.append(" (").append(n.scan.level);
                    sb.append("/").append(f2c(n.scan.frequency)).append(") ");
                }else if (toFind.contains(n)) {
                    sb.append(" ( FIND ").append(n.scan.level);
                    sb.append("/").append(f2c(n.scan.frequency)).append(") ");
                } else if ((now - n.lastScan) < 30000)  {
                    sb.append(" (").append(n.scan.level);
                    sb.append("/").append(f2c(n.scan.frequency)).append(" ").append((now - n.lastScan)/1000).append("s ago) ");
                }
            }

            if (n.connectAttemptCount > 0) {
                sb.append(" con=").append(n.connectAttemptCount).append("/").append(n.connectCount);
            }

            sb.append(" ");
//            if (n.mac != null) {
//                sb.append(" ").append(n.mac);
//            } else if (n.scan != null) {
//                sb.append(" s=").append(n.scan.BSSID);
//            }
            if (n.pass != null) {
                //sb.append("\npass=").append(n.pass);
                sb.append(" net=").append(n.net);
            }
            if (n.mesh != null) {
                sb.append(" mesh=").append(n.mesh);
            }

            if (n.foreign) {
                sb.append(" FOREIGN");
            }
            if (n.p2pDiscoveryAttemptCnt > 0) {
                sb.append(" disc=").append(n.p2pDiscoveryAttemptCnt)
                        .append("/").append(n.p2pDiscoveryCnt);
                if (n.extraDiscoveryInfo != null && n.extraDiscoveryInfo.length() > 0) {
                    sb.append(" ").append(n.extraDiscoveryInfo);
                }
                if (n.p2pLastDiscoveredE > 0) {
                    sb.append("/D:").append(timeOfDayShort(e2s(n.p2pLastDiscoveredE)));
                } else if (n.p2pLastDiscoveryAttemptE > 0) {
                    sb.append("/F:").append(timeOfDayShort(e2s(n.p2pLastDiscoveryAttemptE)));
                }
            }
            // TODO: pwr level
            text.setText(sb.toString());
        }

        return view;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        lm.debugobserver = null;
    }

    @Override
    protected void onResume() {
        super.onResume();
        lm.debugobserver = h;
    }

    @Override
    protected void onPause() {
        super.onPause();
        lm.debugobserver = null;
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view,
                            int position, long id) {
        // Expand the view
        Log.d("V", "Selected " + position + " " + view);

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.lm_devices_menu, menu);

        SubMenu logs = menu.addSubMenu("Logs");
        for (String s: tags.keySet()) {
            logs.add(R.id.logsmenu, 0, 0, "LOGS:" + s);
        }
        return true;
    }

    @Override
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.settings) {
            Intent i = new Intent(this, LMSettingsActivity.class);
            startActivityForResult(i, 1);
        } else if (id == R.id.logs) {
            Intent i = new Intent(this, CommandListActivity.class);
            startActivityForResult(i, 1);
        } else if (id == R.id.view) {
            String url = "http://localhost:5227/status";
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse(url));
            startActivityForResult(i, 5);
            return super.onMenuItemSelected(featureId, item);
        } else if (id == R.id.ap_start) {
            if (lm.apRunning) {
                lm.keepApOn = false;
                lm.ap.stop(lm.serviceHandler.obtainMessage(CMD_UPDATE_CYCLE));
            } else {
                lm.keepApOn = true;
                lm.apEnabled();
            }
        } else if (id == R.id.lm_status) {
            showLMStatus();
            return super.onMenuItemSelected(featureId, item);
        } else if (id == R.id.p2p_listen_on) {
            lm.disc.listen(true);
        } else if (id == R.id.p2p_listen_off) {
            lm.disc.listen(false);
        } else if (id == R.id.battery_status) {
            showBatteryStatus();
            return super.onMenuItemSelected(featureId, item);

        } else if (id == R.id.refresh) {
            lm.updateCycle();
        } else if (id == R.id.discovery) {
            lm.ble.scan();
            lm.disc.start(h, LMesh.SCAN, true);

        } else if (id == R.id.wifi_caps) {
            showWifiCaps();
        } else if (id == R.id.stats) {
            showDump();

//        } else if (id == R.id.ap_stop) {
//            APHotspot aph = new APHotspot(this);
//            aph.setState(null, null);
        } else if (id == R.id.exit) {
            System.exit(0);
        } else if (id == R.id.autoconnect) {
            lm.con.start(this, null, null, 0);
//        } else if (id == R.id.ap_start_legacy) {
//            APHotspot aph = new APHotspot(this);
//            aph.setState("DM-APM", "1234567890");
        } else if (id == R.id.bt_provision) {
            lm.bt.syncAll("WIFI\n" + lm.ssid + "\n" + lm.pass + "\n");
        } else if (id == R.id.bt_disc) {
            lm.bt.makeDiscoverable();
        } else if (id == R.id.show_all) {
            show = "";
            updateLogList();

        } else {
            String t = item.getTitle().toString();
            if (t.startsWith("LOGS:")) {
                show = t.substring(5);
            }
            updateLogList();

        }
        return super.onMenuItemSelected(featureId, item);
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
            AlertDialog ad = new AlertDialog.Builder(LMDevicesActivity.this)
                    .setTitle("Wifi capabilities")
                    .setMessage(title.toString())
                    .create();
            ad.show();
        }

    }

    private void showDStatus(LNode mItem) {
        StringBuilder sb = new StringBuilder();
        Bundle b = new Bundle();

        sb.append(mItem.toString().replace(",", "\n"));
        sb.append(mItem.scan);
        sb.append("\n").append(mItem.device);


        AlertDialog ad = new AlertDialog.Builder(this)
                .setTitle("Node " + mItem.name)
                .setMessage(sb)
                .create();
        ad.show();

    }

    private void showLMStatus() {
        StringBuilder sb = new StringBuilder();
        Bundle b = new Bundle();
        lm.dump(b);
        Utils.bundleToString(sb, b);
        AlertDialog ad = new AlertDialog.Builder(this)
                .setTitle("Wifi")
                .setMessage(sb)
                .create();
        ad.show();

    }

    private void showBatteryStatus() {
        StringBuilder sb = new StringBuilder();
        Bundle b = new Bundle();
        lm.bm.dump(b);
        Utils.bundleToString(sb, b);
        AlertDialog ad = new AlertDialog.Builder(this)
                .setTitle("Battery")
                .setMessage(sb)
                .create();
        ad.show();

    }

    private void showDump() {
        StringBuilder sb = new StringBuilder();
        if (lm.ap != null) {
            Bundle db = new Bundle();
            lm.ap.dump(db);
            appendBundle(sb, db);
        }
        Bundle b = new Bundle();
        lm.con.dump(b);
        appendBundle(sb, b);

        b = new Bundle();
        lm.disc.dump(b);
        appendBundle(sb, b);

        b = new Bundle();
        lm.scanner.dump(b);
        appendBundle(sb, b);

        AlertDialog ad = new AlertDialog.Builder(LMDevicesActivity.this)
                .setTitle("Status dump")
                .setMessage(sb.toString())
                .create();
        ad.show();
    }

    protected StringBuilder appendBundle(StringBuilder sb, Bundle db) {
        for (String k : db.keySet()) {
            sb.append("\n").append(k).append(":").append(db.get(k));
        }
        return sb;
    }
}
