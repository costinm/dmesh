package com.github.costinm.dmesh.lm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.wifi.WifiManager;
import android.net.wifi.WpsInfo;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
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
import android.widget.Toast;

import com.github.costinm.lm.AP;
import com.github.costinm.lm.APHotspot;
import com.github.costinm.lm.Connect;
import com.github.costinm.lm.P2PDiscovery;
import com.github.costinm.lm.P2PWifiNode;
import com.github.costinm.lm.Scan;
import com.github.costinm.lm.WifiMesh;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import static com.github.costinm.dmesh.lm.LMService.TAG;

/**
 * List of visible DMesh connections.
 * <p>
 * Click on item to connect. Long click to disable or show details for each net.
 */
public class LMDebugActivity extends Activity implements AdapterView.OnItemClickListener {

    private static final int START = 1;
    private static final int AP_START = 2;
    private static final int SCAN = 3;
    private static final int CONNECT = 4;

    static List<P2PWifiNode> visibleDMAPs = new ArrayList<>();
    WifiMesh dmesh;
    Scan.Periodic scan;
    SharedPreferences prefs;

    // Used for experimenting with p2p connections (to see if we can get 2 STA)
    WifiP2pManager mP2PManager;
    WifiP2pManager.Channel mChannel;

    private ArrayAdapter<P2PWifiNode> mAdapter;
    Handler h = new Handler() {
        @Override
        public void handleMessage(Message msg) {

            final int what = msg.what;
            switch (what) {
                case AP_START:
                case START:
                case CONNECT:
                case LMService.UPDATE:
                    updateConnection();
                    updateAP(msg, false);
                    visibleDMAPs.clear();
                    visibleDMAPs.addAll(Scan.last);
                    mAdapter.notifyDataSetChanged();
                    break;
                case SCAN:
                    visibleDMAPs.clear();
                    visibleDMAPs.addAll(Scan.last);
                    mAdapter.notifyDataSetChanged();
                    break;
            }
            super.handleMessage(msg);
        }
    };

    private void updateConnection() {
        TextView tv = (TextView) findViewById(R.id.con_status);
        String ssid = dmesh.con.getCurrentWifiSSID();
        if (ssid == null) {
            tv.setText("Last connection:" + timeOfDayShort(e2s(Connect.lastSuccess)));
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Connected: ").append(ssid).append(" net:").append(dmesh.getNet());
        if (Connect.lastSuccess != 0) {
            sb.append("\nLast").append(timeOfDayShort(e2s(Connect.lastSuccess)));
        }
        tv.setText(sb.toString());
    }

    private void updateAP(Message msg, boolean b) {
        TextView tv = (TextView) findViewById(R.id.ap_status);
        if (WifiMesh.ssid == null) {
            String err = msg.getData().getString("err");
            if (err != null) {
                tv.setText(err);
            }
        } else {
            StringBuilder sb = new StringBuilder();
            long last = AP.lastStop;
            if (dmesh.apRunning) {
                sb.append(" *");
                last = AP.lastStart;
            }
            sb.append("AP: ").append(WifiMesh.ssid)
                    .append(" Pass:").append(WifiMesh.pass);

            sb.append("\nRun time:").append(AP.apRunTime / 60000).append("m, ")
                    .append(AP.apStartTimes).append(" times, last=")
                    .append(timeOfDayShort(e2s(last)));

            tv.setText(sb.toString());
        }
    }

    Intent lmServiceIntent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.debug);

        dmesh = WifiMesh.get(this);

        // Has a guard against multiple runs, only generates the callback.
        dmesh.onStart(this, h, h.obtainMessage(START));
        prefs = PreferenceManager.getDefaultSharedPreferences(LMDebugActivity.this);
        mP2PManager = (WifiP2pManager) getSystemService(Context.WIFI_P2P_SERVICE);

        updateConnection();
        updateDetails();
        visibleDMAPs.addAll(Scan.last);
        ListView mListView = (ListView) findViewById(R.id.connections_list);
        mAdapter = new ArrayAdapter<P2PWifiNode>(
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
        mListView.setOnItemClickListener(this);

        mListView.setOnCreateContextMenuListener(this);

        // Triggers an eval()
        lmServiceIntent = new Intent(this, LMService.class);
        this.startService(lmServiceIntent);

        LMService.listeners.add(h);
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
                final P2PWifiNode mItem = mAdapter.getItem(acmi.position);
                dmesh.con.connectToAP(mItem, true, h.obtainMessage(CONNECT));
                // will be sticky, but only used if mode is fixed
                prefs.edit().putString("fixed_ssid", mItem.ssid).apply();
                return false;
            }
        });

        // Attempting to find a way to use the 'additional station'
        // 'false' param doesn't seem to help - just enables the network without attempting
        // to connect.
//        menu.add(3, v.getId(), 0, "Connect soft").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
//            @Override
//            public boolean onMenuItemClick(MenuItem menuItem) {
//                final P2PWifiNode mItem = mAdapter.getItem(acmi.position);
//                dmesh.con.connectToAP(mItem, false, h.obtainMessage(CONNECT));
//                return false;
//            }
//        });

        menu.add(3, v.getId(), 0, "Connect P2P DISPLAY").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                final P2PWifiNode mItem = mAdapter.getItem(acmi.position);
                WifiP2pConfig cfg = new WifiP2pConfig();
                cfg.deviceAddress = mItem.device.deviceAddress;
                cfg.wps.setup = WpsInfo.DISPLAY;
                Log.d(TAG, "Attempt p2p connect " + cfg + " " + mItem.device);
                mP2PManager.connect(getmChannel(), cfg, new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        Log.d(TAG, "P2P ok");
                    }

                    @Override
                    public void onFailure(int i) {
                        Log.d(TAG, "P2P failed " + i);
                        Toast.makeText(LMDebugActivity.this, "Connect failed. Retry." + i,
                                Toast.LENGTH_SHORT).show();
                    }
                });
                return false;
            }
        });
        menu.add(3, v.getId(), 0, "Connect P2P LABEL").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                final P2PWifiNode mItem = mAdapter.getItem(acmi.position);
                WifiP2pConfig cfg = new WifiP2pConfig();
                cfg.deviceAddress = mItem.device.deviceAddress;
                cfg.wps.setup = WpsInfo.LABEL;
                Log.d(TAG, "Attempt p2p connect " + cfg + " " + mItem.device);
                mP2PManager.connect(getmChannel(), cfg, new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        Log.d(TAG, "P2P ok");
                    }

                    @Override
                    public void onFailure(int i) {
                        Log.d(TAG, "P2P failed " + i);
                        Toast.makeText(LMDebugActivity.this, "Connect failed. Retry." + i,
                                Toast.LENGTH_SHORT).show();
                    }
                });
                return false;
            }
        });
        menu.add(3, v.getId(), 0, "Cancel Connect P2P").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                mP2PManager.cancelConnect(getmChannel(), null);
                return false;
            }
        });

    }

    /**
     * Details about the node (dialog or hide/show?)
     */
    private void updateDetails() {
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
            // This is very important - but I haven't figured out how to enable it !!!
            if (isAdditionalStaSupported(mWifiManager)) {
                title.append("Additional Sta");
            }
            if (title.length() > 0) {
                setText(R.id.wifi_info, "Interface capabilities: " + title.toString());
            } else {
                findViewById(R.id.wifi_info).setVisibility(View.GONE);
            }
        }

    }

    @NonNull
    private View getNodeView(ArrayAdapter<P2PWifiNode> arrayAdapter, int position, View convertView, @NonNull ViewGroup parent) {
        View view;
        if (convertView == null) {
            view = getLayoutInflater().inflate(android.R.layout.two_line_list_item, parent, false);
        } else {
            view = convertView;
        }

        TextView text = (TextView) view.findViewById(android.R.id.text1);
        final P2PWifiNode n = arrayAdapter.getItem(position);
        if (n != null) {
            StringBuilder sb = new StringBuilder();
            //sb.append(timeOfDayShort(e2s(n.p2pLastDiscoveredE))).append(" ");
            sb.append(n.ssid);
            if (n.connectAttemptCount > 0) {
                sb.append(" con=").append(n.connectAttemptCount).append("/").append(n.connectCount);
            }

            sb.append(" ");
            if (n.pass != null) {
                sb.append("\npass=").append(n.pass);
                sb.append(" net=").append(n.net);
            }
            if (n.p2pDiscoveryAttemptCnt > 0) {
                sb.append(" disc=").append(n.p2pDiscoveryAttemptCnt)
                        .append("/").append(n.p2pDiscoveryCnt);
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
        LMService.listeners.remove(h);
        dmesh.scanner.stop(this, scan);
        scan = null;
        Log.d(TAG, "Stopping scan " + LMService.listeners.size());
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view,
                            int position, long id) {
        // Expand the view
        Log.d("V", "Selected " + position + " " + view);

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.debug_menu, menu);
        return true;
    }

    @Override
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        int id = item.getItemId();
        switch (id) {
            case R.id.settings: {
                Intent i = new Intent().setComponent(new ComponentName("com.github.costinm.dmesh.lm",
                        "com.github.costinm.dmesh.lm.WifiSettingsActivity"));
                startActivityForResult(i, 1);
                break;
            }
            case R.id.refresh: {
                Intent i = new Intent().setComponent(new ComponentName("com.github.costinm.dmesh.lm",
                        "com.github.costinm.dmesh.lm.LMService"));
                startService(i);
                //dmesh.scanner.scan(1000, h.obtainMessage(SCAN));
                break;
            }
            case R.id.discovery: {
                if (Build.VERSION.SDK_INT >= 16) {
                    P2PDiscovery disc = new P2PDiscovery(this);
                    disc.start(h, SCAN, true);
                }
                break;
            }
            case R.id.autoconnect: {
                dmesh.con.start(this, null, null, 0);
                break;
            }
            case R.id.ap_start: {
                if (dmesh.apRunning) {
                    dmesh.ap.stop(h.obtainMessage(AP_START));
                } else {
                    dmesh.ap.start(Message.obtain(h, AP_START));
                }
                break;
            }
            case R.id.ap_stop: {
                APHotspot aph = new APHotspot(this);
                aph.setState(null, null);
                dmesh.ap.stop(h.obtainMessage(AP_START));
                break;
            }
            case R.id.ap_start_legacy: {
                APHotspot aph = new APHotspot(this);
                aph.setState("DM-APM", "1234567890");
                break;
            }

            case R.id.periodic_scan: {
                if (scan == null) {
                    scan = dmesh.scanner.start(this, 10000, h, SCAN);
                } else {
                    dmesh.scanner.stop(this, scan);
                    scan = null;
                }
                break;
            }

            case R.id.exit: {
                System.exit(0);
            }
        }


        return super.onMenuItemSelected(featureId, item);
    }

    private synchronized WifiP2pManager.Channel getmChannel() {
        if (mChannel == null) {
            mChannel = mP2PManager.initialize(this, this.getMainLooper(), new WifiP2pManager.ChannelListener() {
                @Override
                public void onChannelDisconnected() {
                    mChannel = null;
                }
            });
        }
        return mChannel;
    }

    private boolean isAdditionalStaSupported(WifiManager mWifiManager) {
        try {
            Method m = mWifiManager.getClass().getMethod("isAdditionalStaSupported");
            return (boolean) m.invoke(mWifiManager);
        } catch (NoSuchMethodException e) {
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return false;
    }


    private void setText(int id, String text) {
        TextView tv = (TextView) findViewById(id);
        tv.setText(text);
    }

    // Elapsed to system time
    public static long e2s(long millis) {
        return millis + System.currentTimeMillis() - SystemClock.elapsedRealtime();
    }

    public static String timeOfDayShort(long millis) {
        Calendar c = Calendar.getInstance();
        if (millis >= 0) {
            c.setTimeInMillis(millis);
            return String.format("%tH:%tM", c, c);
        } else {
            return "";
        }
    }
}
