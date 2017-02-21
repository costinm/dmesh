package com.github.costinm.dmesh.lm;

import android.app.Activity;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
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

import com.github.costinm.lm.APHotspot;
import com.github.costinm.lm.Connect;
import com.github.costinm.lm.P2PDiscovery;
import com.github.costinm.lm.P2PWifiNode;
import com.github.costinm.lm.Scan;
import com.github.costinm.lm.WifiMesh;

import java.util.ArrayList;
import java.util.List;

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
    private ArrayAdapter<P2PWifiNode> mAdapter;
    Handler h = new Handler() {
        @Override
        public void handleMessage(Message msg) {

            final int what = msg.what;
            switch (what) {
                case START:
                    updateAP(msg, false);
                    break;
                case AP_START:
                    updateAP(msg, true);
                    break;
                case CONNECT:
                    updateConnection();
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
        TextView tv = (TextView) findViewById(com.github.costinm.lm.R.id.con_status);
        String ssid = dmesh.con.getCurrentWifiSSID();
        if (ssid == null) {
            tv.setText("");
            return;
        }

        tv.setText("Connected: " + ssid + " IP:" + dmesh.con.getIp6WifiClient());
    }

    private void updateAP(Message msg, boolean b) {
        TextView tv = (TextView) findViewById(com.github.costinm.lm.R.id.ap_status);
        if (WifiMesh.ssid == null) {
            String err = msg.getData().getString("err");
            tv.setText(err);
        } else {
            StringBuilder sb = new StringBuilder();
            if (dmesh.apRunning) {
                sb.append(" *");
            }
            sb.append("AP: ").append(WifiMesh.ssid).append(" IP:").append(WifiMesh.ip6)
                    .append(" Pass:").append(WifiMesh.pass);
            tv.setText(sb.toString());
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(com.github.costinm.lm.R.layout.debug);

        dmesh = WifiMesh.get(this);
        dmesh.onStart(this, h, h.obtainMessage(START));

        scan = dmesh.scanner.start(this, 10000, h, SCAN);

        updateConnection();
        visibleDMAPs.addAll(Scan.last);
        ListView mListView = (ListView) findViewById(com.github.costinm.lm.R.id.connections_list);
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

//        mListView.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
//            @Override
//            public boolean onItemLongClick(AdapterView<?> arg0, View arg1,
//                                           int position, long id) {
//                if (position < visibleDMAPs.size()) {
//                    P2PWifiNode n = visibleDMAPs.get(position);
//                    Connect c = new Connect(LMDebugActivity.this, WifiMesh.get(LMDebugActivity.this));
//                    c.connectToAP(n, true, h.obtainMessage(CONNECT));
//                }
//                return true;
//            }
//        });
        // Don't allow background operations while in debug/manual mode.
        LMService.suspend = true;
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        return super.onContextItemSelected(item);
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, final View v, ContextMenu.ContextMenuInfo menuInfo) {
        final ListView lv = (ListView) v;
        final AdapterView.AdapterContextMenuInfo acmi = (AdapterView.AdapterContextMenuInfo) menuInfo;

        //menu.setHeaderTitle(...);
        final Context ctx = v.getContext();
        menu.add(3, v.getId(), 0, "Connect").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                final P2PWifiNode mItem = mAdapter.getItem(acmi.position);
                dmesh.con.connectToAP(mItem, true, h.obtainMessage(CONNECT));
                return false;
            }
        });//groupId, itemId, order, title

        // Attempting to find a way to use the 'additional station'
        //
        menu.add(3, v.getId(), 0, "Connect soft").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                final P2PWifiNode mItem = mAdapter.getItem(acmi.position);
                dmesh.con.connectToAP(mItem, false, h.obtainMessage(CONNECT));
                return false;
            }
        });

//        menu.add(3, v.getId(), 0, "Connect P2P").setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
//            @Override
//            public boolean onMenuItemClick(MenuItem menuItem) {
//                final P2PWifiNode mItem = mAdapter.getItem(v.getId());
//                return false;
//            }
//        });

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
            sb.append(n.ssid);
            if (n.connectAttemptCount > 0) {
                sb.append(" con=").append(n.connectAttemptCount).append("/").append(n.connectCount);
            }

            sb.append(" ");
            if (n.pass != null) {
                sb.append("\npass=").append(n.pass);
                sb.append(" ip=").append(n.ip6);
                String v = n.p2pProp.getString("v");
                if (v != null) {
                    sb.append(" v=").append(v);
                }
                String t = n.p2pProp.getString("t");
                if (t != null) {
                    sb.append(" t=").append(t);
                }
                if (n.p2pDiscoveryAttemptCnt > 0) {
                    sb.append(" disc=").append(n.p2pDiscoveryAttemptCnt).append("/").append(n.p2pDiscoveryCnt);
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
        LMService.suspend = false;
        dmesh.scanner.stop(this, scan);
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view,
                            int position, long id) {
        // Expand the view
        Log.d("V", "Selected " + position + " " + view);

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(com.github.costinm.lm.R.menu.debug_menu, menu);
        return true;
    }

    @Override
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        int id = item.getItemId();

        if (id == com.github.costinm.lm.R.id.refresh) {
            dmesh.scanner.scan(1000, h.obtainMessage(SCAN));
        } else if (id == com.github.costinm.lm.R.id.discovery) {
            if (Build.VERSION.SDK_INT >= 16) {
                P2PDiscovery disc = new P2PDiscovery(this);
                disc.start(h, SCAN, true);
            }
        } else if (id == com.github.costinm.lm.R.id.autoconnect) {
            dmesh.con.start(this, null, null, 0);
        } else if (id == com.github.costinm.lm.R.id.ap_start) {
            if (dmesh.apRunning) {
                dmesh.ap.stop(h.obtainMessage(AP_START));
            } else {
                dmesh.ap.start(Message.obtain(h, AP_START));
            }
        } else if (id == com.github.costinm.lm.R.id.ap_stop) {
            APHotspot aph = new APHotspot(this);
            aph.setState(null, null);
            dmesh.ap.stop(h.obtainMessage(AP_START));
        } else if (id == com.github.costinm.lm.R.id.ap_start_legacy) {
            APHotspot aph = new APHotspot(this);
            aph.setState("DM-APM", "1234567890");
        } else if (id == com.github.costinm.lm.R.id.exit) {
            System.exit(0);
        }


        return super.onMenuItemSelected(featureId, item);
    }

}
