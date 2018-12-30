package com.github.costinm.lm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * Helper for wifi scans. Can do a single scan or a periodic scan, and
 * filters 'direct' or 'DM-' connectable networks.
 * <p>
 * Also filters any network that may need discovery - the caller should
 * decide if it needs to do the expensive discovery, or can connect to
 * a visible network and possibly provision from the net.
 * <p>
 * Also has a 'periodic' mode - mostly for debug ( TODO: remove it ?)
 */
public class Scan {
    private static final String TAG = "LM-Wifi-Scan";

    // Last result of mWifiManager.geScanResults().
    public static List<ScanResult> lastScanResult = new ArrayList<>();

    /**
     * Nodes found on the last scan.
     */
    public static ArrayList<P2PWifiNode> last = new ArrayList<>();

    // Oldest and latest result in 'last', timestamp
    static long oldestResult;
    static long latestResult;
    // stats:
    static int scanRequests;
    // Good to know if the phone updates us in background, without us
    // asking. If yes - may not need to call search very often.
    static int receiverCalled = 0;
    static long startScanTime;
    static long lastScanResultsEMs;
    static long scanLatency;
    final List<Message> pending = new ArrayList<>();
    /**
     * Connectable nodes includes all active AP nodes that can be used by Connect.
     * Discovery adds nodes to this list.
     */
    public ArrayList<P2PWifiNode> connectable = new ArrayList<>();
    public ArrayList<P2PWifiNode> toFind = new ArrayList<>();
    WifiMesh mesh;
    WifiManager mWifiManager;
    List<Periodic> listeners = new ArrayList<>();
    BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            receiverCalled++;
            lastScanResultsEMs = SystemClock.elapsedRealtime();

            if (startScanTime > 0) {
                scanLatency = lastScanResultsEMs - startScanTime;
            }
            update();
            sendMessages();
        }
    };

    // In M, the periodic seems to be going on continuously (at least while charging),
    // every ~1 min. This may be done by hardware - it seems each result is
    // different, so it may wake up AP on changes only.
    public Scan(Context ctx) {
        mWifiManager = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        mesh = WifiMesh.get(ctx);
    }

    private void sendMessages() {
        synchronized (pending) {
            for (Message m : pending) {
                m.sendToTarget();
            }
            pending.clear();
        }
    }

    /**
     * Refresh the list of visible networks.
     * <p>
     * On some systems the periodic results may already be available - if
     * most recent periodic is less than maxAge, return immediately.
     * <p>
     * No callback is generated - the caller can check 'periodic.last' in ~2 seconds.
     *
     * @param maxAgeMs if results are fresh, don't trigger a new periodic.
     */
    public synchronized boolean scan(int maxAgeMs, Message in) {
        long now = SystemClock.elapsedRealtime();

        update();

        long since = now - lastScanResultsEMs;

        if ((lastScanResultsEMs == 0 || since > maxAgeMs)
                && now - startScanTime > 1000) {
            startScanTime = now;
            scanRequests++;
            synchronized (pending) {
                pending.add(in);
            }
            mWifiManager.startScan();
            return true;
        } else {
            in.sendToTarget();
            return false;
        }
    }

    /**
     * Run a periodic periodic. Must be called from a service/activity. Stop must
     * be called.
     * <p>
     * Should only be run frequently while not connected.
     */
    public synchronized Periodic start(Context ctx, int i, Handler handler, int what) {

        if (listeners.size() == 0) {
            IntentFilter f = new IntentFilter();
            f.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
            ctx.registerReceiver(mesh.scanner.receiver, f);
        }
        Periodic p = new Periodic(this, handler, what, i);
        listeners.add(p);
        mWifiManager.startScan();
        Log.d(TAG, "Periodic scan " + i);
        return p;
    }

    public synchronized void stop(Context ctx, Periodic p) {
        if (p == null) {
            return;
        }
        listeners.remove(p);
        p.stop();
        if (listeners.size() == 0) {
            ctx.unregisterReceiver(mesh.scanner.receiver);
            Log.d(TAG, "Periodic scan stop");
        }
    }

    /**
     * Read the currently available periodic results - called when we have a result,
     * or after a scan timeout ( when we don't use the listener )
     */
    public void update() {
        long now = SystemClock.elapsedRealtime();
        List<ScanResult> scanResults = mWifiManager.getScanResults();
        if (scanResults == null) {
            scanResults = new ArrayList<>(); // JB
        }
        if (Build.VERSION.SDK_INT >= 17) {
            oldestResult = 0;
            for (ScanResult sr : scanResults) {
                if (sr.timestamp > latestResult) {
                    latestResult = sr.timestamp;
                }
                if (sr.timestamp < oldestResult || oldestResult == 0) {
                    oldestResult = sr.timestamp;
                }
            }
        }

        lastScanResult = scanResults;

        // Detect if anything changed compared with the previous periodic
        ArrayList<P2PWifiNode> nodeNow = new ArrayList<>();
        for (ScanResult sr : scanResults) {
            String ssid = sr.SSID;
            if (!WifiMesh.isLM(ssid)) {
                continue;
                // TODO: open networks or known networks should be shown,
                // since we can connect.
            }
            // DMesh specific code: update the DIRECT nodes, discover
            // discovery for any unknown node.
            P2PWifiNode n = mesh.bySSID(sr.SSID, sr.BSSID);
            n.scan = sr;
            n.ssid = sr.SSID;
            n.mac = sr.BSSID;
            nodeNow.add(n);
        }

        ArrayList<P2PWifiNode> added = new ArrayList<>();
        ArrayList<P2PWifiNode> removed = new ArrayList<>();
        for (P2PWifiNode sr : last) {
            if (!nodeNow.contains(sr)) {
                removed.add(sr);
            }
        }
        for (P2PWifiNode sr : nodeNow) {
            if (!last.contains(sr)) {
                added.add(sr);
            }
        }

        last = nodeNow;

        // 1. Update connectivity
        connectable.clear();
        toFind.clear();

        for (P2PWifiNode n : last) {
            if (n.pass == null && n.ssid.startsWith("DIRECT-")) {
                continue;
            }
            connectable.add(n);
        }

        updateToFind(last, now);

        //if (listeners.size() > 0) {
            // we have an active listsener
//            Log.d(TAG, " visible:" + scanResults.size() + "/" + last.size() +
//                    " connectable:" + getSSIDs(connectable) +
//                    " toFind:" + getSSIDs(toFind) +
//                    " add:" + getSSIDs(added) + " rm: " + removed);
//        } else { // caller should log (with more context)
//            Log.d(TAG, "visible:" + scanResults.size() +
//                    " connectable:" + getSSIDs(connectable) +
//                    " toFind:" + getSSIDs(toFind) +
//                    " add:" + getSSIDs(added) + " rm:" + removed);
        //}

        notifyHandlers();
    }

    /**
     * Process the last discovery to see if we can/want to discover any node.
     */
    void updateToFind(ArrayList<P2PWifiNode> lastScan, long now) {
        for (P2PWifiNode n : lastScan) {
            if (!n.ssid.startsWith("DIRECT")) {
                continue;
            }
            long since = (now - n.p2pLastDiscoveryAttemptE) / 1000;
            if (n.pass == null) {
                if (n.p2pDiscoveryAttemptCnt > 5 && n.p2pDiscoveryCnt == 0
                        && since < 3600) {
                    Log.d(TAG, "Skip node with 5 failed discoveries in last hour " + n.ssid);
                    continue; // ignore bad node
                }
                if (since > 600) { // don't try a node for 10 min
                    toFind.add(n);
                }
            } else if (since > 3600) {
                // Password or net may have changed
                toFind.add(n);
            }
        }
    }


    public synchronized void notifyHandlers() {
        for (Periodic h : listeners) {
            Message m2 = Message.obtain(h.out.obtainMessage(h.what));
            m2.sendToTarget();
        }
    }

    public static ArrayList<String> getSSIDs(ArrayList<P2PWifiNode> n) {
        ArrayList<String> out = new ArrayList<>();
        for (P2PWifiNode nn : n) {
            out.add(nn.ssid);
        }
        return out;
    }

    public void dump(Bundle b, StringBuilder sb) {
        long now = SystemClock.elapsedRealtime();
        b.putLong("periodic.starts_cnt", scanRequests);
        b.putLong("periodic.events_cnt", receiverCalled);
        if (scanLatency > 0) {
            b.putLong("periodic.time_ms", scanLatency);
        }
        if (oldestResult > 0) {
            b.putLong("periodic.oldest_ms", now - oldestResult / 1000); // ~15s
            b.putLong("periodic.newst_ms", now - latestResult / 1000);
        }
    }

    public static class Periodic implements Runnable {
        Scan scan;
        Handler out;
        int what;
        long interval;


        Periodic(Scan ctx, Handler handler, int what, int i) {
            this.what = what;
            out = handler;
            scan = ctx;
            this.interval = i;
            out.postDelayed(this, interval);
        }

        void stop() {
            interval = 0;
            out.removeCallbacks(this);
        }

        @Override
        public void run() {
            startScanTime = SystemClock.elapsedRealtime();
            scanRequests++;
            scan.mWifiManager.startScan();
            if (interval > 0) {
                out.postDelayed(this, interval);
            }
        }
    }
}
