package com.github.costinm.lm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.logs.Events;

import java.util.ArrayList;
import java.util.List;


// Note: In pie, scan is deprecated and throttled ( 4 scans in 2 min )
//

/**
 * Helper for wifi scans. Can do a single scan or a periodic scan, and
 * filters 'direct' or 'DM-' connectable networks.
 * <p>
 * Also filters any network that may need discovery - the caller should
 * decide if it needs to do the expensive discovery, or can connect to
 * a visible network and possibly provision from the net.
 * <p>
 * Also has a 'periodic' mode - mostly for lm_debug ( TODO: remove it ?)
 * <p>
 *     Scan can also happen due to other apps or off-loaded. For example when connected
 *     to a wifi, scans can be ~3 min, with 1 min when disconnected, and few 10 sec appart
 *     when location changes.
 *     If connected to a wifi (internet connectivity), we may skip scans.
 * </p>
 */
public class Scan {
    private static final String TAG = "LM-Scan";

    // Last result of mWifiManager.geScanResults(). Includes unfiltered SSIDs.
    public static List<ScanResult> lastScanResult = new ArrayList<>();

    /**
     * Nodes found on the last scan. Only SSIDs of type DIRECT or DM.
     */
    public static ArrayList<LNode> last = new ArrayList<>();

    // Oldest and latest result in 'last', timestamp. Ex. 500ms.
    static long oldestResult;

    //
    static long latestResult;

    // stats:
    static int scanRequests;

    // Good to know if the phone updates us in background, without us
    // asking. If yes - may not need to call search very often.
    static int receiverCalled = 0;

    // elapsed time of last start scan.
    static long startScanTime;

    // elapsed realtime of last results
    static long lastScanResultsEMs;

    // Time to complete last explicit scan. About 3.5 sec on N6 - should be less than 5
    // sec deadline.
    static long scanLatency;
    static long maxScanLatency;

    WifiManager mWifiManager;
    IntentFilter f;

    LMesh lm;

    // Time when startScan was called last time by this app, or 0 if
    // no explicit scan in progress.
    long scanStart;

    List<LNode> blacklist = new ArrayList<>();

    // Nodes added/removed in the last scan.
    List<LNode> added = new ArrayList<>();
    List<LNode> removed = new ArrayList<>();

    // receiver is called either on requested scan or on background scans by system.
    BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            receiverCalled++;
            Long now = SystemClock.elapsedRealtime();
            long sinceLast = now - lastScanResultsEMs;
            lastScanResultsEMs = SystemClock.elapsedRealtime();

            if (startScanTime > 0) {
                scanLatency = lastScanResultsEMs - startScanTime;
            }
            if (sinceLast > maxScanLatency && receiverCalled > 1) {
                maxScanLatency = sinceLast;
            }
            update();
            if (scanStart > 0) { // explicitly requested scan.
                if (lastScanResult.size() == 0) {
                    return; // ignore, let timeout happen.
                }
                scanStart = 0;
                LMesh.disStatus.scanEnd = now;
                lm.event(LMesh.SCAN, "SCAN OK " + scanLatency + " " + scanStatus());
            } else {
                // If the device has no wifi, platform scans automatically - on N7/v23 every 15
                // sec if screen is on.
                LMesh.disStatus.scanBg++;

                if (added.size() == 0 && removed.size() == 0) {
                    Log.d(TAG, "Scan BG, nothing added " + sinceLast/1000 + scanStatus());
                    return;
                }

                Events.get().add("SCAN", "BG", scanStatus());
                lm.event(LMesh.SCAN, "SCAN BG " + sinceLast + " " + scanStatus());
            }
        }
    };

    // In M, the periodic seems to be going on continuously (at least while charging),
    // every ~1 min. This may be done by hardware - it seems each result is
    // different, so it may wake up AP on changes only.
    Scan(Context ctx, LMesh lMesh) {
        mWifiManager = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        lm = lMesh;
    }

    String scanStatus() {
        StringBuilder sb = new StringBuilder();
        long now = SystemClock.elapsedRealtime();

        sb.append("|w:").append(lm.con.getCurrentWifiSSID()).append(" ");
        sb.append("|a:");
        if (lm.apRunning) {
            sb.append(" on ").append((now - AP.lastStart) / 1000);
        } else {
            sb.append(" off ").append((now - AP.lastStop) / 1000);
        }
        sb.append(" ");
        addScanInfo(sb);
        return sb.toString();
    }

    void addScanInfo(StringBuilder sb) {
        sb.append("|c: ");
        for (LNode c: lm.connectable) {
            if (c.scan == null) {
                sb.append(c.ssid).append(" ");
                continue;
            }
            sb.append(c.ssid).append("/").append(c.scan.BSSID)
                    .append("/").append(c.scan.frequency)
                    .append("/").append(c.scan.level).append(" ");
        }
        sb.append("|f: ");
        for (LNode c: lm.toFind) {
            if (c.scan == null) {
                sb.append(c.ssid).append(" ");
                continue;
            }
            sb.append(c.ssid).append("/").append(c.scan.BSSID)
                    .append("/").append(c.scan.frequency)
                    .append("/").append(c.scan.level).append(" ");
        }
        sb.append("|bl: ");
        for (LNode c: blacklist) {
            if (c.scan == null) {
                sb.append(c.ssid).append(" ");
                continue;
            }
            sb.append(c.ssid).append("/").append(c.p2pDiscoveryAttemptCnt)
                    .append("/").append(SystemClock.elapsedRealtime() - c.p2pLastDiscoveryAttemptE)
                    .append("/").append(c.p2pDiscoveryCnt)
                    .append("/").append(c.scan.level).append(" ");
        }
        sb.append("|add: ");
        for (LNode c: added) {
            sb.append(c.ssid).append(" ");
        }
        sb.append("|rm: ");
        for (LNode c: removed) {
            sb.append(c.ssid).append(" ");
        }
        sb.append("|v: ").append(lastScanResult.size());
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
    synchronized boolean scan(int maxAgeMs) {
        if (maxAgeMs < 5000) {
            maxAgeMs = 5000;
        }
        long now = SystemClock.elapsedRealtime();

        update();

        long since = now - lastScanResultsEMs;

        if ((lastScanResultsEMs == 0 || since > maxAgeMs)) {
            startScanTime = now;
            scanRequests++;

            boolean started = mWifiManager.startScan();
            if (!started) {
                // May happen if wifi is busy. Typically means other app scanning, results may happen
                // in bg.
                Log.d(TAG, "startScan failed, waiting for background");
            }
            scanStart = now;
            LMesh.disStatus.scanStart = now;
            lm.serviceHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    if (scanStart > 0) {
                        update(); // may still have some results
                        LMesh.disStatus.scanTimeout = true;
                        LMesh.disStatus.scanEnd = SystemClock.elapsedRealtime();
                        scanStart = 0;
                        lm.event(LMesh.SCAN, "SCAN T 0 " + scanStatus());
                    }
                }
            }, 5000);
            return true;
        } else {
            lm.event(LMesh.SCAN, "SCAN O " + since/1000 + " " + scanStatus());
            return false;
        }
    }

    public synchronized void registerReceiver(Context ctx) {
        if (f == null) {
            f = new IntentFilter();
            f.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
            ctx.registerReceiver(receiver, f);
        }
    }

    // Can be called to unregister, will not receive background scan results.
    public synchronized void unregisterReceiver(Context ctx) {
        if (f != null) {
            ctx.unregisterReceiver(receiver);
            f = null;
        }
    }

    /**
     * Read the currently available periodic results - called when we have a result,
     * or after a scan timeout ( when we don't use the listener )
     */
    public synchronized void update() {
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
        ArrayList<LNode> nodeNow = new ArrayList<>();
        for (ScanResult sr : scanResults) {
            String ssid = sr.SSID;
            if (!LMesh.isLM(ssid)) {
                continue;
                // TODO: open networks or known networks should be shown,
                // since we can connect.
            }
            // DMesh specific code: updateSsidAndPass the DIRECT nodes, discover
            // discovery for any unknown node.
            LNode n = lm.bySSID(sr.SSID, sr.BSSID);
            n.scan = sr;
            n.ssid = sr.SSID;
            n.mac = sr.BSSID;
            n.lastChange = now;
            n.lastScan = now;
            nodeNow.add(n);
        }

        added.clear();
        removed.clear();
        for (LNode sr : last) {
            if (!nodeNow.contains(sr)) {
                removed.add(sr);
            }
        }
        for (LNode sr : nodeNow) {
            if (!last.contains(sr)) {
                added.add(sr);
            }
        }

        last = nodeNow;

        // 1. Update connectivity
        LMesh.connectable.clear();
        LMesh.toFind.clear();

        for (LNode n : last) {
            maybeAddConnectable(n);
        }

        updateToFind(last, now);
    }

    public void maybeAddConnectable(LNode n) {
        if (n.pass == null && n.ssid.startsWith("DIRECT-")) {
            return;
        }
        if (LMesh.connectable.contains(n)) {
            return;
        }
        if (lm.privateNet.length() > 0) {
            if (n.mesh == null || !n.mesh.equals(lm.privateNet)) {
                return;
            }
            Log.d(TAG, "Private net allow " + lm.privateNet + " " + n.mesh);
        }
        // TODO: if last discovery is old - drop
        LMesh.connectable.add(n);
    }

    /**
     * Process the last scan to see if we can/want to discover any node.
     */
    void updateToFind(ArrayList<LNode> last, long now) {
        blacklist.clear();

        for (LNode n : last) {
            if (!n.ssid.startsWith("DIRECT")) {
                continue;
            }
            // DIRECT-XX-
            if (n.ssid.substring(10).startsWith("HP ")) {
                continue;
            }
            long since = (now - n.p2pLastDiscoveryAttemptE) / 1000;
            if (n.pass == null) {
                if (n.foreign) { // advertises, but not .dm - so clear foreign
                    blacklist.add(n);
                    continue;
                }
                if (n.p2pDiscoveryAttemptCnt > 5 && n.p2pDiscoveryCnt == 0
                        && since < 3600) {
                    Log.d(TAG, "Skip node with 5 failed discoveries in last hour " + n.ssid);
                    blacklist.add(n);
                    continue; // ignore bad node
                }
                if (since > 5 * 60) { // don't re-try a node for 5 min
                    LMesh.toFind.add(n);
                } else {
                    blacklist.add(n);
                }
            } else if (((now - n.p2pLastDiscoveredE) / 1000) > 3600) {
                // Password or net may have changed
                LMesh.toFind.add(n);
            }
        }
    }

    void dump(Bundle b) {
        long now = SystemClock.elapsedRealtime();
        b.putString("scan.starts", scanRequests + "/" + receiverCalled);
        if (scanLatency > 0) {
            b.putString("scan.time_ms", scanLatency + "/" + maxScanLatency);
        }
        if (oldestResult > 0) {
            b.putString("scan.range", (now - oldestResult / 1000) + "/" + (now - latestResult / 1000));
        }
        b.putString("scan.last", scanStatus());
    }
}
