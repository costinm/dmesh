package com.github.costinm.dmesh.lm;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.PowerManager;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.util.Log;

import com.github.costinm.lm.AP;
import com.github.costinm.lm.P2PDiscovery;
import com.github.costinm.lm.Scan;
import com.github.costinm.lm.WifiMesh;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;


/**
 * Simplistic automatic mesh creation.
 * <p>
 * This is only for the test/minimal app - the proper way is to coordinate
 * using the network layer.
 *
 * We assume the process will be around - but technically just net layer neds to run at all
 * times to keep the sockets open.
 */
public class LMService extends Service {


    public static final String TAG = "LM-Wifi-Service";
    public static final int UPDATE = 1000;
    final static int SCAN = 2;
    final static int SCAN_TO = 3;
    final static int DISC_AFTER_STOP_AP = 4;
    final static int DISC_AFTER_STOP_AP2 = 13;
    final static int CONNECT = 5;
    final static int POST_DISC = 6;
    final static int CONNECT2 = 7;
    final static int ON_CREATE = 8;
    final static int STOP_AP = 9;
    final static int STARTING_AP = 10;
    final static int AP_ACTIVE = 11;
    final static int AP_INACTIVE = 12;
    final static int POST_INITIAL_SCAN_DISC = 14;

    private static final int PERIODIC_JOB_START = 1;
    static long startupTime;
    Handler h;
    Messenger in;
    Messenger out; // only one out is supported
    WifiMesh lm;
    int state;
    PowerManager pm;
    BatteryManager bm;

    // Ap startup is independent, happens in CONNECT or SCAN
    private SharedPreferences prefs;

    // Quick hack to allow the activity to update itself.
    // Will use proper messengers in final version.
    static List<Handler> listeners = new ArrayList<>();

    /**
     * Run the normal scan/discover/connect/AP state machine
     */
    public static final int CMD_SCAN = 3;

    /**
     * Returns the messenger, allowing the network layer to control and
     * get events. (for the split net/link debug apps - in final version
     * a single app will combine both layers)
     */
    @Override
    public IBinder onBind(Intent intent) {
        if (in == null) {
            // Calls on the messenger will not be in the main thread !
            Handler h1 = new Handler() {
                @Override
                public void handleMessage(Message msg) {
                    int what = msg.what;
                    if (msg.replyTo != null) {
                        out = msg.replyTo;
                    }
                    switch (what) {
                        case CMD_SCAN:
                            eval();
                            break;

                    }
                }
            };
            in = new Messenger(h1);
        }
        return in.getBinder();
    }

    @Override
    public synchronized boolean onUnbind(Intent intent) {
        out = null;
        // TODO: restore foreground service, notification, periodic evals.
        return super.onUnbind(intent);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "Stopping");
    }

    long nextAPStart = 0;
    boolean fg = false;

    @Override
    public void onCreate() {
        super.onCreate();

        pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            bm = (BatteryManager) getSystemService(Context.BATTERY_SERVICE);
        }
        lm = WifiMesh.get(this);

        h = new Handler() {
            @Override
            public void handleMessage(Message msg) {
                onMessage(msg);
            }
        };
        evalStart = SystemClock.elapsedRealtime();
        startupTime = SystemClock.elapsedRealtime();
        state = ON_CREATE;

        // Will stop the AP if running from previous instance.
        lm.onStart(this, h, h.obtainMessage(state));

        AP.lastStop = SystemClock.elapsedRealtime();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            startForeground(1, getNotification());
        }
    }

    private Notification getNotification() {
        StringBuilder title = new StringBuilder().append("LM ");
        if (lm.apRunning) {
            title.append("*");
        }
        String ssid = lm.con.getCurrentWifiSSID();
        if (ssid != null) {
            title.append(" Wifi:").append(ssid);
        }

        StringBuilder txt = new StringBuilder();
        txt.append("Visible:").append(lm.scanner.connectable.size());
        // TODO: also show 'groups', 'private', estimated size, active group name

        Intent i = new Intent(this, LMDebugActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 1, i, 0);
        return new Notification.Builder(this)
                .setSmallIcon(R.drawable.ic_stat_fg)
                .setContentTitle(title)
                .setContentText(txt)
                .setContentIntent(pi)
                .build();
    }


    void eval() {
        long now = SystemClock.elapsedRealtime();
        if (evalStart > 0 && now - evalStart > 30000) {
            Log.d(TAG, "Stuck in " + state);
            state = PERIODIC_JOB_START;
        }
        if (state == PERIODIC_JOB_START) {
            h.removeMessages(PERIODIC_JOB_START); // remove queued startup messages.
            h.obtainMessage(PERIODIC_JOB_START).sendToTarget();
            Log.d(TAG, "Eval " + lm.apRunning + " " + lm.con.getCurrentWifiSSID());
        } else {
            Log.d(TAG, "Skipping eval, in process " + state + " " + (SystemClock.elapsedRealtime() - evalStart));
        }
    }

    long evalStart;

    private void onMessage(Message msg) {
        int what = msg.what;
        //Log.d(TAG, "Msg=" + what + " state=" + state);

        switch (what) {
            case ON_CREATE:
                // auto-connect / auto-ap disabled, init only.
                // Called after 'onStartup' is completed - AP in known state
                if (prefs.getBoolean(Starter.LM_ENABLED, true)) {
                    nextAPStart = startupTime + new Random().nextInt(10000);
                    h.sendMessage(h.obtainMessage(PERIODIC_JOB_START)); // eval, connect, etc
                }
                break;
            case PERIODIC_JOB_START:
                evalStart = SystemClock.elapsedRealtime();
                state = SCAN;
                if (lm.scanner.scan(3000, h.obtainMessage(SCAN))) {
                    // In some cases there is no timeout
                    h.sendMessageDelayed(h.obtainMessage(SCAN_TO), 5000);
                } // else: SCAN callback already sent, background scan and fresh results.
                break;
            case SCAN:
                if (state == SCAN) { // timeout message
                    Log.d(TAG, "Fresh results ..." + lm.scanner.connectable + " " +
                            (SystemClock.elapsedRealtime() - evalStart));
                    state = CONNECT;
                    afterInitialScan();
                }
                break;
            case SCAN_TO:
                if (state == SCAN) { // timeout message
                    state = CONNECT;
                    lm.scanner.update(); // may still have some results
                    afterInitialScan();
                }
                break;
            case POST_INITIAL_SCAN_DISC:
                afterInitialScanDiscovery();
                break;
            case CONNECT:
                Log.d(TAG, "Connect done..." + lm.con.getCurrentWifiSSID());
                afterConnect();
                break;
            case DISC_AFTER_STOP_AP:
                Log.d(TAG, "Discovery after STOP AP...");
                h.sendMessageDelayed(h.obtainMessage(DISC_AFTER_STOP_AP2), 1000);
                break;
            case DISC_AFTER_STOP_AP2:
                new P2PDiscovery(this).start(h, POST_DISC, false);
                break;
            case POST_DISC:
                Log.d(TAG, "Post discovery..." + lm.scanner.connectable);
                if (lm.scanner.connectable.size() == 0) {
                    afterConnect();
                } else if (lm.con.getCurrentWifiSSID() != null) {
                    afterConnect();
                } else {
                    lm.con.start(this, lm.scanner.connectable, h, CONNECT2);
                }
                break;
            case CONNECT2:
                Log.d(TAG, "Post connect2...");
                afterConnect();
                break;
            case STARTING_AP:
                Log.d(TAG, "Initialization...");
                if (lm.apRunning) {
                    h.sendMessageDelayed(h.obtainMessage(STOP_AP), intPref("ap_on", 600));
                }
                break;
            case STOP_AP:
                Log.d(TAG, "Stopping AP");
                lm.ap.stop(null);
                break;
            case AP_ACTIVE: // AP has been started
                for (Handler h : listeners) {
                    h.obtainMessage(UPDATE).sendToTarget();
                }
                final int apOn = intPref("ap_on", 600) * 1000;

                String apmode = prefs.getString("ap_mode", "auto");
                if (!"on".equals(apmode))  {
                    h.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            lm.ap.stop(h.obtainMessage(AP_INACTIVE));
                        }
                    }, apOn);
                }
                // Don't attempt to stop of "on". It may still be stopped to
                // allow discovery (which doesn't seem to work well if ap is running).
                // After discovery/connect, AP should be turned back on.
                Log.d(TAG, "AP started for " + (apOn / 1000));
                break;
            case AP_INACTIVE: // AP has been stopped
                int apOff = intPref("ap_off", 1800) * 1000;
                Log.d(TAG, "AP stopped");
                h.sendMessage(h.obtainMessage(PERIODIC_JOB_START)); // eval, connect, etc
                h.sendMessageDelayed(h.obtainMessage(PERIODIC_JOB_START), apOff);
                break;
        }
    }

    /**
     * Called after first step, the periodic SCAN.
     * <p>
     * If AP is off (so discovery is possible) and discovery is needed, will initiate a discovery.
     * If AP is on, or no new nodes: move to next step, afterInitialScanDiscovery, to check/attempt
     * connection.
     * <p>
     * In 'fixed'/debug mode and connected to desired net, or if connection disabled - will jump
     * to 'after connect', skipping discovery or attempts to connect.
     */
    private void afterInitialScan() {
        String wmode = prefs.getString("wifi_mode", "auto");
        if ("off".equals(wmode)) {
            afterConnect();
            return;
        }
        if ("fixed".equals(wmode)) {
            // TODO: list of whitelisted networks, use group list
            // Possibly base it on known networks (i.e. devices that extend known nets)
            String net = prefs.getString("fixed_ssid", "");
            if (net.length() > 0) {
                lm.con.fixedNetworkOverride = net;

                if (net.equals(lm.con.getCurrentWifiSSID())) {
                    // already connected (using standard connection manager)
                    afterConnect();
                    return;
                }
            }
            // TODO: only connect to net. Allow for discovery
        } else {
            lm.con.fixedNetworkOverride = null;
        }

        if (!lm.apRunning) {
            // TODO: We want to periodically discover, to join larger mesh.
            if (lm.scanner.toFind.size() > 0) {
                Log.d(TAG, "Discovering " + Scan.getSSIDs(lm.scanner.toFind) + " " + lm.con.getCurrentWifiSSID());
                new P2PDiscovery(this).start(h, POST_INITIAL_SCAN_DISC, false);
                return; // event will call afterInitialScanDiscovery
            } else {
                afterInitialScanDiscovery();
            }
        } else {
            // TODO: if 'to find' or connectable, may need to stop the AP.
            // Not doing it now because the network layer may use other non-AP nodes to do
            // the discovery (to join networks), and propagate the info. This will also
            // rest the timers on 'discovered' nodes, reducing individual node need to discover.
            afterInitialScanDiscovery();
        }
    }

    /**
     * Called after the initial SCAN, and optional DISCOVERY.
     * <p>
     * If we already have a Wifi connection, move to 'afterConnect'.
     * <p>
     * Otherwise, attempt to connect.
     */
    private void afterInitialScanDiscovery() {

        if (lm.con.getCurrentWifiSSID() != null) {
            // TODO: if signal strength is bad, look for different one.
            // TODO: join meshes, if discovery found other larger meshes around.
            Log.d(TAG, "After scan... "
                    + (lm.apRunning ? "AP " : "")
                    + lm.con.getCurrentWifiSSID() + " con=" + lm.scanner.connectable
                    + " disc=" + lm.scanner.toFind + " aps=" + lm.scanner.lastScanResult.size());
            afterConnect();

        } else if (lm.scanner.connectable.size() > 0) {
            Log.d(TAG, "After scan... "
                    + (lm.apRunning ? "AP" : "")
                    + " Connecting... con=" + lm.scanner.connectable
                    + " disc=" + lm.scanner.toFind + " aps=" + lm.scanner.lastScanResult.size());
            lm.con.start(this, lm.scanner.connectable, h, CONNECT);
        } else if (lm.scanner.toFind.size() > 0) {
            // No conectable nodes - but some discoverable. Make sure the
            // AP is stopped.
            if (lm.apRunning) {
                Log.d(TAG, "After scan... "
                        + (lm.apRunning ? "AP" : "")
                        + " Stopping AP for discovery con=" + lm.scanner.connectable
                        + " disc=" + lm.scanner.toFind + " aps=" + lm.scanner.lastScanResult.size());
                state = DISC_AFTER_STOP_AP;
                lm.ap.stop(h.obtainMessage(DISC_AFTER_STOP_AP));
            } else {
                Log.d(TAG, "After scan... "
                        + (lm.apRunning ? "AP" : "")
                        + " discovery con=" + lm.scanner.connectable
                        + " disc=" + lm.scanner.toFind + " aps=" + lm.scanner.lastScanResult.size());
                state = DISC_AFTER_STOP_AP;
                new P2PDiscovery(this).start(h, POST_DISC, false);
            }
        } else {
            // Maybe start the AP, if the timer is right and AP.
            Log.d(TAG, "After scan2... "
                    + (lm.apRunning ? "AP " : "")
                    + lm.con.getCurrentWifiSSID() + " con=" + lm.scanner.connectable
                    + " disc=" + lm.scanner.toFind + " aps=" + lm.scanner.lastScanResult.size());
            afterConnect();
        }
    }

    /**
     * At this point we attempted to connect any possible node.
     */
    private void afterConnect() {
        state = PERIODIC_JOB_START;

        long now = SystemClock.elapsedRealtime();

        String apMode = prefs.getString("ap_mode", "auto");

        long next = intPref("rescan_no_connection", 30) * 1000; // time to scan again if not connected
        boolean shouldStartAP = !lm.apRunning;
        if ("off".equals(apMode)) {
            shouldStartAP = false;
            if (lm.apRunning) {
                lm.ap.stop(null);
            }
        }

        // connected, no need to scan again.
        if (lm.con.getCurrentWifiSSID() != null) {
            next = intPref("rescan_connection", 300) * 1000; // 5 min

            // we are connected, and 2+ APs already visible - don't start
            // another AP.
            if (lm.scanner.connectable.size() > 3 && !"on".equals(apMode)) {
                shouldStartAP = false;
                Log.d(TAG, "After connect - too many visible APs " + lm.scanner.connectable);
            }
        }

        int apOff = intPref("ap_off", 1800) * 1000;

        if (apOff > 0 && shouldStartAP) {
            if (nextAPStart < now || "on".equals(apMode)) {
                long sinceStop = now - AP.lastStop;
                Log.d(TAG, "Starting after " + sinceStop + " " + lm.con.getCurrentWifiSSID());
                nextAPStart = now + apOff;
                lm.ap.start(h.obtainMessage(AP_ACTIVE));
            }
        }

        // Notify activity/listeners that we completed a connect cycle. Ap may be starting.
        for (Handler h : listeners) {
            h.obtainMessage(UPDATE).sendToTarget();
        }
        if (prefs.getBoolean("periodic_scans", true) && prefs.getBoolean(Starter.LM_ENABLED, true)) {
            h.removeMessages(PERIODIC_JOB_START);
            h.sendMessageDelayed(h.obtainMessage(PERIODIC_JOB_START), next);
            Log.d(TAG, "Eval done, reschedule " + next + " ap=" + lm.apRunning + " wifi=" + lm.con.getCurrentWifiSSID()
                    + " connectable:" + Scan.getSSIDs(lm.scanner.connectable)
                    + (lm.scanner.toFind.size() == 0 ? "" : " disc:" + Scan.getSSIDs(lm.scanner.toFind))
            );
        } else {
            Log.d(TAG, "Eval done, PERIODIC DISABLED " + next + " ap=" + lm.apRunning + " wifi=" + lm.con.getCurrentWifiSSID());
        }
    }

    int intPref(String key, int val) {
        String s = prefs.getString(key, null);
        if (s == null) {
            return val;
        }
        return Integer.parseInt(s);
    }


    /**
     * Debug:
     * adb shell am startservice --ei what 2 com.github.costinm.dmesh.lm/.LMService
     */
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (prefs.getBoolean("lm_fg", true)) {
            if (!fg) {
                startForeground(1, getNotification());
                fg = true;
                Log.d(TAG, "Starting fg");
            }
        } else {
            if (fg) {
                stopForeground(true);
                stopSelf();
            }
        }
        // Called by the starter, if the preference is enabled.

        eval();
        return super.onStartCommand(intent, flags, startId);

    }
}
