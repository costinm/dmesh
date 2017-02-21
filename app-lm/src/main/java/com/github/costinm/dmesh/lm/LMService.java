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
import com.github.costinm.lm.WifiMesh;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;


/**
 * Simplistic automatic mesh creation.
 * <p>
 * This is only for the test/minimal app - the proper way is to coordinate
 * using the network layer.
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
    final static int INIT_ONLY = 8;
    final static int STOP_AP = 9;
    final static int STARTING_AP = 10;
    final static int AP_ACTIVE = 11;
    final static int AP_INACTIVE = 12;

    private static final int STARTUP = 1;

    Handler h;
    Messenger in;
    WifiMesh lm;
    int state;
    PowerManager pm;
    BatteryManager bm;

    // Ap startup is independent, happens in CONNECT or SCAN
    private SharedPreferences prefs;

    // Quick hack to allow the activity to update itself.
    // Will use proper messengers in final version.
    static List<Handler> listeners = new ArrayList<>();
    static boolean suspend = false;

    /**
     * Returns the messenger, allowing the caller to send control messages.
     */
    @Override
    public IBinder onBind(Intent intent) {
        if (in == null) {
            Handler h1 = new Handler() {
                @Override
                public void handleMessage(Message msg) {
                    int what = msg.what;
                    switch (what) {
                        case STARTUP:
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
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "Stopping");
    }

    static long startupTime;
    long nextAPStart = 0;

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

        startupTime = SystemClock.elapsedRealtime();
        state = INIT_ONLY;
        lm.onStart(this, h, h.obtainMessage(state));
        AP.lastStop = SystemClock.elapsedRealtime();

        Log.d(TAG, "Starting");
    }

    void eval() {
        if (suspend) {
            return;
        }
        startForeground(1, getNotification());

        if (state == STARTUP) {
            h.removeMessages(STARTUP);
            h.obtainMessage(STARTUP).sendToTarget();
        }
        // TODO: periodic scan if not connected
        // periodic start AP
        // auto-afterInitialScan when possible
        // TODO: start foreground
    }

    private Notification getNotification() {
        String title = "DMesh ";
        if (lm.apRunning) {
            title += "AP ";
        }
        String ssid = lm.con.getCurrentWifiSSID();
        if (ssid != null) {
            if (WifiMesh.isLM(ssid)) {
                title += "Active";
            } else {
                title += "Connected";
            }
        } else {
            title += "Disconnected";
        }
        StringBuilder txt = new StringBuilder();
        if (ssid != null) {
            txt.append(ssid);
        }

        Intent i = new Intent(this, LMActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 1, i, 0);
        return new Notification.Builder(this)
                // Set required fields, including the small icon, the
                // notification title, and text.
                .setSmallIcon(R.drawable.ic_stat_fg)
                .setContentTitle(title)
                .setContentText(txt.toString())
                .setContentIntent(pi)
                .build();
    }

    private void onMessage(Message msg) {
        if (suspend) {
            return;
        }
        int what = msg.what;
        //Log.d(TAG, "Msg=" + what + " state=" + state);

        switch (what) {
            case STARTUP:
                state = SCAN;
                lm.scanner.scan(1000, h.obtainMessage(SCAN));
                // In some cases there is no timeout
                h.sendMessageDelayed(h.obtainMessage(SCAN_TO), 5000);
                break;
            case SCAN:
                if (state == SCAN) { // timeout message
                    state = CONNECT;
                    afterInitialScan();
                }
                break;
            case SCAN_TO:
                if (state == SCAN) { // timeout message
                    state = CONNECT;
                    lm.scanner.update();
                    afterInitialScan();
                }
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
                Log.d(TAG, "AP started");
                for (Handler h : listeners) {
                    h.obtainMessage(UPDATE).sendToTarget();
                }
                final int apOn = intPref("ap_on", 600) * 1000;
                h.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        lm.ap.stop(h.obtainMessage(AP_INACTIVE));
                    }
                }, apOn);
                break;
            case AP_INACTIVE: // AP has been stopped
                int apOff = intPref("ap_off", 1800) * 1000;
                Log.d(TAG, "AP stopped");
                h.sendMessage(h.obtainMessage(STARTUP)); // eval, connect, etc
                h.sendMessageDelayed(h.obtainMessage(STARTUP), apOff);
                break;
            case INIT_ONLY:
                // auto-connect / auto-ap disabled, init only.
                if (prefs.getBoolean(Starter.LM_ENABLED, true)) {
                    h.sendMessage(h.obtainMessage(STARTUP)); // eval, connect, etc
                    nextAPStart = startupTime + new Random().nextInt(10000);
                }
                break;
        }
    }

    private void afterInitialScan() {

        if (lm.con.getCurrentWifiSSID() != null) {
            // TODO: if signal strength is bad, look for different one.
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
        state = STARTUP;

        if (!prefs.getBoolean(Starter.LM_ENABLED, true)) {
            // don't start AP, don't re-schedule.
            return;
        }

        long now = SystemClock.elapsedRealtime();

        long next = 15000;
        boolean shouldStartAP = !lm.apRunning;

        // connected, no need to scan again.
        if (lm.con.getCurrentWifiSSID() != null) {
            next = 300 * 1000; // 5 min

            // we are connected, and 3+ APs already visible - don't start
            // another AP.
            if (lm.scanner.connectable.size() > 2) {
                shouldStartAP = false;
                Log.d(TAG, "After connect - too many visible APs " + lm.scanner.connectable);
            }
        }

        int apOff = intPref("ap_off", 1800) * 1000;

        if (apOff > 0 && shouldStartAP) {
            long sinceStop = now - AP.lastStop;
            if (nextAPStart < now) {
                Log.d(TAG, "Starting after " + sinceStop + " " + lm.con.getCurrentWifiSSID());
                nextAPStart = now + apOff;
                lm.ap.start(h.obtainMessage(AP_ACTIVE));
            }
        }


        // TODO: listen to wifi disconnect, trigger it based on that.

        h.removeMessages(STARTUP);
        h.sendMessageDelayed(h.obtainMessage(STARTUP), next);

        for (Handler h : listeners) {
            h.obtainMessage(UPDATE).sendToTarget();
        }
        startForeground(1, getNotification());
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
        // Called by the starter, if the preference is enabled.

        eval();
        return super.onStartCommand(intent, flags, startId);

    }
}
