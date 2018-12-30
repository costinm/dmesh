package com.github.costinm.lm;

import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.net.wifi.WpsInfo;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.Toast;

import com.github.costinm.dmesh.libdm.BatteryMonitor;
import com.github.costinm.dmesh.libdm.DMUDS;
import com.github.costinm.dmesh.logs.Events;
import com.github.costinm.dmesh.vpn.VpnService;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Random;


/**
 * Wraps the various helpers, status.
 * <p>
 * This is a singleton, keeps history/status and results of various
 * operations. The individual components (receivers, etc) will be unregistered
 * and shouldn't be held locked.
 * <p>
 * While in AP mode a wake lock must be held, and this must be available.
 * Otherwise the info is a cache.
 * <p>
 * Rules when powered:
 * - No AP and DIRECT connections
 * -- If AP mode is on, don't connect to another DIRECT network. Can connect to a regular net
 * -- If connected to DIRECT - don't enable AP
 * - If APs visible and not on regular net, periodic to connect first
 * - If connected, look for the APs advertising same connected net.
 * <p>
 * Rules when active: same as powered
 * - if outgoing queue > 0 - discover AP
 * <p>
 * Rules on sync:
 * - even if connected to wifi, go over each AP and try to connect
 * - if connected, wait for a 'hold' from net layer (10s)?
 * - if no hold, move to next AP
 * - when done, possibly discover AP ( not clear when )
 * - if no network, or can't connect - discover AP for 15 min (or max job)
 * <p>
 * Keep track of recent connections - it means other devices are connectable
 */
@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class LMesh extends LMAPI {

    /**
     * How long to keep the AP on, in sec.
     * Default 600s
     */
    public static final String PREF_AP_ON = "ap_on";
    /**
     * Min interval between AP starts. If 0, AP will not start. AP will start on this
     * interval only if needed - usually if there are less than 3 connectable APs.
     *
     * Default 1800s
     */
    public static final String PREF_AP_MIN_INTERVAL = "ap_off";
    /**
     * Min interval between scans, if connected to the mesh
     *
     * Def: 300s
     */
    public static final String PREF_SCAN_CONNECTED = "rescan_connection";
    /**
     *
     * Def: 30s
     */
    public static final String PREF_SCAN_NOT_CONNECTED = "rescan_no_connection";
    /**
     * "on" - keep the AP on at all times. Can be used for a powered, fixed device.
     * "auto" - periodic AP. Don't start if other APs present.
     * "off" - never start the AP.
     * "schedule" - ignore presence of other APs, periodic.
     */
    public static final String PREF_AP_MODE = "ap_mode";
    /**
     * "auto"
     * "off" - do not attempt to connect to local mesh
     * "fixed" - will connect to a fixed network
     */
    public static final String PREF_CONNECT_MODE = "wifi_mode";
    /**
     * If PREF_CONNECT_MODE is fixed, this is the ssid to connect.
     *
     * Set in the debug activity, when clicking on a connection.
     * TODO: list of networks
     */
    public static final String PREF_FIXED_SSID = "fixed_ssid";
    /**
     * If off, it will not attempt to do periodic scans.
     *
     * Default on.
     */
    public static final String PREF_ENABLE_PERIODIC_SCANS = "periodic_scans";
    public static final String PREF_FG = "stay_fg";
    static final String TAG = "LM-Wifi";
    static final String[] states = new String[] {
            "start",
            "idle",
            "scan",
            "discovery",
            "connect",
            "ap",
    };
    /**
     * Wifi mesh initializing. When done, the START event will
     * be generated and we'll do the initial scan/updateCycle.
     */
    final static int STATE_STARTING = 0;
    /**
     * No scan, discovery, connect happening, state is stable.
     * From this state the device can:
     * - move to SCAN
     * - registerReceiver/unregisterReceiver the AP.
     */
    static final int STATE_IDLE = 1;
    /**
     * Most operations depend on having a SCAN. When this
     * state is entered, the wifi scan is initiated. When done
     * or timeout a SCAN event will be generated.
     *
     * Next state can be
     * - DISCOVERY - if refresh or new nodes are found (other conditions
     * may apply). If this state is entered, AP will be stopped.
     * - CONNECT - if we want a new or different connection
     * - registerReceiver/unregisterReceiver AP - if already connected or no possible connection
     */
    final static int STATE_SCAN = 2;
    /**
     * After the initial scan, will enter this state if we need
     * to discover. The AP may need to be stopped.
     *
     * When discovery is done, a DISCOVERY event is generated and
     * next state can be:
     * - CONNECT - if connectable nodes found
     * - IDLE - if no connectable node, no decision on AP
     * - ap registerReceiver/unregisterReceiver
     */
    final static int STATE_DISCOVERY = 3;
    /**
     * Attempting to connect.
     *
     * After this state device will:
     * - return to IDLE
     * - ap registerReceiver / unregisterReceiver
     */
    final static int STATE_CONNECT = 4;
    final static int STATE_AP_STARTING = 5;
    // Internal use
    final static int DISC_AFTER_STOP_AP2 = 1013;
    final static int POST_DISC_AFTER_STOP_AP = 1006;
    final static int CONNECT2 = 1007;

    final static int POST_INITIAL_SCAN_DISC = 1014;
    /**
     * Max number of visible/connectable APs. If more, don't attempt to start the AP mode.
     *
     * Default 3.
     *
     * Note: if 3 nodes are active, the ap on interval (10m) and cycle (30m) will
     * not allow all to be on.
     */
    private static final String PREF_MAX_APS = "max_ap";
    /**
     * SSID and WPA key, set after last P2P registerReceiver.
     * Both may change periodically, can be used to connect a legacy device.
     *
     * Typically DIRECT-xx-Android-XXXX
     * or
     * DIRECT-xx-NAME
     *
     * Last 4 bytes are also used as local identifier in announces.
     *
     *
     */
    public static String ssid;
    public static String pass;
    /**
     * Connectable nodes includes all active AP nodes that can be used by Connect.
     * Discovery adds nodes to this list.
     */
    public static ArrayList<LNode> connectable = new ArrayList<>();
    /**
     * Subset of 'last scan', containing nodes we don't know about or
     * discovered too long ago or invalidated. If not empty, a discovery
     * step will be added after scan. Updated by scan.
     */
    public static ArrayList<LNode> toFind = new ArrayList<>();
    static long startupTime;
    static Handler serviceHandler;
    static Messenger serviceHandlerMsg;
    private static LMesh sMesh;
    private final PowerManager.WakeLock wakeLock;
    private final WifiManager wm;
    private final WifiManager.MulticastLock mlock;

    // APs, peersByName and other devices we know about
    // The list should be < ~100. Updated by bySSID()
    public ArrayList<LNode> devices = new ArrayList<>();

    public Scan scanner;
    public P2PDiscovery disc;
    // All nodes found via discovery. Will have a timestamp of last discovery.
    public ArrayList<LNode> lastDiscovery = new ArrayList<>();
    /**
     * Set when we get a callback with 'group owner = true'.
     * Flipping state will trigger onStart/onStop
     */
    public boolean apRunning = false;
    public AP ap;
    public Connect con;
    /**
     * Will be set if the debug or other activity is running and want to receive
     * updates.
     */
    public Messenger observer;
    public int state;
    public Runnable jobStopper;
    // Ap startup is independent, happens in CONNECT or SCAN
    protected SharedPreferences prefs;
    Handler debugobserver;
    PowerManager pm;
    long nextAPStart = 0;
    long evalStart;
    public Context ctx;
    boolean started = false;
    boolean enabled = true;
    boolean updateRequested = false;
    private boolean vpnEnabled;
    LMonitor lmon;
    LMService service;

    Bt bt;
    Ble ble;

    // Held while a message is received / processed - for 5 seconds
    private static PowerManager.WakeLock wakeLockRcv;

    private LMesh(Context c) {
        startupTime = SystemClock.elapsedRealtime();
        ctx = c.getApplicationContext();
        con = new Connect(ctx, this);
        pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
        prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DMNetWakeLock");
        wakeLock.setReferenceCounted(true);
        wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);

        mlock = wm.createMulticastLock("DMWiFiMulticast");
        mlock.setReferenceCounted(false);
        mlock.acquire(); // TODO: release/acquire based on mesh setting

        wakeLockRcv = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DMPacketWakeLock");
        nextAPStart = startupTime + 5000 + new Random().nextInt(10000);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            disc = new P2PDiscovery(ctx, this);
        }
        scanner = new Scan(ctx, this);

        new Thread(new Runnable() {
            @Override
            public void run() {
                Looper.prepare();
                LMesh.serviceHandler = new Handler() {
                    @Override
                    public void handleMessage(Message msg) {
                        onMessage(msg);
                    }
                };
                LMesh.serviceHandlerMsg = new Messenger(LMesh.serviceHandler);
                initAfterHandler();
                Looper.loop();
            }
        }).start();

        ssid = prefs.getString("ssid", "");
        pass = prefs.getString("pass", "");
        if (dmUDS != null) {
            dmUDS.userAgent = ssid;
            dmUDS.sendUserAgent();
        }
        MESH_NAME = prefs.getString("name", "");

        bt = new Bt(ctx, serviceHandler);
        ble = new Ble(ctx, serviceHandler, this);
    }

    private void initAfterHandler() {
        bm = new BatteryMonitor(ctx, serviceHandler);
        lmon = new LMonitor(ctx, serviceHandler);
        lmon.updateConnectivityLegacy();
        dmUDS = new DMUDS(ctx, serviceHandler, "dmesh") {
            @Override
            protected void onNativeConnect(String meshName, byte[] addr) {
                if (!meshName.equals(LMesh.MESH_NAME)) {
                    prefs.edit().putString("name", meshName).commit();
                    LMesh.MESH_NAME = meshName;
                    Events.get().add("DM", "Name", meshName);
                }
                //onNativeConnect(MESH_NAME, addr);
            }
        };

        scanner.registerReceiver(ctx);
        if (disc != null) {
            disc.registerReceiver();
        }
    }

    DMUDS dmUDS;

    // This is the public-key derived name of the device inside the mesh.
    public static String MESH_NAME = "";

    /**
     * Return the local visible name for the device. Based on P2P SSID -
     * which is advertised and visible anyways when starting the P2P.
     *
     * This is broadcast in P2P 'listen' mode and BLE advertising when the
     * device is off, and used for local UI and pairing.
     *
     * Restricted to 11 chars - to fit BLE announce.
     *
     * The IPv6 address uses 64 bit local address (11 char b64)
     * MAC is 48 (8 chars b64)
     * Zero tier uses 40bit (7 chars b64, 8 b32, 10 hex)
     * IPv4 32 bit
     * 4 chars encode 3 bytes for 10.x addresses
     */
    public String getMeshName() {
       if (ssid.length() > 0 ) {
           return ssidShortName(ssid);
       }
       return MESH_NAME;
    }

    public static String ssidShortName(String ssid) {
        if (ssid.startsWith("DIRECT-") && ssid.length() > 10) {
            //String shortn = ssid.substring(7); // NT-Android_c530
            if (ssid.contains("-Android_")) {
                return ssid.substring(18); // c530
            } else {
                String shortn = ssid.substring(10);
                int l = shortn.length();
                if (l > 10) {
                    shortn = shortn.substring(l-10, l);
                }
                shortn.replace(" ", "-");
                return shortn;
            }
        }
        return ssid;
    }

    /**
     * Should be called only once, when the app starts, in onCreate.
     * Will generate a START event.
     *
     * Will initialize the AP for a short interval to determine capabilities and the
     * SSID/AP of the node.
     */
    public void onStart(final Context ctx) {
        if (started) {
            return;
        }
        boolean hasWA = ctx.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE);
        if (hasWA) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                new Nan(ctx, serviceHandler).startWifiAware();
            }
        }

        ap = new AP(this, ctx, serviceHandler);

        evalStart = SystemClock.elapsedRealtime();
        state = STATE_STARTING;

        // Make sure Hotspot AP is stopped. Interferes with the scan/discovery
        //new APHotspot(ctx).setState(null, null);

        // Will stop the AP if running from previous iteration, then start an eval
        ap.onStartup();

        started = true;

        Log.d(TAG, "onStart " + status());
    }


    public static LMesh get(Context c) {
        if (sMesh == null) {
            sMesh = new LMesh(c.getApplicationContext());
        }
        return sMesh;
    }

    static boolean isLM(String ssid) {
        return ssid != null &&
                (ssid.startsWith("DIRECT-") || ssid.startsWith("DM-")) &&
                ssid.length() > 10 && !(ssid.substring(10).startsWith("HP "));
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

    public StringBuilder status() {
        StringBuilder sb = new StringBuilder();
        if (apRunning) {
            sb.append("AP ");
        }
        String net = getNet();
        if (net != null) {
            sb.append("net=" + net + " ");
        }
        if (scanner != null) {
            sb.append(scanner.scanStatus());
        }
        long now = SystemClock.elapsedRealtime();
        sb.append(" sinceStart=").append((now -startupTime)/ 1000);
        return sb;
    }


    // ----------- Events and notifications ------------


    /**
     * Called on internal events. Will add, notify the observer and dispatch to the state machine.
     */
    public synchronized void event(int what, String msg) {
        Log.d(TAG, msg);
        if (observer != null) {
            Message m = Message.obtain();
            m.what = what;
            //Message m = observer.obtainMessage(what);
            if (msg != null) {
                m.getData().putString("msg", msg);
            }
            try {
                observer.send(m);
            } catch (RemoteException e) {
                e.printStackTrace();
                observer = null;
            }
        }
        updateUI(what, msg);

        if (serviceHandler != null) {
            serviceHandler.obtainMessage(what).sendToTarget();
        }
    }

    private void updateUI(int what, String msg) {
        Handler h1 = debugobserver;
        if (h1 != null) {
            Message m = h1.obtainMessage(what);
            if (msg != null) {
                m.getData().putString("msg", msg);
            }
            m.sendToTarget();
        }
    }

    /**
     * Helper to find a node by ssid or mac.
     *
     * Will cleanup or add the node if not found.
     *
     * Called by discovery, periodic, connect.
     * The mac addresses don't always match.
     */
    LNode bySSID(String ssid, String mac) {
        LNode bySID = null;
        if (ssid != null) {
            for (int i = devices.size() - 1; i >= 0; i--) {
                LNode nn = devices.get(i);
                if (ssid.equalsIgnoreCase(nn.ssid)) {
                    if (bySID != null) {
                        devices.remove(i);
                        Log.d(TAG, "Duplicate SID " + ssid + " " + mac + " " + bySID.mac);
                    }
                    if (bySID != null && bySID.mac != null && mac != null && !bySID.mac.equals(mac)) {
                        Log.d(TAG, "Different MAC " + ssid + " " + mac + " " + bySID.mac);
                    }
                    bySID = nn;
                }
            }
        }
        if (bySID == null) {
            // Not found - try to find by MAC
            for (int i = devices.size() - 1; i >= 0; i--) {
                LNode nn = devices.get(i);
                if (mac.equals(nn.mac)) {
                    if (bySID != null && bySID != nn) {
                        devices.remove(i);
                        Log.d(TAG, "Duplicate MAC " + ssid + " " + mac + " " + bySID.mac);
                    }
                    bySID = nn;
                }
            }
        }

        if (bySID == null) {
            bySID = new LNode();
            devices.add(bySID);
        }
        if (ssid != null) {
            bySID.ssid = ssid;
        }
        if (mac != null) {
            bySID.mac = mac;
        }

        return bySID;
    }

    /**
     * Called by P2P discovery to add a device, using the P2P included 's'
     * parameter, which is the visible SSID.
     */
    LNode bySSID(String ssid) {
        LNode bySID = null;
        if (ssid != null) {
            for (int i = devices.size() - 1; i >= 0; i--) {
                LNode nn = devices.get(i);
                if (ssid.equalsIgnoreCase(nn.ssid)) {
                    if (bySID != null) {
                        devices.remove(i);
                        Log.d(TAG, "Duplicate SID " + ssid);
                    }
                    bySID = nn;
                }
            }
        }

        if (bySID == null) {
            bySID = new LNode();
            devices.add(bySID);
        }
        if (ssid != null) {
            bySID.ssid = ssid;
        }
        return bySID;
    }

    LNode byMeshName(String mname) {
        if (mname != null) {
            for (int i = devices.size() - 1; i >= 0; i--) {
                LNode nn = devices.get(i);
                if (mname.equalsIgnoreCase(nn.meshName)) {
                    return nn;
                }
            }
        }

        LNode n = new LNode();
        n.meshName = mname;
        devices.add(n);
        return n;
    }

    int meshNodes() {
        int n = 0;
        for (int i = devices.size() - 1; i >= 0; i--) {
            LNode nn = devices.get(i);
            if (nn.pass != null) {
                n++;
            }
        }
        return n;
    }

    /**
     * Debug info for the service.
     */
    public void dump(Bundle b) {
        if (ap != null) {
            ap.dump(b);
        }
        con.dump(b);
        disc.dump(b);
        scanner.dump(b);
    }

    // Used to be part of service, but local mesh can be handled in an activity as well.
    // Doesn't really need to be foreground or resident - dhcp doesn't stay alive anyways.

    /**
     * Network name - defaults to the local SSID. Normally the SSID of the root node.
     */
    public String getNet() {
        if (con.connectedNode != null && con.connectedNode.net != null) {
            return con.connectedNode.net;
        }
        if (con.getCurrentWifiSSID() != null) {
            return con.getCurrentWifiSSID();
        }
        return ssid;
    }

    // Set by the UI when user requests to enable the AP manually.
    // AP will start and keep running. Discovery may fail on some devices.
    // Wifi scans may fail too.
    // This mode is also activated by setting 'ap off' interval to 0.
    boolean keepApOn = false;

    /**
     * Request setting the state of the AP..
     *
     * An AP_STATE_CHANGED event will be generated for the service.
     * The command may fail or timeout - the event will be generated
     * even if it fails.
     *
     * Called
     *  - manually from UI. 'keepApOn' may be set to true so survives
     *  - from native process ( A )
     *  -
     */
    public void apEnabled() {
            if (apRunning) {
                // TODO: extend the duration
                event(AP_STATE_CHANGED, "AP already enabled");

                return;
            }
            ap.start();

    }

    /**
     * Called by AP, to update the SSID and PASS.
     *
     */
    public void setSsid(String networkName, String passphrase) {
        if (networkName.equals(ssid) && passphrase.equals(pass)) {
            return;
        }
        ssid = networkName;
        pass = passphrase;
        prefs.edit().putString("ssid", ssid).putString("pass", pass).commit();

        if (dmUDS != null) {
            dmUDS.userAgent = ssid;
            dmUDS.sendUserAgent();
        }
        if (debugobserver != null) {
            debugobserver.obtainMessage(AP_STATE_CHANGED).sendToTarget();
        }
    }


    static DiscoveryStatus disStatus = new DiscoveryStatus();
    static DiscoveryStatus lastDiscStatus =  new DiscoveryStatus();

    String privateNet = "";
    String privateNetKey;

    private void updatePrefs() {
        enabled = prefs.getBoolean("lm_enabed", true);
        privateNet = prefs.getString("private_net", "");
        privateNetKey = prefs.getString("private_net_key", "12345678");
    }

    BatteryMonitor bm;


    public String battery() {
        if (bm == null || bm.bm == null) {
            return "";
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            int avg = bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE);
            int now = bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW);
            long cc = bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER);

            return "Battery: now=" + now + " avg=" + avg + " cc=" + cc;
        }
        return "";
    }

    long batteryCC() {
        if (bm == null || bm.bm == null) {
            return 0;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER);
        }
        return 0;
    }

    void maybeStartVpn() {
        vpnEnabled = prefs.getBoolean("vpn_enabled", false);
        if (vpnEnabled && DMUDS.iface == null) {
            if (dmUDS == null) {
                return;
            }
            if (dmUDS.addr[0] == 0) {
                return;
            }
            ComponentName cn = ctx.startService(new Intent(ctx, VpnService.class)
                    .putExtra("ctl", serviceHandlerMsg)
                    .putExtra("app", PendingIntent.getActivity(ctx, 15,
                            new Intent(ctx, LMSettingsActivity.class), 0))
                    .putExtra("addr", dmUDS.addr)
            );
            Log.d(TAG, "Start VPN " + cn);
        }

        if (!vpnEnabled && DMUDS.iface != null) {
            VpnService.close();
            if (dmUDS != null) {
                dmUDS.sendCmd("K");
            }
        }
    }

    long cc0;

    /**
     * Triggered by the CMD_UPDATE_CYCLE command. Non blocking.
     *
     * During eval, state will change: IDLE, SCAN, DISCOVERY, CONNECT, AP_STARTING
     *
     * Eval can take up to 30 seconds, depending on discovery.
     */
    public synchronized void updateCycle() {
        // TODO: pass a message and handler to notify end.
        long now = SystemClock.elapsedRealtime();

        updatePrefs();

        if (!enabled) {
            Log.d(TAG, "Stopping AP, cleanup - LM disabled");
            if (apRunning) {
                ap.stop(serviceHandler.obtainMessage(EV_AP_STOP));
            }
            con.cleanup();
            return;
        }

        ble.advertise(this);
        cc0 = batteryCC();
        maybeStartVpn();

        if (disStatus.start > 0 && disStatus.end == 0 &&
                (now - evalStart > 30000)) {
            Log.d(TAG, "Stuck in " + state); // 20 sec discovery, 5 scan
            state = STATE_IDLE;
            disStatus = new DiscoveryStatus();
        }

        if (disStatus.start > 0 && disStatus.end == 0) {
            Log.d(TAG, "Skipping updateCycle, in process " + state + " " + (SystemClock.elapsedRealtime() - evalStart));
            updateRequested = true;
            return;
        }

        disStatus.start = now;
        disStatus.onStart(this);

        if (apRunning) {
            int apOn = intPref(PREF_AP_ON, 600) * 1000; // 5 min
            if (apOn == 0 || apOn + ap.lastStart < now) {
                ap.stop(serviceHandler.obtainMessage(CMD_UPDATE_CYCLE));
                return;
            }
            // TODO: most devices can't scan/discover while AP runs
        }

        serviceHandler.removeMessages(CMD_UPDATE_CYCLE); // remove queued startup messages.
        Log.d(TAG, "Eval " + status());
        updateRequested = false;
        evalStart = now;

        final boolean discover = now - disc.lastDiscovery > 14 * 60000;
                if (discover) {
                    state = STATE_DISCOVERY;
                    disc.start(serviceHandler, POST_INITIAL_SCAN_DISC, true);
                } else {
                    state = STATE_SCAN;
                    // After 5 sec will generate a SCAN event.
                    scanner.scan(30000);
                }
    }

    boolean hasMobileInternet() {
        return lmon != null && lmon.mobileAddress.size() > 0;
    }

    boolean hasWifiInternet() {
        return con != null && con.getCurrentWifiSSID() != null && !con.getCurrentWifiSSID().startsWith("DIRECT-");
    }

    boolean hasDMeshConnection() {
        return con != null && con.getCurrentWifiSSID() != null && con.getCurrentWifiSSID().startsWith("DIRECT-");
    }

    /**
     * Control interface and state machine for LMesh.
     */
    public void onMessage(Message msg) {
        int what = msg.what;

        updateUI(msg.what, "");
        if (what < 256) {
            handleCmd((char)what, msg);
            return;
        }
        if (what == DMUDS.DMN_MSG) {
            handleNative((char)what, msg);
            return;
        }
        if (!enabled) {
            return;
        }

        //Log.d(TAG, "MSG: " + what + " STATE:" + state);

        switch (what) {
            case SCAN:
                if (state == STATE_SCAN || state == STATE_IDLE) {
                    // will attempt to connect
                    if (disStatus.start == 0) { // this is a background scan
                        disStatus.onStart(this);
                    }
                    sendScanResults();
                    afterInitialScan();
                }
                break;
            case POST_INITIAL_SCAN_DISC:
                afterInitialScanDiscovery();
                break;
            case CONNECT:
                Log.d(TAG, "Connect done..." + con.getCurrentWifiSSID());
                afterConnect();
                break;
                // Special case: AP stopped specifically for discovery
            case DISC_AFTER_STOP_AP2:
                disc.start(serviceHandler, POST_DISC_AFTER_STOP_AP, false);
                break;
            case POST_DISC_AFTER_STOP_AP:
                afterDiscoveryPostAPStop2();
                break;
            case CONNECT2:
                Log.d(TAG, "Post connect2...");
                afterConnect();
                break;

            case EV_AP_STOP:
                serviceHandler.obtainMessage(CMD_UPDATE_CYCLE).sendToTarget();
                break;

            case AP_STATE_CHANGED:
                if (state == STATE_AP_STARTING) {
                    state = STATE_IDLE;
                    final int apOn = intPref(PREF_AP_ON, 600);
                    int apOff = intPref(PREF_AP_MIN_INTERVAL, 1800) * 1000; // 30 min
                    if (apRunning) {
                        if (apOff > 0 && !keepApOn) {
                            serviceHandler.postDelayed(new Runnable() {
                                @Override
                                public void run() {
                                    ap.stop(serviceHandler.obtainMessage(CMD_UPDATE_CYCLE));
                                }
                            }, apOn * 1000 + 1000);
                        }
                        if (service != null) {
                            service.updateNotification();
                        }
                        afterAP();
                    } else {
                        Log.w(TAG, "AP failed to start");
                        afterAP();
                    }
                } else if (state == STATE_DISCOVERY){
                    // Ap stopped to allow discovery
                    Log.d(TAG, "Discovery after STOP AP...");
                    serviceHandler.sendMessageDelayed(serviceHandler.obtainMessage(DISC_AFTER_STOP_AP2), 1000);
                    break;
                }
                break;
            // Messages from VpnService - integrating with DMUDS
            case VpnService.EV_VPN_ON:
                // VPN has started
                if (dmUDS != null) {
                    dmUDS.sendVpn(DMUDS.iface);
                }
                break;
            // Messages from the battery monitor

        }
    }

    void sendScanResults() {
        JSONObject js = new JSONObject();
        for (ScanResult sr: scanner.lastScanResult) {
            try {
                JSONObject sro = new JSONObject();
                sro.put("SignalLevel", sr.level);
                sro.put("Frequency", sr.frequency);
                sro.put("BSSID", sr.BSSID);
                sro.put("SSID", sr.SSID);
                sro.put("Flags", sr.capabilities);
                js.put(sr.SSID, sro);
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }

        dmUDS.sendCmd((byte)22, js.toString());
    }

    void sendDiscoveryResults() {
        JSONObject js = new JSONObject();
        for (LNode sr: lastDiscovery) {
            try {
                JSONObject sro = new JSONObject();
                sro.put("P2PMac", sr.mac);
                sro.put("Name", sr.name);

                // Extracted from the TXT record
                sro.put("SSID", sr.ssid);
                sro.put("Pass", sr.pass);
                sro.put("Net", sr.net);
                sro.put("Mesh", sr.mesh);
                sro.put("Build", sr.build);

                js.put(sr.mac, sro);
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        if (dmUDS != null) {
            dmUDS.sendCmd((byte) 23, js.toString());
        }
    }

    private void handleNative(char what, Message msg) {
        switch (msg.arg1) {


        }
    }

    /**
     * Grab a wake lock for 5 seconds, to allow the TCP/UDP packet to be
     * processed.
     */
    public static synchronized void wakeLock() {
        if (!wakeLockRcv.isHeld()) {
            wakeLockRcv.acquire(5000);
        }
    }

    public void handleCmd(String cmd, Intent intent) {
        switch (cmd) {
            case "refresh":
                refresh();
                
            case "mesh_start":
                meshStart();
        }
        
    }

    /**
     * Initiate a local mesh, based on user request.
     *
     * - will scan for DIRECT- networks, and auto-connect if one is found
     * - if none is found, start AP mode for 5 min
     * - will scan for legacy Bluetooth devices and provision with known Wifi DIRECT
     *
     */
    private void meshStart() {

    }

    private void refresh() {
        updateCycle();
    }

    /**
     * Commands from the control plane (dmesh native)
     */
    void handleCmd(char what, Message msg) {
        StringBuilder os = new StringBuilder();
        String[] args = (String[]) msg.obj;

        switch (what) {
            case CMD_UPDATE_CYCLE: // 'u' Run a full update cycle.
                updateCycle();
                break;
            case 'S': // start a scan (may or may not work when AP is on)
                scanner.scan(6000);
                break;
            case 'b': // listen mode on/off
                disc.listen(args[1] == "1");
                break;
            case 'e': // start a discovery
                state = STATE_DISCOVERY;
                disc.start(serviceHandler, POST_INITIAL_SCAN_DISC, true);
                break;
            case 'A': // Enable AP
                apEnabled();
                break;
            case 'a': // Disable AP
                ap.stop(serviceHandler.obtainMessage(CMD_UPDATE_CYCLE));
                break;
//            case 'H': // Enable AP hotspot
//                APHotspot aph = new APHotspot(ctx);
//                aph.setState("DM-APM", "1234567890");
//                break;
//            case 'h': // Enable AP hotspot
//                APHotspot aph1 = new APHotspot(ctx);
//                aph1.setState(null, null);
//                break;
            case 'm': // connect  p2p
                disc.connect(serviceHandler, 0, args[1]);
                break;
            // ----- State and Debug -------
            case 'v': // get properties
                Bundle b = new Bundle();
                dump(b);
                appendBundle("P", os, b);
                break;
            case 'D':
                os.append("D\n");
                for (LNode d : devices) {
                    os.append(d.toString()).append('\n');
                }
                os.append('\n');
                break;
            case 'd':
                os.append("d\n");
                for (LNode d : lastDiscovery) {
                    os.append(d.toString()).append('\n');
                }
                os.append('\n');
                break;
            case 'c':
                os.append("c\n");
                for (LNode d : connectable) {
                    os.append(d.toString()).append('\n');
                }
                os.append('\n');
                break;
            case 'l':
                os.append("l\n");
                for (LNode d : scanner.last) {
                    os.append(d.toString()).append('\n');
                }
                os.append('\n');
                break;
            case 'f':
                os.append("f\n");
                for (LNode d : toFind) {
                    os.append(d.toString()).append('\n');
                }
                os.append('\n');
                break;
            case 'U':
                if (service != null) {
                    service.updateNotification();
                }
                return;
            case 'N':
                if (service != null) {
                    service.setNotification(args[1], args[2]);
                }
                return;
            case 'L':
                wakeLock();
                return;

            case 'w': // get properties
                b = new Bundle();
                dump(b);
                dmUDS.sendCmd((byte)'M', b);
                return;
        }
        if (os.length() > 0) {
            Messenger mg = observer;
            if (mg == null) {
                return;
            }
            Message m = new Message();
            m.getData().putString("msg", os.toString());
            try {
                mg.send(m);
            } catch (RemoteException e) {
                e.printStackTrace();
            }

            if (dmUDS != null) {
                dmUDS.sendCmd((byte)'m', os.toString());
            }
        }

    }

    private synchronized void appendBundle(String cmd, StringBuilder os, Bundle b) {
        os.append(cmd);
        os.append("\n");
        for (String k : b.keySet()) {
            Object o = b.get(k);
            if (o instanceof CharSequence) {
                os.append(k).append(":").append((CharSequence) o).append("\n");
            } else if (o != null){
                os.append(k).append(":").append(o.toString()).append("\n");
            }
        }
        os.append("\n");
    }

    // Will start a connection - which results in an 'afterConnect' callback, or
    // call afterConnect.
    // Return false if not enough info ( no connections )
    private boolean needsConnect() {
        String wmode = prefs.getString(PREF_CONNECT_MODE, "auto");
        if ("off".equals(wmode)) {
            return false;
        }
        if ("fixed".equals(wmode)) {
            // TODO: list of whitelisted networks, use group list
            // Possibly base it on known networks (i.e. devices that extend known nets)
            String net = prefs.getString(PREF_FIXED_SSID, "");
            if (net.length() > 0) {
                con.fixedNetworkOverride = net;

                if (net.equals(con.getCurrentWifiSSID())) {
                    // already connected (using standard connection manager)
                    return false;
                }
            }
            // TODO: only connect to net. Allow for discovery
        } else {
            con.fixedNetworkOverride = null;
        }


        return true;
    }

    /**
     * Called after first step, the periodic SCAN.
     * <p>
     * If AP is off (so discovery is possible) and discovery is needed, will initiate a discovery.
     * If AP is on, or no new nodes: move to next step, afterInitialScanDiscovery, to check/attempt
     * connection.
     * <p>
     * In 'fixed'/lm_debug mode and connected to desired net, or if connection disabled - will jump
     * to 'after connect', skipping discovery or attempts to connect.
     */
    private void afterInitialScan() {
        state = STATE_CONNECT;
        if (!needsConnect()) {
            // no discovery, no connect attempt.
            afterConnect();
            return;
        }

        // TODO: We want to periodically discover, to join larger mesh.
        if (LMesh.connectable.size() == 0 || LMesh.toFind.size() > 0) {
            Log.d(TAG, "Discovering " + LNode.getSSIDs(LMesh.toFind) + " " + con.getCurrentWifiSSID());
            state = STATE_DISCOVERY;
            disc.start(serviceHandler, POST_INITIAL_SCAN_DISC, false);
            // event will call afterInitialScanDiscovery
        } else {
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
        if (LMesh.toFind.size() > 0) {
            Log.d(TAG, "After discovery, not found: " + ssids(LMesh.toFind));
        }
        if (!needsConnect()) {
            afterConnect();
        } else if (alreadyConnected()) {
            // TODO: if signal strength is bad, look for different one.
            // TODO: join meshes, if discovery found other larger meshes around.
            Log.d(TAG, "After scan, connected. "
                    + (apRunning ? "AP " : "") + " ssid="
                    + con.getCurrentWifiSSID() + " con=" + ssids(LMesh.connectable)
                    + " disc=" + ssids(lastDiscovery)
                    + " aps=" + Scan.lastScanResult.size());
            afterConnect();
        } else if (LMesh.connectable.size() > 0) {
            Log.d(TAG, "After scan, connecting "
                    + (apRunning ? "AP" : "")
                    + " Connecting... con=" + ssids(LMesh.connectable)
                    + " disc=" + ssids(lastDiscovery)
                    + " aps=" + Scan.lastScanResult.size());
            con.start(ctx, LMesh.connectable, serviceHandler, CONNECT);
        } else if (LMesh.toFind.size() > 0) {
            // No conectable nodes - but some discoverable. Make sure the
            // AP is stopped.
            if (apRunning) {
                Log.d(TAG, "After scanm AP running... "
                        + "AP"
                        + " Stopping AP for discovery con=" + ssids(LMesh.connectable)
                        + " toFind=" + ssids(LMesh.toFind)
                        + " disc=" + ssids(lastDiscovery)
                        +  " aps=" + Scan.lastScanResult.size());
                state = STATE_DISCOVERY;
                ap.stop(serviceHandler.obtainMessage(DISC_AFTER_STOP_AP2));
            } else {
                Log.d(TAG, "After scan...  AP"
                        + " discovery con=" + ssids(LMesh.connectable)
                        + " disc=" + ssids(lastDiscovery)
                        + " aps=" + Scan.lastScanResult.size());
//                state = STATE_DISCOVERY;
//                disc.start(serviceHandler, POST_DISC_AFTER_STOP_AP, false);
                afterConnect();
            }
        } else {
            // Maybe registerReceiver the AP, if the timer is right and AP.
            Log.d(TAG, "After scan2... "
                    + (apRunning ? "AP " : "")
                    + con.getCurrentWifiSSID() + " con=" + ssids(LMesh.connectable)
                    + " disc=" + ssids(lastDiscovery)
                    + " aps=" + Scan.lastScanResult.size());
            afterConnect();
        }
    }

    // Discovery after the AP stop complete.
    private void afterDiscoveryPostAPStop2() {
        // After a P2P discovery - either after scan or after ap was turned off to allow
        // discovery to work.
        Log.d(TAG, "Post discovery..." + LMesh.connectable);

        if (alreadyConnected() || !needsConnect()) {
            afterConnect();
        } else if (LMesh.connectable.size() == 0) {
            // No possible connection
            afterConnect();
        } else {
            // Attempt to connect
            con.start(ctx, LMesh.connectable, serviceHandler, CONNECT2);
        }
    }


    private boolean alreadyConnected() {
        if (con.getCurrentWifiSSID() == null) {
            return false;
        }
        if (prefs.getBoolean("prefer_mesh", false)) {
            String c = con.getCurrentWifiSSID();
            if (!c.startsWith("DIRECT-") && !c.startsWith("DM-")) {
                return false;
            }
        }
        return true;
    }

    public String ssids(List<LNode> l) {
        StringBuilder sb = new StringBuilder();
        for (LNode ln: l) {
            if (ln.scan != null) {
                sb.append(ln.scan.SSID).append(",");
            } else {
                sb.append(ln.mac).append(",");
            }
        }
        return sb.toString();
    }


    /**
     * At this point we attempted to connect any possible node.
     * Evaluate if we should start the AP
     */
    private void afterConnect() {
        state = STATE_IDLE;

        ble.scan();

        long now = SystemClock.elapsedRealtime();

        int apOn = intPref(PREF_AP_ON, 600) * 1000; // 5 min

        if (0 == apOn) {
            if (apRunning) {
                ap.stop(null);
            }
            afterAP();
            return;
        }

        if (apRunning) {
            afterAP();
            return;
        }

        int apOff = intPref(PREF_AP_MIN_INTERVAL, 1800) * 1000; // 30 min

        // connected, no need to scan again.
        if (con.getCurrentWifiSSID() != null) {
            // we are connected, and 2+ APs already visible
            if (LMesh.connectable.size() > intPref(PREF_MAX_APS, 3) && apOff != 0 && !keepApOn) {
                Log.d(TAG, "After connect - too many visible APs " + LMesh.connectable);
                afterAP();
                return;
            }
        }


        // Setting or manual control
        if (keepApOn || apOff == 0) {
            long sinceStop = now - AP.lastStop;
            Log.d(TAG, "Starting AP OFF=0 " + (sinceStop / 1000) +
                    " time=" + apOn/1000 + "/" + apOff/1000 +
                    " con=" + con.getCurrentWifiSSID());
            state = STATE_AP_STARTING;
            apEnabled();
            return;
        }

        // Don't start automatically - wastes battery.
        // Use BT, BLE or UI to initiate a new mesh.
//        if ((ap.lastStop == 0 && nextAPStart < now)) {
//            long sinceStop = now - AP.lastStop;
//            Log.d(TAG, "Starting AP initial " +
//                    " con=" + con.getCurrentWifiSSID());
//            state = STATE_AP_STARTING;
//            apEnabled();
//            return;
//        }

        if (bm.isCharging() && (ap.lastStop + apOff < now) && apOn > 0
                && ssid != null && connectable.size() < 3) {
            long sinceStop = now - AP.lastStop;
            Log.d(TAG, "Starting AP after " + (sinceStop / 1000) +
                    " time=" + apOn/1000 + "/" + apOff/1000 +
                    " con=" + con.getCurrentWifiSSID());
            nextAPStart = now + (apOff + apOn) * 1000;
            state = STATE_AP_STARTING;
            apEnabled();
            return;
        }

        afterAP();
    }

    /**
     * afterAP is the final step of the eval.
     * At this point, device may be connected, and may run an AP.
     */
    public void afterAP() {
        long now = SystemClock.elapsedRealtime();


        if (updateRequested) {
            Log.d(TAG, "Re-update");
            serviceHandler.obtainMessage(CMD_UPDATE_CYCLE).sendToTarget();
        }

        // Notify activity/listeners that we completed a connect cycle. Ap may be starting.
        Log.d(TAG, "Update done wifi=" + con.getCurrentWifiSSID() + " batt=" + (batteryCC() - cc0) +
                (apRunning ? "AP on for " + (now - AP.lastStart)/1000 :
                        "AP off for " + (AP.lastStop > 0 ? (now - AP.lastStop)/1000 : 0)));

        if (!apRunning && con.getCurrentWifiSSID() == null
                && prefs.getBoolean("listen_on", true)) {
            disc.listen(true);
        }

        disStatus.onEnd(this, lastDiscStatus);

        if (prefs.getBoolean(PREF_ENABLE_PERIODIC_SCANS, true)) {
            // time to scan again if not connected - 65 sec.
            // Background scans may happen more frequently (60 sec)
            long next = intPref(PREF_SCAN_NOT_CONNECTED, 65) * 1000;
            // connected, no need to scan again.
            if (con.getCurrentWifiSSID() != null) {
                next = intPref(PREF_SCAN_CONNECTED, 300) * 1000; // 5 min
            }

            serviceHandler.removeMessages(CMD_UPDATE_CYCLE);

            // TODO: use a time schedule !!!
            // Next scan should start at a fixed time, and discovery AP should be on at that
            // time.
            // For example: scan

            serviceHandler.sendMessageDelayed(serviceHandler.obtainMessage(CMD_UPDATE_CYCLE), next);
            Log.d(TAG, "Eval done, reschedule " + next + " ap=" + apRunning + " wifi=" + con.getCurrentWifiSSID()
                    + " connectable:" + LNode.getSSIDs(LMesh.connectable)
                    + (LMesh.toFind.size() == 0 ? "" : " disc:" + LNode.getSSIDs(LMesh.toFind))
            );
        } else {
            Log.d(TAG, "Eval done, PERIODIC DISABLED, job only " + " ap=" + apRunning + " wifi=" + con.getCurrentWifiSSID());
        }

        // Wake lock will be lost after this
        Runnable jobDone = jobStopper;
        if (jobDone != null) {
            jobDone.run();
        }

        cleanupOldDevices();

        lastDiscStatus = disStatus;
        disStatus = new DiscoveryStatus();
    }

    private void cleanupOldDevices() {
        for (LNode n: devices) {

        }
    }

    int intPref(String key, int val) {
        String s = prefs.getString(key, null);
        if (s == null) {
            return val;
        }
        return Integer.parseInt(s);
    }


    public void setObserver(Handler observer) {
        this.debugobserver = observer;
    }

    public int visible() {
        int n = 0;
        long now = SystemClock.elapsedRealtime();
        for (LNode nn: devices) {
            // 5m
            if (now - nn.lastScan < 300 * 1000) {
                n++;
            }
        }
        return n;
    }
}
