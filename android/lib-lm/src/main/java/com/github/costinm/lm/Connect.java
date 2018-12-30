package com.github.costinm.lm;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.NetworkInfo;
import android.net.ProxyInfo;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.logs.Events;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static android.net.wifi.WifiManager.ERROR_AUTHENTICATING;
import static android.net.wifi.WifiManager.EXTRA_NETWORK_INFO;
import static android.net.wifi.WifiManager.EXTRA_NEW_STATE;
import static android.net.wifi.WifiManager.EXTRA_SUPPLICANT_ERROR;
import static android.net.wifi.WifiManager.EXTRA_WIFI_INFO;
import static com.github.costinm.lm.LMesh.UPDATE;


/**
 * Auto-connect to a DMesh SSID [TODO: or open network].
 * Will try all visible networks unless one is explicitly requested.
 * <p>
 * 'DMesh' networks are defined as DIRECT networks that advertise
 * the password trough some mechanism - bluetooth, IP-based discover server,
 * Wifi DIRECT DNS-SD. They are provided by other android devices:
 * - AP has a fixed IP v4 address (192.168.49.1).
 * - DHCP doesn't seem to work on any device while in 'doze' mode - even if
 * apps are foreground, the dhcpd process is not.
 * <p>
 * As such, reflection is used to set a random static IPv4 address, so the
 * connection can be initiated. However since we can't probe or handle conflicts,
 * the link-local IPv6 address will be used for communication.
 * <p>
 * Gingerbread doesn't support IPv6 - working on a more complicated
 * implementation using user-space multicast to assign an address.
 * <p>
 * RFC3927 defines "Dynamic config of IPv4 Link-Local Addresses"
 * - 169.254/16 "Stateless Address Autoconf"
 * - first and last 256 addresses reserved
 * - random number, seeded from MAC ( we can use SSID for this)
 * - for our case, we can also use hash of SSID
 * - ARP probes are used - we can't.
 * <p>
 * We'll substitute a "multicast" probe for the ARP: GB will multicast its
 * name and IP. The AP will send back a new IP address. TODO: we could use
 * 2 ranges, one for 'discovery' - 64 addresses, and the rest allocated
 * for GB. This is only needed/planned for devices without IPv6.
 */
@SuppressWarnings({"unchecked", "TryWithIdenticalCatches"})
public class Connect {

    // Debug: D/ConnectivityService
    // D/NetworkMonitor
    // D/WifiStateMachine
    //

    static final String TAG = "LM-Wifi-Con";
    /**
     * Last time we connected to a network (system time)
     */
    public static long lastSuccess;
    // Result of last 'onWMStateChanged'.
    // WifiInfo can be obtained directly - it has the netId, state, rssi, speed, freq, ip
    // Also as hidden are the txBad/retries/etc
    public NetworkInfo lastNetInfo;
    // set by wifi state changed events. Null if not connected to any SSID
    public LNode connectedNode;
    // TODO: remove on error !!!
    // TODO: notify after each failure and after all attempts are done.
    // TODO: notify on the status/progress of connection
    // TODO: temp blacklist.
    public int conAttempts;
    public int conSuccess;
    WifiManager mWifiManager;
    LMesh dmesh;

    // List of visible APs we can connect. Set by wifi AP periodic events.
    ArrayList<String> configured = new ArrayList<>();

    LNode currentCandidateInProgress;
    long startTimeE; // 0 if not started

    // For testing only - if set will connect only to this network.
    public String fixedNetworkOverride;

    // Active only while attempting to connect, not interested in wifi events
    // otherwise.
    Receiver receiver = new Receiver();

    // Current handler where the events will be posted
    Handler handler;
    // Base 'what'
    int what;

    // TODO: could discover 'ACTION_PICK_WIFI_NETWORK' after configuring the visible networks for
    // user preference (with system UI)
    StringBuilder attemptL = new StringBuilder();
    NetworkInfo.DetailedState lastConnectingState;
    private ArrayList<LNode> tryingNow = new ArrayList<>();
    private ArrayList<LNode> tryAll = new ArrayList<>();
    private Context ctx;

    public Connect(Context ctx, LMesh mesh) {
        this.ctx = ctx.getApplicationContext();
        dmesh = mesh;

        mWifiManager = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);

        /*

        String current = "\"" + getCurrentWifiSSID() + "\"";

        List<WifiConfiguration> existing = mWifiManager.getConfiguredNetworks();
        if (existing != null) {
            for (WifiConfiguration exCfg : existing) {
                // Don't want the system to periodic to connect by itself.
                // Note that means we lose the saved passwords - upper layer should store them
                // to optimize startup ! This will only delete networks we created.
                if (exCfg.SSID.startsWith("\"DIRECT-") && !current.equals(exCfg.SSID)) {
                    mWifiManager.removeNetwork(exCfg.networkId);
                } else {
                    configured.add(exCfg.SSID);
                }
            }
        }
*/
    }

    // For lm_debug - v4 address is set as static (to avoid DHCP) - just checking...
    private static InetAddress toInetAddress(int addr) {
        try {
            return InetAddress.getByAddress(new byte[]{(byte) addr, (byte) (addr >>> 8),
                    (byte) (addr >>> 16), (byte) (addr >>> 24)});
        } catch (UnknownHostException e) {
            //should never happen
            return null;
        }
    }

    /**
     * Remove quotes
     */
    public static String cleanSSID(String ssid) {
        if (ssid == null) {
            return null;
        }
        if (ssid.startsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }
        return ssid;
    }

    /**
     * Return the cleaned up SSID of the client Wifi connection, if we are connected.
     */
    public String getCurrentWifiSSID() {
        WifiInfo info = mWifiManager.getConnectionInfo();
        if (info == null) {
            return null;
        }
        SupplicantState st = info.getSupplicantState();
        if (st != SupplicantState.ASSOCIATED && st != SupplicantState.COMPLETED) {
            return null;
        }
        if (info.getSSID() == null || info.getSSID().startsWith("<") || info.getSSID().startsWith("\"<")) {
            return null;
        }
        if (info.getSSID().startsWith("0x")) {
            Log.d(TAG, "WRONG INFO " + info);
            return null;
        }
        if (st != SupplicantState.COMPLETED) {
            Log.d(TAG, "STATE: " + info.getSupplicantState());
        }

        return cleanSSID(info.getSSID());
    }

    public synchronized void dump(Bundle b) {
        if (currentCandidateInProgress != null) {
            b.putString("con.candidate", currentCandidateInProgress.ssid);
        }
//        if (tryingNow.size() > 0) {
//            b.putParcelableArrayList("con.trying", tryingNow);
//        }
//        if (connectedNode != null) {
//            b.putParcelable("con.connected", connectedNode);
//        }
        if (conAttempts > 0) {
            b.putLong("con.attempts_cnt", conAttempts);
        }
        if (conSuccess > 0) {
            b.putLong("con.success_cnt", conSuccess);
            b.putLong("con.success_time", lastSuccess);
        }
    }

    /**
     * Attempt to connect to one of the visible and accessible nets.
     *
     * @param lastScan - subset of networks to try - typically all visible+connectable networks,
     *                 or recently discovered networks
     */
    public synchronized boolean start(Context ctx, ArrayList<LNode> lastScan, Handler h, int what) {
        if (startTimeE != 0) {
            return false;
        }
        this.handler = h;
        this.what = what;

        if (lastScan == null) {
            lastScan = LMesh.connectable;
        }

        if (currentCandidateInProgress != null) {
            dmesh.event(UPDATE, "CONNECT " + currentCandidateInProgress);
            return false;
        }

        tryingNow.clear();
        tryAll.clear();

        for (LNode n : lastScan) {
            if (n.pass == null && n.ssid.startsWith("DIRECT-")) {
                continue;
            }
            if (fixedNetworkOverride != null) {
                if (!n.ssid.equals(fixedNetworkOverride)) {
                    // only allow connections to the specified test network,
                    // ignore all others
                    continue;
                }
            }
            tryingNow.add(n);
        }
        tryAll.addAll(tryingNow);
        if (tryAll.size() == 0) {
            return false;
        }

        IntentFilter f = new IntentFilter();
        f.addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION);
        f.addAction(WifiManager.SUPPLICANT_CONNECTION_CHANGE_ACTION);
        this.ctx = ctx;
        ctx.registerReceiver(receiver, f);

        startTimeE = SystemClock.elapsedRealtime();

        nextNetwork(tryingNow);
        return true;
    }

    public synchronized boolean inProgress() {
        return startTimeE != 0;
    }

    private synchronized void nextNetwork(final ArrayList<LNode> remaining) {
        currentCandidateInProgress = null;
        LNode candidate = null;
        for (LNode n : tryingNow) {
            if (candidate == null) {
                candidate = n;
                continue;
            }
            // Give preference to DM-AP nodes - the promise is of powered, dhcp-capable
            // node (maybe a home router virtual net).
            if (n.ssid.startsWith("DM-AP")) {
                candidate = n;
                break;
            }
            // TODO: more decisions - signal strength, history, number
            // of failed recent connections.
            if (candidate.lastConnectAttempt > n.lastConnectAttempt) {
                candidate = n;
            }
        }

        if (candidate == null) { // no viable candidate - done
            finish();
            return;
        }

        final LNode currentCandidate = candidate;
        currentCandidateInProgress = candidate;

        // Normal: ~5 sec.
        // Max observed: N: 32 sec

        // 20 sec timeout for DHCP

        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                afterNetworkAttempt(remaining, currentCandidate);
            }
        }, 40000);

        connectToAP(candidate, true, null);

        // Observed 32 sec - typical 3..5 sec.

    }

    void finish() {
        long t = SystemClock.elapsedRealtime() - startTimeE;
        Log.i(TAG, "Connect ssid= attempted= t=" + t);
        startTimeE = 0;
        ctx.unregisterReceiver(receiver);

        if (handler != null) {
            handler.obtainMessage(what).sendToTarget();
            handler = null;
        }
    }

    synchronized void afterNetworkAttempt(final ArrayList<LNode> remaining,
                                          final LNode currentCandidate) {
        if (currentCandidate != currentCandidateInProgress) {
            // Should not happen (unless another bug in scheduling)
            Log.e(TAG, "Unexpected change in currentCandidateInProgress " + currentCandidate + " " + currentCandidateInProgress);
        }

        remaining.remove(currentCandidateInProgress);

        if (connectedNode != null) {
            if (!connectedNode.ssid.equals(currentCandidate.ssid)) {
                Log.e(TAG, "Unexpected change of SSID " + currentCandidate + " " + currentCandidateInProgress);
            }
            Log.d(TAG, "Successfully connected " + currentCandidateInProgress.ssid + " " + getCurrentWifiSSID());
            currentCandidateInProgress.connectCount++;
            currentCandidateInProgress = null;
            finish();
            return;
        }

        // No more tries
        mWifiManager.disableNetwork(currentCandidateInProgress.cmNetworkId);
        boolean ok = mWifiManager.removeNetwork(currentCandidateInProgress.cmNetworkId);
        Log.d(TAG, "Removing network after failure " + currentCandidateInProgress + " " + ok);
        currentCandidateInProgress = null;

        // TODO: if failed, remove it

        nextNetwork(remaining);

    }

    /**
     * Single node attempt.
     */
    public void connectToAP(LNode n, boolean forceConnect, Message in) {
        long now = System.currentTimeMillis();

        // If AP in deep sleep (no dhcp ?):
        //07-04 21:45:04.455 E/WifiConfigStore( 2469): blacklisted
        // "DIRECT-tP-Android_40e9"WPA_PSK to 0 due to IP config failures,
        // count=1 disableReason=2 be:f5:ac:b3:22:72 ipfail=2
        n.lastConnectAttempt = now;
        n.connectAttemptCount++;


        int i = addNetworkToNetworkManager(mWifiManager, n.ssid, n.pass);
        if (i < 0) {
            Events.get().add("CON", "ERR", "ADD");
            dmesh.event(UPDATE, "CON_ERR ADD_NM " + n.ssid);
            return;
        }
        n.cmNetworkId = i;


        // This will only register - true will also connect.
        // Not clear how to connect without losing primary

        // On Cyanogne (API 21/5.0.2/LRX) this actually works, disconnects the main user
        //

        // Option 1:
        //  - don't call unless no network or tested device with multiple connections
        //  - if no network: call with true

        boolean ok = mWifiManager.enableNetwork(i, forceConnect);
        if (!ok) {
            Events.get().add("CON", "ERR", "ENABLE");
            dmesh.event(UPDATE, "CON_ERR ENABLE " + i + " " + n.ssid);
        } else {
            conAttempts++;
            dmesh.event(UPDATE, "CON_START " + n.ssid + " " + n.pass
                    + " " + ((now - n.lastConnectAttempt) / 1000) + "  " + n.connectAttemptCount + " "
                    + n.connectCount);
        }

        // It can take 2..10 sec to activate.- or fail
        // Next candidate can be tried after.

    }

    private void removeNetwork(String ssid) {

        String ssid2 = '"' + ssid + '"';

        List<WifiConfiguration> existing = mWifiManager.getConfiguredNetworks();
        if (existing != null) {
            // DIRECT networks change pass and ESSID often, usually at the same time.
            for (WifiConfiguration exCfg : existing) {
                if (exCfg.SSID == null) {
                    Log.d(TAG, "No SSID " + exCfg);
                    mWifiManager.removeNetwork(exCfg.networkId);
                    continue;
                }
                if (exCfg.SSID.equals(ssid) || exCfg.SSID.equals(ssid2)) {
                    //mWifiManager.updateNetwork(exCfg);
                    // Not clear we need to updateSsidAndPass - password should be good, if we fail to
                    // connect due to bad pass - we should just delete.
                    Log.d(TAG, "Found network " + exCfg);
                    //return exCfg.networkId;
                    mWifiManager.removeNetwork(exCfg.networkId);
                }
            }
        }

    }

    /**
     * Add a DM node to wifi config.
     */
    @SuppressLint("NewApi")
    private int addNetworkToNetworkManager(WifiManager mWifiManager, String ssid, String passphrase) {

        String ssid2 = '"' + ssid + '"';

        List<WifiConfiguration> existing = mWifiManager.getConfiguredNetworks();
        if (existing == null) {
            Log.d(TAG, "No existing networks ?");
            return -1; //
        } else {
            // DIRECT networks change pass and ESSID often, usually at the same time.
            for (WifiConfiguration exCfg : existing) {
                if (exCfg.SSID == null) {
                    Log.d(TAG, "No SSID " + exCfg);
                    mWifiManager.removeNetwork(exCfg.networkId);
                    continue;
                }
                if (exCfg.SSID.equals(ssid) || exCfg.SSID.equals(ssid2)) {
                    //mWifiManager.updateNetwork(exCfg);
                    // Not clear we need to updateSsidAndPass - password should be good, if we fail to
                    // connect due to bad pass - we should just delete.
                    Log.d(TAG, "Found network " + exCfg);
                    // TODO: remove on failure
                    return exCfg.networkId;
                    //mWifiManager.removeNetwork(exCfg.networkId);
                }
            }
        }

        WifiConfiguration cfg = new WifiConfiguration();
        // First set up IpAssignment to STATIC.
        // Doesn't work on 25 !

        // For legacy AP, it seems 192.168.43.1 is used ? And 42 to 49 IP range.

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
//                && Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            try {
                // UNASSIGNED doesn't work - is set as DHCP

                Object ipAssignment = Reflect.getEnumValue("android.net.IpConfiguration$IpAssignment", "STATIC");
                Reflect.callMethod(cfg, "setIpAssignment", new String[]{"android.net.IpConfiguration$IpAssignment"}, new Object[]{ipAssignment});
                int i = new Random().nextInt(250);
                i += 2;

                // Then set properties in StaticIpConfiguration.
                Object staticIpConfig = Reflect.newInstance("android.net.StaticIpConfiguration");
                Object linkAddress = Reflect.newInstance("android.net.LinkAddress", new Class<?>[]{InetAddress.class, int.class},
                        new Object[]{InetAddress.getByName("192.168.49." + i), 24});
//                    Object linkAddress = newInstance("android.net.LinkAddress", new Class<?>[]{InetAddress.class, int.class},
//                            new Object[]{InetAddress.getByName("0.0.0.0"), 24});
//                    Object linkAddress = newInstance("android.net.LinkAddress", new Class<?>[]{InetAddress.class, int.class},
//                            new Object[]{InetAddress.getByName("169.254.49." + i), 24});

                Reflect.setField(staticIpConfig, "ipAddress", linkAddress);
                //Reflect.setField(staticIpConfig, "gateway", InetAddress.getByName("192.168.49.1"));
                Reflect.getField(staticIpConfig, "dnsServers", ArrayList.class).clear();
                Reflect.getField(staticIpConfig, "dnsServers", ArrayList.class).add(InetAddress.getByName("1.1.1.1"));

                Reflect.callMethod(cfg, "setStaticIpConfiguration", new String[]{"android.net.StaticIpConfiguration"}, new Object[]{staticIpConfig});

                //setEphemeral(cfg);
                setNoInternet(cfg);

            } catch (Throwable t) {
                t.printStackTrace();
            }

        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            // does not have permission to modify proxy Settings in Pie
            // Must have NETWORK_SETTINGS, or be device or profile owner.
            cfg.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", 15004));

        }

        //manager.updateNetwork(config);
        //manager.saveConfiguration();

        if (passphrase == null) {
            cfg.SSID = ssid2;
            cfg.preSharedKey = '"' + "1234567890" + '"';
            cfg.priority = 1;
        } else {
            // http://stackoverflow.com/questions/2140133/how-and-what-to-set-to-android-wificonfiguration-presharedkey-to-connect-to-the
            // TODO: connect - it should be an open SSID - all communication is
            cfg.SSID = ssid2;
            cfg.preSharedKey = '"' + passphrase + '"';
            cfg.priority = 5;
        }

        int i = mWifiManager.addNetwork(cfg);
        if (i < 0) {
            // Do clients care ? Nothing to do about it.
            Log.d(TAG, "Failed to add SSID ");
            return -1;
        }
        Log.d(TAG, "Added wifi network " + cfg);
        mWifiManager.saveConfiguration();

        // TODO: delete old networks, keep track independently of passh
        return i;
    }

    /**
     * Hidden field - do not save or auto-join
     */
    private void setEphemeral(WifiConfiguration cfg) {
        try {
            Field ephemeral = cfg.getClass().getField("ephemeral");
            ephemeral.set(cfg, true);
        } catch (NoSuchFieldException ignored) {
        } catch (IllegalAccessException ignored) {
        }
        // TODO: Ipconfiguration ?
        // TODO: check 'lastFailure'
    }

    /**
     */
    private void setNoInternet(WifiConfiguration cfg) {
        try {
            Field f = cfg.getClass().getField("noInternetAccessExpected");
            f.set(cfg, true);
        } catch (NoSuchFieldException ignored) {
        } catch (IllegalAccessException ignored) {
        }
    }

    /**
     * "android.net.wifi.supplicant.CONNECTION_CHANGE"
     */
    public void onSuplicantStateChanged(Context c, Intent i) {
        SupplicantState ss = i.getParcelableExtra(EXTRA_NEW_STATE);
        final int errCode = i.getIntExtra(EXTRA_SUPPLICANT_ERROR, 0);
        switch (errCode) {
            case ERROR_AUTHENTICATING:
            default:
                Log.d(TAG, "Suplicant state: " + ss + " " + errCode);
                // No other errors defined in API
        }
    }

    public void onWMRssiChanged() {
        // TODO: track currentCandidateInProgress net rssi, connect to better network.
    }

    public void onNetworkIdsChanged() {
        // refresh the ID->ESSID mappings
    }

    /**
     * android.net.wifi.WIFI_STATE_CHANGED - wifi enabled, disabled, progress.
     * EXTRA_WIFI_STATE, EXTRA_PREVIOUS_WIFI_STATE
     */
    public void onWMWifiStateChanged(Context c, Intent i) {
    }

    /**
     * android.net.wifi.STATE_CHANGE
     * "One extra provides the new state
     * in the form of a {@link android.net.NetworkInfo} object. If the new
     * state is CONNECTED, additional extras may provide the BSSID and WifiInfo of
     * the access point."
     */
    public synchronized void onWMStateChanged(Context c, Intent intent) {
        // Requires ACCESS_NETWORK_STATE


        //  state: DISCONNECTED/DISCONNECTED -> linkProperties(linkAddress, routes, dns)
        //  state: DISCONNECTED/DISCONNECTED -> linkProperties(), bssid=MAC

        // CONNECTED/CONNECTED, extra=SSID -> wifiInfo(SSID, BSSID, SuplicantState: COMPLETED/ASSOCIATED,
        //   rssi, link speed/freq, net idString, ), bassid=MAC, linkProperties(linkAddress,routes,dns)


        // DISCONNECTED/SCANNING

        // CONNECTING/CONNECTING
        // CONNECTING/CONNECTING + extra = SSID
        // CONNECTING/AUTHENTICATING + extra = SSID
        // CONNECTING/AUTHENTICATING + extra=SSID + bssid=MAC
        // CONNECTING/OBTAINING_IPADDR + extra=SSID
        // CONNECTING/OBTAINING_IPADDR, extra: "costin"], linkProperties={InterfaceName: wlan0 LinkAddresses: []  Routes: [fe80::/64 -> :: wlan0,] DnsAddresses: []}, bssid=60:e3:27:fb:80:46}]

        // CONNECTED/CONNECTED -
        // CONNECTED/CONNECTED - same plus bssid = MAC

        // Net.Connectivity_change is last
        // CONNECTED/CONNECTED, extra=SSID, no linkProperties,networkType=1, inetCondition=0, extraInfo="costin"

        NetworkInfo netInfo = intent.getParcelableExtra(EXTRA_NETWORK_INFO);

        lastNetInfo = netInfo;

        // wifiInfo: status=connected, netid, ip (for v4), ssid, bssid etc
        // netInfo: type=WIFI, extra=SSID
        // Requires ACCESS_NETWORK_STATE

        // wifiInfo is typically null
        switch (netInfo.getState()) {
            case CONNECTED:
                break;
            case CONNECTING:
                lastConnectingState = netInfo.getDetailedState();
                break;
            case DISCONNECTED:
                break;
            case DISCONNECTING:
            case SUSPENDED:
            case UNKNOWN:
            default:
                // Log - not very useful
                Log.d(TAG, "WifiState: " + netInfo + " " + currentCandidateInProgress);
        }

        if (!netInfo.isConnected()) {
            String ssid = netInfo.getExtraInfo();
            if (netInfo.getDetailedState() == NetworkInfo.DetailedState.AUTHENTICATING) {
                Log.d(TAG, "AP found, AUTHENTICATING " + ssid + " " + netInfo + " " + currentCandidateInProgress);
                // If it doesn't get to next step - remove the net, discover again
            } else if (netInfo.getDetailedState() == NetworkInfo.DetailedState.OBTAINING_IPADDR) {
                if (ssid == null) {
                    Log.d(TAG, "OBTAININT_IPADDR " + currentCandidateInProgress);
                } else {
                    Log.d(TAG, "OBTAINING_IPADDR " + ssid + " " + netInfo + " " + currentCandidateInProgress);
                }
                // Typically this is where it gets stuck
//            } else if (netInfo.getDetailedState() == NetworkInfo.DetailedState.SCANNING) {
                // DISCONNECTED / SCANNING
//                if (ssid != null && !ssid.startsWith("<")) {
//                    Log.d(TAG, "Scanning to connect " + ssid);
//                } else {
//                    Log.d(TAG, "Scanning... " + (connectedNode == null ? currentCandidateInProgress : connectedNode));
//                }
//            } else if (netInfo.getDetailedState() == NetworkInfo.DetailedState.CONNECTING) {
                // ignore
            } else if (netInfo.getDetailedState() == NetworkInfo.DetailedState.DISCONNECTING) {
                Log.d(TAG, "Disconnecting... " + connectedNode);
//            } else if (netInfo.getDetailedState() == NetworkInfo.DetailedState.DISCONNECTED) {
                // ignore
            } else {
                Log.d(TAG, "WifiState: " + netInfo + " " + currentCandidateInProgress);
            }

            if (netInfo.getState() == NetworkInfo.State.DISCONNECTED) {
                if (connectedNode != null) {
                    dmesh.event(UPDATE, "CON_DISCONNECT " + connectedNode);
                    connectedNode.connectedTime += (System.currentTimeMillis() - connectedNode.lastConnect);
                    Events.get().add("CON", "STOP", connectedNode.ssid + " " +
                            connectedNode.connectedTime/1000);
                    connectedNode = null;
                }
            }
            return;
        }

        // We are connected to a wifi net.

        WifiInfo wifiInfo = intent.getParcelableExtra(EXTRA_WIFI_INFO);
        if (wifiInfo == null) {
            return;
        }
        //String ssidFromBroadcast = intent.getStringExtra(EXTRA_BSSID);
        String ssid = cleanSSID(wifiInfo.getSSID());

        if (ssid != null && ssid.startsWith("<")) {
            Log.e(TAG, "Connected but strange sid " + ssid + " " + intent.getExtras());
            return; // <unknown ssid>
        }

        if (connectedNode == null) {
            connectedNode = dmesh.bySSID(ssid, wifiInfo.getBSSID());
            connectedNode.connectCount++;
            connectedNode.lastConnect = System.currentTimeMillis();

            conSuccess++;
            lastSuccess = System.currentTimeMillis();

            dmesh.event(UPDATE, "CONNECTED " + " " + connectedNode + " " + wifiInfo.getRssi() +
                    " " + currentCandidateInProgress);
            Events.get().add("CON", "START", ssid + " " + wifiInfo.getRssi() +
                " " + currentCandidateInProgress);

            Message m = handler.obtainMessage(what);
            m.getData().putString("ssid", connectedNode.ssid);
            m.sendToTarget();
        } else if (!connectedNode.ssid.equals(ssid)) {
            Events.get().add("CON", "START_O", ssid + " " + wifiInfo.getRssi() +
                    " " + currentCandidateInProgress + " " +connectedNode.ssid);
            dmesh.event(UPDATE, "CON_ERR SSID " + ssid + " " + connectedNode.ssid);
        }

        // Connected 60:e3:27:fb:80:46 SSID: costin, BSSID: 60:e3:27:fb:80:46,
        // Supplicant state: COMPLETED, RSSI: -127, Link speed: -1Mbps,
        // Frequency: -1MHz, Net ID: 0, Metered hint: false, score: 0
        // NetInfo: [type: WIFI[], state: CONNECTED/CONNECTED, extra: "costin", isAvailable: true]

    }

    // Remove dmesh connections
    public void cleanup() {
        List<WifiConfiguration> existing = mWifiManager.getConfiguredNetworks();
        if (existing != null) {
            // DIRECT networks change pass and ESSID often, usually at the same time.
            for (WifiConfiguration exCfg : existing) {
                if (exCfg.SSID == null) {
                    Log.d(TAG, "No SSID " + exCfg);
                    mWifiManager.removeNetwork(exCfg.networkId);
                    continue;
                }
                if (!exCfg.SSID.startsWith("\"DM-AP") &&
                    !exCfg.SSID.startsWith("\"DIRECT-")) {
                    return;
                }
                //mWifiManager.updateNetwork(exCfg);
                // Not clear we need to updateSsidAndPass - password should be good, if we fail to
                // connect due to bad pass - we should just delete.
                Log.d(TAG, "Found network " + exCfg);
                //return exCfg.networkId;
                mWifiManager.removeNetwork(exCfg.networkId);
            }
        }

    }

    public class Receiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (WifiManager.SUPPLICANT_CONNECTION_CHANGE_ACTION.equals(action)) {
                onSuplicantStateChanged(context, intent);
            } else if (WifiManager.NETWORK_STATE_CHANGED_ACTION.equals(action)) {
                onWMStateChanged(context, intent);
            }

        }
    }
}