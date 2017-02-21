package com.github.costinm.lm;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.util.ArrayList;


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
public class WifiMesh {

    static final String TAG = "LM-Wifi";
    public static String ssid;
    public static String pass;
    public static ArrayList<String> ip6;

    static WifiMesh sMesh;

    // APs, peers and other devices we know about
    // The list should be < ~100
    public ArrayList<P2PWifiNode> devices = new ArrayList<>();

    public Scan scanner;
    public P2PDiscovery disc;

    // All nodes found via discovery. Will have a timestamp of last discovery.
    public ArrayList<P2PWifiNode> lastDiscovery = new ArrayList<>();

    /**
     * Set when we get a callback with 'group owner = true'.
     * Flipping state will trigger onStart/onStop
     */
    public boolean apRunning = false;
    public AP ap;
    public Connect con;

    public static WifiMesh get(Context c) {
        if (sMesh == null) {
            sMesh = new WifiMesh();
            sMesh.init(c.getApplicationContext());
        }
        return sMesh;
    }


    public static boolean isLM(String ssid) {
        return ssid != null && (ssid.startsWith("DIRECT-") || ssid.startsWith("DM-"));
    }

    private void init(Context c) {
        Context ctx = c.getApplicationContext();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            disc = new P2PDiscovery(ctx);
        }

        con = new Connect(c, this);
        ap = new AP(this, ctx);
        scanner = new Scan(ctx);

    }

    public void setPrivate(String group, String pass) {
        // TODO: add group to advertisment, use pass to encrypt the Wifi pass.
        // This would allow only specific devices to form a network, similar
        // with closed 802.11s.
    }

    /**
     * Called if network info was persisted or obtained out-of-band
     * (NFC, BT, barcodes)
     */
    public void addNetwork(String ssid, String pass, String ip6) {
        P2PWifiNode n = bySSID(ssid, null);
        n.pass = pass;
        n.ip6 = ip6;
    }

    // ----------- Events and notifications ------------

    /**
     * Called by discovery, periodic, connect.
     * The mac addresses don't always match.
     */
    public P2PWifiNode bySSID(String ssid, String mac) {
        P2PWifiNode bySID = null;
        if (ssid != null) {
            for (int i = devices.size() - 1; i >= 0; i--) {
                P2PWifiNode nn = devices.get(i);
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
                P2PWifiNode nn = devices.get(i);
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
            bySID = new P2PWifiNode();
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


    void event(String from, String msg) {
        Log.d(from, msg);
    }

    /**
     * Debug info for the service.
     */
    public StringBuilder dump(Bundle b, StringBuilder sb) {
        if (ap != null) {
            ap.dump(b, sb);
        }
        con.dump(b, sb);
        disc.dump(b, sb);
        scanner.dump(b, sb);
        return sb;
    }

    /**
     * Should be called only once, when the app starts. Subsequent calls will
     * return the ssid, ip6 and pass.
     * <p>
     * If AP is stopped, it'll periodic it briefly to find the SSID, pass, IP6.
     * If AP is running, it will be stopped.
     *
     * @param msg - must be associated with a Handler, and have the 'what'
     *            set. Will be sent back to target when completed.
     */
    public void onStart(Context ctx, Handler h, Message msg) {
        if (ssid != null) {
            if (msg != null) {
                msg.sendToTarget();
            }
            return;
        }
        // Make sure Hotspot AP is stopped. Interferes with the scan
        new APHotspot(ctx).setState(null, null);

        new AP(this, ctx).onStartup(h, msg);
    }

}
