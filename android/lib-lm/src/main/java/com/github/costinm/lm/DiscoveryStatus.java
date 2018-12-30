package com.github.costinm.lm;

import android.net.wifi.p2p.WifiP2pDevice;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.logs.Events;

import java.util.HashMap;
import java.util.Map;

import static com.github.costinm.lm.LMesh.TAG;

/**
 * Captures a scan result.
 */
public class DiscoveryStatus implements Handler.Callback {

    // Ellapsed time when scan started and ended
    long start;
    long end;

    // Timestamp for the wifi scan part
    public long scanStart;

    // Timestamps for the P2P discovery part
    public long discoveryStart;
    public long discoveryEnd;

    // Anything found by P2P discovery - most will not be DMesh devices.
    // Only includes 'discovery capable' devices.
    // Listen mode devices included.
    // Key is the P2P device name
    Map<String, WifiP2pDevice> peersByName = new HashMap<>();

    // Visible DMesh nodes during scan, keyed by meshName (derived from
    // P2P SSID)
    Map<String, LNode> visible = new HashMap<>();

    // Number of times a TXT record was found
    int serviceDiscovery;

    // Battery statistics to measure power use during scan
    int cStart;
    int cAStart;

    long ccStart;

    long cEnd;
    long cAEnd;
    long ccEnd;

    boolean scanTimeout;
    public long scanEnd;
    public int scanBg;

    // State of Wifi and AP before and after the scan
    boolean apOnStart;
    boolean apOnEnd;

    String wifiOnStart;
    String wifiOnEnd;

    LMesh lm;
    /**
     * Created at startup and _after_ a cycle is completed. Will handle background scan events.
     * Previous cycle is saved.
     */
    public DiscoveryStatus() {
    }

    private boolean same(String s1, String s2) {
        if (s1 == null && s2 == null) {
            return true;
        }
        if (s1 != null && s1.equals(s2)) {
            return true;
        }
        return false;
    }

    public boolean hasChanged(DiscoveryStatus old) {
        if (old == null) {
            return true;
        }
        if (!same(wifiOnStart, old.wifiOnStart) ||
                !same(wifiOnEnd, old.wifiOnEnd) ||
               apOnStart != old.apOnStart ||
                apOnEnd != old.apOnEnd ||
                !visible.keySet().equals(old.visible.keySet())
                ) {
            return true;
        }

        return false;
    }

    /**
     * Called when an updateCycle is started.
     * @param lm
     */
    public void onStart(LMesh lm) {
        start = SystemClock.elapsedRealtime();
        this.lm = lm;
        if (lm.bm != null && lm.bm.bm != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                cAStart = lm.bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE) /1000;
                cStart = lm.bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) / 1000;
                ccStart = lm.bm.bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER);
                if (ccStart == -1) {
                    ccStart = 0;
                }
            }
        }
        apOnStart = lm.apRunning;
        wifiOnStart = lm.con.getCurrentWifiSSID();
    }

    void onBackgroundScan() {

    }

    /**
     * Peer found during discovery in this cycle
     */
    void onDiscoveryPeer(String deviceName, WifiP2pDevice d) {
        peersByName.put(deviceName, d);
    }



    public void onEnd(LMesh lm, DiscoveryStatus old) {

        if (lm.bm != null && lm.bm.bm != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                cAEnd = lm.bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE) / 1000;
                cEnd = lm.bm.bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) / 1000;
                ccEnd = lm.bm.bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER);
                if (ccEnd == -1) {
                    ccEnd = 0;
                }
            }
        }
        end = SystemClock.elapsedRealtime();
        apOnEnd = lm.apRunning;
        wifiOnEnd = lm.con.getCurrentWifiSSID();

        StringBuilder sb = new StringBuilder();

        if (apOnStart || apOnEnd) {
            sb.append(apOnStart ? "APON" : "APOFF").append("-");
            sb.append(apOnEnd ? "APON" : "APOFF").append(" ");
        }
        if (wifiOnStart != null || wifiOnEnd != null) {
            if (wifiOnStart != null && wifiOnStart.equals(wifiOnEnd)) {
                sb.append(" Wifi:").append(wifiOnStart).append("\n");
            } else{
                sb.append(" Wifi:").append(wifiOnStart).append("/").append(wifiOnEnd).append("\n");
            }
        }
        sb.append("Scan:");
        lm.scanner.addScanInfo(sb);

        if (scanStart > 0) {
            sb.append(" ms:" + (scanEnd - scanStart));
        }
        if (scanBg > 0) {
            sb.append(" bg:" + scanBg);
        }
        if (scanTimeout) {
            sb.append(" scan:TIMEOUT");
        }
        
        if (discoveryStart > 0) {
            sb.append("\nDiscovery: " + LNode.getSSIDs(lm.lastDiscovery) + " " + (discoveryEnd - discoveryStart));
        }
        if (lm.toFind.size() > 0) {
            sb.append("\nNotFound: " + lm.toFind);
        }
        
        sb.append("\nBattery: " + lm.bm.batteryPct +
                        (lm.bm.idleStart > 0 ? " Idle " + (end - lm.bm.idleStart)/1000 :"") +
                " Current: " + cStart + "/" + cEnd + " " +
                        cAStart + "/" + cAEnd);
        if (ccEnd != ccStart) {
            sb.append(" used:" + (ccEnd - ccStart) / 1000);
        }
        for (String k : peersByName.keySet()) {
            WifiP2pDevice p = peersByName.get(k); 
            sb.append("\nPeer: " + k + " " + p.deviceAddress + " " +
                    (p.isGroupOwner() ? "GO " : "Listen "));
        }
        
        Log.d(TAG, sb.toString());
        if (this.hasChanged(old)) {
            Events.get().add("SCAN", "PER", sb.toString());
        }
    }

    /**
     * Messages related to the discovery state machine.
     */
    @Override
    public boolean handleMessage(Message msg) {
        return false;
    }
}
