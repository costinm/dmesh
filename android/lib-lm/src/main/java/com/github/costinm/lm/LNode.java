package com.github.costinm.lm;

import android.net.wifi.ScanResult;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.SystemClock;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Info about a lm node. This includes P2P "DIRECT-" nodes and DM- open
 * networks.
 *
 * The ssid, pass, ip6 may change over time.
 */
public class LNode {
    // Network name - can be the root's wifi net
    public String net;

    // Private mesh, set in user preferences.
    public String mesh;

    // This is the real SSID extracted from the TXT, should match the scan beacon
    // The name of the device is the suffix, after DIRECT- and the 2 random chars.
    public String ssid;

    // If it was ever discovered, the 'device name' according to discovery.
    // Set in ... Wifi/Advanced/P2P
    public String name;

    // Generated node name.
    public String meshName;

    // Usually changes when the ssid changes.
    public String pass;

    // A device may use a different mac when
    // connecting from the AP BSSID. The p2p discovery node may also be
    // different. MAC can be reset - usually at boot time.
    // This is the MAC from discovery - if the device was discovered. It matches the
    // MAC in the link local address - so could be used to communicate without multicast.
    public String mac;

    // What we found in device discovery - full txt or ptr
    // record. For DMesh devices there is only one record, which is
    // extracted into various components.
    public String extraDiscoveryInfo;

    // Time first discovered, scanned or connected to.
    public long lastChange;

    // Last time the device was scanned or discovered
    public long lastScan;

    // Set on last discovery - contains user-specified name which is not
    // auto-reset.
    // Set on client connect - only useful info is the MAC.
    public WifiP2pDevice device;

    // Result of last periodic. MAC is typically different from p2p discovery.
    // signal strength, ssid, mac.
    // TODO: how can we use 'distance' and other fields ?
    public ScanResult scan;

    // Last time we sent a P2P discover (may have failed)
    public long p2pLastDiscoveryAttemptE;
    // How many times we found the node via discovery
    public int p2pDiscoveryCnt;
    public int p2pDiscoveryAttemptCnt;
    // Last time device responded to discovery.
    public long p2pLastDiscoveredE;

    // Key-value pairs returned in the p2p discovery SD announce.
    public Map<String,String> p2pProp = new HashMap<>();

    // Last time a 'connect' was attempted on this node
    public long lastConnectAttempt;
    public long lastConnect;
    public int connectCount;
    public int connectAttemptCount;
    // Last time the node connected to us.
    public long lastClientCon;
    public int clientConCount;
    public long connectedTime;
    public int cmNetworkId;

    public boolean foreign = false;

    // Advertised build
    public String build;

    private static long e2s(long millis) {
        return millis + System.currentTimeMillis() - SystemClock.elapsedRealtime();
    }

    /**
     * Used for debugging, return the SSIDs from a list of nodes
     */
    static ArrayList<String> getSSIDs(ArrayList<LNode> n) {
        ArrayList<String> out = new ArrayList<>();
        for (LNode nn : n) {
            out.add(nn.ssid);
        }
        return out;
    }

    /**
     * Serialize the device
     *
     * Comma separated list of key : value
     *
     * @return
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (ssid != null) {
            sb.append("ssid:").append(ssid).append(",");
        }
        if (pass != null) {
            sb.append("pass:").append(pass).append(",");
        }
        if (device != null) {
            sb.append("name:").append(device.deviceName).append(",");
            sb.append("mac:").append(device.deviceAddress).append(",");
        }
        if (scan != null) {
            sb.append("smac:").append(scan.BSSID).append(",");
            sb.append("pwr:").append(scan.level).append(",");
            sb.append("f:").append(scan.frequency).append(",");
        }
        if (build != null) {
            sb.append("build:").append(build).append(",");
        }
        if (extraDiscoveryInfo != null) {
            sb.append("disc:").append(extraDiscoveryInfo).append(",");
        }
        if (connectCount > 0) {
            sb.append("con:").append(connectCount).append(",");
            sb.append("conT:").append(e2s(lastClientCon));
            sb.append("contime:").append(connectedTime);
        }
        if (connectAttemptCount > 0) {
            sb.append("conA:").append(connectAttemptCount).append(",");
        }
        long now = SystemClock.elapsedRealtime();
        if (p2pLastDiscoveryAttemptE > 0) {
            sb.append("disc:").append(now - p2pLastDiscoveryAttemptE);
            if (p2pLastDiscoveredE > 0) {
                sb.append('/').append(now - p2pLastDiscoveredE).append('/').append(p2pLastDiscoveredE - p2pLastDiscoveryAttemptE);
            }
            sb.append(',');
        }
        return sb.toString();

    }

    // MAC or SSID
    public boolean equals(Object o) {
        if (!(o instanceof LNode)) {
            return false;
        }
        if (mac != null) {
            return mac.equals(((LNode) o).mac);
        }
        return ssid != null && ssid.equals(((LNode) o).ssid);

    }
}
