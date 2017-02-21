package com.github.costinm.lm;

import android.net.wifi.ScanResult;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Bundle;
import android.os.SystemClock;

/**
 * The ssid, pass, ip6 may change over time.
 */
public class P2PWifiNode {

    public String ssid;

    // Usually changes when the ssid changes.
    public String pass;

    /**
     * Local-network IP6 address of the node.
     */
    public String ip6;

    // A device may use a different mac when
    // connecting from the AP BSSID. The p2p discovery node may also be
    // different. MAC can be reset - usually at boot time.
    public String mac;

    // What we found in device discovery - full txt or ptr
    // record. For DMesh devices there is only one record, which is
    // extracted into various components.
    public String dnsSDDomain;

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
    public Bundle p2pProp = new Bundle();

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


    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (device != null) {
            sb.append("mac:").append(device.deviceAddress).append(",");
            sb.append("name:").append(device.deviceName).append(",");
        }
        if (ssid != null) {
            sb.append("ssid:").append(ssid).append(",");
        }
        if (pass != null) {
            sb.append("pass:").append(pass).append(",");
        }
        if (dnsSDDomain != null) {
            sb.append("disc:").append(dnsSDDomain).append(",");
        }
        if (scan != null) {
            sb.append("smac:").append(scan.BSSID).append(",");
            sb.append("pwr:").append(scan.level).append(",");
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
    private static long e2s(long millis) {
        return millis + System.currentTimeMillis() - SystemClock.elapsedRealtime();
    }

    public boolean equals(Object o) {
        if (!(o instanceof P2PWifiNode)) {
            return false;
        }
        if (mac != null) {
            return mac.equals(((P2PWifiNode) o).mac);
        }
        return ssid != null && ssid.equals(((P2PWifiNode) o).ssid);

    }

    public String getName() {
        if (device != null) {
            // 'friendly name' set by user, doesn't change
            if (device.deviceName != null) {
                return device.deviceName;
            }
        }
        // last part of ssid is usually constant.
        // full mac and ssid will change on some devices.
        if (ssid != null) {
            return ssid;
        }
        return mac;
    }
}
