package com.github.costinm.dmesh.lm3;

import android.bluetooth.BluetoothDevice;
import android.net.wifi.ScanResult;
import android.net.wifi.aware.PeerHandle;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Bundle;

import java.util.ArrayList;
import java.util.Map;

public class Device {

    public static final String DEFAULT_PSK = "1234567890";

    // Set if device is currently visible as a peer (wifi will also be set)
    public String discAddr;

    // Set if found via P2P Peers or SD
    WifiP2pDevice wifi;

    BluetoothDevice dev;

    PeerHandle nan;

    public static final String SSID = "s";
    public static final String PSK= "p";

    // Main wifi network of the device ( if connected to a mesh - root network )
    public static final String NET = "n";

    // Direct wifi network of the device ( if connected to a mesh - root network )
    public static final String WIFISSID = "w";

    /**
     * Set if the object was visible in last scan results.
     */
    public static final String FREQ = "f";
    public static final String LEVEL = "l";

    /**
     * Set if the object was visible in last scan results.
     */
    public static final String BSSID = "b";

    /**
     *  capabilities - from scan result
     */
    public static final String CAP = "c";

    /**
     * Set if device was found in a P2P peer. Other fields will not be set unless a TXT discovery
     * also happened.
     */
    public static final String P2PAddr = "d";
    public static final String P2PName = "N";

    public static final String P2PConnected = "gc";

    public Bundle data = new Bundle();

    public Device(WifiP2pDevice wifiP2pDevice) {
        this.wifi = wifiP2pDevice;

        discAddr = wifiP2pDevice.deviceAddress;

        data.putString(P2PAddr, wifiP2pDevice.deviceAddress);
        data.putString(P2PName, wifiP2pDevice.deviceName);

        Map<String, String> txt= Wifi.txtDiscoveryByP2P.get(wifiP2pDevice.deviceAddress);
        if (txt != null) {
            for (String k: txt.keySet()) {
                data.putString(k, txt.get(k));
            }
        }

        StringBuilder sb = new StringBuilder();
                if (!wifi.isGroupOwner()) {
                    sb.append(" !GO");
                }
                if (!wifi.isServiceDiscoveryCapable()) {
                    sb.append(" !SD");
                }
                if (!wifi.wpsPbcSupported()) {
                    sb.append(" !PBC");
                }
                if (!wifi.wpsDisplaySupported()) {
                    sb.append(" !DIS");
                }
                if (!wifi.wpsKeypadSupported()) {
                    sb.append(" !KPA");
                }

        if (sb.length() > 0) {
            data.putString("p2pcap", sb.toString());
        }


    }

    public Device(ScanResult sr) {
        setScanResult(sr);

        Map<String, String> txt= Wifi.txtDiscoveryBySSID.get(sr.SSID);
        if (txt != null) {
            for (String k: txt.keySet()) {
                data.putString(k, txt.get(k));
            }
        } else {
            if (sr.SSID.startsWith("DIRECT-DM-ESH") || sr.SSID.startsWith("DMESH-")) {
                data.putString(PSK, DEFAULT_PSK);
            }
        }


    }

    // Unmarshal
    public Device(Bundle b) {
        data = b;
        discAddr = data.getString(P2PAddr);
    }

    public String getSD(String key) {
        return data.getString(key);
    }

    public void setScanResult(ScanResult sr) {
        data.putString(SSID, sr.SSID);
        data.putString(BSSID, sr.BSSID);
        data.putInt(FREQ, sr.frequency);
        data.putInt(LEVEL, sr.level);
        data.putString(CAP, sr.capabilities);
    }
    public boolean isConnected() {
        return data.getString("gc", "0").equals("1");
    }

    public int getLevel() {
        return data.getInt(LEVEL, 0);
    }
    public int getFreq() {
        return data.getInt(FREQ, 0);
    }
}
