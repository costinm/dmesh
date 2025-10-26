package com.github.costinm.dmesh.lm3;

import android.bluetooth.BluetoothDevice;
import android.net.wifi.ScanResult;
import android.net.wifi.aware.DiscoverySession;
import android.net.wifi.aware.PeerHandle;
import android.net.wifi.p2p.WifiP2pDevice;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;

import com.github.costinm.dmesh.android.util.Hex;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Info about a discovered device.
 * <p>
 * Discovery may use Wifi scan, Wifi-Direct, BLE, legacy BT, NAN.
 * <p>
 * A device may be:
 * - 'visible' - i.e. known to be nearby, but whithout knowing its capabilities
 * - 'discovered' - a connectivity method is avaialble, device is mesh capable.
 * Currently Wifi SSID+PSK or WifiDirect Q method are used. In future BT, BLE, NAN might also
 * be used.
 * <p>
 * The device info is fed to the native app, and used in the debug UI.
 */
public class Device {

    public static final String DEFAULT_PSK = "12345678";

    // Set if device is currently visible as a peer (wifi will also be set)
    public String discAddr;
    public static final String SSID = "s";
    public static final String PSK = "p";
    public static final String ID4 = "i";
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
     * capabilities - from scan result
     */
    public static final String CAP = "c";

    /**
     * Set if device was found in a P2P peer. Other fields will not be set unless a TXT discovery
     * also happened.
     */
    public static final String P2PAddr = "d";
    public static final String P2PName = "N";

    public static final String P2PConnected = "gc";

    // Set if device is currently visible as a peer (wifi will also be set)
    public String id;
    public DiscoverySession nanSession;
    public Bundle data = new Bundle();
    long lastScan;
    // Set if found via P2P Peers or SD
    WifiP2pDevice wifi;
    BluetoothDevice dev;
    PeerHandle nan;

    /**
     * Create a device from P2P peer discovery.
     */
    public Device(WifiP2pDevice wifiP2pDevice) {
        this.wifi = wifiP2pDevice;

        id = wifiP2pDevice.deviceAddress;

        data.putString(P2PAddr, wifiP2pDevice.deviceAddress);
        data.putString(P2PName, wifiP2pDevice.deviceName);

        Map<String, String> txt = Wifi.txtDiscoveryByP2P.get(wifiP2pDevice.deviceAddress);
        if (txt != null) {
            for (String k : txt.keySet()) {
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

        lastScan = SystemClock.elapsedRealtime();
    }

    /**
     * Createa device from a scan result.
     */
    public Device(ScanResult sr) {
        setScanResult(sr);

        Map<String, String> txt = Wifi.txtDiscoveryBySSID.get(sr.SSID);
        if (txt != null) {
            for (String k : txt.keySet()) {
                data.putString(k, txt.get(k));
            }
        } else {
            if (sr.SSID.startsWith("DIRECT-DM-ESH") || sr.SSID.startsWith("DMESH-")) {
                data.putString(PSK, DEFAULT_PSK);
            }
        }

        lastScan = SystemClock.elapsedRealtime();
    }

    public Device(BluetoothDevice device, String name) {
        this.dev = device;
        updateNode(name, "/ble/");
    }

    /**
     * Wifi aware.
     */
    public Device(PeerHandle peerHandle, byte[] si) {
        nan = peerHandle;

        long now = SystemClock.elapsedRealtime();
        lastScan = now;

        if (si.length < 8) {
            id = "0";
        } else {
            id = new String(Hex.encode(si, 0, 8));
        }

        // Use bytes 12-16 as string to represent the ID.
        if (si.length >= 16) {
            id = new String(si, 12, 4);
        }

        data.putString(P2PAddr, "/nan/" + id);
    }

    // Unmarshal
    public Device(Bundle b) {
        data = b;
        id = data.getString(P2PAddr);
    }

    /**
     * ssidHash provides a hash of the mySSID, to fit in small packets (BLE in particular).
     * TODO: use it everywhere, no need to send the mySSID in clear. This is a part of the device
     * identities.
     */
    public static String ssidHash(String ssid) {
        int hashCode = ssid.hashCode();
        byte[] hashB = ByteBuffer.allocate(4).putInt(hashCode).array();
        // 32 bit / 6 = 6 byte string, but last byte only 4 values.
        byte[] hashStr = Base64.encode(hashB, Base64.NO_PADDING | Base64.NO_WRAP);

        return new String(hashStr).substring(0, 4);
    }

    /**
     * Called by BLE and NAN when a node is re-discovered.
     */
    public void updateNode(String ssidFlags, String idPrefix) {
        long now = SystemClock.elapsedRealtime();
        lastScan = now;
        if (ssidFlags.length() != 16) {
            return;
        }
        id = ssidFlags.substring(12, 16);

        data.putString(P2PAddr, idPrefix + id);
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
