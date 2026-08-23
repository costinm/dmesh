package com.github.costinm.dmesh.lm3;

import android.bluetooth.BluetoothDevice;
import android.net.wifi.ScanResult;
import android.net.wifi.aware.DiscoverySession;
import android.net.wifi.aware.PeerHandle;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;

import com.github.costinm.dmesh.android.util.Hex;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Info about a discovered device, common across communication protocols.
 * <p>
 * Discovery may use Wi-Fi scan, BLE, and NAN.
 * <p>
 * A device may be:
 * - 'visible' - i.e. known to be nearby, but whithout knowing its capabilities
 * - 'discovered' - a connectivity method is avaialble, device is mesh capable.
 * NAN is the primary rendezvous mechanism; Wi-Fi scan only observes nearby
 * DMesh APs.
 * <p>
 */
public class Device {

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

    /** Cross-bearer device address or opaque discovery identifier. */
    public static final String RADIO_ADDR = "d";

    // ------------- Data about the device -------------------

    // Set if device is currently visible as a peer (wifi will also be set)
    public String id;

    public Bundle data = new Bundle();

    long lastScan;

    public String desc;

    // Depending on how the device was found.
    public DiscoverySession nanSession;

    BluetoothDevice dev;

    PeerHandle nan;

    public Device(String name, String data) {
        id = name;
        desc = data;
    }

    /**
     * Createa device from a scan result.
     */
    public Device(ScanResult sr) {
        setScanResult(sr);

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

        data.putString(RADIO_ADDR, "/nan/" + id);
    }

    // Unmarshal
    public Device(Bundle b) {
        data = b;
        id = data.getString(RADIO_ADDR);
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

        data.putString(RADIO_ADDR, idPrefix + id);
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

    public int getLevel() {
        return data.getInt(LEVEL, 0);
    }

    public int getFreq() {
        return data.getInt(FREQ, 0);
    }
}
