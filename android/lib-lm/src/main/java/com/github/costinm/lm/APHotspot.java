package com.github.costinm.lm;

import android.content.Context;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.util.Log;

/**
 * Control the 'hotspot' mode, using introspection.
 * <p>
 * This is no longer used - but I spent a lot of time getting it to work,
 * so feel bad about removing it.
 * <p>
 * The problem is that it will open a full hotspot - routing to the mobile
 * connection. In P2P mode, the mobile connection is not available - so
 * we can control what gets forwarded.
 * <p>
 * <p>
 * It does not appear to be possible to have client and AP active at the
 * same time - which is the other major problem, the idea of 'device scan'
 * is to connect to a Wifi network and expand it.
 * <p>
 * It may be used to allow legacy (pre JB, or with discovery broken)
 * devices to connect. It may also be used if an old device has a BT
 * or USB connection that needs to be shared.
 * <p>
 * Another disadvantage is that it overrides the 'share internet connection' setting,
 * replacing it with an open SSID - it should not be called if that is set.
 * <p>
 * One benefit would be that it's faster to connect - no discovery needed.
 * <p>
 * A password seems to be required for using static IP address - and without
 * static IP address we can't connect if the AP is in doze.
 */
public class APHotspot {
    /* Created hostapd.conf:

interface=wlan0
driver=nl80211
ctrl_interface=/data/misc/wifi/hostapd
ssid=....
channel=6
ieee80211n=1
hw_mode=g
ignore_broadcast_ssid=0
wowlan_triggers=any
wpa=2
rsn_pairwise=CCMP
wpa_psk=f851c31610...

     */


    static final String TAG = "LM-Wifi-AP";

    Context ctx;
    WifiManager mWifiManager;
    WifiConfiguration legacyAp;
    WifiConfiguration oldLegacyAp;

    public APHotspot(Context ctx) {
        init(ctx);
    }

    void init(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        mWifiManager = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
    }

    /**
     * Set the state of the AP. If ssid = null, will be stopped.
     */
    public void setState(String ssid, String pass) {
        try {
            if (ssid == null) {
                if ((Boolean) Reflect.callMethod(mWifiManager, "isWifiApEnabled", new Class[]{},
                        new Object[]{})) {
                    WifiMesh.get(ctx).event("AP", "Stopping legacy AP");
                    stopLegacyAp();
                }
            } else {
                createLegacyAp(ssid, pass);
            }
        } catch (Exception e) {
            WifiMesh.get(ctx).event("AP", "Failing to get wifi ap status " + e.toString());
        }
    }

    boolean createLegacyAp(String ssid, String pass) {
        /*
         * Will replace the 'wifi hotspot' configuration - probably not a good idea.
         * <p/>
         * Will also disconnect from wifi client.
         * <p/>
         * Requires 'WRITE_SETTINGS'
         */

        mWifiManager.setWifiEnabled(false);


        legacyAp = new WifiConfiguration();

        legacyAp.SSID = ssid;
        legacyAp.status = WifiConfiguration.Status.ENABLED;

        if (pass != null) {
            // OPEN=WPA, SHARED=WEP
            legacyAp.allowedKeyManagement.set(4); // WPA2_PSK,  hidden
            legacyAp.preSharedKey = pass;
        } else {
            legacyAp.allowedKeyManagement.clear(); // None (each bit is a kind)
        }

        // WifiApConfigStore:
        // SSID, public int apBand (0=2G, 1=5G), public int apChannel(1-11, 36...), authType (NONE), PSK
        // Nothing else seems to be used or settable.

        try {
            oldLegacyAp = (WifiConfiguration) Reflect.callMethod(mWifiManager, "getWifiApConfiguration",
                    new Class[]{}, new Object[]{});
            if (oldLegacyAp != null) {
                Log.d(TAG, "Found existing AP config " + oldLegacyAp);
            }


            Boolean b = (Boolean) Reflect.callMethod(mWifiManager, "setWifiApEnabled",
                    new Class[]{WifiConfiguration.class, Boolean.TYPE},
                    new Object[]{legacyAp, Boolean.TRUE});
            if (!b) {
                WifiMesh.get(ctx).event("AP", "Enable legacy AP failed");
            }
            return b;
        } catch (Throwable t) {
            WifiMesh.get(ctx).event("AP", "Failed to enable legacy AP " + t.toString());
            return false;
        }
    }

    /**
     * Disable the AP mode (portable wifi hotspot)
     */
    void stopLegacyAp() {
        try {
            if (legacyAp == null) {
                legacyAp = (WifiConfiguration) Reflect.callMethod(mWifiManager, "getWifiApConfiguration",
                        new Class[]{}, new Object[]{});
            }
            Boolean b = (Boolean) Reflect.callMethod(mWifiManager, "setWifiApEnabled",
                    new Class[]{WifiConfiguration.class, Boolean.TYPE},
                    new Object[]{legacyAp, Boolean.FALSE});
            if (!b) {
                WifiMesh.get(ctx).event("AP", "Disable legacy AP failed");
            }
        } catch (Throwable t) {
            WifiMesh.get(ctx).event("AP", "Failed to disable legacy AP " + t.toString());
        }

        if (oldLegacyAp != null) {
            try {
                Reflect.callMethod(mWifiManager, "setWifiApConfiguration",
                        new Class[]{WifiConfiguration.class},
                        new Object[]{oldLegacyAp});
            } catch (Throwable e) {
                WifiMesh.get(ctx).event("AP", "Failed to restore legacy AP " + e.toString());
            }
        }

        mWifiManager.setWifiEnabled(true);
    }

    // Other OS products:
    // See: https://github.com/mvdan/accesspoint
    // - will parse arp table to get 'peers'


}
