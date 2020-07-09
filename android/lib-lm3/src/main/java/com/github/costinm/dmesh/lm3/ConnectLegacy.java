package com.github.costinm.dmesh.lm3;

import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.util.Log;

import com.github.costinm.dmesh.android.util.Reflect;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ConnectLegacy {

    private static final String TAG = "Connect";


    public int connect(WifiManager mWifiManager, String ssid, String passphrase) {

        int id = findNetwork(mWifiManager, ssid);
        if ( id != -1 ) {
            boolean removed = mWifiManager.removeNetwork(id);
            if (!removed) {
                Log.d(TAG, "Failed to remove existing network");
            } else {
                id = -1;
            }
        }

        String ssid2 = '"' + ssid + '"';
        WifiConfiguration cfg = new WifiConfiguration();
        // First set up IpAssignment to STATIC.

        // For legacy AP, it seems 192.168.43.1 is used ? And 42 to 49 IP range.

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            //&& Build.VERSION.SDK_INT < Build.VERSION_CODES.O) { // 21
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
                Reflect.setField(staticIpConfig, "gateway", InetAddress.getByName("192.168.49.1"));
                Reflect.getField(staticIpConfig, "dnsServers", ArrayList.class).clear();
                Reflect.getField(staticIpConfig, "dnsServers", ArrayList.class).add(InetAddress.getByName("192.168.49.1"));

                Reflect.callMethod(cfg, "setStaticIpConfiguration", new String[]{"android.net.StaticIpConfiguration"}, new Object[]{staticIpConfig});
            } catch (Throwable t) {
                t.printStackTrace();
            }
        }
        //manager.updateNetwork(config);
        //manager.saveConfiguration();
        //setEphemeral(cfg);
        setNoInternet(cfg);
        if (passphrase == null) {
            cfg.SSID = ssid2;
            cfg.preSharedKey = '"' + Device.DEFAULT_PSK + '"';
            cfg.priority = 1;
        } else {
            // http://stackoverflow.com/questions/2140133/how-and-what-to-set-to-android-wificonfiguration-presharedkey-to-connect-to-the
            // TODO: connect - it should be an open SSID - all communication is
            cfg.SSID = ssid2;
            cfg.preSharedKey = '"' + passphrase + '"';
            cfg.priority = 5;
        }


        if (id >= 0) {
            cfg.networkId = id;
            int i2 = mWifiManager.updateNetwork(cfg);
            Log.d(TAG, "Updated network " + i2);
        } else {
            int i = mWifiManager.addNetwork(cfg);
            if (i < 0) {
                // Do clients care ? Nothing to do about it.
                Log.d(TAG, "Failed to addNetwork " + i);
                return -1;
            }
            id = i;
        }
        Log.d(TAG, "Added wifi network " + cfg);

        // Seems to be needed.
        mWifiManager.saveConfiguration();

        mWifiManager.enableNetwork(id, true);
        return id;
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
     *
     */
    private void setNoInternet(WifiConfiguration cfg) {
        try {
            Field ephemeral = cfg.getClass().getField("noInternetAccessExpected");
            ephemeral.set(cfg, true);
        } catch (NoSuchFieldException ignored) {
        } catch (IllegalAccessException ignored) {
        }
    }

    private int findNetwork(WifiManager mWifiManager, String ssid) {
        String ssid2 = '"' + ssid + '"';

        List<WifiConfiguration> existing = mWifiManager.getConfiguredNetworks();
        if (existing == null) {
            Log.d(TAG, "No existing networks or Q.");
            return -1;
        } else {
            for (WifiConfiguration exCfg : existing) {
                if (exCfg.SSID == null) {
                    continue;
                }

                if (exCfg.SSID.equals(ssid) || exCfg.SSID.equals(ssid2)) {
                    Log.d(TAG, "Found network " + exCfg);
                    return exCfg.networkId;
                }
            }
        }
        return -1;
    }

}
