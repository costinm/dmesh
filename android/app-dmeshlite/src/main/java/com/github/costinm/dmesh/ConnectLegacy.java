package com.github.costinm.dmesh;

import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.util.Log;

import com.github.costinm.dmesh.android.util.Reflect;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Connect using original API. Reflection is used to set a random address and avoid
 * DHCP.
 *
 * This won't work in 29+, but works great in all other devices.
 *
 * This is a subset of the localMesh package, with GB support.
 */
public class ConnectLegacy {

    private static final String TAG = "Connect";

    /**
     * Adds and activate a SSID/pass to the manager, and activate it.
     *
     * If found, the old instance is removed (password may have changed)
     *
     * Randonm static IP will be used - many times DHCP is broken when sleeping.
     */
    public int add(WifiManager mWifiManager, String ssid, String passphrase) {
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
        } else {
            try {
                setIpAssignment("STATIC", cfg); //or "DHCP" for dynamic setting
                int i = new Random().nextInt(250);
                i += 2;
                setIpAddress(InetAddress.getByName("192.168.49." + i), 24, cfg);
                setGateway(InetAddress.getByName("192.168.49.1"), cfg);
                setDNS(InetAddress.getByName("19.168.49.1"), cfg);
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
            cfg.preSharedKey = '"' + "12345678" + '"';
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
                Log.d(TAG, "Failed to addMap2Bundle SSID ");
                return -1;
            }
            id = i;
        }
        Log.d(TAG, "Added wifi network " + cfg);

        // Seems to be needed.
        mWifiManager.saveConfiguration();

        return id;
    }

    public static void setIpAssignment(String assign , WifiConfiguration wifiConf)
            throws SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException{
        setEnumField(wifiConf, assign, "ipAssignment");
    }

    public static void setIpAddress(InetAddress addr, int prefixLength, WifiConfiguration wifiConf)
            throws SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException,
            NoSuchMethodException, ClassNotFoundException, InstantiationException, InvocationTargetException{
        Object linkProperties = getField(wifiConf, "linkProperties");
        if(linkProperties == null)return;
        Class laClass = Class.forName("android.net.LinkAddress");
        Constructor laConstructor = laClass.getConstructor(new Class[]{InetAddress.class, int.class});
        Object linkAddress = laConstructor.newInstance(addr, prefixLength);

        ArrayList mLinkAddresses = (ArrayList)getDeclaredField(linkProperties, "mLinkAddresses");
        mLinkAddresses.clear();
        mLinkAddresses.add(linkAddress);
    }

    public static void setGateway(InetAddress gateway, WifiConfiguration wifiConf)
            throws SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException,
            ClassNotFoundException, NoSuchMethodException, InstantiationException, InvocationTargetException {
        Object linkProperties = getField(wifiConf, "linkProperties");
        if(linkProperties == null)return;
        Class routeInfoClass = Class.forName("android.net.RouteInfo");
        Constructor routeInfoConstructor = routeInfoClass.getConstructor(new Class[]{InetAddress.class});
        Object routeInfo = routeInfoConstructor.newInstance(gateway);

        ArrayList mRoutes = (ArrayList)getDeclaredField(linkProperties, "mRoutes");
        mRoutes.clear();
        mRoutes.add(routeInfo);
    }

    public static void setDNS(InetAddress dns, WifiConfiguration wifiConf)
            throws SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException{
        Object linkProperties = getField(wifiConf, "linkProperties");
        if(linkProperties == null)return;

        ArrayList<InetAddress> mDnses = (ArrayList<InetAddress>)getDeclaredField(linkProperties, "mDnses");
        mDnses.clear(); //or addMap2Bundle a new dns address , here I just want to replace DNS1
        mDnses.add(dns);
    }

    public static Object getField(Object obj, String name)
            throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException{
        Field f = obj.getClass().getField(name);
        Object out = f.get(obj);
        return out;
    }

    public static Object getDeclaredField(Object obj, String name)
            throws SecurityException, NoSuchFieldException,
            IllegalArgumentException, IllegalAccessException {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        Object out = f.get(obj);
        return out;
    }

    private static void setEnumField(Object obj, String value, String name)
            throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException{
        Field f = obj.getClass().getField(name);
        f.set(obj, Enum.valueOf((Class<Enum>) f.getType(), value));
    }

    public int connect(WifiManager mWifiManager, String ssid, String passphrase) {
        int id = add(mWifiManager, ssid, passphrase);

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
