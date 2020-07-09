package com.github.costinm.dmesh.libdm.vpn;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ProxyInfo;
import android.os.Build;
import android.os.Handler;
import android.os.Message;

import androidx.annotation.RequiresApi;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.github.costinm.dmesh.libdm.DMesh;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;

/**
 * Simple VPN service.
 *
 * Technically ICS/14 is the first version to support VPN, and could be made to work.
 * However LMP/21 is the first to allow 'disallowedApp' (i.e. iptables by uid), and
 * that greatly simplifies the VPN - so it is the first supported version.
 *
 * The settings activity must call 'prepare' to dial permission.
 *
 * TODO: make sure 'enable at startup' works and starts dmesh
 * TODO: support http proxy mode in Q, file bug for socks mode
 */
@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
public class VpnService extends android.net.VpnService implements Handler.Callback {
    static final String TAG = "DM-VPN";
    /**
     * Singleton - null if vpn is stopped, interface if vpn is running.
     */
    public static ParcelFileDescriptor iface = null;
    public static FileDescriptor fd;

    static PendingIntent appIntent;

    // Not used, for ICS - KK
    public static final int CMD_PROTECT = 1024;
    static byte[] address6;

    public static void maybeStartVpn(SharedPreferences prefs,
                                     Context ctx, DMesh dmUDS) {
        boolean vpnEnabled = prefs.getBoolean("vpn_enabled", false);

        if (vpnEnabled && iface == null) {
            if (dmUDS.addr[0] == 0) {
                // A new update will happen after native process starts
                return;
            }
            Intent ai = new Intent();
            ai.setComponent(new ComponentName(ctx.getPackageName(),
                    ctx.getPackageName() + ".SetupActivity"));
            appIntent = PendingIntent.getActivity(ctx, 15, ai, 0);
            address6 = dmUDS.addr;

            Intent i = new Intent(ctx, VpnService.class);
            try {
                ComponentName cn = ctx.startService(i);
                Log.d(TAG, "Start VPN " + cn);
            } catch(Throwable t) {
                // "not allowed to start, app in background" ?
                t.printStackTrace();
            }
        }
        if (!vpnEnabled && iface != null) {
            stopVpn();
            if (dmUDS != null) {
                dmUDS.stopVpn();
            }
        }
    }

    public static void stopVpn() {
        if (iface != null) {
            close();
        }
    }

    @Override
    public void onCreate() {
        Log.d(TAG, "VPN CREATED");
    }

    @Override
    public void onDestroy()
    {
        Log.d(TAG, "VPN DESTROY");
        close();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        Log.d(TAG, "VPN START " + intent);
        if (address6 == null || address6[0] == 0) {
            Log.d(TAG, "Invalid parameters");
            return START_NOT_STICKY;
        }

        Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent!= null) {
            Log.d(TAG, "VPN SETUP REQUIRED " + prepareIntent);
            return START_NOT_STICKY;
        }

        startVPN();
        return START_NOT_STICKY;
    }

    @Override
    public boolean handleMessage(Message message) {
        switch (message.what) {
            case CMD_PROTECT:
                allow(message.arg1);
                break;
        }
        return true;
    }

    /**
     * If the singleton interface is on, closeNative it.
     * This is not sufficient if the fd is sent to the app - will need to also closeNative the dup.
     */
    public static void close() {
        if (iface != null) {
            try {
                iface.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            iface = null;
            // TODO: send payload to DMesh
        }
    }

    // TODO: Can be used with ICS/JB/KK - passing fds.
    public void allow(int s) {
        protect(s);
    }


    public static final int MTU = 1400;

    /**
     * Start the VPN.
     * <p>
     * Must be called only after the mesh is registered, either with
     * the local DMesh or with the VPN server.
     */
    public void startVPN() {
        try {
            if (iface != null) {
                return;
            }
            Intent i = VpnService.prepare(this); //dm.ctx);
            if (i != null) {
                Log.e(TAG, "Needs permission " + i);
                return;
            }
            // Before starting, if on mobile we resolve the IP
            Builder builder = new Builder();

            builder.setMtu(MTU);

            byte[] ba = new byte[4];
            ba[0] = 10;
            ba[1] = 10;
            ba[2] = address6[14];
            ba[3] = address6[15];
            try {
                InetAddress ia = InetAddress.getByAddress(ba);
                builder.addAddress(ia, 24);
                InetAddress meshIp = Inet6Address.getByAddress("", address6);
                builder.addAddress(meshIp, 64);
                Log.d(TAG, "SETTING IP 4" + ia + " " + meshIp);
            } catch (UnknownHostException e) {
                // Can't happen
            }

            String dns = "1.1.1.1";
            builder.addDnsServer(dns);
            builder.addDnsServer("2606:4700:4700::1111");

            //builder.addSearchDomain(".dm." + dm.rClient.vpn);

            // TODO: If device has no conection to wifi or internet, 0/0.
            // TODO: exclude the wifi interface (if 10.x.y.0)
            //builder.addRoute("10.0.0.0", 8);

            // Some public or configurable VPN servers are better - this way all traffic
            // is encrypted, untrusted border (internet connected) gateways can't see it.
            builder.addRoute("0.0.0.0", 0);
            builder.addRoute("2000::", 3);
            builder.addRoute("fd00::", 8);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                builder.addDisallowedApplication(getPackageName());
                builder.allowFamily(AF_INET);
                builder.allowFamily(AF_INET6);
                builder.setBlocking(true);
            }
            if (Build.VERSION.SDK_INT >= 29) {
                // On Q, some apps will use http direct, bypassing TUN
                builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", 15003));
            }

            // TODO: for 22, setUnderlyingNeworks (used for the upstream)

            if (appIntent != null) {
                builder.setConfigureIntent(appIntent); // used in the VPN UI
            }

            // Create a new interface using the builder and save the parameters.
            iface = builder
                    .setSession("dmesh") // not required
                    .establish();
            if (iface == null) {
                Log.d(TAG, "Failed to start, permissions not granted or VPN disabled");
                return;
            }

            Log.d(TAG, "New interface: " + iface);

            fd = iface.getFileDescriptor();


            DMesh uds = DMesh.get(this);
            if (uds != null) {
                uds.sendVpn(fd);
            }
        } catch (Throwable t) {
            Log.i(TAG, "VPN connection failed " + t);
            t.printStackTrace();
        }
    }


}
