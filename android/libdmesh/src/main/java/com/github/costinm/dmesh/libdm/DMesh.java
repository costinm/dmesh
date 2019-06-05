package com.github.costinm.dmesh.libdm;

import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.Credentials;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;
import android.util.Base64;
import android.util.Log;

import com.github.costinm.dmesh.android.util.MsgClient;
import com.github.costinm.dmesh.android.util.MsgMux;
import com.github.costinm.dmesh.android.util.NativeProcess;
import com.github.costinm.dmesh.android.util.UDS;
import com.github.costinm.dmesh.libdm.vpn.VpnService;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;


/**
 * DMesh communication with the native server. DMesh is needed to pass the vpn descriptor.
 * <p>
 * The protocol is ad-hoc, will need to be updated - currently it's line based, empty line
 * ends a message (similar with http1.1). First line is space separated, arbitrary number of
 * parameters. Command is first - most commands are 1..3 chars. There is no response, both
 * sides send one-way messages.
 * <p>
 * Similar protocol is used by dmroot native app for non-android.
 * </p>
 */
public class DMesh extends UDS {

    // 2001:20::/28 + 96 bit hash
    public static final byte[] RFC7343_host_id = new byte[]{
            (byte)0xFD, 0x00, 0x00, 0, 0, 0, 0, 0
    };

    private static final String TAG = "LMUDS";
    public static final String DMWIFI = "com.github.costinm.dmwifi";

    /**
     * Singleton - null if vpn is stopped, interface if vpn is running.
     */
    public static ParcelFileDescriptor iface = null;
    /**
     *  IPv6 address bytes
     */
    public final byte[] addr = new byte[16];

    final Context ctx;

    private final String name;
    private final SharedPreferences prefs;

    public String userAgent = "";

    // TODO: update from the status of the IP address or listener
    public boolean apRunning;

    NativeProcess dmGo;

    ArrayList<String> dmGoCmd = new ArrayList<>();

    static DMesh singleton;

    MsgClient wifi;

    static final boolean wifiOne = false;

    public static DMesh get() {
        return singleton;
    }

    // Will not work in all cases - Q with P2P (no internet) doesn't return anything.
    // The P2P connection is tracked at P2P level.
    public String getCurrentSSID() {
//        WifiInfo cinfo = mWifiManager.getConnectionInfo();
//        if (cinfo != null) {
//            return NetUtil.cleanSSID(cinfo.getSSID());
//        }
        return null;
    }

    // Singleton
    public DMesh(final Context ctx, String name) {
        super(ctx, "DMesh");

        singleton = this;
        this.name = name;

        this.ctx = ctx;
        prefs = PreferenceManager.getDefaultSharedPreferences(ctx);

        wifi = MsgMux.get(ctx).dial(DMWIFI, new Handler.Callback() {
            @Override
            public boolean handleMessage(Message message) {
                DMesh.this.handleMessage(message);
                return false;
            }
        });

        wifi.handers.put("wifi", new MsgMux.MessageHandler() {
            @Override
            public void handleMessage(Message m, Messenger replyTo, String[] args) {
                // Send it to UDS
                send(m.getData().getString(":uri"), m.getData());
            }
        });

        wifi.bind(ctx);

        // Forward to the wifi app if present
        Handler.Callback wifiFw = new Handler.Callback() {
            @Override
            public boolean handleMessage(Message message) {
                Log.d(TAG, "Send to wifi app " + message.getData());
                wifi.send(message);
                return false;
            }
        };
        udsHandlers.put("wifi", wifiFw);
        udsHandlers.put("nan", wifiFw);
        udsHandlers.put("bt", wifiFw);
        udsHandlers.put("ble", wifiFw);

        // just notifies when battery changes, tracks battery status, sends broadcasts.
        BatteryMonitor bm = new BatteryMonitor(ctx);


        udsHandlers.put("upgrade", new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                Bundle arg = msg.getData();
                final String cmd = arg.getString(":uri");

                String[] argv = cmd.split("/");
                upgrade(argv.length > 3 ? argv[2] : null);
                return false;
            }
        });

        // Get preferences (TODO: remove, just initial values and onchange)
        udsHandlers.put("P", new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                // Request native preferences.
                sendPrefs();
                return false;
            }
        });

        // Set preference
        udsHandlers.put("p", new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                Bundle arg = msg.getData();
                final String cmd = arg.getString(":uri");
                String[] cmdArg = cmd.split("/");
                if (cmdArg[2].equals("s")) {
                    prefs.edit().putString(cmdArg[3], cmdArg[4]).apply();
                } else if (cmdArg[2].equals("i")) {
                    prefs.edit().putInt(cmdArg[3], Integer.parseInt(cmdArg[4])).apply();
                }
                return false;
            }
        });

        // Identity - called when the private key is rotated.
        //
        udsHandlers.put("I", new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                Bundle arg = msg.getData();
                final String cmd = arg.getString(":uri");
                String[] cmdArg = cmd.split("/");
                byte[] msgB = Base64.decode(cmdArg[2], Base64.URL_SAFE);
                if (msgB.length == 16) {
                    System.arraycopy(msgB, 0, addr, 0, 16);
                } else {
                    System.arraycopy(RFC7343_host_id, 0, addr, 0, 8);
                    System.arraycopy(msgB, 0, addr, 8, 8);
                }

                String MESH_NAME = Base64.encodeToString(addr, 11, 5, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
                MsgMux.broadcast("DM", "Name", MESH_NAME);

                Log.d("DMesh", "Received ID " + MESH_NAME);

                sendUserAgent();

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    if (iface != null) {
                        sendVpn(iface.getFileDescriptor());
                    } else {
                        VpnService.maybeStartVpn(prefs, ctx, DMesh.this, null, DMSettingsActivity.class);
                    }
                }

                return false;
            }
        });


        start();
    }

    public void run() {
        Log.d(TAG, "Starting native process");

        dmGo = new NativeProcess(ctx, "libDM.so", dmGoCmd);
        dmGo.keepAlive = true;

        while (ls == null) {
            try {
                ls = new LocalServerSocket(name);
            } catch (IOException e) {
                e.printStackTrace();
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
            }
        }
        dmGo.start();

        while (running) {
            try {
                final LocalSocket s1 = ls.accept();

                Credentials c = s1.getPeerCredentials();

                System.err.println("DMesh connection uid=" +
                        c.getUid() + " " + c.getPid() + " " + c.getGid()
                        + " appuid=" + ctx.getApplicationInfo().uid);


                socket = s1;


                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        handleLocalSocket(s1);
                    }
                }).start();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    protected void onConnect() {
        sendUserAgent();
        sendPrefs();

        // TODO: Fake startup events - wifi, ap status if started

        String ssid1 = getCurrentSSID();
        if (ssid1 != null) {
            MsgMux.broadcast("CON", "STARTO", "", "ssid", ssid1);
        }
    }


    public synchronized void sendUserAgent() {
        // Model is too vague (Nexus 7), product is razor, etc.
        // PRODUCT: google-manta
        String adv =
                Build.VERSION.SDK_INT + "-" + Build.PRODUCT + "-" +
                        Build.MODEL + "-" + userAgent;
        send("/u/" + adv.replace(' ', '_'), null, null);
    }


    public synchronized void sendPrefs() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Map<String, ?> allp = prefs.getAll();
                send("/P", allp, null);
            }
        });
    }

    public void upgrade(String vpn) {
        final File f = ctx.getExternalFilesDir(null);
        final File f2 = new File(f, "libDM.so");

        if (vpn == null) {
            final File fd = ctx.getFilesDir();
            new File(fd, "libDM.so").delete();
            return;
        }

        ctx.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.d(TAG, "Downloaded " + intent  + " " + f2.exists() + " " + f2.getAbsolutePath());
                ctx.unregisterReceiver(this);
                DMesh.get().send("/KILL", null, null);
            }
        }, new IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE));

        String base = prefs.getString("vpnaddr", "h.webinf.info");

        String url = "https://" + base + "/www/jniLibs/armeabi/libDM.so";

        DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
        request.setDescription("DMesh download");
        request.setTitle("DMesh VPN");

        // in order for this if to run, you must use the android 3.2 to compile your app
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE);
        }
        Uri dest = Uri.withAppendedPath(Uri.fromFile(f), "libDM.so");
        request.setDestinationUri(dest);

        request.setVisibleInDownloadsUi(false);

        Log.d(TAG, "Start: " + f2.getAbsolutePath() + " " + dest);

        // dial download service and enqueue file
        DownloadManager manager = (DownloadManager) ctx.getSystemService(Context.DOWNLOAD_SERVICE);
        manager.enqueue(request);
    }

}
