package com.github.costinm.dmesh.libdm;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Credentials;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.preference.PreferenceManager;
import android.util.Base64;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.util.BatteryMonitor;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.ConnUDS;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.NativeProcess;
import com.github.costinm.dmesh.android.msg.MsgServerUDS;
import com.github.costinm.dmesh.libdm.vpn.VpnService;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
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
public class DMesh {

    // 2001:20::/28 + 96 bit hash
    public static final byte[] RFC7343_host_id = new byte[]{
            (byte) 0xFD, 0x00, 0x00, 0, 0, 0, 0, 0
    };

    private static final String TAG = "LMUDS";

    // Package to use for Android Wifi and networking interaction.
    //public static String DMWIFI = "com.github.costinm.dmesh.lm";

    /**
     * IPv6 address bytes
     */
    public final byte[] addr = new byte[16];

    private final MsgMux mux;

    Context ctx;

    private final String name;
    final SharedPreferences prefs;

    public String userAgent = "";

    public NativeProcess dmGo;

    ArrayList<String> dmGoCmd = new ArrayList<>();

    static DMesh singleton;

    BatteryMonitor bm;

    MsgServerUDS udss;

    /**
     * Provide access to DMesh object. Valid only when the service is running.
     */
    public synchronized static DMesh get(Context ctx) {
        if (singleton == null) {
            singleton = new DMesh(ctx.getApplicationContext());
        }
        if (singleton.ctx != ctx.getApplicationContext()) {
            singleton.ctx = ctx.getApplicationContext();
        }
        return singleton;
    }

    private DMesh(final Context ictx) {
        String name = "dmesh";
        singleton = this;

        this.name = name;

        this.ctx = ictx.getApplicationContext();

        mux = MsgMux.get(ctx);

        udss = new MsgServerUDS(ctx, mux, name) {
            protected void onServerStart() {
                openNative();
            }

            protected void onConnect(ConnUDS con) {
                Credentials c = con.getPeerCredentials();
                if (c == null) {
                    return;
                }
                // SECURITY: only native process running as same UID can interact with the controller.
                if (c.getUid() != ctx.getApplicationInfo().uid) {
                    Log.e(TAG, "UDS Unexpected UID !!!" + ctx.getApplicationInfo().uid +
                            " got " + c.getUid());
                    con.close();
                    return;
                }
                System.err.println("DMesh UDS connection uid=" +
                        c.getUid() + " " + c.getPid() + " " + c.getGid()
                        + " appuid=" + ctx.getApplicationInfo().uid);


                // Model is too vague (Nexus 7), product is razor, etc.
                // PRODUCT: google-manta

                sendPrefs();
            }

        };

        prefs = PreferenceManager.getDefaultSharedPreferences(ctx);

//        new Thread(new Runnable() {
//            @Override
//            public void run() {
//                try {
//                    EnvoyEngine.load(ctx);
//                    EnvoyEngine.run(loadEnvoyConfig(ctx, R.raw.config));
//                } catch (Throwable t) {
//                    t.printStackTrace();
//                }
//            }
//        }).start();


        // just notifies when battery changes, tracks battery status, sends broadcasts.
        bm = new BatteryMonitor(ctx, mux);

        // Identity - called when the private key is rotated, or on startup.
        // This should be the first message from the native app, may be repeated during connection.
        mux.subscribe("I", new MessageHandler() {
            @Override
            public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo, String[] cmdArg) {
                Bundle arg = msg.getData();

                String pub = cmdArg[2];
                byte[] msgB = Base64.decode(pub, Base64.URL_SAFE);
                if (msgB.length == 16) {
                    System.arraycopy(msgB, 0, addr, 0, 16);
                } else {
                    System.arraycopy(RFC7343_host_id, 0, addr, 0, 8);
                    System.arraycopy(msgB, 0, addr, 8, 8);
                }

                bm.sendStatus("connect");

                sendPrefs();

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    if (VpnService.iface != null) {
                        sendVpn(VpnService.iface.getFileDescriptor());
                    } else {
                        VpnService.maybeStartVpn(prefs, ctx, DMesh.this);
                    }
                }
            }
        });


        udss.start();
    }

    private String loadEnvoyConfig(Context context, int configResourceId) throws RuntimeException {
        InputStream inputStream = context.getResources().openRawResource(configResourceId);
        InputStreamReader inputReader = new InputStreamReader(inputStream);
        BufferedReader bufReader = new BufferedReader(inputReader);
        StringBuilder text = new StringBuilder();

        try {
            String line;
            while ((line = bufReader.readLine()) != null) {
                text.append(line);
                text.append('\n');
            }
        } catch (IOException e) {
            return null;
        }
        return text.toString();
    }

    public void sendVpn(FileDescriptor fd) {
        for (ConnUDS uds: udss.active) {
            uds.sendFileDescriptor("/v/fd", fd);
        }
    }

    public void stopVpn() {
        for (ConnUDS uds: udss.active) {
            uds.send("/KILL");
        }
        dmGo.kill();
    }

    // At startup as well as when the preferences change.
    // Not clear it's still needed - prefs have been simplified and native has its own config.
    public synchronized void sendPrefs() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Map<String, ?> allp = prefs.getAll();

                List<String> propList = MsgMux.mapToStringList(allp);
                String adv = Build.VERSION.SDK_INT + "-" + Build.PRODUCT + "-" + Build.MODEL + "-" + userAgent;
                propList.add("ua");
                propList.add(adv.replace(' ', '_'));


                mux.publish("/P/settings", propList.toArray(new String[]{}));
            }
        }).start();
    }

    public void openNative() {
        if (dmGo == null) {
            dmGo = new NativeProcess(ctx, "libDM.so", dmGoCmd);
            dmGo.keepAlive = true;
            dmGo.start();
        }
    }

    public void closeNative() {
        if (dmGo == null) {
            return;
        }
        dmGo.keepAlive = false;

        stopVpn();
        bm.close();
        dmGo = null;
    }
}
