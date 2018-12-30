package com.github.costinm.dmesh.libdm;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Credentials;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;
import android.util.Base64;
import android.util.Log;

import com.github.costinm.dmesh.android.util.NativeProcess;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;


/**
 * DMUDS communication with the native server. DMUDS is needed to pass the vpn descriptor.
 * <p>
 * The protocol is ad-hoc, will need to be updated - currently it's line based, empty line
 * ends a message (similar with http1.1). First line is space separated, arbitrary number of
 * parameters. Command is first - most commands are 1..3 chars. There is no response, both
 * sides send one-way messages.
 * <p>
 * Similar protocol is used by dmroot native app for non-android.
 * </p>
 */
public class DMUDS extends Thread {

    // Main (singleton) server. We support multiple UDP command/monitors, but a single
    // master.
    public static final int DMN_MSG = 2002;
    // 2001:20::/28 + 96 bit hash
    public static final byte[] RFC7343_host_id = new byte[]{
            0x20, 0x01, 0x20, 0, 0, 0, 0, 0
    };
    private static final String TAG = "LMUDS";
    /**
     * Singleton - null if vpn is stopped, interface if vpn is running.
     */
    public static ParcelFileDescriptor iface = null;
    /**
     *  IPv6 address bytes
     */
    public final byte[] addr = new byte[16];

    final Handler ctl;
    final Context ctx;
    private final String name;
    private final SharedPreferences prefs;
    public String userAgent = "";
    LocalServerSocket ls;
    boolean running = true;
    NativeProcess dmGo;
    ArrayList<String> dmGoCmd = new ArrayList<>();
    LocalSocket socket;
    BufferedOutputStream out;

    static DMUDS dmuds;


    /**
     * Sent from native process on startup, after private key and identity
     * are loaded.
     *
     * Param: B64 encoded local ID.
     */
    public static char CMD_INIT = 'I';

    /**
     * Request from native to update the notification.
     */
    public static char CMD_UPDATE_NOTIFICATION = 'U';

    public DMUDS(Context ctx, Handler ctl, String name) {
        super("DMUDS");

        this.name = name;
        this.ctl = ctl;

        this.ctx = ctx;
        prefs = PreferenceManager.getDefaultSharedPreferences(ctx);

        start();
    }

    public void onDestroy() throws IOException {
        running = false;
        if (ls != null) {
            ls.close();
            ls = null;
        }
    }

    public void run() {
        Log.d(TAG, "Starting native process");

        dmGo = new NativeProcess(ctx, "libDM.so", dmGoCmd);
        dmGo.keepAlive = true;
        dmGo.start();
        while (running) {
            try {
                if (ls == null) {
                    try {
                        ls = new LocalServerSocket(name);
                    } catch (IOException e) {
                        e.printStackTrace();
                        try {
                            Thread.sleep(20000);
                        } catch (InterruptedException e1) {
                            e1.printStackTrace();
                        }
                        continue;
                    }
                }
                final LocalSocket s1 = ls.accept();

                Credentials c = s1.getPeerCredentials();
                System.err.println("DMUDS connection uid=" +
                        c.getUid() + " " + c.getPid() + " " + c.getGid()
                        + " appuid=" + ctx.getApplicationInfo().uid);


                if (socket != null) {
                    suspendResidentProcess();
                }

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

    private void handleLocalSocket(LocalSocket s) {
        // TODO: if self, pass the VPN fd. Otherwise - treat it as a proxy
        try {
            if (s == null) {
                return;
            }
            this.socket = s;
            BufferedInputStream is = new BufferedInputStream(socket.getInputStream());
            BufferedOutputStream os = new BufferedOutputStream(socket.getOutputStream());
            out = os;

            sendUserAgent();
            sendPrefs();

            while (running) {
                byte[] data = new byte[4096];

                int b1 = is.read();
                int b2 = is.read();
                int len = b1 * 256 + b2;

                int left = len;
                int off = 0;
                while (left > 0) {
                    int rd = is.read(data, off, left);
                    if (rd == -1) {
                        return;
                    }
                    left -= rd;
                    off += rd;
                }
                if (len < 0) {
                    Log.d("DMUDS", "Invalid length");
                    break;
                }
                String l = new String(data, 0, len);
                if (l == null) {
                    break;
                }
                processNativeCommand(l);
            }
        } catch (IOException ex) {
            Log.d("DMUDS", "FD error " + ex);
            ex.printStackTrace();
        } finally {

            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            dmGo.resumeNative();
        }
    }

    public synchronized void sendUserAgent() {
        // Model is too vague (Nexus 7), product is razor, etc.
        // PRODUCT: google-manta

        String adv =
                Build.VERSION.SDK_INT + "-" + Build.PRODUCT + "-" +
                        Build.MODEL + "-" + userAgent;

        sendCmd("u " + adv.replace(' ', '_'));
    }

    /**
     * Mesh name is the key-based name of the device.
     *
     * The key can be rotated periodically - and should be rotated when
     * the DIRECT ssid is changed (TODO).
     *
     * Within the mesh, the name is resolved to the key-based IP.
     */
    public static String MESH_NAME = "";

    private void processNativeCommand(String l) throws IOException {
        if (l == null || l.length() == 0) {
            return;
        }
        char cmd = l.charAt(0);
        switch (cmd) {
            case 'I': // Sent by native process at startup. Address.
                byte[] msg = Base64.decode(l.substring(1), Base64.URL_SAFE);
                if (msg.length == 16) {
                    System.arraycopy(msg, 0, addr, 0, 16);
                } else {
                    System.arraycopy(RFC7343_host_id, 0, addr, 0, 8);
                    System.arraycopy(msg, 0, addr, 8, 8);
                }

                MESH_NAME = Base64.encodeToString(addr, 11, 5, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

                onNativeConnect(MESH_NAME, addr);
                Log.d("DMUDS", "Received ID from a new master");

                ctl.obtainMessage((int) 'U').sendToTarget();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    if (iface != null) {
                        sendVpn(iface.getFileDescriptor());
                    }
                }
                sendUserAgent();
                break;
            case 'P': // Request native preferences.
                // TODO: deprecated, should be sent on change automatically.
                sendPrefs();
                break;
            case 'p': { // set a preference.
                String[] cmdArg = l.split(" ");
                if (cmdArg[0].charAt(2) == 's') {
                    prefs.edit().putString(cmdArg[1], cmdArg[2]).apply();
                } else if (cmdArg[0].charAt(2) == 'i') {
                    prefs.edit().putInt(cmdArg[1], Integer.parseInt(cmdArg[2])).apply();
                }
                break;
            }
            default: // Native app can also send normal control messages
                String[] cmdArg = l.split(" ");
                ctl.obtainMessage((int) cmd, cmdArg).sendToTarget();
        }
        out.flush();
    }

    protected void onNativeConnect(String meshName, byte[] addr) {
    }

    private synchronized void sendPrefs() throws IOException {
        Map<String, ?> allp = prefs.getAll();
        StringBuilder sb = new StringBuilder();
        for (String k : allp.keySet()) {
            sb.append(k).append(":").append(allp.get(k).toString()).append('\n');
        }
        sendCmd((byte) 'P', sb.toString());
    }

    /**
     * Send a command to the main client. First byte is the command code.
     */
    public synchronized void sendCmd(String r) {
        BufferedOutputStream o = out;
        if (o == null) {
            return;
        }
        try {
            byte[] data = r.getBytes();
            o.write((byte) (data.length / 256));
            o.write((byte) (data.length % 256));
            o.write(data);
            o.flush();
        } catch (Throwable t) {
            Log.d(TAG, "Failed to send vpn" + t.toString());
        }
    }

    public synchronized void sendCmd(byte c, String arg) {
        BufferedOutputStream o = out;
        if (o == null) {
            return;
        }
        try {
            byte[] data = arg.getBytes();
            int l = data.length + 1;
            o.write((byte) (l / 256));
            o.write((byte) (l % 256));
            o.write(c);
            o.write(data);
            o.flush();
//            out.append(r).append(arg);
//            out.append("\n\n");
//            out.flush();
        } catch (Throwable t) {
            Log.d(TAG, "Failed to send vpn" + t.toString());
        }
    }

    public synchronized void sendCmd(byte c, Bundle b) {
        StringBuilder os = new StringBuilder();
        for (String k : b.keySet()) {
            Object o = b.get(k);
            if (o instanceof CharSequence) {
                os.append(k).append(":").append((CharSequence) o).append("\n");
            } else if (o != null) {
                os.append(k).append(":").append(o.toString()).append("\n");
            }
        }
        os.append("\n");
        sendCmd(c, os.toString());
    }

    /**
     * Suspend the resident dmesh program. Used for debugging.
     */
    private void suspendResidentProcess() {
        if (socket != null) {
            dmGo.suspendNative();
            try {
                Log.d(TAG, "Stopping previous process");
                sendCmd("K");
                socket.close();
            } catch (IOException ex) {
                Log.d(TAG, "Attempting to stop failed" + ex);
            } finally {
                socket = null;
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            //dmGo.kill();
            socket = null;
        }

        Log.d(TAG, "Process killed");
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public synchronized void sendVpn(ParcelFileDescriptor fd) {
        sendVpn(fd.getFileDescriptor());
    }

    /**
     * Will be called on vpn startup, once we have a VPN. Sends it to the native process.
     */
    public synchronized void sendVpn(FileDescriptor fd) {
        LocalSocket s = socket;
        if (s == null) {
            return;
        }
        // Doing a dup results in a second open socket, prevents terminating
        //        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
        //            ParcelFileDescriptor pfdv = ParcelFileDescriptor.dup(fd);
        //            fd = pfdv.getFileDescriptor();
        //        }
        try {
            s.setFileDescriptorsForSend(new FileDescriptor[]{fd});

            byte[] msg = new byte[]{0, 1, (byte) 'v'};
            s.getOutputStream().write(msg);
            //s.getOutputStream().write("v\n\n".getBytes());

            s.getOutputStream().flush();
            s.setFileDescriptorsForSend(new FileDescriptor[]{});
            Log.d(TAG, "Sent file descriptor to native process");
        } catch (Throwable t) {
            Log.d(TAG, "Failed to send vpn" + t.toString());
        }
    }


}
