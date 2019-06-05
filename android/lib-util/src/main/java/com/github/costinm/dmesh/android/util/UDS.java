package com.github.costinm.dmesh.android.util;

import android.content.Context;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * UDS implements a MsgService, using a native process to handle the requests.
 */
public class UDS extends Thread implements Handler.Callback {
    private static final String TAG = "LMUDS";
    protected LocalServerSocket ls;

    protected boolean running = true;

    // TODO: support multiple sockets
    protected LocalSocket socket;
    private OutputStream out;
    Context ctx;

    public UDS(Context ctx, String dmuds) {
        super(dmuds);
        this.ctx = ctx;
    }

    // from uds clients
    public Map<String, Handler.Callback> udsHandlers = new HashMap<>();


    protected void onConnect() {

    }

    protected void onDisconnect() {

    }

    protected void handleLocalSocket(LocalSocket s) {
        // TODO: if self, pass the VPN fd. Otherwise - treat it as a proxy
        try {
            if (s == null) {
                return;
            }
            this.socket = s;
            BufferedInputStream is = new BufferedInputStream(socket.getInputStream());
            out = socket.getOutputStream();

            onConnect();

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
                    Log.d(TAG, "Invalid length");
                    break;
                }


                String body = new String(data, 0, len);
                String[] lines = body.split("\n");
                String l = lines[0];

                // UnReserved chars in URI: - . _ ~
                // In paths: + &  =
                // Unsafe: < > [ ]  { } ( ) ` ! * @ , ; | ^

                if (l.startsWith("/")) {

                    String[] cmdArg = l.split("/");

                    Handler.Callback commandHandler = udsHandlers.get(cmdArg[1]);
                    Log.d(TAG, "UDS: " + l + " " + commandHandler);
                    if (commandHandler != null) {
                        try {
                            Message msg = Message.obtain();
                            msg.getData().putString(":uri", l);

                            for (int i = 1; i < lines.length; i++) {
                                String s1 = lines[i];
                                if (s1.contains(":")) {
                                    String[] s1P = s1.split(":", 2);
                                    if (s1P.length == 2) {
                                        msg.getData().putString(s1P[0], s1P[1]);
                                    }
                                }
                            }

                            commandHandler.handleMessage(msg);

                        } catch (Throwable t) {
                            Log.d(TAG, "Error " + cmdArg + " " + t);
                        }
                        continue;
                    }
                    if (cmdArg[1].contains(".")) {
                        Log.d(TAG, "Attempt to dial: " + l);

                        MsgClient msgClient = MsgMux.get(ctx).dial(cmdArg[1], new Handler.Callback() {
                            @Override
                            public boolean handleMessage(Message message) {
                                // Messages from the remote app.
                                return false;
                            }
                        });
                        msgClient.bind(ctx);
                    }

                } else {
                    Log.d(TAG, "Old: " + l);
                }
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
            onDisconnect();
        }
    }

    public synchronized byte[] pack(String c, Map<String,?> meta, byte[] data) {
        byte[] cmdS = c.getBytes();
        int l = cmdS.length + 1;

        byte[] metaS = null;
        if (meta != null) {
            StringBuilder sb = new StringBuilder();
            for (String k : meta.keySet()) {
                sb.append(k).append(":").append(meta.get(k).toString()).append('\n');
            }
            metaS = sb.toString().getBytes();
            l += metaS.length;
        }
        l++;

        if (data != null) {
            l += data.length;
        }

        // TODO: optimize, very inefficient
        byte[] out = new byte[l + 2];
        out[0] = ((byte) (l / 256));
        out[1] = ((byte) (l % 256));

        int off = 2;
        System.arraycopy(cmdS, 0, out, off, cmdS.length);
        off += cmdS.length;
        out[off] = '\n';
        off++;

        if (metaS != null) {
            System.arraycopy(metaS, 0, out, off, metaS.length);
            off += metaS.length;
        }
        out[off] = '\n';
        off++;


        if (data != null) {
            System.arraycopy(data, 0, out, off, data.length);
        }
        return out;
    }


    public synchronized void send(String c, Map<String,?> meta, byte[] data) {
                OutputStream o = out;
                if (o == null) {
                    return;
                }
                try {
                    byte[] out = pack(c, meta, data);
                    if (out.length >  4* 2048) {
                        Log.d(TAG, "Message too long " + out.length);
                        return;
                    }

                    o.write(out);
                    o.flush();
                } catch (Throwable t) {
                    t.printStackTrace();
                    Log.d(TAG, "Failed to send send " + t.toString());
                }
    }

    public synchronized void send(String cmd, Bundle b) {
        Map<String, String> meta = new HashMap<>();
        for (String k : b.keySet()) {
            if (":uri".equals(k)) {
                continue;
            }
            Object o = b.get(k);
            if (o == null) {
                continue;
            }
            String s = null;
            if (o instanceof CharSequence) {
                s = ((CharSequence) o).toString();
            } else if (o instanceof Bundle) {
                s = NetUtil.toJSON((Bundle)o).toString();
            } else if (o instanceof ArrayList) {
                s = NetUtil.toJSON((ArrayList)o).toString();
            } else if (o != null) {
                s = o.toString();
            }
            if (s != null) {
                meta.put(k, s);
            } else {
                Log.d(TAG, "Unexpected type " +  o+ " " +  o.getClass());
            }
        }
        send(cmd, meta, null);
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

            byte[] msg = new byte[]{0, 2, (byte) '/', (byte) 'v'};
            s.getOutputStream().write(msg);
            //s.getOutputStream().write("v\n\n".getBytes());

            s.getOutputStream().flush();
            s.setFileDescriptorsForSend(new FileDescriptor[]{});
            Log.d(TAG, "Sent file descriptor to native process");
        } catch (Throwable t) {
            Log.d(TAG, "Failed to send vpn" + t.toString());
        }
    }


    /**
     * DMUDS handle messages by sending them to the native process.
     */
    @Override
    public boolean handleMessage(final Message msg) {
        final Message msg1 = new Message();
        msg1.setData(msg.getData());

        new Thread(new Runnable() {
            @Override
            public void run() {
                Bundle b = msg1.getData();
                String cmd = b.getString(MsgMux.URI);
                b.remove(MsgMux.URI);

                send(cmd, b);
            }
        }).start();
        return false;
    }
}
