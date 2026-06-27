package com.github.costinm.dmesh.android.msg;

import android.content.Context;
import android.net.Credentials;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Bundle;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * ConnUDS exchanges messages with a native process or other stream-based endpoint.
 */
public class ConnUDS extends MsgConn {
    private static final String TAG = "LMUDS";

    protected boolean running = true;

    // TODO: support multiple sockets
    protected LocalSocket socket;

    Context ctx;
    String conId;
    private OutputStream out;

    public ConnUDS(Context ctx, MsgMux mux, String dmuds) {
        super(mux);
        this.ctx = ctx;
        conId = dmuds;
    }

    public static String proxyConnection(final InputStream in, final OutputStream out) throws IOException {
        try {
            LocalSocket ls = new LocalSocket();
            ls.connect(new LocalSocketAddress("lproxy"));

            final InputStream sin = ls.getInputStream();
            final OutputStream sos = ls.getOutputStream();

            final byte[] bufout = new byte[2048];

            // Remote side
            new Thread(new Runnable() {
                @Override
                public void run() {
                    while (true) {
                        try {
                            int n = sin.read(bufout, 5, 2048 - 5);
                            out.write(bufout, 0, n + 5);
                        } catch (IOException e) {
                            return;
                        }
                    }

                }
            }).start();

            new Thread(new Runnable() {
                @Override
                public void run() {
                    while (true) {
                        try {
                            final byte[] bufin = new byte[2048];
                            int n = in.read(bufin);
                            sos.write(bufin, 5, n - 5);
                        } catch (IOException ex) {
                            break;
                        }
                    }
                }
            }).start();

            return ls.getLocalSocketAddress().getName();
        } catch (IOException ex) {
            return "";
        }
    }

    public Credentials getPeerCredentials() {
        try {
            return socket.getPeerCredentials();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

//    private synchronized void sendPacked(String c, Map<String, ?> meta,
//                                         ArrayList<FileDescriptor> fds) {
//
//        OutputStream o = out;
//        if (o == null) {
//            return;
//        }
//        try {
//            byte[] out = pack(c, meta);
//            if (out.length > 4 * 2048) {
//                Log.d(TAG, "Message too long " + out.length);
//                return;
//            }
//
//            if (fds != null) {
//                socket.setFileDescriptorsForSend(fds.toArray(new FileDescriptor[fds.size()]));
//            }
//            o.write(out);
//            o.flush();
//            if (fds != null) {
//                socket.setFileDescriptorsForSend(new FileDescriptor[]{});
//            }
//        } catch (Throwable t) {
//            Log.d(TAG, "Failed to send send " + t);
//            out = null;
//            try {
//                socket.close();
//            } catch (IOException e) {
//                //e.printStackTrace();
//            }
//        }
//    }

    public boolean send(Message m) {
        Bundle b = m.getData();
        String uri = b.getString(":uri");
        ArrayList<FileDescriptor> fds = null;

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
                s = o.toString();
            } else if (o instanceof Bundle) {
                s = MsgMux.toJSON((Bundle) o).toString();
            } else if (o instanceof ArrayList) {
                s = MsgMux.toJSON((ArrayList) o).toString();
            } else if (o instanceof ParcelFileDescriptor) {
                FileDescriptor fd = ((ParcelFileDescriptor) o).getFileDescriptor();
                if (fds == null) {
                    fds = new ArrayList<>();
                }
                fds.add(fd);
            } else if (o != null) {
                s = o.toString();
            }
            if (s != null) {
                meta.put(k, s);
            } else {
                Log.d(TAG, "Unexpected type " + o + " " + o.getClass());
            }
        }

        // TODO: addMap2Bundle a byte[], with the key ":data"
        //sendPacked(uri, meta, fds);
        return false;
    }

//    /**
//     * Will be called on vpn startup, once we have a VPN. Sends it to the native process.
//     */
//    public synchronized void sendFileDescriptor(String uri, FileDescriptor fd) {
//        LocalSocket s = socket;
//        if (s == null || !fd.valid()) {
//            return;
//        }
//        // Doing a dup results in a second open socket, prevents terminating
//        //        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
//        //            ParcelFileDescriptor pfdv = ParcelFileDescriptor.dup(fd);
//        //            fd = pfdv.getFileDescriptor();
//        //        }
//        try {
//            s.setFileDescriptorsForSend(new FileDescriptor[]{fd});
//
//            byte[] msg = pack(uri, null);
//            s.getOutputStream().write(msg);
//            s.getOutputStream().flush();
//
//            s.setFileDescriptorsForSend(new FileDescriptor[]{});
//            Log.d(TAG, "Sent file descriptor to native process");
//
//        } catch (Throwable t) {
//            Log.d(TAG, "Failed to send vpn" + t);
//        }
//    }
}
