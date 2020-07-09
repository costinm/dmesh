package com.github.costinm.dmesh.android.msg;

import android.os.Bundle;
import android.os.Message;

/**
 * MsgConn represents one messaging connection/channel.
 * <p>
 * Transport may be Messenger, UDS or other stream-based connections.
 */
public class MsgConn {
    private static final String TAG = "MsgConn";

    MsgMux mux;

    String name;

    public MsgConn(MsgMux mux) {
        this.mux = mux;
    }

    public void start() {

    }

    public void close() {
    }

    /**
     * Send a message to the remote side.
     * <p>
     * For server connections (DMMsgService, or internal activeIn with callbacks), it is sent to the client.
     * <p>
     * For client connections (bind to a server), it is sent to the server.
     */
    boolean send(Message m) {
        return false;
    }

    public boolean send(String uri, String... parms) {
        Message m = Message.obtain();
        m.what = 1;
        m.getData().putString(":uri", uri);
        Bundle b = m.getData();
        for (int i = 0; i < parms.length; i += 2) {
            b.putString(parms[i], parms[i + 1]);
        }
        return send(m);
    }
}
