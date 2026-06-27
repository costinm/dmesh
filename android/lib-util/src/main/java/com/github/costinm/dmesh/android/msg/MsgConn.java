package com.github.costinm.dmesh.android.msg;

import android.os.Bundle;
import android.os.Message;

/**
 * MsgConn represents one messaging connection/channel - similar to a H2/SSH connection.
 * The messages are framed.
 *
 * It may use binder, UDS, SSH, H2, virtio or any other transport.
 */
public class MsgConn {
    private static final String TAG = "MsgConn";

    MsgMux mux;

    public String name;

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
    public boolean send(Message m) {
        return false;
    }

    public boolean sendFrame(MsgFrame frame) {
        return send(frame.toMessage());
    }

    public boolean send(String uri, String... parms) {
        MsgFrame frame = new MsgFrame(uri);
        for (int i = 0; i < parms.length; i += 2) {
            frame.fields.put(parms[i], parms[i + 1]);
        }
        return sendFrame(frame);
    }
}
