package com.github.costinm.dmesh.lm;

import android.content.Context;
import android.os.Message;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.DirectBinderConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmeshnative.MeshNode;
import com.github.costinm.dmeshnative.MeshStream;

import java.util.HashMap;
import java.util.Map;

/**
 * Minimal Java adapter for the Rust-owned SSH message bridge.
 *
 * Rust owns the SSH stream, line framing, JSON/human command parsing, and
 * response framing. Java adapts parsed string pairs into MsgFrame and only
 * converts to Android Message where existing MsgMux handlers still require it.
 */
class SshJsonlMsgBridge implements MeshNode.MeshCallback {
    private static final String TAG = "DM-SSH-MSG";

    private final Context context;
    private final MsgMux mux;
    private final Map<Long, BridgeMsgConn> conns = new HashMap<>();

    SshJsonlMsgBridge(Context context, MsgMux mux) {
        this.context = context.getApplicationContext();
        this.mux = mux;
    }

    @Override
    public void onSshConnection(long clientId, String user) {
        Log.d(TAG, "SSH client connected: " + clientId + " user=" + user);
    }

    @Override
    public void onMessage(long clientId, String id, String uri, String[] keys, String[] values) {
        BridgeMsgConn conn = connFor(clientId);
        MsgFrame frame = MsgFrame.fromPairs(id, uri, keys, values);
        if (forwardAppCommand(conn, frame)) {
            return;
        }
        mux.receiveFrame(conn.name, conn, frame);
    }

    private boolean forwardAppCommand(BridgeMsgConn replyTo, MsgFrame frame) {
        if (frame.uri == null || !frame.uri.startsWith("/app/")) {
            return false;
        }
        String[] parts = frame.uri.split("/", 5);
        if (parts.length < 5) {
            MsgFrame err = new MsgFrame("/app/error");
            err.id = frame.id;
            err.fields.put("error", "expected /app/<package>/<service>/<command>");
            replyTo.sendFrame(err);
            return true;
        }
        String pkg = parts[2];
        String service = parts[3];
        if (service.startsWith(".")) {
            service = pkg + service;
        }
        MsgFrame appFrame = new MsgFrame("/" + parts[4]);
        appFrame.id = frame.id;
        appFrame.fields.putAll(frame.fields);
        DirectBinderConn appConn = new DirectBinderConn(mux, context, pkg, service);
        appConn.sendFrame(appFrame);
        MsgFrame ack = new MsgFrame("/app/forwarded");
        ack.id = frame.id;
        ack.fields.put("package", pkg);
        ack.fields.put("service", service);
        ack.fields.put("uri", appFrame.uri);
        replyTo.sendFrame(ack);
        return true;
    }

    @Override
    public void onStream(long clientId, String host, int port, long streamHandle) {
        Log.d(TAG, "Unhandled SSH stream: client=" + clientId + " target=" + host + ":" + port);
        new MeshStream(streamHandle).close();
    }

    @Override
    public void onForwardedTcpip(long connId, String host, int port, long streamHandle) {
        Log.d(TAG, "Unhandled forwarded-tcpip: conn=" + connId + " target=" + host + ":" + port);
        new MeshStream(streamHandle).close();
    }

    private static class BridgeMsgConn extends MsgConn {
        private final long clientId;
        private final MsgMux bridgeMux;

        BridgeMsgConn(MsgMux mux, String name) {
            super(mux);
            this.bridgeMux = mux;
            this.name = name;
            this.clientId = Long.parseLong(name.substring("ssh:".length()));
        }

        @Override
        public boolean sendFrame(MsgFrame frame) {
            boolean ok = MeshNode.sendBridgeJson(clientId, frame.toJsonLine());
            if (!ok) {
                bridgeMux.removeInConnection(name);
            }
            return ok;
        }

        @Override
        public boolean send(Message m) {
            return sendFrame(MsgFrame.fromMessage(m));
        }
    }

    private synchronized BridgeMsgConn connFor(long clientId) {
        BridgeMsgConn conn = conns.get(clientId);
        if (conn != null) {
            return conn;
        }
        String name = "ssh:" + clientId;
        conn = new BridgeMsgConn(mux, name);
        conns.put(clientId, conn);
        Message open = Message.obtain();
        open.getData().putBoolean(":open", true);
        mux.addInConnection(name, conn, open);
        return conn;
    }
}
