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

import org.json.JSONException;

import java.util.HashMap;
import java.util.Map;

/**
 * Minimal Java adapter for the Rust-owned SSH message bridge.
 *
 * Rust owns the SSH stream, line framing, JSON/human command parsing, and
 * response framing. Java adapts JSON frames into MsgFrame and only
 * converts to Android Message where existing MsgMux handlers still require it.
 */
class SshJsonlMsgBridge implements MeshNode.MeshCallback {
    private static final String TAG = "DM-SSH-MSG";

    private final Context context;
    private final MsgMux mux;
    private final DMService service;
    private final Map<Long, BridgeMsgConn> conns = new HashMap<>();
    private final Map<String, AppTarget> appTargets = new HashMap<>();

    SshJsonlMsgBridge(Context context, MsgMux mux) {
        this.context = context.getApplicationContext();
        this.mux = mux;
        this.service = context instanceof DMService ? (DMService) context : null;
        appTargets.put("chat", new AppTarget(
                "com.github.costinm.dmesh.chat",
                "com.github.costinm.dmesh.chat.ChatService",
                "chat"));
    }

    @Override
    public void onSshConnection(long clientId, String user) {
        Log.d(TAG, "SSH client connected: " + clientId + " user=" + user);
    }

    @Override
    public void onMessage(long clientId, String jsonLine) {
        MsgFrame frame;
        try {
            frame = MsgFrame.fromJsonLine(jsonLine);
        } catch (JSONException e) {
            Log.w(TAG, "invalid Rust JSON message: " + jsonLine, e);
            return;
        }
        if (service != null) {
            service.recordJsonFrame(frame);
        }
        if (clientId == 0) {
            return;
        }
        BridgeMsgConn conn = connFor(clientId);
        if (forwardAppCommand(conn, frame)) {
            return;
        }
        mux.receiveFrame(conn.name, conn, frame);
    }

    @Override
    public void onStreamOpened(long clientId, String jsonLine) {
        try {
            MsgFrame frame = MsgFrame.fromJsonLine(jsonLine);
            if (service != null) {
                service.recordJsonFrame(frame);
            }
        } catch (JSONException e) {
            Log.w(TAG, "invalid stream-opened JSON message: " + jsonLine, e);
        }
    }

    private boolean forwardAppCommand(BridgeMsgConn replyTo, MsgFrame frame) {
        if (frame.method == null || !frame.method.startsWith("app.")) {
            return false;
        }
        String[] parts = frame.method.split("\\.", 3);
        if (parts.length < 3) {
            MsgFrame err = new MsgFrame("app.error");
            err.id = frame.id;
            err.fields.put("error", "expected app.<target>.<command>");
            replyTo.sendFrame(err);
            return true;
        }
        String targetName = parts[1];
        AppTarget target = appTargets.get(targetName);
        if (target == null) {
            MsgFrame err = new MsgFrame("app.error");
            err.id = frame.id;
            err.fields.put("error", "unknown app target: " + targetName);
            replyTo.sendFrame(err);
            return true;
        }
        MsgFrame appFrame = new MsgFrame(target.topic + "." + parts[2]);
        appFrame.id = frame.id;
        appFrame.fields.putAll(frame.fields);
        DirectBinderConn appConn = new DirectBinderConn(mux, context, target.packageName, target.serviceName);
        appConn.name = "direct:" + targetName;
        appConn.sendFrame(appFrame);
        MsgFrame ack = new MsgFrame("app.forwarded");
        ack.id = frame.id;
        ack.fields.put("target", targetName);
        ack.fields.put("method", appFrame.method);
        replyTo.sendFrame(ack);
        return true;
    }

    @Override
    public void onStream(long clientId, String host, int port, long streamHandle) {
        if ("mesh-stream".equals(host)) {
            Log.d(TAG, "Accepted upgraded mesh stream: client=" + clientId + " port=" + port);
            handleUpgradedStream(clientId, streamHandle);
            return;
        }
        Log.d(TAG, "Unhandled SSH stream: client=" + clientId + " target=" + host + ":" + port);
        new MeshStream(streamHandle).close();
    }

    private void handleUpgradedStream(long clientId, long streamHandle) {
        MeshStream stream = new MeshStream(streamHandle);
        new Thread(() -> {
            byte[] buf = new byte[4096];
            try {
                while (true) {
                    int n = stream.read(buf);
                    if (n <= 0) {
                        break;
                    }
                    if (service != null) {
                        MsgFrame frame = new MsgFrame("mesh.stream.data");
                        frame.session = "ssh:" + clientId;
                        frame.stream = "ssh:" + clientId + ":binary";
                        frame.type = "event";
                        frame.fields.put("bytes", Integer.toString(n));
                        service.recordJsonFrame(frame);
                    }
                }
            } finally {
                stream.close();
                if (service != null) {
                    MsgFrame frame = new MsgFrame("mesh.stream.close");
                    frame.session = "ssh:" + clientId;
                    frame.stream = "ssh:" + clientId + ":binary";
                    frame.type = "close";
                    service.recordJsonFrame(frame);
                }
            }
        }, "dmesh-upgraded-stream-" + clientId).start();
    }

    @Override
    public void onForwardedTcpip(long connId, String host, int port, long streamHandle) {
        Log.d(TAG, "Unhandled forwarded-tcpip: conn=" + connId + " target=" + host + ":" + port);
        new MeshStream(streamHandle).close();
    }

    private static class AppTarget {
        final String packageName;
        final String serviceName;
        final String topic;

        AppTarget(String packageName, String serviceName, String topic) {
            this.packageName = packageName;
            this.serviceName = serviceName;
            this.topic = topic;
        }
    }

    private static class BridgeMsgConn extends MsgConn {
        private final long clientId;
        private final MsgMux bridgeMux;
        private final DMService service;

        BridgeMsgConn(MsgMux mux, String name, DMService service) {
            super(mux);
            this.bridgeMux = mux;
            this.service = service;
            this.name = name;
            this.clientId = Long.parseLong(name.substring("ssh:".length()));
        }

        @Override
        public boolean sendFrame(MsgFrame frame) {
            if (service != null) {
                service.recordJsonEvent("rust.message.out", frame.toJsonLine());
            }
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
        conn = new BridgeMsgConn(mux, name, service);
        conns.put(clientId, conn);
        Message open = Message.obtain();
        open.getData().putBoolean(":open", true);
        mux.addInConnection(name, conn, open);
        return conn;
    }
}
