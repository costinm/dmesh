package com.github.costinm.dmesh.chat;

import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.BaseMsgService;
import com.github.costinm.dmesh.android.msg.DirectBinder;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;
import com.github.costinm.dmesh.android.msg.MessageHandler;

/**
 * ChatService receives raw messages from the mesh.
 */
public class ChatService extends BaseMsgService implements MessageHandler {
    private static final String TAG = "DMeshChat";

    @Override
    public void onCreate() {
        super.onCreate();
        mux.subscribe("chat", this);
    }

    @Override
    public void handleMessage(String topic, String msgType, android.os.Message m,
                              MsgConn replyTo, String[] args) {
        MsgFrame frame = MsgFrame.fromMessage(m);
        String text = frame.fields.get("text");
        if (text == null) {
            text = frame.fields.get("txt");
        }
        Log.d(TAG, "chat command " + frame.uri + " text=" + text);
        if (replyTo != null) {
            MsgFrame out = new MsgFrame("/chat/message");
            out.fields.put("from", "app-chat");
            out.fields.put("text", text == null ? "" : text);
            replyTo.sendFrame(out);
        }
    }

    @Override
    protected boolean handleDirectMessage(int code, DirectBinder.DirectMessage direct,
                                          Parcel reply) throws RemoteException {
        Log.d(TAG, "direct binder message " + code + " " +
                (direct.frame == null ? "" : direct.frame.toJsonLine()));
        return super.handleDirectMessage(code, direct, reply);
    }
}
