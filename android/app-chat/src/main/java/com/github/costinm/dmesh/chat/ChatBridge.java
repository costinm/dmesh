package com.github.costinm.dmesh.chat;

import android.content.Context;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.DirectBinder;
import com.github.costinm.dmesh.android.msg.MsgFrame;

public class ChatBridge {
    private static final String TAG = "DMeshChat";

    public static void submitText(Context context, String text) {
        Log.d(TAG, "rust ui typed: " + text);
        Context app = context.getApplicationContext();
        Intent intent = new Intent();
        intent.setAction(DirectBinder.ACTION_DIRECT);
        intent.setComponent(new ComponentName(
                "com.github.costinm.dmesh.lm",
                "com.github.costinm.dmesh.lm.DMService"));
        app.bindService(intent, new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                MsgFrame frame = new MsgFrame("/chat/message");
                frame.fields.put("from", "app-chat-ui");
                frame.fields.put("text", text);
                DirectBinder.transact(
                        service,
                        DirectBinder.TRANSACT_MESSAGE,
                        frame,
                        null,
                        null);
                try {
                    app.unbindService(this);
                } catch (Throwable t) {
                    Log.d(TAG, "unbind failed", t);
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
            }
        }, Context.BIND_AUTO_CREATE);
    }
}
