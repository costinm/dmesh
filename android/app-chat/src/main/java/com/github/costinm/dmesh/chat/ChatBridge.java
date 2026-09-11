package com.github.costinm.dmesh.chat;

import android.content.Context;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.DirectBinder;
import com.github.costinm.dmesh.android.msg.MsgFrame;

import java.util.ArrayDeque;
import java.util.ArrayList;

public class ChatBridge {
    private static final String TAG = "DMeshChat";
    private static final Object LOCK = new Object();
    private static final ArrayDeque<String> EVENTS = new ArrayDeque<>();
    private static final ArrayList<MsgFrame> PENDING = new ArrayList<>();
    private static IBinder remote;
    private static ServiceConnection connection;

    private static final DirectBinder CALLBACK = new DirectBinder(new DirectBinder.Receiver() {
        @Override
        public boolean onDirectMessage(int code, DirectBinder.DirectMessage msg, Parcel reply)
                throws RemoteException {
            if (msg.frame != null) {
                enqueueEvent(msg.frame.toJsonLine());
            }
            return true;
        }
    });

    public static void submitText(Context context, String text) {
        Log.d(TAG, "rust ui typed: " + text);
        Context app = context.getApplicationContext();
        sendFrame(app, frameForText(text));
    }

    public static String drainEvents() {
        StringBuilder out = new StringBuilder();
        synchronized (LOCK) {
            while (!EVENTS.isEmpty()) {
                out.append(EVENTS.removeFirst()).append('\n');
            }
        }
        return out.toString();
    }

    private static MsgFrame frameForText(String text) {
        String trimmed = text == null ? "" : text.trim();
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1).trim();
        }
        if (trimmed.equals("messages") || trimmed.startsWith("messages ")) {
            MsgFrame frame = new MsgFrame("messages.subscribe");
            String[] parts = trimmed.split("\\s+", 2);
            frame.fields.put("keys", parts.length > 1 ? parts[1].trim() : "all");
            frame.fields.put("from", "app-chat-ui");
            return frame;
        }
        if (text != null && text.trim().startsWith("/")) {
            String[] parts = trimmed.split("\\s+", 2);
            MsgFrame frame = new MsgFrame(parts[0].replace('/', '.'));
            frame.fields.put("from", "app-chat-ui");
            if (parts.length > 1) {
                frame.fields.put("text", parts[1]);
            }
            return frame;
        }
        MsgFrame frame = new MsgFrame("chat.message");
        frame.fields.put("from", "app-chat-ui");
        frame.fields.put("text", trimmed);
        return frame;
    }

    private static void sendFrame(Context app, MsgFrame frame) {
        synchronized (LOCK) {
            if (remote != null) {
                sendNow(frame);
                return;
            }
            PENDING.add(frame);
        }
        bind(app);
    }

    private static void bind(Context app) {
        synchronized (LOCK) {
            if (connection != null) {
                return;
            }
        }
        Intent intent = new Intent();
        intent.setAction(DirectBinder.ACTION_DIRECT);
        intent.setComponent(new ComponentName(
                "com.github.costinm.dmesh.lm",
                "com.github.costinm.dmesh.lm.DMService"));
        ServiceConnection sc = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                ArrayList<MsgFrame> copy;
                synchronized (LOCK) {
                    remote = service;
                    copy = new ArrayList<>(PENDING);
                    PENDING.clear();
                }
                for (MsgFrame frame : copy) {
                    sendNow(frame);
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                synchronized (LOCK) {
                    remote = null;
                    connection = null;
                }
            }
        };
        synchronized (LOCK) {
            connection = sc;
        }
        if (!app.bindService(intent, sc, Context.BIND_AUTO_CREATE)) {
            synchronized (LOCK) {
                connection = null;
            }
            enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"bind to app-dmesh failed\"}}");
        }
    }

    private static void sendNow(MsgFrame frame) {
        IBinder binder;
        synchronized (LOCK) {
            binder = remote;
        }
        Log.i(TAG, "sendNow: binder=" + binder + " frame=" + (frame != null ? frame.method : null));
        if (binder == null) {
            Log.w(TAG, "sendNow: binder is null!");
            return;
        }
        Log.i(TAG, "sendNow: isBinderAlive=" + binder.isBinderAlive() + " ping=" + binder.pingBinder());
        
        // Check if this is a streaming subscription vs request
        boolean isSubscribe = frame != null && "messages.subscribe".equals(frame.method);
        
        if (isSubscribe) {
            // For continuous subscriptions, use 1-way transaction with CALLBACK binder
            boolean ok = false;
            try {
                ok = DirectBinder.transactAsync(
                        binder,
                        DirectBinder.TRANSACT_MESSAGE,
                        frame,
                        CALLBACK,
                        null);
            } catch (Throwable t) {
                Log.e(TAG, "sendNow: DirectBinder.transactAsync threw", t);
                enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"transact exception: " + t + "\"}}");
                return;
            }
            Log.i(TAG, "sendNow async transact returned ok=" + ok);
            if (!ok) {
                enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"direct binder send failed (returned false)\"}}");
            }
        } else {
            // Try 2-way synchronous transaction first to receive direct responses
            MsgFrame[] replyOut = new MsgFrame[1];
            boolean ok = false;
            try {
                ok = DirectBinder.transactSync(
                        binder,
                        DirectBinder.TRANSACT_MESSAGE,
                        frame,
                        null,
                        replyOut);
            } catch (Throwable t) {
                Log.e(TAG, "sendNow: DirectBinder.transactSync threw", t);
            }
            if (ok && replyOut[0] != null) {
                Log.i(TAG, "sendNow sync response received: " + replyOut[0].method);
                enqueueEvent(replyOut[0].toJsonLine());
            } else if (!ok) {
                // Fallback to async transaction with CALLBACK
                Log.i(TAG, "sendNow sync not handled or failed, trying async fallback");
                try {
                    ok = DirectBinder.transactAsync(
                            binder,
                            DirectBinder.TRANSACT_MESSAGE,
                            frame,
                            CALLBACK,
                            null);
                } catch (Throwable t) {
                    Log.e(TAG, "sendNow: DirectBinder.transactAsync fallback threw", t);
                    enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"transact exception: " + t + "\"}}");
                    return;
                }
                if (!ok) {
                    enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"direct binder send failed (returned false)\"}}");
                }
            }
        }
    }

    private static void enqueueEvent(String line) {
        synchronized (LOCK) {
            EVENTS.addLast(line);
            while (EVENTS.size() > 512) {
                EVENTS.removeFirst();
            }
        }
    }
}
