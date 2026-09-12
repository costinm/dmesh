package com.github.costinm.dmesh.chat;

import android.content.Context;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import com.github.costinm.dmesh.DirectBinder;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;

public class ChatBridge {
    private static final String TAG = "DMeshChat";
    private static final Object LOCK = new Object();
    private static final ArrayDeque<String> EVENTS = new ArrayDeque<>();
    private static IBinder remote;

    private static ServiceConnection connection;

    private static final DirectBinder CALLBACK = new DirectBinder((code, msg, reply) -> {
        enqueueEvent(new String(msg.payload, StandardCharsets.UTF_8));
        return true;
    });

    public static void submitText(Context context, String text) {
        Log.d(TAG, "rust ui typed: " + text);
        Context app = context.getApplicationContext();
        sendPayload(app, requestForText(text));
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

    private static class ChatRequest {
        final String method;
        final byte[] payload;
        final Bundle extras;

        ChatRequest(String method, byte[] payload, Bundle extras) {
            this.method = method;
            this.payload = payload;
            this.extras = extras;
        }
    }

    private static final ArrayList<ChatRequest> PENDING = new ArrayList<>();

    private static ChatRequest requestForText(String text) {
        String trimmed = text == null ? "" : text.trim();
        String method;
        String body = trimmed;
        if (trimmed.equals("/messages") || trimmed.startsWith("/messages ")) {
            method = "messages.subscribe";
            String[] parts = trimmed.split("\\s+", 2);
            body = parts.length > 1 ? parts[1].trim() : "all";
        } else if (trimmed.startsWith("/")) {
            String[] parts = trimmed.split("\\s+", 2);
            method = parts[0].substring(1).replace('/', '.');
            body = parts.length > 1 ? parts[1] : "";
        } else {
            method = "chat.message";
        }
        try {
            JSONObject data = new JSONObject();
            data.put("from", "app-chat-ui");
            data.put("text", body);
            if ("messages.subscribe".equals(method)) data.put("keys", body);
            byte[] payload = new JSONObject().put("method", method).put("data", data)
                    .toString().getBytes(StandardCharsets.UTF_8);
            Bundle extras = new Bundle();
            extras.putString(DirectBinder.METHOD, method);
            extras.putString("keys", body);
            extras.putString("text", body);
            extras.putString("from", "app-chat-ui");
            return new ChatRequest(method, payload, extras);
        } catch (Exception e) {
            throw new IllegalStateException("cannot encode chat request", e);
        }
    }

    private static void sendPayload(Context app, ChatRequest req) {
        synchronized (LOCK) {
            if (remote != null) {
                sendNow(req);
                return;
            }
            PENDING.add(req);
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
                ArrayList<ChatRequest> copy;
                synchronized (LOCK) {
                    remote = service;
                    copy = new ArrayList<>(PENDING);
                    PENDING.clear();
                }
                for (ChatRequest req : copy) {
                    sendNow(req);
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

    private static void sendNow(ChatRequest req) {
        IBinder binder;
        synchronized (LOCK) {
            binder = remote;
        }
        if (binder == null || req == null) {
            return;
        }

        // 1-way async for continuous subscriptions, 2-way sync for queries/commands
        if ("messages.subscribe".equals(req.method)) {
            boolean ok = DirectBinder.transactAsync(
                    binder, DirectBinder.TRANSACT_MESSAGE, req.payload, "json", req.extras, CALLBACK, null);
            if (!ok) {
                enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"direct binder async send failed\"}}");
            }
        } else {
            DirectBinder.DirectMessage[] replyOut = new DirectBinder.DirectMessage[1];
            boolean ok = DirectBinder.transactSync(
                    binder, DirectBinder.TRANSACT_MESSAGE, req.payload, "json", req.extras, null, replyOut);
            if (ok && replyOut[0] != null && replyOut[0].payload != null && replyOut[0].payload.length > 0) {
                enqueueEvent(new String(replyOut[0].payload, StandardCharsets.UTF_8));
            } else if (!ok) {
                // Fallback to async if sync is unsupported or failed
                boolean asyncOk = DirectBinder.transactAsync(
                        binder, DirectBinder.TRANSACT_MESSAGE, req.payload, "json", req.extras, CALLBACK, null);
                if (!asyncOk) {
                    enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"direct binder send failed\"}}");
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
