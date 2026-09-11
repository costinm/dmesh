package com.github.costinm.dmesh.chat;

import android.content.Context;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
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
    private static final ArrayList<byte[]> PENDING = new ArrayList<>();
    private static IBinder remote;
    private static ServiceConnection connection;

    private static final DirectBinder CALLBACK = new DirectBinder((code, msg, reply) -> {
        enqueueEvent(new String(msg.payload, StandardCharsets.UTF_8));
        return true;
    });

    public static void submitText(Context context, String text) {
        Log.d(TAG, "rust ui typed: " + text);
        Context app = context.getApplicationContext();
        sendPayload(app, payloadForText(text));
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

    private static byte[] payloadForText(String text) {
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
            return new JSONObject().put("method", method).put("data", data)
                    .toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("cannot encode chat request", e);
        }
    }

    private static void sendPayload(Context app, byte[] payload) {
        synchronized (LOCK) {
            if (remote != null) {
                sendNow(payload);
                return;
            }
            PENDING.add(payload);
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
                ArrayList<byte[]> copy;
                synchronized (LOCK) {
                    remote = service;
                    copy = new ArrayList<>(PENDING);
                    PENDING.clear();
                }
                for (byte[] payload : copy) {
                    sendNow(payload);
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

    private static void sendNow(byte[] payload) {
        IBinder binder;
        synchronized (LOCK) {
            binder = remote;
        }
        if (binder == null) {
            return;
        }
        boolean ok = DirectBinder.transact(
                binder, DirectBinder.TRANSACT_MESSAGE, payload, "json", null, CALLBACK, null);
        if (!ok) {
            enqueueEvent("{\"method\":\"messages.error\",\"data\":{\"error\":\"direct binder send failed\"}}");
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
