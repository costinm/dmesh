package com.github.costinm.dmesh.android.msg;

import android.os.Bundle;
import android.os.Message;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Transport-neutral message frame.
 *
 * Rust, SSH, raw Binder, and future non-Android transports should use this
 * shape: method plus string key/value fields. Android Message/Bundle is only
 * an adapter for existing platform handlers.
 */
public class MsgFrame {
    public String id;
    public String replyTo;
    public String session;
    public String stream;
    public String type;
    public String from;
    public String to;
    public String method;
    public String uri;
    public final LinkedHashMap<String, String> fields = new LinkedHashMap<>();

    public MsgFrame(String method) {
        this.method = method;
        this.uri = method;
    }

    public static MsgFrame fromPairs(String id, String method, String[] keys, String[] values) {
        MsgFrame frame = new MsgFrame(method);
        frame.id = id;
        int n = Math.min(keys == null ? 0 : keys.length, values == null ? 0 : values.length);
        for (int i = 0; i < n; i++) {
            frame.fields.put(keys[i], values[i]);
        }
        return frame;
    }

    public static MsgFrame fromJsonLine(String line) throws JSONException {
        JSONObject root = new JSONObject(line);
        String method = root.optString("method", null);
        if (method == null || method.isEmpty()) {
            throw new JSONException("missing method");
        }
        MsgFrame frame = new MsgFrame(method);
        frame.id = root.optString("id", null);
        frame.replyTo = root.optString("replyTo", null);
        frame.session = root.optString("session", null);
        frame.stream = root.optString("stream", null);
        frame.type = root.optString("type", null);
        frame.from = root.optString("from", null);
        frame.to = root.optString("to", null);
        JSONObject data = root.optJSONObject("data");
        if (data != null) {
            copyJsonObject(frame, data, false);
        }
        copyJsonObject(frame, root, true);
        return frame;
    }

    private static void copyJsonObject(MsgFrame frame, JSONObject obj, boolean topLevel)
            throws JSONException {
        java.util.Iterator<String> keys = obj.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (topLevel && ("id".equals(key) || "replyTo".equals(key) ||
                    "session".equals(key) || "stream".equals(key) || "type".equals(key) ||
                    "from".equals(key) || "to".equals(key) ||
                    "method".equals(key) || "data".equals(key))) {
                continue;
            }
            Object value = obj.get(key);
            if (value == JSONObject.NULL) {
                continue;
            }
            frame.fields.put(key, value.toString());
        }
    }

    public static MsgFrame fromMessage(Message msg) {
        Bundle data = msg.getData();
        MsgFrame frame = new MsgFrame(data.getString(MsgMux.URI));
        frame.id = data.getString(":rid");
        frame.replyTo = data.getString(":replyTo");
        frame.session = data.getString(":session");
        frame.stream = data.getString(":stream");
        frame.type = data.getString(":type");
        frame.from = data.getString(":from");
        frame.to = data.getString(":to");
        for (String key : data.keySet()) {
            if (MsgMux.URI.equals(key) || ":rid".equals(key) || ":replyTo".equals(key) ||
                    ":session".equals(key) || ":stream".equals(key) || ":type".equals(key) ||
                    ":from".equals(key) || ":to".equals(key) || ":method".equals(key)) {
                continue;
            }
            Object value = data.get(key);
            if (value != null) {
                frame.fields.put(key, value.toString());
            }
        }
        return frame;
    }

    public Message toMessage() {
        Message msg = Message.obtain();
        msg.what = MsgMux.TXT;
        Bundle data = msg.getData();
        data.putString(MsgMux.URI, method);
        if (id != null && !id.isEmpty()) {
            data.putString(":rid", id);
        }
        putMeta(data, ":replyTo", replyTo);
        putMeta(data, ":session", session);
        putMeta(data, ":stream", stream);
        putMeta(data, ":type", type);
        putMeta(data, ":from", from);
        putMeta(data, ":to", to);
        for (Map.Entry<String, String> field : fields.entrySet()) {
            data.putString(field.getKey(), field.getValue());
        }
        return msg;
    }

    private static void putMeta(Bundle data, String key, String value) {
        if (value != null && !value.isEmpty()) {
            data.putString(key, value);
        }
    }

    public String toJsonLine() {
        JSONObject root = new JSONObject();
        JSONObject data = new JSONObject();
        try {
            if (id != null && !id.isEmpty()) {
                root.put("id", id);
            }
            putJsonMeta(root, "replyTo", replyTo);
            putJsonMeta(root, "session", session);
            putJsonMeta(root, "stream", stream);
            putJsonMeta(root, "type", type);
            putJsonMeta(root, "from", from);
            putJsonMeta(root, "to", to);
            putJsonMeta(root, "method", method);
            for (Map.Entry<String, String> field : fields.entrySet()) {
                String key = field.getKey();
                if (key.startsWith(":")) {
                    root.put(key.substring(1), field.getValue());
                } else {
                    data.put(key, field.getValue());
                }
            }
            if (data.length() > 0) {
                root.put("data", data);
            }
        } catch (JSONException e) {
            throw new IllegalArgumentException(e);
        }
        return root.toString();
    }

    private static void putJsonMeta(JSONObject root, String key, String value) throws JSONException {
        if (value != null && !value.isEmpty()) {
            root.put(key, value);
        }
    }

    public boolean matchesKeys(String keys) {
        if (keys == null || keys.trim().isEmpty() ||
                "all".equals(keys.trim()) || "*".equals(keys.trim())) {
            return true;
        }
        String current = method == null ? "" : method;
        for (String raw : keys.split(",")) {
            String key = raw.trim();
            if (key.isEmpty()) {
                continue;
            }
            if (current.equals(key) || current.startsWith(key + ".")) {
                return true;
            }
            if (fields.containsKey(key)) {
                return true;
            }
        }
        return false;
    }
}
