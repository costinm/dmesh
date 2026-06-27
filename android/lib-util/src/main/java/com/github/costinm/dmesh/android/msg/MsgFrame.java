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
 * shape: URI plus string key/value fields. Android Message/Bundle is only an
 * adapter for existing platform handlers.
 */
public class MsgFrame {
    public String id;
    public String uri;
    public final LinkedHashMap<String, String> fields = new LinkedHashMap<>();

    public MsgFrame(String uri) {
        this.uri = uri;
    }

    public static MsgFrame fromPairs(String id, String uri, String[] keys, String[] values) {
        MsgFrame frame = new MsgFrame(uri);
        frame.id = id;
        int n = Math.min(keys == null ? 0 : keys.length, values == null ? 0 : values.length);
        for (int i = 0; i < n; i++) {
            frame.fields.put(keys[i], values[i]);
        }
        return frame;
    }

    public static MsgFrame fromMessage(Message msg) {
        Bundle data = msg.getData();
        MsgFrame frame = new MsgFrame(data.getString(MsgMux.URI));
        frame.id = data.getString(":rid");
        for (String key : data.keySet()) {
            if (MsgMux.URI.equals(key) || ":rid".equals(key)) {
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
        data.putString(MsgMux.URI, uri);
        if (id != null && !id.isEmpty()) {
            data.putString(":rid", id);
        }
        for (Map.Entry<String, String> field : fields.entrySet()) {
            data.putString(field.getKey(), field.getValue());
        }
        return msg;
    }

    public String toJsonLine() {
        JSONObject root = new JSONObject();
        JSONObject data = new JSONObject();
        try {
            if (id != null && !id.isEmpty()) {
                root.put("id", id);
            }
            root.put("uri", uri);
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
}
