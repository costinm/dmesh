package com.github.costinm.dmesh.lm;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;

import com.github.costinm.dmesh.DirectBinder;
import com.github.costinm.dmesh.MeshStream;
import com.github.costinm.dmeshnative.MeshNode;


/**
 * ADB/root-only command surface for local testing and provisioning.
 *
 * Example:
 * adb shell content call --uri content://com.github.costinm.dmesh.lm.shell \
 *   --method command --arg 'msg /wifi/scan'
 */
public class DMeshShellProvider extends ContentProvider {
    static final String AUTHORITY = "com.github.costinm.dmesh.lm.shell";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        enforceShellOrRoot();
        String line = arg;
        if ((line == null || line.isEmpty()) && extras != null) {
            line = extras.getString("line");
        }
        if ("message".equals(method)) {
            DMService service = DMService.getActiveService();
            if (service == null) {
                Bundle out = new Bundle();
                out.putString("status", "dmesh_service_unavailable");
                return out;
            }
            try {
                // app-dmesh is the Binder server and Rust router; it must not
                // bind to its own service through MeshClient. A local shell
                // message ingress will be added with the common Rust router,
                // rather than creating a second Java dispatch path here.
                messageFromShell(line, extras);
                Bundle out = new Bundle();
                out.putString("status", "local_message_ingress_unavailable");
                out.putString("error", "use command until the Rust message ingress is available");
                return out;
            } catch (IllegalArgumentException error) {
                Bundle out = new Bundle();
                out.putString("status", "invalid_message");
                out.putString("error", error.getMessage());
                return out;
            }
        }
        if ("provision-root-key".equals(method)) {
            String key = extras == null ? null : extras.getString("key");
            String url = extras == null ? null : extras.getString("url");
            if (url != null && !url.isEmpty()) {
                line = "key add-url url=" + url;
            } else {
                line = "key add " + (key == null ? "" : key);
            }
        } else if ("provision-ssh-key".equals(method)) {
            String key = extras == null ? null : extras.getString("key");
            String type = extras == null ? "user" : extras.getString("type", "user");
            line = "key add type=" + type + " " + (key == null ? "" : key);
        } else if ("ssh".equals(method)) {
            line = "ssh " + (line == null ? "" : line);
        } else if (!"command".equals(method)) {
            line = method + (line == null ? "" : " " + line);
        }

        DMService service = DMService.getActiveService();
        Bundle out = new Bundle();
        if (service == null || service.shellMeshNode() == null) {
            out.putString("status", "rust_unavailable");
            return out;
        }
        String projection = MeshNode.shellTransportCommand(line);
        out.putString("rust_projection", projection);
        out.putString("platform_result", service.applyShellTransportProjection(projection));
        return out;
    }

    private static void enforceShellOrRoot() {
        int uid = Binder.getCallingUid();
        if (uid != 0 && uid != 2000) {
            throw new SecurityException("DMesh shell accepts only root or ADB shell callers");
        }
    }

    private static MeshStream messageFromShell(String line, Bundle extras) {
        Bundle suppliedEnvelope = extras == null ? null : extras.getBundle("envelope");
        if (suppliedEnvelope != null) {
            return MeshStream.fromDirect(new byte[0], "bundle", suppliedEnvelope);
        }
        String[] words = splitMessage(line == null ? "" : line);
        if (words.length == 0 || words[0].isEmpty()) {
            throw new IllegalArgumentException("message requires a method");
        }
        MeshStream stream = new MeshStream(words[0]);
        for (int i = 1; i < words.length; i++) {
            String[] pair = words[i].split("=", 2);
            String key = pair[0];
            String value = pair.length == 2 ? pair[1] : "true";
            if (key.isEmpty()) throw new IllegalArgumentException("empty message key");
            putMessageValue(stream, key, value);
        }
        if (extras != null) {
            Bundle suppliedData = extras.getBundle("data");
            if (suppliedData != null) stream.data.putAll(suppliedData);
        }
        return stream;
    }

    private static void putMessageValue(MeshStream stream, String key, String value) {
        switch (key) {
            case DirectBinder.ID: stream.id = value; return;
            case DirectBinder.REPLY_TO: stream.replyTo = value; return;
            case DirectBinder.SESSION: stream.session = value; return;
            case DirectBinder.STREAM: stream.stream = value; return;
            case DirectBinder.TYPE: stream.type = value; return;
            case DirectBinder.FROM: stream.from = value; return;
            case DirectBinder.TO: stream.to = value; return;
            default: putTypedValue(stream.data, key, value);
        }
    }

    private static void putTypedValue(Bundle data, String key, String value) {
        if (value.startsWith("i:")) data.putInt(key, Integer.parseInt(value.substring(2)));
        else if (value.startsWith("l:")) data.putLong(key, Long.parseLong(value.substring(2)));
        else if (value.startsWith("f:")) data.putFloat(key, Float.parseFloat(value.substring(2)));
        else if (value.startsWith("d:")) data.putDouble(key, Double.parseDouble(value.substring(2)));
        else if ("true".equals(value) || "false".equals(value)) data.putBoolean(key, Boolean.parseBoolean(value));
        else data.putString(key, value);
    }

    /** Small lexer: quotes and backslash protect whitespace and '=' values. */
    private static String[] splitMessage(String line) {
        java.util.ArrayList<String> words = new java.util.ArrayList<>();
        StringBuilder current = new StringBuilder();
        char quote = 0;
        boolean escaped = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (escaped) { current.append(c); escaped = false; }
            else if (c == '\\') escaped = true;
            else if (quote != 0) { if (c == quote) quote = 0; else current.append(c); }
            else if (c == '\'' || c == '"') quote = c;
            else if (Character.isWhitespace(c)) {
                if (current.length() > 0) { words.add(current.toString()); current.setLength(0); }
            } else current.append(c);
        }
        if (escaped) current.append('\\');
        if (quote != 0) throw new IllegalArgumentException("unterminated quote");
        if (current.length() > 0) words.add(current.toString());
        return words.toArray(new String[0]);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
