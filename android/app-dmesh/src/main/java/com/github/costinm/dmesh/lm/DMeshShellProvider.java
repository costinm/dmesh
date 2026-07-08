package com.github.costinm.dmesh.lm;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;

import com.github.costinm.dmesh.android.msg.MsgMux;

import java.util.Map;

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
        MsgMux mux = service == null ? MsgMux.get(getContext()) : service.shellMux();
        DMeshCommand.Result result = DMeshCommand.run(
                getContext(),
                mux,
                service == null ? null : service.shellMeshNode(),
                line);
        Bundle out = new Bundle();
        for (Map.Entry<String, String> entry : result.fields.entrySet()) {
            out.putString(entry.getKey(), entry.getValue());
        }
        return out;
    }

    private static void enforceShellOrRoot() {
        int uid = Binder.getCallingUid();
        if (uid != 0 && uid != 2000) {
            throw new SecurityException("DMesh shell accepts only root or ADB shell callers");
        }
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
