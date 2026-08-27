package com.github.costinm.dmesh.chat;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import com.github.costinm.dmesh.DirectBinder;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * ChatService receives raw messages from the mesh.
 */
public class ChatService extends Service {
    private static final String TAG = "DMeshChat";
    private final DirectBinder directBinder = new DirectBinder(this::handleRawMessage);

    @Override
    public IBinder onBind(Intent intent) {
        return intent != null && DirectBinder.ACTION_DIRECT.equals(intent.getAction()) ? directBinder : null;
    }

    private boolean handleRawMessage(int code, DirectBinder.DirectMessage message, Parcel reply)
            throws RemoteException {
        try {
            JSONObject request = new JSONObject(new String(message.payload, StandardCharsets.UTF_8));
            String method = request.optString("method", "");
            JSONObject data = request.optJSONObject("data");
            String text = data == null ? "" : data.optString("text", data.optString("txt", ""));
            Log.d(TAG, "raw command " + method + " text=" + text);
            if (message.callback != null) {
                JSONObject response = new JSONObject();
                response.put("method", "chat.message");
                response.put("id", request.optString("id", ""));
                JSONObject body = new JSONObject();
                body.put("from", "app-chat");
                body.put("text", text);
                response.put("data", body);
                DirectBinder.transact(message.callback, DirectBinder.TRANSACT_EVENT,
                        response.toString().getBytes(StandardCharsets.UTF_8), "json", null, null, null);
            }
            return true;
        } catch (Exception error) {
            Log.w(TAG, "invalid raw message", error);
            return false;
        }
    }
}
