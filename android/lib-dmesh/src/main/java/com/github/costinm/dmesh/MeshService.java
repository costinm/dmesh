package com.github.costinm.dmesh;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

/** DirectBinder-only Android service base for an explicit mesh endpoint. */
public class MeshService extends Service {
    private static final String TAG = "MeshService";
    private final DirectBinder directBinder = new DirectBinder(this::handleDirectMessage);

    @Override public IBinder onBind(Intent intent) {
        Log.d(TAG, "BIND " + intent);
        return intent != null && DirectBinder.ACTION_DIRECT.equals(intent.getAction())
                ? directBinder : null;
    }

    protected boolean handleDirectMessage(int code, DirectBinder.DirectMessage message, Parcel reply)
            throws RemoteException {
        if (code != DirectBinder.TRANSACT_MESSAGE && code != DirectBinder.TRANSACT_EVENT) return false;
        return onDirectStream(message, reply);
    }

    /** Platform-adapter hook; services must not install a Java message router. */
    protected boolean onDirectStream(DirectBinder.DirectMessage message, Parcel reply)
            throws RemoteException {
        return onDirectStream(message == null ? null : message.stream,
                message == null ? null : message.callback, reply);
    }

    /** Platform-adapter hook; services must not install a Java message router. */
    protected boolean onDirectStream(MeshStream stream, IBinder callback, Parcel reply)
            throws RemoteException {
        return false;
    }
}
