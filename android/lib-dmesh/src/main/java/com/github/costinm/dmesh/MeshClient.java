package com.github.costinm.dmesh;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;

import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;

/**
 * App-facing DirectBinder client for the foreground DMesh service.
 *
 * Apps do not select or bind other mesh applications directly. Rust in
 * app-dmesh applies policy and routes a submitted stream locally or remotely.
 * An app that was activated by app-dmesh may instead attach the callback Binder
 * supplied with that inbound request; both forms talk only to app-dmesh.
 */
public final class MeshClient implements AutoCloseable {
    private static final String TAG = "MeshClient";
    public static final long IDLE_GRACE_MS = 8_000L;
    public static final String DMESH_PACKAGE = "com.github.costinm.dmesh.lm";
    public static final String DMESH_SERVICE = "com.github.costinm.dmesh.lm.DMService";

    private static MeshClient singleton;

    public interface StreamReceiver {
        void onStream(MeshStream stream);
    }

    private final Context ctx;
    private StreamReceiver receiver;
    private final java.util.ArrayList<MeshStream> pending = new java.util.ArrayList<>();
    private final HashSet<String> activeRequestIds = new HashSet<>();
    private final Map<String, StreamReceiver> replyReceivers = new HashMap<>();
    private final Handler leaseHandler = new Handler(Looper.getMainLooper());
    private long lastMessageAt;
    private IBinder remote;
    private ServiceConnection connection;

    private final DirectBinder callback;

    private MeshClient(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        this.receiver = stream -> { };
        this.callback = new DirectBinder((code, message, reply) -> {
            noteIncoming(message.stream);
            StreamReceiver callback = message.stream == null || message.stream.replyTo == null
                    ? null : replyReceivers.remove(message.stream.replyTo);
            (callback == null ? this.receiver : callback).onStream(message.stream);
            return true;
        });
    }

    /** Returns this process's client for the explicit foreground DMesh service. */
    public static synchronized MeshClient get(Context context) {
        if (singleton == null) singleton = new MeshClient(context);
        return singleton;
    }

    /**
     * Uses app-dmesh's callback Binder supplied on an inbound DirectBinder
     * request. This is for a service activated by app-dmesh; it never selects
     * a third-party target.
     */
    public static MeshClient fromDirectBinder(Context context, IBinder appDmeshBinder) {
        if (appDmeshBinder == null) throw new IllegalArgumentException("missing app-dmesh Binder");
        MeshClient client = new MeshClient(context);
        client.remote = appDmeshBinder;
        return client;
    }

    /** Installs the optional receiver for unsolicited app-dmesh events. */
    public synchronized void setStreamReceiver(StreamReceiver receiver) {
        this.receiver = receiver == null ? stream -> { } : receiver;
    }

    /** Begins the bounded lifecycle lease to the foreground DMesh service. */
    public void bind() {
        openBinding();
    }

    @Override public synchronized void close() {
        leaseHandler.removeCallbacksAndMessages(this);
        activeRequestIds.clear();
        replyReceivers.clear();
        releaseBinding();
    }

    /** Sends a one-way message or request through app-dmesh. */
    public boolean sendStream(MeshStream stream) {
        return sendStream(stream, null);
    }

    /** Sends a request and receives its correlated reply through the supplied callback. */
    public synchronized boolean sendStream(MeshStream stream, StreamReceiver replyReceiver) {
        if (stream != null && hasId(stream.id) && replyReceiver != null) {
            replyReceivers.put(stream.id, replyReceiver);
        }
        if (remote == null) {
            pending.add(stream);
            openBinding();
            return true;
        }
        return sendNow(stream);
    }

    private void releaseBinding() {
        if (connection != null) {
            try {
                ctx.unbindService(connection);
            } catch (Throwable error) {
                Log.d(TAG, "unbind failed", error);
            }
        }
        connection = null;
        remote = null;
        pending.clear();
    }

    private void openBinding() {
        if (connection != null) return;
        Intent intent = new Intent(DirectBinder.ACTION_DIRECT);
        intent.setComponent(new ComponentName(DMESH_PACKAGE, DMESH_SERVICE));
        connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                remote = service;
                Log.d(TAG, "connected " + name);
                flushPending();
            }

            @Override public void onServiceDisconnected(ComponentName name) {
                Log.d(TAG, "disconnected " + name);
                remote = null;
                connection = null;
            }
        };
        if (!ctx.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            Log.d(TAG, "bind failed " + DMESH_PACKAGE + "/" + DMESH_SERVICE);
            connection = null;
        }
    }

    private void flushPending() {
        java.util.ArrayList<MeshStream> copy = new java.util.ArrayList<>(pending);
        pending.clear();
        for (MeshStream stream : copy) sendNow(stream);
    }

    private boolean sendNow(MeshStream stream) {
        IBinder binder = remote;
        if (binder == null) return false;
        noteOutgoing(stream);
        boolean sent = DirectBinder.transact(binder, DirectBinder.TRANSACT_MESSAGE,
                stream, callback, null);
        if (!sent && stream != null && hasId(stream.id)) {
            activeRequestIds.remove(stream.id);
            replyReceivers.remove(stream.id);
            scheduleReleaseIfIdle();
        }
        return sent;
    }

    private void noteOutgoing(MeshStream stream) {
        lastMessageAt = SystemClock.elapsedRealtime();
        if (stream != null && hasId(stream.id)) activeRequestIds.add(stream.id);
        leaseHandler.removeCallbacksAndMessages(this);
        if (stream == null || !hasId(stream.id)) scheduleReleaseIfIdle();
    }

    private void noteIncoming(MeshStream stream) {
        lastMessageAt = SystemClock.elapsedRealtime();
        if (stream != null && hasId(stream.replyTo)) activeRequestIds.remove(stream.replyTo);
        scheduleReleaseIfIdle();
    }

    private void scheduleReleaseIfIdle() {
        if (!activeRequestIds.isEmpty() || connection == null) return;
        leaseHandler.removeCallbacksAndMessages(this);
        long remaining = IDLE_GRACE_MS - (SystemClock.elapsedRealtime() - lastMessageAt);
        leaseHandler.postAtTime(this::releaseAfterIdle, this,
                SystemClock.uptimeMillis() + Math.max(0L, remaining));
    }

    private void releaseAfterIdle() {
        if (activeRequestIds.isEmpty()
                && SystemClock.elapsedRealtime() - lastMessageAt >= IDLE_GRACE_MS) {
            releaseBinding();
        } else {
            scheduleReleaseIfIdle();
        }
    }

    private static boolean hasId(String id) {
        return id != null && !id.isEmpty();
    }
}
