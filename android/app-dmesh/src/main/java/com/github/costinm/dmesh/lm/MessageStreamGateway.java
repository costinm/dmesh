package com.github.costinm.dmesh.lm;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.DirectBinder;
import com.github.costinm.dmesh.MeshClient;
import com.github.costinm.dmesh.MeshStream;
import com.github.costinm.dmeshnative.CborMessageCodec;
import com.github.costinm.dmeshnative.MeshNode;
import com.github.costinm.dmeshnative.MeshNativeStream;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;

/**
 * Transport-neutral Android message gateway.
 *
 * SSH direct streams, QUIC-lite control streams, and HTTP/2 streams each adapt
 * their byte channel to an {@link Endpoint}. This class owns the one Java CBOR
 * to MeshStream/Bundle projection and the Android-only DirectBinder routing.
 */
public final class MessageStreamGateway implements MeshNode.MeshCallback {
    private static final String TAG = "DM-MSG-GW";

    /** A bidirectional bounded-message channel supplied by a transport adapter. */
    public interface Endpoint {
        /** Stable only for the lifetime of this transport connection. */
        String id();

        /** Sends one unframed message record; the transport owns its framing. */
        boolean send(byte[] record);
    }

    /** Framework NAN work remains Java-owned; Rust supplies a validated MAC. */
    public interface NanWakeup {
        void request(String target);
    }

    private final Context context;
    private final Runnable activeDiscovery;
    private final NanWakeup nanWakeup;
    private final Map<String, AppLease> appConnections = new HashMap<>();
    private final Map<Long, NativeEndpoint> nativeEndpoints = new HashMap<>();

    public MessageStreamGateway(Context context, Runnable activeDiscovery, NanWakeup nanWakeup) {
        this.context = context.getApplicationContext();
        this.activeDiscovery = activeDiscovery;
        this.nanWakeup = nanWakeup;
    }

    @Override
    public void onTransportConnection(long clientId, String peer) {
        Log.d(TAG, "native stream client connected: " + clientId + " peer=" + peer);
    }

    /** JNI callback for the native stream transport; JNI passes only the record bytes. */
    @Override
    public void onMessage(long clientId, byte[] record) {
        if (clientId != 0) onMessage(nativeEndpointFor(clientId), record);
    }

    /** Compatibility for existing prebuilt libdmesh.so calling onMessage(long, String). */
    @Override
    public void onMessage(long clientId, String recordStr) {
        if (clientId != 0 && recordStr != null) {
            onMessage(nativeEndpointFor(clientId), recordStr.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }


    @Override
    public void onMessageClosed(long clientId) {
        NativeEndpoint endpoint;
        synchronized (this) {
            endpoint = nativeEndpoints.remove(clientId);
        }
        if (endpoint != null) close(endpoint);
    }

    @Override
    public void onDiscoveryActive() {
        if (activeDiscovery != null) activeDiscovery.run();
    }

    @Override
    public void onNanWakeup(String target) {
        if (nanWakeup != null) nanWakeup.request(target);
    }

    @Override
    public void onInboundStream(long clientId, String host, int port, long streamHandle) {
        Log.d(TAG, "Unhandled native stream: client=" + clientId + " target=" + host + ':' + port);
        new MeshNativeStream(streamHandle).close();
    }

    @Override
    public void onForwardedStream(long connId, String host, int port, long streamHandle) {
        Log.d(TAG, "Unhandled forwarded native stream: client=" + connId
                + " target=" + host + ':' + port);
        new MeshNativeStream(streamHandle).close();
    }

    /** Delivers one complete bounded record from any supported transport. */
    public void onMessage(Endpoint endpoint, byte[] record) {
        final MeshStream stream;
        try {
            stream = CborMessageCodec.decode(record);
        } catch (IllegalArgumentException error) {
            Log.w(TAG, "invalid message record from " + endpoint.id(), error);
            return;
        }
        if (!forwardAppCommand(endpoint, stream)) send(endpoint, error(stream,
                "message requires a Rust-selected explicit intent: destination"));
    }

    /**
     * Binder ingress from an app. The Binder capability identifies app-dmesh;
     * routing remains inside this gateway rather than in the calling app.
     */
    public boolean onDirectMessage(MeshStream stream, IBinder callback) {
        Endpoint endpoint = new DirectEndpoint(callback);
        if (!forwardAppCommand(endpoint, stream)) {
            send(endpoint, error(stream,
                    "message requires a Rust-selected explicit intent: destination"));
            return false;
        }
        return true;
    }

    /** Releases all message and Android lifecycle state held for one transport connection. */
    public synchronized void close(Endpoint endpoint) {
        String endpointId = endpoint.id();
        String prefix = endpointId + ":";
        java.util.Iterator<Map.Entry<String, AppLease>> iterator = appConnections.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, AppLease> entry = iterator.next();
            if (entry.getKey().startsWith(prefix)) {
                entry.getValue().close();
                iterator.remove();
            }
        }
    }

    private boolean forwardAppCommand(Endpoint replyTo, MeshStream stream) {
        boolean intentTarget = stream.to != null && stream.to.startsWith("intent:");
        boolean appMethod = stream.method != null && stream.method.startsWith("app.");
        if (!intentTarget && !appMethod) return false;
        if (stream.method == null || stream.method.isEmpty()) {
            send(replyTo, error(stream, "DirectBinder target requires a method"));
            return true;
        }
        if (!intentTarget) {
            send(replyTo, error(stream, "app target requires an explicit intent: destination in to"));
            return true;
        }
        final Intent target;
        try {
            target = Intent.parseUri(stream.to, Intent.URI_INTENT_SCHEME);
        } catch (java.net.URISyntaxException error) {
            send(replyTo, error(stream, "invalid DirectBinder intent target: " + error.getMessage()));
            return true;
        }
        ComponentName component = target.getComponent();
        if (component == null) {
            send(replyTo, error(stream, "DirectBinder target intent must name an explicit service component"));
            return true;
        }
        directConnection(component, replyTo).sendStream(stream);
        return true;
    }

    private static MeshStream error(MeshStream request, String text) {
        MeshStream error = new MeshStream("app.error");
        error.replyTo = request.id;
        error.data.putString("error", text);
        return error;
    }

    private synchronized AppLease directConnection(ComponentName component, Endpoint replyTo) {
        String key = replyTo.id() + ":" + component.flattenToShortString();
        AppLease connection = appConnections.get(key);
        if (connection != null) return connection;
        connection = new AppLease(context, component, frame -> send(replyTo, frame));
        appConnections.put(key, connection);
        return connection;
    }

    private static boolean send(Endpoint endpoint, MeshStream stream) {
        return endpoint.send(CborMessageCodec.encode(stream));
    }

    private synchronized NativeEndpoint nativeEndpointFor(long clientId) {
        NativeEndpoint endpoint = nativeEndpoints.get(clientId);
        if (endpoint == null) {
            endpoint = new NativeEndpoint(clientId);
            nativeEndpoints.put(clientId, endpoint);
        }
        return endpoint;
    }

    /** Native direct-stream endpoint; other transports implement {@link Endpoint} themselves. */
    private static final class NativeEndpoint implements Endpoint {
        private final long clientId;

        NativeEndpoint(long clientId) {
            this.clientId = clientId;
        }

        @Override public String id() {
            return "native:" + clientId;
        }

        @Override public boolean send(byte[] record) {
            return MeshNode.sendBridgeMessage(clientId, record);
        }
    }

    /** Projects a gateway reply back to an Android app's DirectBinder callback. */
    private static final class DirectEndpoint implements Endpoint {
        private final IBinder callback;

        DirectEndpoint(IBinder callback) {
            this.callback = callback;
        }

        @Override public String id() {
            return "binder:" + System.identityHashCode(callback);
        }

        @Override public boolean send(byte[] record) {
            if (callback == null) return false;
            try {
                return DirectBinder.transact(callback, DirectBinder.TRANSACT_EVENT,
                        CborMessageCodec.decode(record), null, null);
            } catch (IllegalArgumentException error) {
                Log.w(TAG, "unable to project DirectBinder response", error);
                return false;
            }
        }
    }

    /**
     * Private app-dmesh lifecycle lease for a Rust-selected explicit app target.
     * It deliberately is not part of the app SDK: only the gateway is allowed
     * to activate another application.
     */
    private static final class AppLease implements AutoCloseable {
        private final Context context;
        private final ComponentName target;
        private final StreamReceiver receiver;
        private final ArrayList<MeshStream> pending = new ArrayList<>();
        private final HashSet<String> activeIds = new HashSet<>();
        private final Handler handler = new Handler(Looper.getMainLooper());
        private final DirectBinder callback;
        private long lastMessageAt;
        private IBinder remote;
        private ServiceConnection connection;

        AppLease(Context context, ComponentName target, StreamReceiver receiver) {
            this.context = context.getApplicationContext();
            this.target = target;
            this.receiver = receiver;
            callback = new DirectBinder((code, message, reply) -> {
                noteIncoming(message.stream);
                receiver.onStream(message.stream);
                return true;
            });
        }

        boolean sendStream(MeshStream stream) {
            if (remote == null) {
                pending.add(stream);
                bind();
                return true;
            }
            return sendNow(stream);
        }

        @Override public void close() {
            handler.removeCallbacksAndMessages(this);
            activeIds.clear();
            release();
        }

        private void bind() {
            if (connection != null) return;
            Intent intent = new Intent(DirectBinder.ACTION_DIRECT).setComponent(target);
            connection = new ServiceConnection() {
                @Override public void onServiceConnected(ComponentName name, IBinder service) {
                    remote = service;
                    ArrayList<MeshStream> copy = new ArrayList<>(pending);
                    pending.clear();
                    for (MeshStream stream : copy) sendNow(stream);
                }

                @Override public void onServiceDisconnected(ComponentName name) {
                    remote = null;
                    connection = null;
                }
            };
            if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                connection = null;
            }
        }

        private boolean sendNow(MeshStream stream) {
            if (remote == null) return false;
            noteOutgoing(stream);
            boolean sent = DirectBinder.transact(remote, DirectBinder.TRANSACT_MESSAGE,
                    stream, callback, null);
            if (!sent && stream != null && hasId(stream.id)) activeIds.remove(stream.id);
            if (!sent) scheduleRelease();
            return sent;
        }

        private void noteOutgoing(MeshStream stream) {
            lastMessageAt = SystemClock.elapsedRealtime();
            if (stream != null && hasId(stream.id)) activeIds.add(stream.id);
            handler.removeCallbacksAndMessages(this);
            if (stream == null || !hasId(stream.id)) scheduleRelease();
        }

        private void noteIncoming(MeshStream stream) {
            lastMessageAt = SystemClock.elapsedRealtime();
            if (stream != null && hasId(stream.replyTo)) activeIds.remove(stream.replyTo);
            scheduleRelease();
        }

        private void scheduleRelease() {
            if (!activeIds.isEmpty() || connection == null) return;
            handler.removeCallbacksAndMessages(this);
            long delay = Math.max(0L, MeshClient.IDLE_GRACE_MS
                    - (SystemClock.elapsedRealtime() - lastMessageAt));
            handler.postAtTime(this::releaseAfterIdle, this, SystemClock.uptimeMillis() + delay);
        }

        private void releaseAfterIdle() {
            if (activeIds.isEmpty()
                    && SystemClock.elapsedRealtime() - lastMessageAt >= MeshClient.IDLE_GRACE_MS) {
                release();
            } else {
                scheduleRelease();
            }
        }

        private void release() {
            if (connection != null) {
                try { context.unbindService(connection); } catch (Throwable ignored) { }
            }
            connection = null;
            remote = null;
            pending.clear();
        }

        private static boolean hasId(String id) {
            return id != null && !id.isEmpty();
        }
    }

    private interface StreamReceiver {
        void onStream(MeshStream stream);
    }

}
