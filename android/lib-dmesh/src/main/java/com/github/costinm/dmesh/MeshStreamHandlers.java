package com.github.costinm.dmesh;

import android.os.IBinder;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Named stream handlers usable through JNI, mesh streams, or DirectBinder. */
public final class MeshStreamHandlers {
    private final Map<String, MeshStreamHandler> handlers = new ConcurrentHashMap<>();

    public void register(String name, MeshStreamHandler handler) {
        if (name == null || name.isEmpty() || handler == null) {
            throw new IllegalArgumentException("handler name and implementation required");
        }
        handlers.put(name, handler);
    }

    public void unregister(String name) {
        if (name != null) handlers.remove(name);
    }

    public MeshStream handle(String name, MeshStream request) throws Exception {
        if (request == null) throw new IllegalArgumentException("missing stream request");
        MeshStreamHandler handler = handlers.get(name);
        if (handler == null) throw new IllegalArgumentException("unknown stream handler: " + name);
        MeshStream response = handler.handle(request);
        if (response == null) throw new IllegalStateException("stream handler returned no response");
        if (response.replyTo == null) response.replyTo = request.id;
        return response;
    }

    /** Raw CBOR boundary used by JNI; no Java objects cross the native boundary. */
    public byte[] handleRecord(String name, byte[] record) throws Exception {
        if (record == null || record.length > DirectBinder.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("stream handler request exceeds limit");
        }
        MeshStream response = handle(name, CborMessageCodec.decode(record));
        byte[] encoded = CborMessageCodec.encode(response);
        if (encoded.length > DirectBinder.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("stream handler response exceeds limit");
        }
        return encoded;
    }

    /** An app service may return this Binder from onBind to expose its handlers. */
    public IBinder asDirectBinder() {
        return new DirectBinder((code, message, reply) -> {
            MeshStream request = message.stream;
            if (request == null || request.method == null) return false;
            MeshStream response;
            try {
                response = handle(request.method, request);
            } catch (Exception error) {
                response = new MeshStream("stream.error");
                response.replyTo = request.id;
                response.data.putString("error", error.getMessage());
            }
            if (message.callback != null) {
                return DirectBinder.transactAsync(message.callback, DirectBinder.TRANSACT_EVENT,
                        response, null, null);
            }
            if (reply != null) {
                DirectBinder.writeReply(reply, response);
                return true;
            }
            return false;
        });
    }
}
