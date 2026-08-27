package com.github.costinm.dmesh;

import android.os.Bundle;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Transport-neutral Java projection of one mesh stream's metadata and bounded
 * initial body. It is the common shape for an HTTP/2 request, SSH channel,
 * QUIC-lite stream, or DirectBinder rendezvous. {@link #payload} is the
 * bounded body; the optional full-duplex FD stream is carried separately by
 * the selected transport.
 */
public class MeshStream {
    public String id;
    public String replyTo;
    public String session;
    public String stream;
    public String type;
    public String from;
    public String to;
    public String method;
    public String uri;
    /** Opaque bounded body, normally CBOR. */
    public byte[] payload = new byte[0];
    /** Payload representation; Binder itself remains encoding-neutral. */
    public String encoding = "cbor";
    /** Typed Android projection of the schema-owned body map. */
    public Bundle data = new Bundle();
    /** Legacy string-only compatibility view; do not add new uses. */
    public final LinkedHashMap<String, String> fields = new LinkedHashMap<>();

    public MeshStream(String method) {
        this.method = method;
        this.uri = method;
    }

    /** Project one DirectBinder envelope into the portable stream shape. */
    public static MeshStream fromDirect(byte[] payload, String encoding, Bundle extras) {
        MeshStream stream = new MeshStream(extras == null ? null : extras.getString(DirectBinder.METHOD));
        if (extras != null) {
            stream.id = extras.getString(DirectBinder.ID);
            stream.replyTo = extras.getString(DirectBinder.REPLY_TO);
            stream.session = extras.getString(DirectBinder.SESSION);
            stream.stream = extras.getString(DirectBinder.STREAM);
            stream.type = extras.getString(DirectBinder.TYPE);
            stream.from = extras.getString(DirectBinder.FROM);
            stream.to = extras.getString(DirectBinder.TO);
            Bundle typedData = extras.getBundle("data");
            if (typedData != null) {
                stream.data = new Bundle(typedData);
                for (String key : typedData.keySet()) {
                    Object value = typedData.get(key);
                    if (value instanceof String) stream.fields.put(key, (String) value);
                }
            }
        }
        stream.payload = payload == null ? new byte[0] : payload;
        stream.encoding = encoding == null || encoding.isEmpty() ? "cbor" : encoding;
        return stream;
    }

    /** Encodes Java-visible metadata for DirectBinder without decoding the body. */
    public Bundle toDirectExtras() {
        Bundle extras = DirectBinder.envelope(id, method, to, from);
        putBundle(extras, DirectBinder.REPLY_TO, replyTo);
        putBundle(extras, DirectBinder.SESSION, session);
        putBundle(extras, DirectBinder.STREAM, stream);
        putBundle(extras, DirectBinder.TYPE, type);
        Bundle typedData = new Bundle(data);
        for (Map.Entry<String, String> field : fields.entrySet()) {
            if (!typedData.containsKey(field.getKey())) {
                typedData.putString(field.getKey(), field.getValue());
            }
        }
        if (!typedData.isEmpty()) extras.putBundle("data", typedData);
        return extras;
    }

    private static void putBundle(Bundle extras, String key, String value) {
        if (value != null && !value.isEmpty()) extras.putString(key, value);
    }

}
