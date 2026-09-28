package com.github.costinm.dmesh;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tagged record envelope shared by requests and responses on the DMesh wire.
 *
 * Envelope keys follow the common tagged-CBOR contract: {@code 1} component,
 * {@code 2} method (numeric tag or text name), {@code 3} id, {@code 5} field
 * map, {@code 6} result, {@code 7} error, {@code 9} {@code to}, {@code 10}
 * binary payload. Typed field maps use numeric tags as {@link Long} keys so
 * decoded and generated code agree without a schema. Generated marshalling
 * classes and DirectBinder handlers build on this type; whole envelopes
 * marshal to {@code byte[]} through {@link CborMessageCodec}.
 */
public final class Envelope {
    public Long componentTag;
    public String componentName;
    public Long methodTag;
    public String methodName;
    public Object id;
    public final Map<Object, Object> env = new LinkedHashMap<>();
    public Object result;
    public Object error;
    public Object to;
    public byte[] data;

    /** Encode the envelope as definite-length CBOR. */
    public byte[] encode() {
        Map<Object, Object> root = new LinkedHashMap<>();
        if (componentTag != null) root.put(1, componentTag);
        else if (componentName != null) root.put(1, componentName);
        if (methodTag != null) root.put(2, methodTag);
        else if (methodName != null) root.put(2, methodName);
        if (id != null) root.put(3, id);
        if (!env.isEmpty()) root.put(5, env);
        if (result != null) root.put(6, result);
        if (error != null) root.put(7, error);
        if (to != null) root.put(9, to);
        if (data != null) root.put(10, data);
        return CborMessageCodec.encodeValue(root);
    }

    /** Decode one tagged record envelope, ignoring unknown keys. */
    public static Envelope decode(byte[] bytes) {
        Object value = CborMessageCodec.decodeValue(bytes);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("tagged record must be a CBOR map");
        }
        Envelope envelope = new Envelope();
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
            if (!(entry.getKey() instanceof Number)) {
                throw new IllegalArgumentException("record envelope keys must be integers");
            }
            Object fieldValue = entry.getValue();
            switch (((Number) entry.getKey()).intValue()) {
                case 1:
                    if (fieldValue instanceof Number) {
                        envelope.componentTag = ((Number) fieldValue).longValue();
                    } else {
                        envelope.componentName = String.valueOf(fieldValue);
                    }
                    break;
                case 2:
                    if (fieldValue instanceof Number) {
                        envelope.methodTag = ((Number) fieldValue).longValue();
                    } else {
                        envelope.methodName = String.valueOf(fieldValue);
                    }
                    break;
                case 3:
                    envelope.id = fieldValue;
                    break;
                case 5:
                    if (!(fieldValue instanceof Map)) {
                        throw new IllegalArgumentException("record fields must be a map");
                    }
                    envelope.env.putAll((Map<?, ?>) fieldValue);
                    break;
                case 6:
                    envelope.result = fieldValue;
                    break;
                case 7:
                    envelope.error = fieldValue;
                    break;
                case 9:
                    envelope.to = fieldValue;
                    break;
                case 10:
                    envelope.data = (byte[]) fieldValue;
                    break;
                default:
                    break;
            }
        }
        return envelope;
    }

    /** Put one numeric-tagged request field. */
    public void putField(long tag, Object value) {
        env.put(tag, value);
    }

    /** Read one numeric-tagged request field. */
    public Object getField(long tag) {
        return env.get(tag);
    }

    /** Put one numeric-tagged response field, creating the result map. */
    @SuppressWarnings("unchecked")
    public void putResultField(long tag, Object value) {
        if (!(result instanceof Map)) {
            result = new LinkedHashMap<Object, Object>();
        }
        ((Map<Object, Object>) result).put(tag, value);
    }

    /** Read one numeric-tagged response field. */
    public Object getResultField(long tag) {
        return result instanceof Map ? ((Map<?, ?>) result).get(tag) : null;
    }

    public static List<Object> asList(Object value) {
        return new ArrayList<>((List<?>) value);
    }

    public static List<Integer> asIntList(Object value) {
        List<Integer> out = new ArrayList<>();
        for (Object item : (List<?>) value) out.add(((Number) item).intValue());
        return out;
    }

    public static List<Long> asLongList(Object value) {
        List<Long> out = new ArrayList<>();
        for (Object item : (List<?>) value) out.add(((Number) item).longValue());
        return out;
    }

    public static List<Double> asDoubleList(Object value) {
        List<Double> out = new ArrayList<>();
        for (Object item : (List<?>) value) out.add(((Number) item).doubleValue());
        return out;
    }

    public static List<String> asStringList(Object value) {
        List<String> out = new ArrayList<>();
        for (Object item : (List<?>) value) out.add((String) item);
        return out;
    }
}
