package com.github.costinm.dmesh;

import android.os.Bundle;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.HashSet;

/**
 * Small definite-length CBOR adapter for DMesh message envelopes. JNI carries
 * only these bytes; Android apps continue to use MeshStream and Bundle.
 *
 * Besides the Bundle adapter this class exposes a generic value API used by
 * {@link Envelope} and generated marshalling: maps and lists encode with
 * their natural keys, integers decode as signed Long values, and
 * doubles use the 8-byte CBOR form. Decoding accepts definite-length values
 * only; tags, undefined and other simple values are rejected. Half, single and
 * double precision floats are supported. Limits are
 * 1 MiB input/output, 128 entries per container, 4096 values and 32 levels.
 * Duplicate map keys and trailing bytes are rejected.
 */
public final class CborMessageCodec {
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int MAX_ITEMS = 4096;
    private static final int MAX_DEPTH = 32;
    private static final int MAX_CONTAINER = 128;

    private CborMessageCodec() {
    }

    /** Encode one generic CBOR value (no Bundle required). */
    public static byte[] encodeValue(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeValue(out, value, 0, new int[1]);
        if (out.size() > MAX_BYTES) throw new IllegalArgumentException("CBOR output exceeds limit");
        return out.toByteArray();
    }

    /** Decode one generic CBOR value, rejecting trailing data. */
    public static Object decodeValue(byte[] bytes) {
        Reader reader = new Reader(bytes);
        Object value = reader.readGenericValue();
        if (!reader.done()) throw new IllegalArgumentException("trailing CBOR data");
        return value;
    }

    // Envelope keys are integer tags. Decode known fields normally and skip
    // unknown values without materializing their potentially extended CBOR.
    static Map<Object, Object> decodeEnvelopeMap(byte[] bytes) {
        Reader reader = new Reader(bytes);
        Map<Object, Object> value = reader.readEnvelopeMap();
        if (!reader.done()) throw new IllegalArgumentException("trailing CBOR data");
        return value;
    }

    public static byte[] encode(MeshStream stream) {
        return encodeBundle(stream.toDirectExtras());
    }

    /** Encode a bounded typed Bundle for a schema-owned platform adapter. */
    public static byte[] encodeBundle(Bundle bundle) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBundle(out, bundle, 0, new int[] {1});
        if (out.size() > MAX_BYTES) throw new IllegalArgumentException("CBOR output exceeds limit");
        return out.toByteArray();
    }

    public static MeshStream decode(byte[] encoded) {
        Reader reader = new Reader(encoded);
        Bundle envelope = reader.readBundle();
        if (!reader.done()) throw new IllegalArgumentException("trailing CBOR data");
        return MeshStream.fromDirect(encoded, "cbor", envelope);
    }

    private static void writeBundle(ByteArrayOutputStream out, Bundle bundle, int depth, int[] items) {
        Bundle value = bundle == null ? Bundle.EMPTY : bundle;
        ArrayList<String> keys = new ArrayList<>(value.keySet());
        Collections.sort(keys);
        checkContainer(keys.size());
        writeType(out, 5, keys.size());
        for (String key : keys) {
            writeValue(out, key, depth + 1, items);
            writeValue(out, value.get(key), depth + 1, items);
        }
    }

    private static void writeValue(ByteArrayOutputStream out, Object value, int depth, int[] items) {
        if (depth > MAX_DEPTH || ++items[0] > MAX_ITEMS) throw new IllegalArgumentException("CBOR nesting or item limit");
        if (out.size() > MAX_BYTES) throw new IllegalArgumentException("CBOR output exceeds limit");
        if (value == null) {
            out.write(0xf6);
        } else if (value instanceof String) {
            writeText(out, (String) value);
        } else if (value instanceof Boolean) {
            out.write((Boolean) value ? 0xf5 : 0xf4);
        } else if (value instanceof Float) {
            out.write(0xfa);
            int bits = Float.floatToRawIntBits((Float) value);
            for (int shift = 24; shift >= 0; shift -= 8) out.write(bits >>> shift);
        } else if (value instanceof Double) {
            out.write(0xfb);
            long bits = Double.doubleToRawLongBits(((Number) value).doubleValue());
            for (int shift = 56; shift >= 0; shift -= 8) out.write((int) (bits >>> shift));
        } else if (value instanceof Integer || value instanceof Long) {
            long number = ((Number) value).longValue();
            if (number >= 0) writeType(out, 0, number);
            else writeType(out, 1, -1L - number);
        } else if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            if (bytes.length > MAX_BYTES - out.size()) throw new IllegalArgumentException("CBOR output exceeds limit");
            writeType(out, 2, bytes.length);
            out.write(bytes, 0, bytes.length);
        } else if (value instanceof Bundle) {
            writeBundle(out, (Bundle) value, depth, items);
        } else if (value instanceof String[]) {
            String[] values = (String[]) value;
            checkContainer(values.length);
            writeType(out, 4, values.length);
            for (String item : values) writeValue(out, item, depth + 1, items);
        } else if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            checkContainer(map.size());
            writeType(out, 5, map.size());
            List<byte[]> encodedKeys = new ArrayList<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                ByteArrayOutputStream keyOut = new ByteArrayOutputStream();
                writeValue(keyOut, entry.getKey(), depth + 1, items);
                byte[] key = keyOut.toByteArray();
                if (key.length > MAX_BYTES - out.size()) throw new IllegalArgumentException("CBOR output exceeds limit");
                for (byte[] previous : encodedKeys) {
                    if (Arrays.equals(previous, key)) throw new IllegalArgumentException("duplicate CBOR map key");
                }
                encodedKeys.add(key);
                out.write(key, 0, key.length);
                writeValue(out, entry.getValue(), depth + 1, items);
            }
        } else if (value instanceof List) {
            List<?> values = (List<?>) value;
            checkContainer(values.size());
            writeType(out, 4, values.size());
            for (Object item : values) writeValue(out, item, depth + 1, items);
        } else {
            throw new IllegalArgumentException("unsupported CBOR Bundle value "
                    + value.getClass().getName());
        }
    }

    private static void writeText(ByteArrayOutputStream out, String value) {
        if (value.length() > MAX_BYTES - out.size()) throw new IllegalArgumentException("CBOR output exceeds limit");
        byte[] bytes;
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            if (encoded.remaining() > MAX_BYTES - out.size()) throw new IllegalArgumentException("CBOR output exceeds limit");
            bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("invalid UTF-16 text", e);
        }
        writeType(out, 3, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    private static void checkContainer(long count) {
        if (count < 0 || count > MAX_CONTAINER) throw new IllegalArgumentException("CBOR container exceeds limit");
    }

    private static void writeType(ByteArrayOutputStream out, int major, long value) {
        if (value < 0) throw new IllegalArgumentException("negative CBOR length");
        int prefix = major << 5;
        if (value < 24) out.write(prefix | (int) value);
        else if (value <= 0xff) { out.write(prefix | 24); out.write((int) value); }
        else if (value <= 0xffff) {
            out.write(prefix | 25); out.write((int) (value >>> 8)); out.write((int) value);
        } else if (value <= 0xffff_ffffL) {
            out.write(prefix | 26);
            for (int shift = 24; shift >= 0; shift -= 8) out.write((int) (value >>> shift));
        } else {
            out.write(prefix | 27);
            for (int shift = 56; shift >= 0; shift -= 8) out.write((int) (value >>> shift));
        }
    }

    private static final class Reader {
        private final byte[] input;
        private int offset;
        private int items;

        Reader(byte[] input) {
            this.input = input == null ? new byte[0] : input;
            if (this.input.length > MAX_BYTES) throw new IllegalArgumentException("CBOR input exceeds limit");
        }

        boolean done() { return offset == input.length; }

        Map<Object, Object> readEnvelopeMap() {
            checkValue(0);
            Header root = header();
            if (root.major != 5) throw new IllegalArgumentException("tagged record must be a CBOR map");
            checkContainer(root.value);
            Map<Object, Object> known = new LinkedHashMap<>();
            HashSet<String> seen = new HashSet<>();
            for (int i = 0; i < root.value; i++) {
                checkValue(1);
                Header key = header();
                if (key.major != 0 && key.major != 1) {
                    throw new IllegalArgumentException("record envelope keys must be integers");
                }
                // Keep the full unsigned argument bits, including unknown keys above Long.MAX_VALUE.
                if (!seen.add(key.major + ":" + Long.toHexString(key.value))) throw new IllegalArgumentException("duplicate CBOR map key");
                boolean selected = key.major == 0 && (key.value == 1 || key.value == 2
                        || key.value == 3 || key.value == 5 || key.value == 6
                        || key.value == 7 || key.value == 9 || key.value == 10);
                if (selected) known.put(Long.valueOf(key.value), readGenericValue(1));
                else skipValue();
            }
            return known;
        }

        /** Skip one item iteratively. Frames track definite or indefinite containers. */
        private void skipValue() {
            int[] kind = new int[MAX_DEPTH + 1];
            int[] remaining = new int[MAX_DEPTH + 1];
            int[] count = new int[MAX_DEPTH + 1];
            int level = 0;
            // A synthetic definite container holds the value at envelope depth 1.
            remaining[0] = 1;
            while (level >= 0) {
                if (remaining[level] == 0) { level--; continue; }
                if (offset >= input.length) throw new IllegalArgumentException("truncated CBOR");
                if ((input[offset] & 0xff) == 0xff) {
                    if (remaining[level] != -1 || (kind[level] == 5 && (count[level] & 1) != 0)) {
                        throw new IllegalArgumentException("unexpected CBOR break");
                    }
                    offset++;
                    level--;
                    continue;
                }
                if (remaining[level] > 0) remaining[level]--;
                if (++count[level] > (kind[level] == 5 ? 2 * MAX_CONTAINER : MAX_CONTAINER)) {
                    throw new IllegalArgumentException("CBOR container exceeds limit");
                }
                checkValue(level + 1);
                Header h = header(true);
                boolean indefinite = h.additional == 31;
                if (kind[level] == 2 || kind[level] == 3) {
                    if (h.major != kind[level] || indefinite) throw new IllegalArgumentException("invalid CBOR string chunk");
                }
                switch (h.major) {
                    case 0: case 1:
                        if (indefinite) throw new IllegalArgumentException("invalid CBOR integer");
                        break;
                    case 2: case 3:
                        if (!indefinite) {
                            if (h.value < 0 || h.value > input.length - offset) throw new IllegalArgumentException("truncated CBOR string");
                            offset += (int) h.value;
                            break;
                        }
                        // Indefinite strings contain only definite chunks of the same major type.
                        if (++level >= kind.length) throw new IllegalArgumentException("CBOR nesting limit");
                        kind[level] = h.major; remaining[level] = -1; count[level] = 0;
                        break;
                    case 4: case 5:
                        if (!indefinite) checkContainer(h.value);
                        if (++level >= kind.length) throw new IllegalArgumentException("CBOR nesting limit");
                        kind[level] = h.major; remaining[level] = indefinite ? -1 : (int) h.value * (h.major == 5 ? 2 : 1); count[level] = 0;
                        break;
                    case 6:
                        if (indefinite) throw new IllegalArgumentException("invalid CBOR tag");
                        if (++level >= kind.length) throw new IllegalArgumentException("CBOR nesting limit");
                        kind[level] = 6; remaining[level] = 1; count[level] = 0;
                        break;
                    case 7:
                        if (indefinite || (h.additional == 24 && h.value < 32)) throw new IllegalArgumentException("invalid CBOR simple value");
                        break;
                    default: throw new IllegalArgumentException("invalid CBOR type");
                }
            }
        }

        /**
         * Decode one generic CBOR value. Maps become LinkedHashMap with
         * natural keys, arrays become ArrayList, integers stay Long so
         * numeric field tags keep a stable key type, and doubles decode to
         * Double. Used by {@link Envelope#decode(byte[])}.
         */
        Object readGenericValue() { return readGenericValue(0); }

        private Object readGenericValue(int depth) {
            checkValue(depth);
            Header header = header();
            switch (header.major) {
                case 0: return Long.valueOf(signedArgument(header));
                case 1: return Long.valueOf(-1L - signedArgument(header));
                case 2: return readBytes(header.value);
                case 3: return readTextBytes(header.value);
                case 4: {
                    checkContainer(header.value);
                    ArrayList<Object> values = new ArrayList<>((int) header.value);
                    for (int i = 0; i < header.value; i++) values.add(readGenericValue(depth + 1));
                    return values;
                }
                case 5: {
                    checkContainer(header.value);
                    LinkedHashMap<Object, Object> map = new LinkedHashMap<>();
                    for (int i = 0; i < header.value; i++) {
                        Object key = readGenericValue(depth + 1);
                        for (Object existing : map.keySet()) {
                            if (Objects.deepEquals(existing, key)) throw new IllegalArgumentException("duplicate CBOR map key");
                        }
                        map.put(key, readGenericValue(depth + 1));
                    }
                    return map;
                }
                case 7:
                    if (header.additional == 20) return Boolean.FALSE;
                    if (header.additional == 21) return Boolean.TRUE;
                    if (header.additional == 22) return null;
                    if (header.additional == 25) return halfFloat((int) header.value);
                    if (header.additional == 26)
                        return Float.intBitsToFloat((int) header.value);
                    if (header.additional == 27)
                        return Double.longBitsToDouble(header.value);
                    // fall through
                default: throw new IllegalArgumentException("unsupported CBOR type");
            }
        }

        Bundle readBundle() {
            checkValue(0);
            Header header = header();
            if (header.major != 5) throw new IllegalArgumentException("CBOR message must be a map");
            checkContainer(header.value);
            Bundle bundle = new Bundle();
            for (int i = 0; i < header.value; i++) {
                String key = readText();
                if (bundle.containsKey(key)) throw new IllegalArgumentException("duplicate CBOR map key");
                put(bundle, key, readValue(1));
            }
            return bundle;
        }

        private Object readValue(int depth) {
            checkValue(depth);
            Header header = header();
            switch (header.major) {
                case 0: return integer(signedArgument(header));
                case 1: return integer(-1L - signedArgument(header));
                case 2: return readBytes(header.value);
                case 3: return readTextBytes(header.value);
                case 4: return readStringList(header.value, depth);
                case 5: return readBundle(header.value, depth);
                case 7:
                    if (header.additional == 20) return false;
                    if (header.additional == 21) return true;
                    if (header.additional == 22) return null;
                    if (header.additional == 25) return halfFloat((int) header.value);
                    if (header.additional == 26) return Float.intBitsToFloat((int) header.value);
                    if (header.additional == 27) return Double.longBitsToDouble(header.value);
                    // fall through
                default: throw new IllegalArgumentException("unsupported CBOR type");
            }
        }

        private Object integer(long value) {
            if (value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE) {
                return Integer.valueOf((int) value);
            }
            return Long.valueOf(value);
        }

        private Bundle readBundle(long count, int depth) {
            checkContainer(count);
            Bundle bundle = new Bundle();
            for (int i = 0; i < count; i++) {
                String key = readText(depth + 1);
                if (bundle.containsKey(key)) throw new IllegalArgumentException("duplicate CBOR map key");
                put(bundle, key, readValue(depth + 1));
            }
            return bundle;
        }

        private ArrayList<String> readStringList(long count, int depth) {
            checkContainer(count);
            ArrayList<String> values = new ArrayList<>((int) count);
            for (int i = 0; i < count; i++) {
                Object value = readValue(depth + 1);
                if (!(value instanceof String)) throw new IllegalArgumentException("CBOR array is not String[]");
                values.add((String) value);
            }
            return values;
        }

        @SuppressWarnings("unchecked")
        private void put(Bundle bundle, String key, Object value) {
            if (value == null) bundle.putString(key, null);
            else if (value instanceof String) bundle.putString(key, (String) value);
            else if (value instanceof Boolean) bundle.putBoolean(key, (Boolean) value);
            else if (value instanceof Integer) bundle.putInt(key, (Integer) value);
            else if (value instanceof Long) bundle.putLong(key, (Long) value);
            else if (value instanceof Float) bundle.putFloat(key, (Float) value);
            else if (value instanceof Double) bundle.putDouble(key, (Double) value);
            else if (value instanceof byte[]) bundle.putByteArray(key, (byte[]) value);
            else if (value instanceof Bundle) bundle.putBundle(key, (Bundle) value);
            else if (value instanceof ArrayList<?>) bundle.putStringArrayList(key, (ArrayList<String>) value);
            else throw new IllegalArgumentException("unsupported decoded CBOR value");
        }

        private String readText() { return readText(1); }

        private String readText(int depth) {
            checkValue(depth);
            return readText(header());
        }

        private String readText(Header header) {
            if (header.major != 3) throw new IllegalArgumentException("CBOR map key must be text");
            return readTextBytes(header.value);
        }

        private String readTextBytes(long count) {
            try {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(readBytes(count))).toString();
            } catch (CharacterCodingException e) {
                throw new IllegalArgumentException("invalid UTF-8", e);
            }
        }

        private byte[] readBytes(long count) {
            if (count < 0 || count > input.length - offset) throw new IllegalArgumentException("truncated CBOR");
            byte[] value = new byte[(int) count];
            System.arraycopy(input, offset, value, 0, value.length);
            offset += value.length;
            return value;
        }

        private void checkValue(int depth) {
            if (depth > MAX_DEPTH || ++items > MAX_ITEMS) throw new IllegalArgumentException("CBOR nesting or item limit");
        }

        private double halfFloat(int bits) {
            int exponent = (bits >>> 10) & 31;
            int fraction = bits & 1023;
            double magnitude;
            if (exponent == 31) magnitude = fraction == 0 ? Double.POSITIVE_INFINITY : Double.NaN;
            else if (exponent == 0) magnitude = Math.scalb((double) fraction, -24);
            else magnitude = Math.scalb((double) (1024 + fraction), exponent - 25);
            return (bits & 0x8000) == 0 ? magnitude : -magnitude;
        }

        private long signedArgument(Header header) {
            if (header.value < 0) throw new IllegalArgumentException("CBOR integer outside signed 64-bit range");
            return header.value;
        }

        private Header header() { return header(false); }

        private Header header(boolean allowIndefinite) {
            if (offset >= input.length) throw new IllegalArgumentException("truncated CBOR");
            int first = input[offset++] & 0xff;
            int additional = first & 31;
            long value;
            if (additional < 24) value = additional;
            else if (additional == 24) value = next();
            else if (additional == 25) value = (next() << 8) | next();
            else if (additional == 26) {
                value = 0;
                for (int i = 0; i < 4; i++) value = (value << 8) | next();
            } else if (additional == 27) {
                value = 0;
                for (int i = 0; i < 8; i++) value = (value << 8) | next();
            } else if (additional == 31 && allowIndefinite) value = 0;
            else throw new IllegalArgumentException("reserved or indefinite CBOR head");
            return new Header(first >>> 5, additional, value);
        }

        private int next() {
            if (offset >= input.length) throw new IllegalArgumentException("truncated CBOR");
            return input[offset++] & 0xff;
        }
    }

    private static final class Header {
        final int major;
        final int additional;
        final long value;
        Header(int major, int additional, long value) {
            this.major = major;
            this.additional = additional;
            this.value = value;
        }
    }
}
