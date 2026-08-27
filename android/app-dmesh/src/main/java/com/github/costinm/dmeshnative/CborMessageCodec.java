package com.github.costinm.dmeshnative;

import android.os.Bundle;

import com.github.costinm.dmesh.DirectBinder;
import com.github.costinm.dmesh.MeshStream;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Small definite-length CBOR adapter for DMesh message envelopes. JNI carries
 * only these bytes; Android apps continue to use MeshStream and Bundle.
 */
public final class CborMessageCodec {
    private CborMessageCodec() {
    }

    public static byte[] encode(MeshStream stream) {
        return encodeBundle(stream.toDirectExtras());
    }

    /** Encode a bounded typed Bundle for a schema-owned platform adapter. */
    public static byte[] encodeBundle(Bundle bundle) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBundle(out, bundle);
        return out.toByteArray();
    }

    public static MeshStream decode(byte[] encoded) {
        Reader reader = new Reader(encoded);
        Bundle envelope = reader.readBundle();
        if (!reader.done()) throw new IllegalArgumentException("trailing CBOR data");
        return MeshStream.fromDirect(encoded, "cbor", envelope);
    }

    private static void writeBundle(ByteArrayOutputStream out, Bundle bundle) {
        Bundle value = bundle == null ? Bundle.EMPTY : bundle;
        ArrayList<String> keys = new ArrayList<>(value.keySet());
        Collections.sort(keys);
        writeType(out, 5, keys.size());
        for (String key : keys) {
            writeText(out, key);
            writeValue(out, value.get(key));
        }
    }

    private static void writeValue(ByteArrayOutputStream out, Object value) {
        if (value == null) {
            out.write(0xf6);
        } else if (value instanceof String) {
            writeText(out, (String) value);
        } else if (value instanceof Boolean) {
            out.write((Boolean) value ? 0xf5 : 0xf4);
        } else if (value instanceof Integer || value instanceof Long) {
            long number = ((Number) value).longValue();
            if (number >= 0) writeType(out, 0, number);
            else writeType(out, 1, -1L - number);
        } else if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            writeType(out, 2, bytes.length);
            out.write(bytes, 0, bytes.length);
        } else if (value instanceof Bundle) {
            writeBundle(out, (Bundle) value);
        } else if (value instanceof String[]) {
            String[] values = (String[]) value;
            writeType(out, 4, values.length);
            for (String item : values) writeText(out, item);
        } else if (value instanceof ArrayList<?>) {
            ArrayList<?> values = (ArrayList<?>) value;
            writeType(out, 4, values.size());
            for (Object item : values) writeValue(out, item);
        } else {
            throw new IllegalArgumentException("unsupported CBOR Bundle value "
                    + value.getClass().getName());
        }
    }

    private static void writeText(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeType(out, 3, bytes.length);
        out.write(bytes, 0, bytes.length);
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

        Reader(byte[] input) {
            this.input = input == null ? new byte[0] : input;
        }

        boolean done() { return offset == input.length; }

        Bundle readBundle() {
            Header header = header();
            if (header.major != 5) throw new IllegalArgumentException("CBOR message must be a map");
            if (header.value > 128) throw new IllegalArgumentException("CBOR map exceeds limit");
            Bundle bundle = new Bundle();
            for (int i = 0; i < header.value; i++) {
                String key = readText();
                put(bundle, key, readValue());
            }
            return bundle;
        }

        private Object readValue() {
            Header header = header();
            switch (header.major) {
                case 0: return integer(header.value);
                case 1: return integer(-1L - header.value);
                case 2: return readBytes(header.value);
                case 3: return readTextBytes(header.value);
                case 4: return readStringList(header.value);
                case 5: return readBundle(header.value);
                case 7:
                    if (header.additional == 20) return false;
                    if (header.additional == 21) return true;
                    if (header.additional == 22) return null;
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

        private Bundle readBundle(long count) {
            if (count > 128) throw new IllegalArgumentException("CBOR map exceeds limit");
            Bundle bundle = new Bundle();
            for (int i = 0; i < count; i++) put(bundle, readText(), readValue());
            return bundle;
        }

        private ArrayList<String> readStringList(long count) {
            if (count > 128) throw new IllegalArgumentException("CBOR array exceeds limit");
            ArrayList<String> values = new ArrayList<>((int) count);
            for (int i = 0; i < count; i++) {
                Object value = readValue();
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
            else if (value instanceof byte[]) bundle.putByteArray(key, (byte[]) value);
            else if (value instanceof Bundle) bundle.putBundle(key, (Bundle) value);
            else if (value instanceof ArrayList<?>) bundle.putStringArrayList(key, (ArrayList<String>) value);
            else throw new IllegalArgumentException("unsupported decoded CBOR value");
        }

        private String readText() { return readText(header()); }

        private String readText(Header header) {
            if (header.major != 3) throw new IllegalArgumentException("CBOR map key must be text");
            return readTextBytes(header.value);
        }

        private String readTextBytes(long count) {
            return new String(readBytes(count), StandardCharsets.UTF_8);
        }

        private byte[] readBytes(long count) {
            if (count < 0 || count > input.length - offset) throw new IllegalArgumentException("truncated CBOR");
            byte[] value = new byte[(int) count];
            System.arraycopy(input, offset, value, 0, value.length);
            offset += value.length;
            return value;
        }

        private Header header() {
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
            } else throw new IllegalArgumentException("indefinite CBOR is unsupported");
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
