package com.github.costinm.dmesh;

import org.junit.Test;
import android.os.Bundle;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Arrays;
import static org.junit.Assert.*;

public class CborMessageCodecTest {
    private static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }
    private static void invalid(String s) {
        try { CborMessageCodec.decodeValue(hex(s)); fail(s); }
        catch (IllegalArgumentException expected) { }
    }
    @Test public void integerBoundaries() {
        long[] values = {23, 24, 255, 256, 65535, 65536, Long.MAX_VALUE, Long.MIN_VALUE};
        String[] wire = {"17", "1818", "18ff", "190100", "19ffff", "1a00010000", "1b7fffffffffffffff", "3b7fffffffffffffff"};
        for (int i = 0; i < values.length; i++) {
            assertArrayEquals(hex(wire[i]), CborMessageCodec.encodeValue(values[i]));
            assertEquals(values[i], CborMessageCodec.decodeValue(hex(wire[i])));
        }
        String[] encoded = {"1b8000000000000000", "1bffffffffffffffff", "3b8000000000000000", "3bffffffffffffffff"};
        for (String s : encoded) invalid(s);
        try { CborMessageCodec.encodeValue(new java.math.BigInteger("1")); fail(); } catch (IllegalArgumentException expected) { }
        try { CborMessageCodec.encodeValue(new java.math.BigDecimal("1")); fail(); } catch (IllegalArgumentException expected) { }
    }
    @Test public void strictTypesAndMalformed() {
        assertNull(CborMessageCodec.decodeValue(hex("f6")));
        assertEquals(false, CborMessageCodec.decodeValue(hex("f4")));
        assertEquals(true, CborMessageCodec.decodeValue(hex("f5")));
        assertArrayEquals(hex("f7"), (byte[]) CborMessageCodec.decodeValue(hex("41f7")));
        assertEquals("a", CborMessageCodec.decodeValue(hex("6161")));
        assertArrayEquals(hex("fb3ff8000000000000"), CborMessageCodec.encodeValue(1.5));
        assertEquals(1.5, CborMessageCodec.decodeValue(hex("fb3ff8000000000000")));
        for (String s : Arrays.asList("f7", "1f", "ff", "1c", "a101", "1901", "61ff", "61c0", "0102", "c001", "a201010102", "9b8000000000000000", "bbffffffffffffffff", "5bffffffffffffffff")) invalid(s);
    }
    @Test public void limitsAndEnvelope() {
        byte[] nested = new byte[35]; Arrays.fill(nested, (byte) 0x81); nested[34] = 0;
        try { CborMessageCodec.decodeValue(nested); fail(); } catch (IllegalArgumentException expected) { }
        try { CborMessageCodec.decodeValue(new byte[1024 * 1024 + 1]); fail(); } catch (IllegalArgumentException expected) { }
        Object value = 0L;
        for (int i = 0; i < 34; i++) value = Arrays.asList(value);
        try { CborMessageCodec.encodeValue(value); fail(); } catch (IllegalArgumentException expected) { }
        Envelope envelope = new Envelope(); envelope.componentTag = 49L; envelope.methodName = "status";
        envelope.putField(1, "hello"); envelope.putField(2, new byte[] {(byte) 0xf7});
        Envelope decoded = Envelope.decode(envelope.encode());
        assertEquals(envelope.componentTag, decoded.componentTag); assertEquals("status", decoded.methodName);
        assertEquals("hello", decoded.getField(1)); assertArrayEquals(new byte[] {(byte) 0xf7}, (byte[]) decoded.getField(2));
    }
    @Test public void halfFloats() {
        assertEquals(1.5, (Double) CborMessageCodec.decodeValue(hex("f93e00")), 0);
        assertEquals(Math.scalb(1.0, -24), (Double) CborMessageCodec.decodeValue(hex("f90001")), 0);
        assertEquals(Double.NEGATIVE_INFINITY, (Double) CborMessageCodec.decodeValue(hex("f9fc00")), 0);
        assertTrue(Double.isNaN((Double) CborMessageCodec.decodeValue(hex("f97e00"))));
    }
    @Test public void duplicateEncodedKeys() {
        Map<Object, Object> map = new LinkedHashMap<>(); map.put(1, "a"); map.put(1L, "b");
        try { CborMessageCodec.encodeValue(map); fail(); } catch (IllegalArgumentException expected) { }
        map.clear(); map.put("a", 1); map.put(new byte[] {97}, 2);
        assertEquals(2, ((Map<?, ?>) CborMessageCodec.decodeValue(CborMessageCodec.encodeValue(map))).size());
    }
    @Test public void envelopeTagsAreExact() {
        assertNull(Envelope.decode(hex("a11b0000000100000001182a")).componentTag);
        assertNull(Envelope.decode(hex("a11bffffffffffffffff182a")).componentTag);
        assertEquals(Long.valueOf(49), Envelope.decode(hex("a20118311bfffffffffffffffff6")).componentTag);
        try { Envelope.decode(hex("a21bfffffffffffffffff61bfffffffffffffffff6")); fail(); } catch (IllegalArgumentException expected) { }
        for (String s : Arrays.asList("a1fb3ff0000000000000182a", "a1011b8000000000000000", "a102fb3ff0000000000000")) {
            try { Envelope.decode(hex(s)); fail(s); } catch (IllegalArgumentException expected) { }
        }
    }
    @Test public void bundleFloatRoundTrip() {
        Bundle data = new Bundle(); data.putFloat("finite", 1.5f); data.putFloat("inf", Float.POSITIVE_INFINITY);
        data.putDouble("nan", Double.NaN); data.putDouble("negative", -2.25);
        Bundle root = new Bundle(); root.putBundle("data", data);
        MeshStream decoded = CborMessageCodec.decode(CborMessageCodec.encodeBundle(root));
        assertEquals(1.5f, (Float) decoded.data.get("finite"), 0);
        assertEquals(Float.POSITIVE_INFINITY, (Float) decoded.data.get("inf"), 0);
        assertTrue(Double.isNaN((Double) decoded.data.get("nan")));
        assertEquals(-2.25, (Double) decoded.data.get("negative"), 0);
        try { CborMessageCodec.decode(hex("a161781b8000000000000000")); fail(); } catch (IllegalArgumentException expected) { }
    }

    @Test public void unknownExtendedFieldsAreSkipped() {
        String[] values = {"c1f7", "f93e00", "fa3f800000", "fb3ff0000000000000", "f7", "f820",
                "9f01bf0102ffff", "5f41014102ff", "7f61616162ff", "bf0102ff", "61ff"};
        for (String value : values) {
            Envelope envelope = Envelope.decode(hex("a20118311864" + value));
            assertEquals(Long.valueOf(49), envelope.componentTag);
        }
        assertEquals(Long.valueOf(49), Envelope.decode(hex("a20118311b0000000100000001f7")).componentTag);
        assertNull(Envelope.decode(hex("a106f6")).result);
    }

    @Test public void unknownMalformedFieldsAndKnownExtensionsReject() {
        String[] bad = {"ff", "1f", "1c", "f818", "c1ff", "9bffffffffffffffffff",
                "bfffffffffffffffffff", "bf01ff", "5f6161ff", "7f5fffff", "9f01", "5f4101", "5bffffffffffffffff"};
        for (String value : bad) {
            try { Envelope.decode(hex("a11864" + value)); fail(value); }
            catch (IllegalArgumentException expected) { }
        }
        for (String input : Arrays.asList("a106f7", "a106c101", "a1069f01ff", "a21864f71864f6", "a11864f700")) {
            try { Envelope.decode(hex(input)); fail(input); } catch (IllegalArgumentException expected) { }
        }
        byte[] nested = new byte[39];
        nested[0] = (byte) 0xa1; nested[1] = 0x18; nested[2] = 0x64;
        Arrays.fill(nested, 3, 38, (byte) 0x81); nested[38] = 0;
        try { Envelope.decode(nested); fail(); } catch (IllegalArgumentException expected) { }
    }

}
