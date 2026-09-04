package com.github.costinm.dmesh.wifi;

/**
 * Minimal discriminator for the common tagged-CBOR discovery envelope.
 *
 * Android leaves full control decoding to Rust. The radio owner only needs to
 * recognize the bounded directed {@code announce.discovery} request arriving through
 * Wi-Fi Aware so it can immediately re-emit the current local announce.
 */
final class DmeshControl {
    private static final int ANNOUNCE_COMPONENT = 6;
    private static final int ANNOUNCE_DISCOVERY = 2;

    private DmeshControl() { }

    static boolean isDiscoveryRequest(byte[] value) {
        if (value == null || value.length < 5) return false;
        // Canonical map: {1: control-component, 2: method, 5: config}. The
        // optional request id is key 3 and cannot precede keys 1 or 2.
        int offset = mapHeader(value, 0);
        if (offset < 0 || offset + 4 > value.length) return false;
        return value[offset] == 0x01 && uint(value, offset + 1) == ANNOUNCE_COMPONENT
                && value[offset + 2] == 0x02
                && uint(value, offset + 3) == ANNOUNCE_DISCOVERY;
    }

    private static int mapHeader(byte[] value, int offset) {
        int first = value[offset] & 0xff;
        if ((first & 0xe0) != 0xa0) return -1;
        int additional = first & 0x1f;
        if (additional < 24) return offset + 1;
        if (additional == 24 && offset + 1 < value.length) return offset + 2;
        return -1;
    }

    private static int uint(byte[] value, int offset) {
        if (offset >= value.length) return -1;
        int first = value[offset] & 0xff;
        if (first < 24) return first;
        return first == 0x18 && offset + 1 < value.length ? value[offset + 1] & 0xff : -1;
    }
}
