package com.github.costinm.dmesh.wifi;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Opaque NAN match-filter/query bytes plus active/passive discovery options. */
public final class Discover {
    public final byte[] payload;
    public final List<String> options;

    public Discover(byte[] payload, List<String> options) {
        this.payload = payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length);
        this.options = options == null ? Collections.emptyList() : List.copyOf(options);
    }

    public static Discover empty() { return new Discover(new byte[0], Collections.emptyList()); }
    public boolean isEmpty() { return payload.length == 0; }
}
