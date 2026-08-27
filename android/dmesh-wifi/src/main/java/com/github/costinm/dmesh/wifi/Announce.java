package com.github.costinm.dmesh.wifi;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Opaque common announce bytes plus radio-specific publish options. */
public final class Announce {
    public final byte[] payload;
    public final List<String> options;

    public Announce(byte[] payload, List<String> options) {
        this.payload = payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length);
        this.options = options == null ? Collections.emptyList() : List.copyOf(options);
    }

    public static Announce empty() { return new Announce(new byte[0], Collections.emptyList()); }
    public boolean isEmpty() { return payload.length == 0; }
}
