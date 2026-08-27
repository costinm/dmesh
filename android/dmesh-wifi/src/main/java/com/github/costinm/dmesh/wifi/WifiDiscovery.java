package com.github.costinm.dmesh.wifi;

import java.util.Arrays;

/** One opaque discovery record received by NAN or P2P service discovery. */
public final class WifiDiscovery {
    public final String bearer;
    public final String peer;
    public final byte[] payload;
    public final int rssi;
    public final long receivedElapsedMs;

    public WifiDiscovery(String bearer, String peer, byte[] payload, int rssi, long receivedElapsedMs) {
        this.bearer = bearer;
        this.peer = peer;
        this.payload = payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length);
        this.rssi = rssi;
        this.receivedElapsedMs = receivedElapsedMs;
    }
}
