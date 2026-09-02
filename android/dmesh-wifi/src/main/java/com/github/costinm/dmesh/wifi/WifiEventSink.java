package com.github.costinm.dmesh.wifi;

/** Optional observer for status and opaque service-discovery records. */
public interface WifiEventSink {
    default void onEvent(String event) { }
    default void onDiscovered(WifiDiscovery discovery) { }

    /**
     * One ordinary packet received through a platform discovery bearer.
     *
     * NAN Follow-ups arrive here as a Wi-Fi Aware directed message.  The
     * consumer owns decoding and inventory admission so this remains the same
     * observation path used by every bearer rather than a Java-only follow-up
     * protocol.
     */
    default void onReceived(String transport, String peer, byte[] payload, int rssiDbm) { }
}
