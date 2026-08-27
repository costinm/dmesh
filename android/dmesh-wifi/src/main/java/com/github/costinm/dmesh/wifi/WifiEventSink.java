package com.github.costinm.dmesh.wifi;

/** Optional observer for status and opaque service-discovery records. */
public interface WifiEventSink {
    default void onEvent(String event) { }
    default void onDiscovered(WifiDiscovery discovery) { }
}
