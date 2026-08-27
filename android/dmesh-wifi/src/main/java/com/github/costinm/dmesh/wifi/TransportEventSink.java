package com.github.costinm.dmesh.wifi;

/** One-way platform event boundary for all Android transports. */
public interface TransportEventSink {
    TransportEventSink NONE = (transport, event, payload) -> { };
    void onTransportEvent(String transport, String event, byte[] payload);

    /** Structured BLE discovery metadata; the adapter forwards opaque bytes to Rust. */
    default void onBleDiscovery(String address, int rssi, byte[] serviceData) {
    }
}
