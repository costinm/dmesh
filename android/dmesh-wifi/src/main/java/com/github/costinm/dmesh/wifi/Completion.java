package com.github.costinm.dmesh.wifi;

/** Receives one terminal result on the Wi-Fi controller callback thread. */
@FunctionalInterface
public interface Completion<T> {
    void complete(T value);
}
