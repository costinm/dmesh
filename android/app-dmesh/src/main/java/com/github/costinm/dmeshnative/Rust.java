package com.github.costinm.dmeshnative;

/**
 * Android native library loader for the DMesh JNI bindings.
 */
public class Rust {
    private static boolean loaded = false;

    public static synchronized void loadLibrary() {
        if (loaded) {
            return;
        }

        System.loadLibrary("dmesh");
        loaded = true;
    }

    public static Rust load() {
        loadLibrary();
        return new Rust();
    }
}
