package com.github.costinm.dmeshnative;

/** Native-handle wrapper for a live Rust stream endpoint. */
public class MeshNativeStream implements AutoCloseable {
    private long nativeHandle;

    static {
        Rust.loadLibrary();
    }

    public MeshNativeStream(long nativeHandle) {
        this.nativeHandle = nativeHandle;
    }

    public int read(byte[] buf) {
        return nativeHandle == 0 ? -1 : nativeStreamRead(nativeHandle, buf);
    }

    public void write(byte[] data) {
        if (nativeHandle != 0) nativeStreamWrite(nativeHandle, data);
    }

    @Override public void close() {
        if (nativeHandle != 0) {
            nativeStreamClose(nativeHandle);
            nativeHandle = 0;
        }
    }

    private static native int nativeStreamRead(long handle, byte[] buf);
    private static native void nativeStreamWrite(long handle, byte[] data);
    private static native void nativeStreamClose(long handle);
}
