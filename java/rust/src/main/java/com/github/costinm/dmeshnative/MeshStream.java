package com.github.costinm.dmeshnative;

public class MeshStream implements AutoCloseable {
    private long nativeHandle;

    static {
        Rust.loadLibrary();
    }

    public MeshStream(long nativeHandle) {
        this.nativeHandle = nativeHandle;
    }

    public int read(byte[] buf) {
        if (nativeHandle == 0) {
            return -1;
        }
        return nativeStreamRead(nativeHandle, buf);
    }

    public void write(byte[] data) {
        if (nativeHandle != 0) {
            nativeStreamWrite(nativeHandle, data);
        }
    }

    @Override
    public void close() {
        if (nativeHandle != 0) {
            nativeStreamClose(nativeHandle);
            nativeHandle = 0;
        }
    }

    private static native int nativeStreamRead(long handle, byte[] buf);
    private static native void nativeStreamWrite(long handle, byte[] data);
    private static native void nativeStreamClose(long handle);
}
