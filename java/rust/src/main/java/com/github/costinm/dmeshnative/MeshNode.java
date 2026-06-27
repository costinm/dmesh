package com.github.costinm.dmeshnative;

public class MeshNode implements AutoCloseable {
    private long nativeHandle;
    private final String baseDir;
    private MeshCallback callback;

    static {
        Rust.loadLibrary();
    }

    public MeshNode(String baseDir) {
        this.baseDir = baseDir;
    }

    public void start(int sshPort, int httpPort) {
        nativeHandle = nativeStartMesh(baseDir, sshPort, httpPort);
        if (nativeHandle == 0) {
            throw new RuntimeException("Failed to start MeshNode");
        }
    }

    public void stop() {
        if (nativeHandle != 0) {
            nativeStop(nativeHandle);
            nativeHandle = 0;
        }
    }

    @Override
    public void close() {
        stop();
    }

    public long connect(String host, int port, String user, String serverKey) {
        return nativeConnect(nativeHandle, host, port, user, serverKey);
    }

    public String exec(long connId, String command) {
        return nativeExec(nativeHandle, connId, command);
    }

    public MeshStream openStream(long connId, String host, int port) {
        long streamHandle = nativeOpenStream(nativeHandle, connId, host, port);
        if (streamHandle == 0) {
            return null;
        }
        return new MeshStream(streamHandle);
    }

    public String getPublicKey() {
        return nativeGetPublicKey(nativeHandle);
    }

    public void addLocalForward(long connId, int localPort, String remoteHost, int remotePort) {
        nativeAddLocalForward(nativeHandle, connId, localPort, remoteHost, remotePort);
    }

    public int addRemoteForward(long connId, int remotePort, String localHost, int localPort) {
        return nativeAddRemoteForward(nativeHandle, connId, remotePort, localHost, localPort);
    }

    public void setCallback(MeshCallback callback) {
        this.callback = callback;
        nativeSetCallback(nativeHandle, callback);
    }

    public static long testTunFd(int fd) {
        return nativeTestTunFd(fd);
    }

    public static boolean sendBridgeJson(long clientId, String line) {
        return nativeSendBridgeMessage(clientId, line);
    }

    public interface MeshCallback {
        void onSshConnection(long clientId, String user);
        void onMessage(long clientId, String id, String uri, String[] keys, String[] values);
        void onStream(long clientId, String host, int port, long streamHandle);
        void onForwardedTcpip(long connId, String host, int port, long streamHandle);
    }

    private static native long nativeStartMesh(String baseDir, int sshPort, int httpPort);
    private native void nativeStop(long handle);
    private native long nativeConnect(long handle, String host, int port, String user, String serverKey);
    private native String nativeExec(long handle, long connId, String command);
    private native long nativeOpenStream(long handle, long connId, String host, int port);
    private static native String nativeGetPublicKey(long handle);
    private native void nativeAddLocalForward(long handle, long connId, int localPort, String remoteHost, int remotePort);
    private native int nativeAddRemoteForward(long handle, long connId, int remotePort, String localHost, int localPort);
    private native void nativeSetCallback(long handle, MeshCallback callback);
    private static native long nativeTestTunFd(int fd);
    private static native boolean nativeSendBridgeMessage(long clientId, String line);
}
