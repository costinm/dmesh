package com.github.costinm.dmeshnative;

import java.nio.charset.StandardCharsets;

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
        return nativeStartTunFd(fd);
    }

    public static long startTunFd(int fd) {
        return nativeStartTunFd(fd);
    }

    public static void stopTunFd(long handle) {
        nativeStopTunFd(handle);
    }

    public static boolean sendBridgeJson(long clientId, String line) {
        return nativeSendBridgeMessage(clientId, line);
    }

    public static byte[] radioMessage(String method, String args, byte[] data, int fd) {
        return nativeRadioMessage(method, args == null ? "" : args, data == null ? new byte[0] : data, fd);
    }

    public static byte[] buildBleServiceData(String event, byte[] deviceId, byte[] payload,
                                             int rssi, int snrQ4) {
        return radioMessage("radio.ble.build_service_data",
                "event=" + textArg(event)
                        + " device_id=" + hex(deviceId)
                        + " rssi=" + rssi
                        + " snr_q4=" + snrQ4,
                payload, -1);
    }

    public static String parseBleServiceData(byte[] serviceData, int scanRssi, String address) {
        return radioMessageText("radio.ble.parse_service_data",
                "scan_rssi=" + scanRssi + " address=" + textArg(address), serviceData, -1);
    }

    public static byte[] buildNanServiceInfo(String role, byte[] deviceId, int wakeCount) {
        return radioMessage("radio.nan.build_service_info",
                "role=" + textArg(role)
                        + " device_id=" + hex(deviceId)
                        + " wake_count=" + wakeCount,
                new byte[0], -1);
    }

    public static String parseNanServiceInfo(byte[] serviceInfo) {
        return radioMessageText("radio.nan.parse_service_info", "", serviceInfo, -1);
    }

    public static byte[] buildNanFollowup(String msgType, byte[] deviceId, byte[] targetId,
                                          byte[] payload) {
        return radioMessage("radio.nan.build_followup",
                "msg_type=" + textArg(msgType)
                        + " device_id=" + hex(deviceId)
                        + " target_id=" + hex(targetId),
                payload, -1);
    }

    public static String parseNanFollowup(byte[] followup) {
        return radioMessageText("radio.nan.parse_followup", "", followup, -1);
    }

    private static String radioMessageText(String method, String args, byte[] data, int fd) {
        return new String(radioMessage(method, args, data, fd), StandardCharsets.UTF_8);
    }

    private static String hex(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        char[] out = new char[data.length * 2];
        char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            out[i * 2] = digits[v >>> 4];
            out[i * 2 + 1] = digits[v & 0x0f];
        }
        return new String(out);
    }

    private static String textArg(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case ' ':
                    out.append("\\ ");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    out.append(c);
                    break;
            }
        }
        return out.toString();
    }

    public interface MeshCallback {
        void onSshConnection(long clientId, String user);
        void onMessage(long clientId, String jsonLine);
        void onStreamOpened(long clientId, String jsonLine);
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
    private static native long nativeStartTunFd(int fd);
    private static native void nativeStopTunFd(long handle);
    private static native boolean nativeSendBridgeMessage(long clientId, String line);
    private static native byte[] nativeRadioMessage(String method, String args, byte[] data, int fd);
}
