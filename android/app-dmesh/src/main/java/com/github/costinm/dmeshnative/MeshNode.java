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

    public MeshNativeStream openStream(long connId, String host, int port) {
        long streamHandle = nativeOpenStream(nativeHandle, connId, host, port);
        if (streamHandle == 0) {
            return null;
        }
        return new MeshNativeStream(streamHandle);
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

    /** Emit the shared UDP6 presence record on a newly available local link. */
    public boolean triggerAnnounce() {
        return nativeHandle != 0 && nativeTriggerAnnounce(nativeHandle);
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

    /** Sends one opaque, bounded message record to the SSH bridge. */
    public static boolean sendBridgeMessage(long clientId, byte[] message) {
        return nativeSendBridgeMessage(clientId, message == null ? new byte[0] : message);
    }

    public static byte[] radioMessage(String method, String args, byte[] data, int fd) {
        return nativeRadioMessage(method, args == null ? "" : args, data == null ? new byte[0] : data, fd);
    }

    /** Rust validates a shell command and returns the transport projection for Android. */
    public static String shellTransportCommand(String line) {
        return radioMessageText("radio.shell.command", "",
                line == null ? new byte[0] : line.getBytes(StandardCharsets.UTF_8), -1);
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

    /** Build the bounded CBOR boot/periodic presence Service Info record. */
    public static byte[] buildNanAnnounce(String kind, byte[] deviceId, long uptimeSecs,
                                          int transportMode, long counters) {
        return radioMessage("radio.nan.build_announce",
                "kind=" + textArg(kind)
                        + " device_id=" + hex(deviceId)
                        + " uptime_secs=" + uptimeSecs
                        + " transport_mode=" + transportMode
                        + " counters=" + counters,
                new byte[0], -1);
    }

    /**
     * Resolve the shared comprehensive pair-probe matrix from Android's live
     * discovery inventory. This is planning only: it never changes the phone
     * radio mode; the selected endpoint adapters execute the returned rows.
     */
    public static String planProbePair(String sourceId, String targetId,
                                       int shortBytes, int longBytes) {
        return radioMessageText("radio.probe.plan",
                "source_id=" + textArg(sourceId)
                        + " target_id=" + textArg(targetId)
                        + " short_bytes=" + shortBytes
                        + " long_bytes=" + longBytes,
                new byte[0], -1);
    }

    /**
     * Probe a peer learned by UDP6 multicast through the shared QUIC-lite echo
     * service. {@code scope} is the caller's local P2P interface index, not a
     * property of the remote peer; link-local P2P traffic is invalid without
     * it.
     */
    public static String probeUdp6Echo(String address, int scope, int port, String payload) {
        return radioMessageText("radio.probe.udp6_echo",
                "address=" + textArg(address)
                        + " scope=" + scope
                        + " port=" + port
                        + " payload=" + textArg(payload),
                new byte[0], -1);
    }

    /** Run the common bounded QUIC-lite IPERF service over a scoped P2P link. */
    public static String probeUdp6Iperf(String address, int scope, int port,
                                        int bytes, int packetSize) {
        return radioMessageText("radio.probe.udp6_iperf",
                "address=" + textArg(address)
                        + " scope=" + scope
                        + " port=" + port
                        + " bytes=" + bytes
                        + " packet_size=" + packetSize,
                new byte[0], -1);
    }

    public static String parseNanServiceInfo(byte[] serviceInfo) {
        return radioMessageText("radio.nan.parse_service_info", "", serviceInfo, -1);
    }

    /**
     * Record a framework NAN discovery in Rust before Java retains its
     * session-scoped peer handle. The returned JSON is the canonical decoded
     * identity/info for UI and routing decisions.
     */
    public static String observeNanServiceInfo(String peer, byte[] serviceInfo) {
        return radioMessageText("radio.nan.observe_service_info",
                "peer=" + textArg(peer), serviceInfo, -1);
    }

    /** Rust-owned one-hour inventory across NAN, UDP multicast, and control-plane discovery. */
    public static String knownDevices() {
        return radioMessageText("radio.devices", "", new byte[0], -1);
    }

    /** Rust-owned platform snapshot used for routing and local multicast decisions. */
    public static String localNetworks() {
        return radioMessageText("radio.local_networks", "", new byte[0], -1);
    }

    /** Latest bounded Android power/memory telemetry retained by Rust. */
    public static String powerState() {
        return radioMessageText("radio.power.state", "", new byte[0], -1);
    }

    /** Small Rust-generated status snapshot for the Android status shell. */
    public static String statusText() {
        return radioMessageText("radio.status_text", "", new byte[0], -1);
    }

    /** @deprecated Use {@link #knownDevices()}; the inventory is not NAN-only. */
    @Deprecated
    public static String knownNanDevices() {
        return knownDevices();
    }

    /** Rust-owned bounded receipt list for NAN follow-ups. */
    public static String knownNanFollowups() {
        return radioMessageText("radio.nan.followups", "", new byte[0], -1);
    }

    /** Forward one Android Wi-Fi Aware lifecycle/callback event to Rust. */
    public static void recordNanEvent(String event, String peer, byte[] payload) {
        radioMessage("radio.nan.event", "event=" + textArg(event)
                + " peer=" + textArg(peer), payload, -1);
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

    public static boolean injectNanFollowup(byte[] followup, int rssi) {
        byte[] result = radioMessage(
                "radio.nan.inject_frame",
                "rssi=" + rssi,
                followup, -1);
        return result != null && result.length > 0;
    }

    public static boolean injectBleFrame(byte[] serviceData, int rssi, String address) {
        byte[] result = radioMessage(
                "radio.ble.inject_frame",
                "scan_rssi=" + rssi + " address=" + textArg(address),
                serviceData, -1);
        return result != null && result.length > 0;
    }

    private static String radioMessageText(String method, String args, byte[] data, int fd) {
        // Text control/probe callers need the Rust error verbatim enough to
        // record a failed lifecycle or bearer stage.  Do not route this via
        // radioMessage(): that byte-oriented JNI method deliberately returns
        // an empty buffer on failure so a binary NAN/BLE frame can never be
        // mistaken for a JSON error record.
        return nativeRadioMessageText(method, args == null ? "" : args,
                data == null ? new byte[0] : data, fd);
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
        void onTransportConnection(long clientId, String peer);
        /** Opaque message bytes; dmeshnative maps them to the Android Bundle API. */
        void onMessage(long clientId, byte[] message);
        /** The transport endpoint is gone; release its Android-side gateway state. */
        void onMessageClosed(long clientId);
        void onInboundStream(long clientId, String host, int port, long streamHandle);
        void onForwardedStream(long connId, String host, int port, long streamHandle);
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
    private native boolean nativeTriggerAnnounce(long handle);
    private static native long nativeTestTunFd(int fd);
    private static native long nativeStartTunFd(int fd);
    private static native void nativeStopTunFd(long handle);
    private static native boolean nativeSendBridgeMessage(long clientId, byte[] message);
    private static native byte[] nativeRadioMessage(String method, String args, byte[] data, int fd);
    private static native String nativeRadioMessageText(String method, String args, byte[] data, int fd);
}
