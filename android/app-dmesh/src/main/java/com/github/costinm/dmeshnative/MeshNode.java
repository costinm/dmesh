package com.github.costinm.dmeshnative;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.ParcelFileDescriptor;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.nio.channels.DatagramChannel;
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
        start(null, sshPort, httpPort);
    }

    /**
     * Start the common Rust mesh with an Android-network-bound UDP FD.
     *
     * Android selects routes by a per-socket network mark. A socket opened by
     * Rust alone has no mark and may receive an IPv6 datagram but be unable to
     * route its reply. Java performs only that platform-specific socket setup;
     * Rust owns the QUIC listener and every packet/handler decision after the
     * FD handoff.
     */
    public void start(Context context, int sshPort, int httpPort) {
        int udpFd = -1;
        if (context != null) {
            try {
                udpFd = openNetworkUdpSocket(context, 3336);
            } catch (IOException error) {
                throw new RuntimeException("Failed to open Android mesh UDP socket", error);
            }
        }
        nativeHandle = nativeStartMesh(baseDir, sshPort, httpPort, udpFd);
        if (nativeHandle == 0) {
            if (udpFd >= 0) {
                try { ParcelFileDescriptor.adoptFd(udpFd).close(); } catch (IOException ignored) { }
            }
            throw new RuntimeException("Failed to start MeshNode");
        }
    }

    /**
     * Store provisioned DMesh root material in this app's Rust data directory.
     * The native side validates and writes it atomically; it never exposes the
     * bytes through settings or a handler. Restart the mesh service afterwards
     * so its QUIC association owner derives the new reset-key branch.
     */
    public boolean provisionDeviceSecret(byte[] secret) {
        return nativeProvisionDeviceSecret(baseDir, secret);
    }

    private static int openNetworkUdpSocket(Context context, int port) throws IOException {
        DatagramChannel channel = DatagramChannel.open(StandardProtocolFamily.INET6);
        try {
            channel.configureBlocking(false);
            java.net.DatagramSocket socket = channel.socket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(InetAddress.getByName("::"), port));
            ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
            Network network = activeWifiNetwork(manager);
            if (network != null) network.bindSocket(socket);
            ParcelFileDescriptor descriptor = ParcelFileDescriptor.fromDatagramSocket(socket);
            return descriptor.detachFd();
        } finally {
            channel.close();
        }
    }

    /**
     * Link-local DMesh UDP must use the Wi-Fi network that owns the received
     * address. `getActiveNetwork()` may be cellular even while Wi-Fi Aware or
     * STA is carrying the packet; binding an IPv6 socket to that default lets
     * it receive a datagram but routes its OPEN_ACK onto the wrong network.
     *
     * This is Android's platform-only route selection. Rust still owns the
     * socket after handoff, all QUIC association state, and every handler.
     */
    private static Network activeWifiNetwork(ConnectivityManager manager) {
        if (manager == null) return null;
        Network fallback = manager.getActiveNetwork();
        for (Network candidate : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(candidate);
            if (capabilities != null
                    && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return candidate;
            }
        }
        return fallback;
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

    /**
     * Legacy ADB-provider compatibility only. New callers must send the
     * common tagged control schema through Rust rather than inventing text
     * commands in Java.
     */
    public static String shellTransportCommand(String line) {
        return radioMessageText("radio.shell.command", "",
                line == null ? new byte[0] : line.getBytes(StandardCharsets.UTF_8), -1);
    }

    public static byte[] buildNanServiceInfo(String role, byte[] deviceId, int wakeCount) {
        return radioMessage("radio.nan.build_service_info",
                "role=" + textArg(role)
                        + " device_id=" + hex(deviceId)
                        + " wake_count=" + wakeCount,
                new byte[0], -1);
    }

    /** Build the bounded CBOR discovery presence Service Info record. */
    public static byte[] buildNanAnnounce(byte[] deviceId, long uptimeSecs,
                                          int transportMode, long counters, String deviceName,
                                          String networkName, String staLinkLocalV6,
                                          String apLinkLocalV6) {
        return radioMessage("radio.nan.build_announce",
                "device_id=" + hex(deviceId)
                        + " uptime_secs=" + uptimeSecs
                        + " transport_mode=" + transportMode
                        + " counters=" + counters
                        + " device_name=" + textArg(deviceName)
                        + " network_name=" + textArg(networkName)
                        + " sta_link_local_v6=" + textArg(staLinkLocalV6)
                        + " ap_link_local_v6=" + textArg(apLinkLocalV6),
                new byte[0], -1);
    }

    /**
     * Resolve the shared comprehensive pair-probe matrix from Android's live
     * discovery inventory. This is planning only: it never changes the phone
     * radio mode; the selected endpoint adapters execute the returned rows.
     */
    public static String planProbePair(String sourceId, String targetId,
                                       int shortBytes, int longBytes) {
        return radioMessageText("probe.plan",
                "source_id=" + textArg(sourceId)
                        + " target_id=" + textArg(targetId)
                        + " short_bytes=" + shortBytes
                        + " long_bytes=" + longBytes,
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
        return radioMessageText("discovery.nodes", "", new byte[0], -1);
    }

    /** Rust-owned platform snapshot used for routing and local multicast decisions. */
    public static String localNetworks() {
        return radioMessageText("discovery.status", "", new byte[0], -1);
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

    /** Record a packet delivered by the public Wi-Fi Aware message callback. */
    public static String observeNanPacket(String peer, byte[] packet, int rssi) {
        return radioMessageText("radio.nan.observe_packet",
                "peer=" + textArg(peer) + " rssi=" + rssi, packet, -1);
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
        /** Compatibility for existing prebuilt libdmesh.so calling onMessage(long, String). */
        void onMessage(long clientId, String message);
        /** The transport endpoint is gone; release its Android-side gateway state. */
        void onMessageClosed(long clientId);

        void onInboundStream(long clientId, String host, int port, long streamHandle);
        void onForwardedStream(long connId, String host, int port, long streamHandle);
    }

    private static native long nativeStartMesh(String baseDir, int sshPort, int httpPort, int udpFd);
    private static native boolean nativeProvisionDeviceSecret(String baseDir, byte[] secret);
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
