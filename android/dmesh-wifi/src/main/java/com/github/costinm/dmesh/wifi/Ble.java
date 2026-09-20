package com.github.costinm.dmesh.wifi;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.ParcelUuid;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

/** Android BLE scan/advertise adapter; it owns neither DMesh commands nor wire encoding. */
public final class Ble {
    public static final String ACTION_SCAN_RESULT = "com.github.costinm.dmesh.wifi.BLE_SCAN";
    public static final ParcelUuid DMESH_PAIRING = new ParcelUuid(UUID.fromString("5f6b6f80-4f2a-4a6f-8c42-4d6573680001"));
    public static final ParcelUuid DMESH_IPSP = ParcelUuid.fromString("00001820-0000-1000-8000-00805f9b34fb");
    public interface BearerBridge {
        void onBearerConnected(String bearer);
        void onBearerDisconnected(String bearer);
        void onBearerChunk(String bearer, byte[] data, int length);
        boolean sendBearerFrame(String bearer, byte[] frame, int length);
    }

    private static volatile Ble active;
    private final Context context;
    private final Handler handler;
    private final TransportEventSink events;
    private final BluetoothLeScanner scanner;
    private final BluetoothLeAdvertiser advertiser;
    private boolean scanning;
    private boolean advertising;
    private byte[] advertised = new byte[0];
    private BearerBridge bridge;
    private BluetoothSocket socket;
    private InputStream cocIn;
    private OutputStream cocOut;
    private Thread cocThread;
    private volatile boolean cocConnected;
    private int cocPsm = 128;
    private String cocAddress = "";
    // Set by disconnect() to abort an in-progress connect attempt and to keep
    // the read-loop teardown from reporting a self-initiated close as a
    // failure.
    private volatile boolean cocClosing;
    // The channel mid-connect(), exposed so disconnect() can unblock it.
    private volatile BluetoothSocket cocPendingChannel;
    // Matches Rust's COC_FRAME_MAX (PACKET + 2) in crates/dmesh/src/bearer.rs.
    // The Rust bearer never emits a larger frame; rejecting here keeps Java
    // and Rust length-framing synchronized.
    private static final int COC_FRAME_MAX = 1102;

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override public void onScanResult(int callbackType, ScanResult result) {
            BluetoothDevice device = result.getDevice();
            ScanRecord record = result.getScanRecord();
            byte[] data = record == null ? null : record.getServiceData(DMESH_IPSP);
            if (data == null) data = new byte[0];
            String address = "";
            try { address = device == null ? "" : device.getAddress(); } catch (SecurityException ignored) { }
            // BLE discovery and future pairing/CoC ownership remain inside
            // dmesh-wifi. Do not project advertisement bytes as a mesh API:
            // once paired, CoC presents the shared UART byte stream directly.
            emit("scan_result:rssi=" + result.getRssi() + ":addr=" + address, data);
        }
        @Override public void onScanFailed(int errorCode) { emit("scan_failed:code=" + errorCode, new byte[0]); }
    };
    private final AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
        @Override public void onStartSuccess(AdvertiseSettings settings) { advertising = true; emit("advertise_started", advertised); }
        @Override public void onStartFailure(int errorCode) { advertising = false; emit("advertise_failed:code=" + errorCode, advertised); }
    };

    public Ble(Context context, Handler handler) { this(context, handler, TransportEventSink.NONE); }
    public Ble(Context context, Handler handler, TransportEventSink events) {
        this.context = context.getApplicationContext();
        this.handler = handler;
        this.events = events == null ? TransportEventSink.NONE : events;
        BluetoothManager manager = this.context.getSystemService(BluetoothManager.class);
        BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
        scanner = adapter == null ? null : adapter.getBluetoothLeScanner();
        advertiser = adapter == null ? null : adapter.getBluetoothLeAdvertiser();
        active = this;
    }
    public static void handlePendingIntentScan(Context ignored, Intent intent) {
        Ble current = active;
        if (current == null || intent == null) return;
        int error = intent.getIntExtra(BluetoothLeScanner.EXTRA_ERROR_CODE, 0);
        if (error != 0) { current.emit("scan_failed:code=" + error, new byte[0]); return; }
        java.util.ArrayList<ScanResult> results = intent.getParcelableArrayListExtra(BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT);
        if (results != null) for (ScanResult result : results) current.scanCallback.onScanResult(0, result);
    }
    public void scan() {
        if (!has(Manifest.permission.BLUETOOTH_SCAN)) { emit("scan_denied", new byte[0]); return; }
        if (scanner == null) { emit("scan_unsupported", new byte[0]); return; }
        if (scanning) { emit("scan_unchanged", new byte[0]); return; }
        ScanFilter filter = new ScanFilter.Builder().setServiceUuid(DMESH_IPSP).build();
        ScanSettings settings = new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_POWER).build();
        scanner.startScan(Collections.singletonList(filter), settings, scanCallback);
        scanning = true; emit("scan_started", new byte[0]);
    }
    public void scanStop() {
        if (scanner != null && has(Manifest.permission.BLUETOOTH_SCAN)) scanner.stopScan(scanCallback);
        scanning = false; emit("scan_stopped", new byte[0]);
    }
    /** Advertise a complete Rust-encoded IPSP service-data payload. */
    public void advertise(byte[] serviceData) {
        if (serviceData == null) { advertiseStop(); return; }
        if (!has(Manifest.permission.BLUETOOTH_ADVERTISE)) { emit("advertise_denied", new byte[0]); return; }
        if (advertiser == null) { emit("advertise_unsupported", new byte[0]); return; }
        advertised = Arrays.copyOf(serviceData, serviceData.length);
        AdvertiseData data = new AdvertiseData.Builder().addServiceUuid(DMESH_IPSP).addServiceData(DMESH_IPSP, advertised).build();
        AdvertiseSettings settings = new AdvertiseSettings.Builder().setConnectable(false).setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER).build();
        advertiser.stopAdvertising(advertiseCallback);
        advertiser.startAdvertising(settings, data, advertiseCallback);
    }
    public void advertiseStop() {
        if (advertiser != null && has(Manifest.permission.BLUETOOTH_ADVERTISE)) advertiser.stopAdvertising(advertiseCallback);
        advertising = false; advertised = new byte[0]; emit("advertise_stopped", new byte[0]);
    }
    public void setBearerBridge(BearerBridge bridge) { this.bridge = bridge; }
    public boolean connect(String address, int psm) {
        if (address == null || address.isEmpty()) { emit("coc_connect_invalid", new byte[0]); return false; }
        if (!has(Manifest.permission.BLUETOOTH_CONNECT)) { emit("coc_connect_denied", new byte[0]); return false; }
        BluetoothManager manager = context.getSystemService(BluetoothManager.class);
        BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null || !adapter.isEnabled()) { emit("coc_unavailable", new byte[0]); return false; }
        final BluetoothDevice device;
        try { device = adapter.getRemoteDevice(address); } catch (Exception exception) {
            emit("coc_connect_invalid", new byte[0]);
            return false;
        }
        final int channelPsm = psm > 0 ? psm : 128;
        Thread thread = new Thread(() -> runCoc(device, address, channelPsm), "dmesh-ble-coc");
        // Validation, ownership, and start share one lock: two concurrent
        // binder calls must not both pass an alive check and interleave two
        // sockets and read loops into the same bearer state.
        synchronized (this) {
            if (cocConnected) {
                if (channelPsm == cocPsm && address.equalsIgnoreCase(cocAddress)) {
                    emit("coc_connect_unchanged", new byte[0]);
                    return true;
                }
                emit("coc_connect_active", new byte[0]);
                return false;
            }
            if (cocThread != null && cocThread.isAlive()) { emit("coc_connect_pending", new byte[0]); return false; }
            cocClosing = false;
            cocPsm = channelPsm;
            cocAddress = address;
            cocThread = thread;
            thread.start();
        }
        emit("coc_connecting:address=" + address + ":psm=" + channelPsm, new byte[0]);
        return true;
    }
    private void runCoc(BluetoothDevice device, String address, int channelPsm) {
        BluetoothSocket channel = null;
        try {
            if (scanner != null && has(Manifest.permission.BLUETOOTH_SCAN)) {
                // Dedicated callback: the persistent scan() callback may
                // already be registered, and reusing it here would either
                // fail startScan or make stopScan tear down the ongoing
                // discovery scan.
                ScanCallback prescan = new ScanCallback() { };
                try {
                    scanner.startScan(Collections.singletonList(
                                    new ScanFilter.Builder().setDeviceAddress(address.toUpperCase()).build()),
                            new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
                            prescan);
                    Thread.sleep(1500);
                } finally {
                    scanner.stopScan(prescan);
                }
            }
            if (cocClosing) { emit("coc_connect_aborted", new byte[0]); return; }
            channel = device.createInsecureL2capChannel(channelPsm);
            cocPendingChannel = channel;
            channel.connect();
            synchronized (this) {
                if (cocClosing) { emit("coc_connect_aborted", new byte[0]); return; }
                socket = channel;
                cocIn = channel.getInputStream();
                cocOut = channel.getOutputStream();
                cocConnected = true;
            }
        } catch (InterruptedException exception) {
            emit("coc_connect_aborted", new byte[0]);
        } catch (Exception exception) {
            if (cocClosing) emit("coc_connect_aborted", new byte[0]);
            else emit("coc_connect_failed:" + exception.getClass().getSimpleName() + ":" + exception.getMessage(), new byte[0]);
        } finally {
            cocPendingChannel = null;
            if (channel != null && !cocConnected) closeQuietly(channel);
        }
        if (!cocConnected) { failConnection(); return; }
        emit("coc_connected:psm=" + channelPsm, new byte[0]);
        BearerBridge currentBridge = bridge;
        try {
            if (currentBridge != null) currentBridge.onBearerConnected("ble");
            readLoop();
        } catch (Exception exception) {
            // A mid-session read failure is not a connect failure; a
            // self-initiated disconnect already reported coc_disconnected.
            if (!cocClosing) emit("coc_read_failed:" + exception.getClass().getSimpleName() + ":" + exception.getMessage(), new byte[0]);
            failConnection();
        }
    }
    public boolean writeFrame(byte[] frame, int length) {
        if (frame == null || length < 2 || length > frame.length || length > COC_FRAME_MAX) return false;
        OutputStream out;
        synchronized (this) {
            if (!cocConnected || cocOut == null) return false;
            out = cocOut;
        }
        try {
            synchronized (out) {
                out.write(frame, 0, length);
                out.flush();
            }
            android.util.Log.v("DMESH-BLE", "ble coc_tx_frame:bytes=" + length);
            return true;
        } catch (IOException exception) {
            failConnection();
            return false;
        }
    }
    public void disconnect() {
        cocClosing = true;
        boolean connected;
        Thread pending = null;
        BluetoothSocket channel = null;
        synchronized (this) {
            connected = cocConnected;
            if (!connected) {
                if (cocThread != null && cocThread.isAlive()) pending = cocThread;
                channel = cocPendingChannel;
            }
        }
        if (connected) { failConnection(); return; }
        // Abort an in-progress connect: closing the pending channel unblocks
        // connect(), and interrupt() unblocks the prescan sleep.
        if (channel != null) closeQuietly(channel);
        if (pending != null) pending.interrupt();
    }
    private void readLoop() throws IOException {
        InputStream in;
        synchronized (this) {
            if (!cocConnected || cocIn == null) return;
            in = cocIn;
        }
        byte[] buffer = new byte[2048];
        while (cocConnected) {
            int read = in.read(buffer);
            if (read <= 0) { emit("coc_read_closed:bytes=" + read, new byte[0]); break; }
            android.util.Log.v("DMESH-BLE", "ble coc_rx_chunk:bytes=" + read);
            BearerBridge currentBridge = bridge;
            if (currentBridge != null) {
                currentBridge.onBearerChunk("ble", buffer, read);
            }
        }
        failConnection();
    }
    private void failConnection() {
        boolean wasConnected;
        synchronized (this) {
            if (!cocConnected && socket == null && cocIn == null && cocOut == null) return;
            wasConnected = cocConnected;
            cocConnected = false;
            closeQuietly(cocIn);
            closeQuietly(cocOut);
            cocIn = null;
            cocOut = null;
            closeQuietly(socket);
            socket = null;
        }
        emit("coc_disconnected", new byte[0]);
        if (wasConnected && bridge != null) bridge.onBearerDisconnected("ble");
    }
    private static void closeQuietly(java.io.Closeable value) {
        if (value != null) {
            try { value.close(); } catch (IOException ignored) { }
        }
    }
    public void close() { scanStop(); advertiseStop(); disconnect(); if (active == this) active = null; }
    public synchronized String snapshot() { return "scan=" + scanning + " advertise=" + advertising + " advertise_bytes=" + advertised.length + " coc=" + cocConnected + " psm=" + cocPsm; }
    private boolean has(String permission) { return context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED; }
    private void emit(String event, byte[] payload) { handler.post(() -> events.onTransportEvent("ble", event, payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length))); }
}
