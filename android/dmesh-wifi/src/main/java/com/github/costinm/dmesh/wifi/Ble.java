package com.github.costinm.dmesh.wifi;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

/** Android BLE scan/advertise adapter; it owns neither DMesh commands nor wire encoding. */
public final class Ble {
    public static final String ACTION_SCAN_RESULT = "com.github.costinm.dmesh.wifi.BLE_SCAN";
    public static final ParcelUuid DMESH_PAIRING = new ParcelUuid(UUID.fromString("5f6b6f80-4f2a-4a6f-8c42-4d6573680001"));
    public static final ParcelUuid DMESH_IPSP = ParcelUuid.fromString("00001820-0000-1000-8000-00805f9b34fb");
    private static volatile Ble active;
    private final Context context;
    private final Handler handler;
    private final TransportEventSink events;
    private final BluetoothLeScanner scanner;
    private final BluetoothLeAdvertiser advertiser;
    private boolean scanning;
    private boolean advertising;
    private byte[] advertised = new byte[0];

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
    public void close() { scanStop(); advertiseStop(); if (active == this) active = null; }
    public synchronized String snapshot() { return "scan=" + scanning + " advertise=" + advertising + " advertise_bytes=" + advertised.length; }
    private boolean has(String permission) { return context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED; }
    private void emit(String event, byte[] payload) { handler.post(() -> events.onTransportEvent("ble", event, payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length))); }
}
