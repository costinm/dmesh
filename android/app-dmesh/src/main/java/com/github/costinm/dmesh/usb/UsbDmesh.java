package com.github.costinm.dmesh.usb;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;

public final class UsbDmesh {
    public static final String PERMISSION_ACTION = "com.github.costinm.dmesh.lm.USB_PERMISSION";
    private static final int ESPRESSIF_VENDOR_ID = 0x303a;
    private final Context context;
    private final Bridge bridge;
    private final UsbManager manager;
    private final Object lock = new Object();
    private volatile boolean started;
    private volatile boolean running;
    private volatile String state = "unavailable";
    private volatile String lastError = "";
    private volatile String deviceInfo = "";
    private volatile String currentDeviceName = "";
    private UsbDevice pendingDevice;
    private UsbDeviceConnection connection;
    private UsbInterface dataInterface;
    private UsbEndpoint inEndpoint;
    private UsbEndpoint outEndpoint;
    private Thread readThread;

    public interface Bridge {
        void onUsbOpen(String info);
        void onUsbClose(String info);
        void onUsbChunk(byte[] data, int length);
    }

    public UsbDmesh(Context context, Bridge bridge) {
        this.context = context.getApplicationContext();
        this.bridge = bridge;
        this.manager = (UsbManager) this.context.getSystemService(Context.USB_SERVICE);
        if (manager == null) state = "unavailable";
        else state = "idle";
    }

    public void start() {
        synchronized (lock) {
            if (manager == null || started) return;
            started = true;
            IntentFilter filter = new IntentFilter();
            filter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
            filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                context.registerReceiver(receiver, filter);
            }
            state = "idle";
            autoOpen();
        }
    }

    public void stop() {
        synchronized (lock) {
            if (!started) return;
            started = false;
            try {
                context.unregisterReceiver(receiver);
            } catch (IllegalArgumentException ignored) {
            }
            closeLocked();
        }
        bridge.onUsbClose(status());
    }

    public String status() {
        JSONObject out = new JSONObject();
        try {
            out.put("available", manager != null);
            out.put("started", started);
            out.put("connected", connection != null);
            out.put("state", state);
            out.put("error", lastError);
            out.put("device", deviceInfo);
            out.put("bearer", "usb");
        } catch (Exception ignored) {
        }
        return out.toString();
    }

    public String devices() {
        try {
            JSONObject out = new JSONObject();
            JSONArray items = new JSONArray();
            if (manager != null) {
                for (UsbDevice device : manager.getDeviceList().values()) {
                    try {
                        items.put(describe(device, manager.hasPermission(device)));
                    } catch (Exception ignored) {
                    }
                }
            }
            out.put("devices", items);
            return out.toString();
        } catch (Exception e) {
            return "{\"devices\":[]}";
        }
    }

    public boolean open(int vendorId, int productId) {
        if (manager == null) {
            state = "unavailable";
            return false;
        }
        UsbDevice device = null;
        for (UsbDevice candidate : manager.getDeviceList().values()) {
            if (candidate.getVendorId() == vendorId && candidate.getProductId() == productId) {
                device = candidate;
                break;
            }
        }
        return openDevice(device);
    }

    public boolean openByDeviceName(String name) {
        if (manager == null) {
            state = "unavailable";
            return false;
        }
        UsbDevice device = null;
        if (name != null) {
            for (UsbDevice candidate : manager.getDeviceList().values()) {
                if (candidate.getDeviceName().equals(name)) {
                    device = candidate;
                    break;
                }
            }
        }
        return openDevice(device);
    }

    public boolean openAuto() {
        autoOpen();
        return connection != null;
    }

    /**
     * Accept only a grant that identifies the device this instance actually
     * requested. The receiver is exported, so any app can broadcast the
     * action; without the device match one forged `granted=false` broadcast
     * would clear the pending request and make the real grant a no-op.
     */
    public boolean onPermissionGranted(UsbDevice device, boolean granted) {
        synchronized (lock) {
            UsbDevice pending = pendingDevice;
            if (pending == null) return false;
            if (device == null
                    || !pending.getDeviceName().equals(device.getDeviceName())) {
                return false;
            }
            pendingDevice = null;
            if (!granted) {
                state = "permission_denied";
                lastError = "usb_permission_denied";
                return false;
            }
            return openDeviceLocked(device);
        }
    }

    public void close() {
        synchronized (lock) {
            closeLocked();
        }
        bridge.onUsbClose(status());
    }

    public boolean writeFrame(byte[] frame, int length) {
        UsbDeviceConnection localConnection;
        UsbEndpoint localOut;
        synchronized (lock) {
            localConnection = connection;
            localOut = outEndpoint;
        }
        if (localConnection == null || localOut == null || frame == null || length <= 0) {
            state = "closed";
            return false;
        }
        try {
            int offset = 0;
            while (offset < length) {
                int sent = localConnection.bulkTransfer(localOut, frame, offset, length - offset, 1000);
                if (sent <= 0) {
                    state = "error";
                    lastError = "usb_write_failed:" + sent;
                    close();
                    return false;
                }
                offset += sent;
            }
            return true;
        } catch (RuntimeException e) {
            state = "error";
            lastError = e.getClass().getSimpleName();
            close();
            return false;
        }
    }

    private void autoOpen() {
        if (manager == null) return;
        for (UsbDevice device : manager.getDeviceList().values()) {
            if (eligible(device)) {
                if (manager.hasPermission(device)) {
                    openDevice(device);
                } else {
                    requestPermission(device);
                }
                return;
            }
        }
        state = "idle";
        lastError = "no_eligible_usb_device";
    }

    private boolean openDevice(UsbDevice device) {
        synchronized (lock) {
            return openDeviceLocked(device);
        }
    }

    private boolean openDeviceLocked(UsbDevice device) {
        if (manager == null) {
            state = "unavailable";
            return false;
        }
        if (device == null) {
            state = "error";
            lastError = "usb_device_not_found";
            return false;
        }
        if (connection != null && currentDeviceName.equals(device.getDeviceName())) return true;
        if (connection != null) bridge.onUsbClose(status());
        closeLocked();
        if (!manager.hasPermission(device)) {
            requestPermission(device);
            return false;
        }
        try {
            UsbDeviceConnection raw = manager.openDevice(device);
            if (raw == null) {
                state = "error";
                lastError = "usb_open_failed";
                return false;
            }
            connection = raw;
            dataInterface = chooseInterface(device);
            if (dataInterface == null) {
                state = "error";
                lastError = "usb_no_bulk_interface";
                releaseLocked();
                return false;
            }
            if (!connection.claimInterface(dataInterface, true)) {
                state = "error";
                lastError = "usb_claim_failed";
                releaseLocked();
                return false;
            }
            inEndpoint = findBulkEndpoint(dataInterface, UsbConstants.USB_DIR_IN);
            outEndpoint = findBulkEndpoint(dataInterface, UsbConstants.USB_DIR_OUT);
            if (inEndpoint == null || outEndpoint == null) {
                state = "error";
                lastError = "usb_no_bulk_endpoints";
                releaseLocked();
                return false;
            }
            configureLineCoding(device);
            currentDeviceName = device.getDeviceName();
            deviceInfo = describe(device, true).toString();
            state = "connected";
            lastError = "";
            startReadThread();
            bridge.onUsbOpen(status());
            return true;
        } catch (RuntimeException e) {
            state = "error";
            lastError = e.getClass().getSimpleName();
            releaseLocked();
            return false;
        }
    }

    private void requestPermission(UsbDevice device) {
        if (manager == null || device == null) return;
        synchronized (lock) {
            pendingDevice = device;
            state = "permission_pending";
            lastError = "";
            try {
                // An explicit package scope is mandatory for PendingIntents on
                // API 34+: an implicit intent throws and the permission flow
                // would degrade to a permanent "error" state.
                PendingIntent intent = PendingIntent.getBroadcast(context, 0,
                        new Intent(PERMISSION_ACTION).setPackage(context.getPackageName()),
                        Build.VERSION.SDK_INT >= 31
                                ? PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
                                : PendingIntent.FLAG_UPDATE_CURRENT);
                manager.requestPermission(device, intent);
            } catch (RuntimeException e) {
                pendingDevice = null;
                state = "error";
                lastError = "usb_permission_request_failed";
            }
        }
    }

    private void closeLocked() {
        running = false;
        Thread thread = readThread;
        if (thread != null) {
            try {
                thread.join(250);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        releaseLocked();
        readThread = null;
        state = "closed";
    }

    private void releaseLocked() {
        if (dataInterface != null && connection != null) {
            try {
                connection.releaseInterface(dataInterface);
            } catch (RuntimeException ignored) {
            }
        }
        if (connection != null) {
            try {
                connection.close();
            } catch (RuntimeException ignored) {
            }
        }
        connection = null;
        dataInterface = null;
        inEndpoint = null;
        outEndpoint = null;
        currentDeviceName = "";
        deviceInfo = "";
    }

    private void startReadThread() {
        running = true;
        readThread = new Thread(() -> {
            byte[] buffer = new byte[4096];
            while (running) {
                UsbDeviceConnection localConnection = connection;
                UsbEndpoint localIn = inEndpoint;
                if (localConnection == null || localIn == null) break;
                int count;
                try {
                    count = localConnection.bulkTransfer(localIn, buffer, 0, buffer.length, 3000);
                } catch (RuntimeException e) {
                    state = "error";
                    lastError = "usb_read_failed";
                    break;
                }
                if (count > 0) {
                    bridge.onUsbChunk(Arrays.copyOf(buffer, count), count);
                } else if (count < 0) {
                    // Android reports a bulk-transfer timeout as a negative
                    // result. An idle serial bearer is healthy; keep polling
                    // and reserve teardown for detach/real I/O failures.
                    continue;
                }
            }
            if (running) {
                close();
            }
        }, "dmesh-usb-read");
        readThread.start();
    }

    private void configureLineCoding(UsbDevice device) {
        if (connection == null) return;
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface candidate = device.getInterface(i);
            if (candidate == null) continue;
            try {
                // USB CDC SET_LINE_CODING is exactly seven bytes. This is a
                // best-effort adapter configuration: USB Serial/JTAG devices
                // may not implement CDC ACM and must remain usable.
                byte[] lineCoding = {
                        0x00, (byte) 0xc2, 0x01, 0x00,
                        0x00, 0x00, 0x08
                };
                int configured = connection.controlTransfer(
                        0x21, 0x20, 0, candidate.getId(), lineCoding, lineCoding.length, 500);
                if (configured >= 0) {
                    connection.controlTransfer(0x21, 0x22, 1, candidate.getId(), new byte[0], 0, 500);
                }
            } catch (RuntimeException ignored) {
            }
        }
    }

    private UsbInterface chooseInterface(UsbDevice device) {
        UsbInterface selected = null;
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface candidate = device.getInterface(i);
            if (candidate != null
                    && hasBulkEndpoint(candidate, UsbConstants.USB_DIR_IN)
                    && hasBulkEndpoint(candidate, UsbConstants.USB_DIR_OUT)) {
                selected = candidate;
                break;
            }
        }
        return selected;
    }

    private UsbEndpoint findBulkEndpoint(UsbInterface candidate, int direction) {
        for (int i = 0; i < candidate.getEndpointCount(); i++) {
            UsbEndpoint endpoint = candidate.getEndpoint(i);
            if (endpoint != null
                    && endpoint.getDirection() == direction
                    && endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                return endpoint;
            }
        }
        return null;
    }

    private boolean hasBulkEndpoint(UsbInterface candidate, int direction) {
        return candidate != null && findBulkEndpoint(candidate, direction) != null;
    }

    private boolean eligible(UsbDevice device) {
        if (device == null || device.getVendorId() != ESPRESSIF_VENDOR_ID) return false;
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface candidate = device.getInterface(i);
            if (hasBulkEndpoint(candidate, UsbConstants.USB_DIR_IN)
                    && hasBulkEndpoint(candidate, UsbConstants.USB_DIR_OUT)) {
                return true;
            }
        }
        return false;
    }

    private static JSONObject describe(UsbDevice device, boolean authorized) {
        JSONObject out = new JSONObject();
        try {
            out.put("vendor_id", device.getVendorId());
            out.put("product_id", device.getProductId());
            out.put("name", device.getDeviceName());
            out.put("manufacturer", device.getManufacturerName());
            out.put("product", device.getProductName());
            out.put("authorized", authorized);
            try {
                out.put("serial", device.getSerialNumber());
            } catch (Exception ignored) {
                out.put("serial", "");
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                if (device != null && eligible(device) && !state.equals("connected")) {
                    if (manager != null && manager.hasPermission(device)) {
                        openDevice(device);
                    } else {
                        requestPermission(device);
                    }
                }
            } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
                UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                if (device != null && device.getDeviceName().equals(currentDeviceName)) {
                    close();
                }
            }
        }
    };
}
