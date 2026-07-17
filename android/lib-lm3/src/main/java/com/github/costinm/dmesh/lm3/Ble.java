package com.github.costinm.dmesh.lm3;

import android.Manifest;
import android.app.PendingIntent;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothServerSocket;
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
import android.os.Message;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.util.Log;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.widget.Toast;

import com.github.costinm.dmesh.android.msg.ConnUDS;
import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.DMeshCompanionPrefs;
import com.github.costinm.dmesh.android.util.Hex;
import com.github.costinm.dmeshnative.MeshNode;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static android.bluetooth.BluetoothAdapter.STATE_DISCONNECTED;
import static android.bluetooth.BluetoothProfile.GATT_SERVER;
import static android.bluetooth.BluetoothProfile.STATE_CONNECTED;


/**
 * BLE support
 * <p>
 * Advertiser (peripheral) added on L/21 - 18 supports only startLeScan with byte[] record.
 * <p>
 * Announce: 31 bytes max
 * <p>
 * Link layer is 23 (27 bytes  - 4 reserved for L2CAP).
 * OpCode: 1 B
 * AttHandle: 2B
 * Payload: 20 bytes
 * <p>
 * BLE4.2 - max 251 (from 27), payload 244B - may allow 50kB/s
 * <p>
 * <p>
 * Attributes/services:
 * - 'alert' - title, etc
 * - device info
 * - battery
 * <p>
 * <p>
 * Device address seems to change every ~10 min, so privacy concerns with Bt2
 * are resolved.
 * <p>
 * GATT: attribute send/receive
 * - 128bit UUID key
 * -
 * <p>
 * https://www.jaredwolff.com/get-started-with-bluetooth-low-energy/
 * - hcitool lescan
 * - gatttool
 * <p>
 * Debugging:
 * - system logs with D/BtGatt
 * - Nordic's debug apps
 */
public class Ble implements MessageHandler {
    static final String TAG = "LM-BLE";
    public static final String ACTION_SCAN_RESULT = "com.github.costinm.dmesh.lm3.BLE_SCAN";

    // Required for the notification - will be set to enable, 2902.
    public static UUID BLE_DESC_CLIENT_CONFIG = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    static UUID dmeshPairingUUID = UUID.fromString("5f6b6f80-4f2a-4a6f-8c42-4d6573680001");
    public static ParcelUuid DMESH_PAIRING = new ParcelUuid(dmeshPairingUUID);
    static UUID dmeshOperationalUUID = UUID.fromString("5f6b6f80-4f2a-4a6f-8c42-4d6573680002");
    public static ParcelUuid DMESH_OPERATIONAL = new ParcelUuid(dmeshOperationalUUID);
    static UUID meshtasticUUID = UUID.fromString("6ba1b218-15a8-461f-9fa8-5dcae273eafd");
    public static ParcelUuid MESHTASTIC = new ParcelUuid(meshtasticUUID);
    static UUID dmeshGattUUID = UUID.fromString("5f6b6f80-4f2a-4a6f-8c42-4d6573680003");
    public static ParcelUuid DMESH_GATT = new ParcelUuid(dmeshGattUUID);
    static UUID dmeshRxUUID = UUID.fromString("5f6b6f80-4f2a-4a6f-8c42-4d6573680004");
    static UUID dmeshTxUUID = UUID.fromString("5f6b6f80-4f2a-4a6f-8c42-4d6573680005");
    static Map<String, Device> devices = new HashMap<>();
    static Map<String, String> deviceIdsByAddress = new HashMap<>();
    static Map<String, Long> externalDevices = new HashMap<>();
    static Map<String, String> lastDmeshDiscovery = new HashMap<>();
    static Map<String, Long> lastDmeshDiscoveryAt = new HashMap<>();
    static Map<String, Long> lastDmeshPairingAt = new HashMap<>();
    static Map<String, Long> lastDmeshPullAt = new HashMap<>();
    static boolean scanFailed = false;
    private static final long DMESH_DISCOVERY_REPEAT_MS = 30000;
    private static final long DMESH_PULL_REPEAT_MS = 45000;
    private static final int BLE_READY_MAX_BYTES = 1200;
    private static final long BLE_PULL_TIMEOUT_MS = 15000;
    private final BluetoothManager bluetoothManager;
    LocalMesh wifi;
    boolean mScanning = false;
    Handler mHandler;
    Context ctx;
    BluetoothLeScanner leScanner;
    BluetoothAdapter mBluetoothAdapter;
    int discoveryCnt;
    int scanCnt;
    boolean adv = false;
    int psm;

    int mConnectionState;
    BluetoothGattServerCallback mGattServer = new ServerCallback();
    // HTTP Body (closest) 2AB9
    BluetoothGatt btGattClient;
    PullSession activePull;
    // Notification char. Can also be receive char if we share.
    BluetoothGattCharacteristic sendPort;
    BluetoothGattCharacteristic receivePort;
    // 21 bytes advertisment, first byte is 0x5x (type + flags).
    // null if not advertising
    byte[] currentAdvBytes;


    // === GATT Server implementation
    // String 2A3D
    private BluetoothLeAdvertiser mBluetoothLeAdvertiser;
    private ScanCallback mScanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            scanCnt++;
            BluetoothDevice device = result.getDevice();

            ScanRecord sr = result.getScanRecord();
            if (sr == null) {
                return;
            }

            Map<ParcelUuid, byte[]> sd = sr.getServiceData();
            if (sd != null) {
                byte[] record = sd.get(DMESH_OPERATIONAL);
                if (record != null && processDiscovery(device, record, result.getRssi())) {
                    super.onScanResult(callbackType, result);
                    return;
                }
            }

            List<ParcelUuid> suid = sr.getServiceUuids();
            if (suid == null || suid.size() == 0) {
                return;
            }
            if (suid.contains(MESHTASTIC)) {
                processExternalDiscovery(device, sr, result.getRssi(),
                        "meshtastic", MESHTASTIC.toString(), "");
            }
            if (suid.contains(DMESH_PAIRING)) {
                processPairingDiscovery(device, sr, result.getRssi());
            }
            if (!suid.contains(DMESH_OPERATIONAL)) {
                return;
            }

            if (sd == null) {
                return;
            }

            byte[] record = sd.get(DMESH_OPERATIONAL);
            if (record == null) {
                return;
            }

            discoveryCnt++;
            processDiscovery(device, record, result.getRssi());

            super.onScanResult(callbackType, result);
        }

        @Override
        public void onBatchScanResults(List<ScanResult> results) {
            Log.d(TAG, "Batched results " + results.size());
            for (ScanResult sr : results) {
                onScanResult(0, sr);
            }
            super.onBatchScanResults(results);
        }

        @Override
        public void onScanFailed(int errorCode) {
            if (scanFailed) {
                return;
            }
            if (errorCode == 1) {
                mScanning = true;
                MsgMux.get(ctx).publish("BLE.scan", "state", "already_started");
                return;
            }
            MsgMux.get(ctx).publish("BLE.ERR.onScanFailed", "error", "" + errorCode);
            super.onScanFailed(errorCode);
            scanFailed = true;
        }
    };
    private AdvertiseCallback mAdvertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.i(TAG, "LE Advertise Started " + settingsInEffect);
            adv = true;
            MsgMux.get(ctx).publish("BLE.advertise", "state", "started");
        }

        @Override
        public void onStartFailure(int errorCode) {
            // 1 = data too large (31 is the limit)
            Log.w(TAG, "LE Advertise Failed: " + errorCode);
            MsgMux.get(ctx).publish("BLE.ERR.advertise", "error", "" + errorCode);
            currentAdvBytes = null;
        }
    };

    //static UUID eddyCharN = UUID.fromString("00002A3D-0000-1000-8000-00805f9b34fb");
    // TODO: if we have visible devices or mesh active, stop scanning
    private BluetoothGattServer gatS;

    public Ble(Context ctx, LocalMesh wifi, Handler handler) {
        this.ctx = ctx;
        this.mHandler = handler;
        this.wifi = wifi;

        bluetoothManager = (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
        if (bluetoothManager == null) {
            return;
        }

        mBluetoothAdapter = bluetoothManager.getAdapter();
        if (mBluetoothAdapter == null) {
            return;
        }

        leScanner = mBluetoothAdapter.getBluetoothLeScanner();

        mBluetoothLeAdvertiser = mBluetoothAdapter.getBluetoothLeAdvertiser();

        if (leScanner == null) {
            Log.d(TAG, "BLE without scan support");
            return; // don't bother with just advertising
        }

        initServer();

        String name = "";

        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
            name = mBluetoothAdapter.getName();
            try {
                if (mBluetoothLeAdvertiser == null) {
                    MsgMux.get(ctx).publish("BLE.start",
                            "name", name,
                            "adv", "-1");
                } else {
                    MsgMux.get(ctx).publish("BLE.start",
                            "name", name,
                            "psm", "" + psm);
                }
            } catch (Throwable t) {
                t.printStackTrace();
            }
        }


    }

    public static void handlePendingIntentScan(Context ctx, Intent intent) {
        LocalMesh lm = LocalMesh.get(ctx.getApplicationContext());
        if (lm.ble != null) {
            lm.ble.onPendingIntentScan(intent);
        }
    }

    private void onPendingIntentScan(Intent intent) {
        if (intent == null) {
            return;
        }
        int error = intent.getIntExtra(BluetoothLeScanner.EXTRA_ERROR_CODE, 0);
        if (error != 0) {
            MsgMux.get(ctx).publish("BLE.ERR.pendingIntentScan", "error", Integer.toString(error));
            return;
        }
        ArrayList<ScanResult> results = intent.getParcelableArrayListExtra(BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT);
        if (results == null) {
            return;
        }
        for (ScanResult result : results) {
            mScanCallback.onScanResult(0, result);
        }
    }

    // Will be called when a DMesh device is found, or found again after 60 sec.
    protected void onDiscovery(Device bd, String name, boolean firstTime) {
        MsgMux.get(ctx).publish("wifi.BLE.DISC",
                "name", name,
                "cnt", "" + discoveryCnt);
        // Update the status.
        wifi.sendWifiDiscoveryStatus("ble", name);
    }

    private boolean processDiscovery(BluetoothDevice device, byte[] record, int rssi) {
        String addr = deviceAddress(device);
        String parsed = MeshNode.parseBleServiceData(record, rssi, addr);
        if (parsed == null || parsed.equals("{}")) {
            return false;
        }
        JSONObject data;
        try {
            data = new JSONObject(parsed);
        } catch (JSONException e) {
            MsgMux.get(ctx).publish("BLE.ERR.parse", "error", e.toString(), "addr", addr);
            return false;
        }
        String id = dmeshDeviceId(data, addr);
        if (id.length() == 0) {
            return false;
        }
        Device bd = new Device(id, parsed);
        bd.dev = device;
        bd.data.putString(Device.P2PAddr, "/ble/" + id);
        bd.data.putString("proto", "dmesh_ble");
        bd.data.putString("ble_layout", optText(data, "layout"));
        bd.data.putString("ble_event", dmeshEvent(data));
        bd.data.putString("ble_pending", optText(data, "pending"));
        bd.data.putString("ble_payload_len", optText(data, "payload_len"));
        bd.data.putString("ble_payload_hash", dmeshPacketId(data));
        bd.data.putString("ble_addr", addr);
        bd.data.putInt(Device.LEVEL, rssi);
        Device old = devices.get(id);
        devices.put(id, bd);
        deviceIdsByAddress.put(addr, id);
        long now = SystemClock.elapsedRealtime();
        bd.lastScan = now;
        if (old == null || now - old.lastScan > 120000) {
            onDiscovery(bd, id, old == null);
        }
        boolean pending = hasPendingPayload(data);
        boolean connectable = data.optBoolean("connectable_response", false);
        boolean companionAllowed = DMeshCompanionPrefs.isAllowed(ctx, id, addr);
        if (pending && companionAllowed) {
            maybePullPending(device, id, addr, connectable);
        }
        String signature = dmeshSignature(data, id);
        Long lastAt = lastDmeshDiscoveryAt.get(id);
        String lastSignature = lastDmeshDiscovery.get(id);
        boolean duplicate = data.optBoolean("duplicate", false)
                || (signature.equals(lastSignature) && lastAt != null
                && now - lastAt < DMESH_DISCOVERY_REPEAT_MS);
        if (duplicate) {
            return true;
        }
        lastDmeshDiscovery.put(id, signature);
        lastDmeshDiscoveryAt.put(id, now);
        MsgMux.get(ctx).publish("BLE.DISC",
                "proto", "dmesh",
                "id", id,
                "addr", addr,
                "rssi", Integer.toString(rssi),
                "layout", optText(data, "layout"),
                "event", dmeshEvent(data),
                "pending", optText(data, "pending"),
                "payload_len", optText(data, "payload_len"),
                "payload_hash", dmeshPacketId(data),
                "prefix", shortPrefix(optText(data, "prefix")),
                "scan_rssi", optText(data, "scan_rssi"),
                "companion", companionAllowed ? "allowed" : "ignored",
                "pull", pending && companionAllowed ? (connectable ? "gatt" : "probe") : "none");
        return true;
    }

    private String dmeshDeviceId(JSONObject data, String addr) {
        String id = data.optString("device_id", "");
        if (!id.isEmpty()) {
            return id;
        }
        String src = data.optString("src_hex", data.optString("src", ""));
        if (!src.isEmpty()) {
            return src.replace("0x", "");
        }
        return addr == null ? "" : addr.replace(":", "").toLowerCase();
    }

    private String dmeshEvent(JSONObject data) {
        String event = data.optString("event", "");
        if (!event.isEmpty()) {
            return event;
        }
        String pending = data.optString("pending", "");
        return pending.isEmpty() || "0".equals(pending) ? "announce" : "payload_pending";
    }

    private String dmeshPacketId(JSONObject data) {
        String hash = data.optString("payload_hash", "");
        if (!hash.isEmpty()) {
            return hash;
        }
        hash = data.optString("payload_hash_u32", "");
        if (!hash.isEmpty()) {
            return hash;
        }
        return data.optString("packet_id_hex", data.optString("packet_id", ""));
    }

    private String optText(JSONObject data, String key) {
        if (!data.has(key) || data.isNull(key)) {
            return "";
        }
        return String.valueOf(data.opt(key));
    }

    private boolean hasPendingPayload(JSONObject data) {
        int pending = data.optInt("pending", 0);
        int payloadLen = data.optInt("payload_len", 0);
        String event = data.optString("event", "");
        return pending > 0 || payloadLen > 0 || "payload_pending".equals(event) || "lora_rx".equals(event);
    }

    private String shortPrefix(String prefix) {
        if (prefix == null || prefix.length() <= 24) {
            return prefix == null ? "" : prefix;
        }
        return prefix.substring(0, 24);
    }

    private String dmeshSignature(JSONObject data, String id) {
        return id + "|" + optText(data, "layout") + "|" + dmeshEvent(data) + "|"
                + optText(data, "pending") + "|" + optText(data, "payload_len") + "|"
                + dmeshPacketId(data) + "|" + shortPrefix(optText(data, "prefix"));
    }

    private void maybePullPending(BluetoothDevice device, String id, String addr, boolean connectable) {
        long now = SystemClock.elapsedRealtime();
        Long last = lastDmeshPullAt.get(id);
        if (last != null && now - last < DMESH_PULL_REPEAT_MS) {
            return;
        }
        lastDmeshPullAt.put(id, now);
        MsgMux.get(ctx).publish("BLE.PENDING",
                "id", id,
                "addr", addr,
                "connectable", Boolean.toString(connectable),
                "action", connectable ? "connect" : "probe");
        if (connectable) {
            connect(addr);
        } else if (device != null) {
            connectDevice(device, addr, false);
        }
    }

    private void processExternalDiscovery(BluetoothDevice device, ScanRecord record, int rssi, String proto,
                                          String service, String compatible) {
        String address = deviceAddress(device);
        String name = deviceName(device, record);
        String key = proto + ":" + address + ":" + name;
        Long old = externalDevices.get(key);
        long now = SystemClock.elapsedRealtime();
        if (old != null && now - old < 120000) {
            return;
        }
        externalDevices.put(key, now);
        MsgMux.get(ctx).publish("BLE.DISC",
                "proto", proto,
                "compatible", compatible,
                "service", service,
                "name", name,
                "addr", address,
                "rssi", Integer.toString(rssi));
    }

    private void processPairingDiscovery(BluetoothDevice device, ScanRecord record, int rssi) {
        String address = deviceAddress(device);
        String name = deviceName(device, record);
        if (address.isEmpty()) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        DMeshCompanionPrefs.recordPairingDiscovery(ctx, address, name, now);
        Device bd = new Device(address, "dmesh_pairing");
        bd.dev = device;
        bd.lastScan = now;
        bd.data.putString(Device.P2PAddr, "/ble/" + address);
        bd.data.putString("proto", "dmesh_pairing");
        bd.data.putString("ble_addr", address);
        bd.data.putString("name", name);
        bd.data.putInt(Device.LEVEL, rssi);
        devices.put(address, bd);
        Long old = lastDmeshPairingAt.get(address);
        if (old == null || now - old >= 5000) {
            lastDmeshPairingAt.put(address, now);
            MsgMux.get(ctx).publish("BLE.DISC",
                    "proto", "dmesh_pairing",
                    "service", DMESH_PAIRING.toString(),
                    "name", name,
                    "addr", address,
                    "rssi", Integer.toString(rssi),
                    "pairing", DMeshCompanionPrefs.isPairingActive(ctx, now) ? "active" : "idle");
        }
        if (!DMeshCompanionPrefs.isPairingActive(ctx, now)
                || DMeshCompanionPrefs.isConfigured(ctx)) {
            return;
        }
        DMeshCompanionPrefs.save(ctx, -1, "", address, name);
        DMeshCompanionPrefs.stopPairingWindow(ctx);
        try {
            device.createBond();
        } catch (SecurityException e) {
            MsgMux.get(ctx).publish("COMPANION.ERROR", "error", "bond_permission", "addr", address);
        } catch (RuntimeException e) {
            MsgMux.get(ctx).publish("COMPANION.ERROR", "error", e.toString(), "addr", address);
        }
        MsgMux.get(ctx).publish("COMPANION.ASSOCIATE",
                "state", "direct_scan",
                "addr", address,
                "name", name);
    }

    private String deviceAddress(BluetoothDevice device) {
        if (device == null) {
            return "";
        }
        try {
            return device.getAddress();
        } catch (SecurityException e) {
            return "";
        }
    }

    private String deviceName(BluetoothDevice device, ScanRecord record) {
        String name = record == null ? null : record.getDeviceName();
        if (name == null && device != null) {
            try {
                name = device.getName();
            } catch (SecurityException e) {
                name = "";
            }
        }
        return name == null ? "" : name;
    }

    public void advertise(byte[] urlb) {
        if (mBluetoothAdapter == null || mBluetoothLeAdvertiser == null) {
            MsgMux.get(ctx).publish("BLE.ERR.unsupported", "advertiser", "missing");
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.ERR.permission", "permission", Manifest.permission.BLUETOOTH_ADVERTISE);
            return;
        }
        if (urlb == null) {
            mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
            adv = false;
            currentAdvBytes = null;
            MsgMux.get(ctx).publish("BLE.advertise", "state", "stopped");
            return;

        }

        byte[] advBytes = Arrays.copyOf(urlb, urlb.length);

        if (currentAdvBytes != null && Arrays.equals(currentAdvBytes, advBytes)) {
            MsgMux.get(ctx).publish("BLE.advertise", "state", adv ? "started" : "pending");
            return;
        }

        currentAdvBytes = advBytes;

        // LOW_POWER, LOW_LATENCY, BALANCED
        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                // 1 sec (BALANCED=250ms)
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
                .setConnectable(false)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();

        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(DMESH_OPERATIONAL)
                .addServiceData(DMESH_OPERATIONAL, advBytes)
                .build();

        mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
        }
        mBluetoothLeAdvertiser.startAdvertising(settings, data, mAdvertiseCallback);
        MsgMux.get(ctx).publish("BLE.advertise", "state", "starting", "uuid", DMESH_OPERATIONAL.toString());
    }

    public void scanStop() {
        if (leScanner == null) {
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.ERR.permission", "permission", Manifest.permission.BLUETOOTH_SCAN);
            return;
        }
        leScanner.stopScan(mScanCallback);
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            leScanner.stopScan(scanPendingIntent());
        }
        mScanning = false;
        MsgMux.get(ctx).publish("BLE.stop");
    }

    public void scan() {
        if (mScanning) {
            MsgMux.get(ctx).publish("BLE.scan", "state", "already_started");
            return;
        }
        if (leScanner == null) {
            MsgMux.get(ctx).publish("BLE.ERR.unsupported", "scanner", "missing");
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.ERR.permission", "permission", Manifest.permission.BLUETOOTH_SCAN);
            return;
        }
        // Stops scanning after a pre-defined scan period.

        leScanner.stopScan(mScanCallback);
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            leScanner.stopScan(scanPendingIntent());
        }
        mScanning = false;
        mHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                startScan();
            }
        }, 500);
    }

    public void startScan() {
        mScanning = true;

        // can pass UUID[] of GATT services.

        List<ScanFilter> filters = new ArrayList<>();
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(DMESH_OPERATIONAL)
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(DMESH_PAIRING)
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceData(DMESH_OPERATIONAL, new byte[0], new byte[0])
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(MESHTASTIC)
                .build());

        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED) {
            leScanner.startScan(
                    filters,
                    new ScanSettings.Builder()
                            //.setReportDelay(2000) - breaks KindeFire10
                            .build(), mScanCallback);
            try {
                leScanner.startScan(filters, new ScanSettings.Builder().build(), scanPendingIntent());
            } catch (RuntimeException e) {
                MsgMux.get(ctx).publish("BLE.ERR.pendingIntentScan", "error", e.toString());
            }
            MsgMux.get(ctx).publish("BLE.scan", "filters", "dmesh_operational,dmesh_pairing,meshtastic", "wake", "pending_intent");
        } else {
            MsgMux.get(ctx).publish("BLE.ERR.permission", "permission", Manifest.permission.BLUETOOTH_SCAN);
        }
    }

    private PendingIntent scanPendingIntent() {
        Intent intent = new Intent(ACTION_SCAN_RESULT);
        intent.setPackage(ctx.getPackageName());
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (android.os.Build.VERSION.SDK_INT >= 23) {
            flags |= PendingIntent.FLAG_MUTABLE;
        }
        return PendingIntent.getBroadcast(ctx, 27, intent, flags);
    }

    // == GATT client implementation

    @Override
    public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo, String[] argv) {
        String action = msgType;
        String argAddr = "";
        if (argv != null && argv.length >= 3) {
            action = argv[2];
            if (argv.length > 3) {
                argAddr = argv[3];
            }
        }
        MsgFrame frame = MsgFrame.fromMessage(msg);
        if (frame != null && frame.fields.containsKey("addr")) {
            argAddr = frame.fields.get("addr");
        }
        if ("adv".equals(action)) {
            byte[] deviceId = wifi.deviceIdBytes();
            if (argv != null && argv.length > 3) {
                advertise(MeshNode.buildBleServiceData("payload_pending", deviceId, argv[3].getBytes(), 0, 0));
            } else {
                advertise(MeshNode.buildBleServiceData("wake_request", deviceId, new byte[0], 0, 0));
            }
        }
        if ("scan".equals(action)) {
            scan();
        }
        if ("pair".equals(action) || "pairing".equals(action)) {
            pair(argAddr);
        }
        if ("bond".equals(action)) {
            bond(argAddr);
        }
        if ("unbond".equals(action) || "remove_bond".equals(action) || "reset_bond".equals(action)) {
            unbond(argAddr);
        }
        if ("cmd".equals(action) || "command".equals(action)) {
            String command = frame == null ? "" : frame.fields.get("text");
            if ((command == null || command.isEmpty()) && argv != null && argv.length > 4) {
                StringBuilder sb = new StringBuilder();
                for (int i = 4; i < argv.length; i++) {
                    if (i > 4) {
                        sb.append(' ');
                    }
                    sb.append(argv[i]);
                }
                command = sb.toString();
            }
            command(argAddr, command);
        }
        if ("stop".equals(action)) {
            scanStop();
        }
    }

    private void handleServer(BluetoothServerSocket ss) {
        while (true) {
            try {
                final BluetoothSocket s = ss.accept();
                try {
                    handleServerConnection(s);
                } catch(Throwable t) {
                    t.printStackTrace();
                }
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
    }

    protected void handleServerConnection(BluetoothSocket s) throws IOException {
        String cid = ConnUDS.proxyConnection(s.getInputStream(), s.getOutputStream());
        if (cid == "") {
            s.close();
            return;
        }
        MsgMux.get(ctx).publish("BT.scon",
                "raddr", s.getRemoteDevice().getAddress(),
                "cid", cid);
    }
    BluetoothServerSocket ss;
    //BluetoothGattCharacteristic notChar;
    void initServer() {
        try {
            // TODO: use normal advertisment to indicate support for L2 channel and the PSM
            if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                return;
            }
            ss = bluetoothManager.getAdapter().listenUsingInsecureL2capChannel();
            psm = ss.getPsm();
            new Thread(new Runnable() {
                @Override
                public void run() {
                    handleServer(ss);
                }
            }).start();
            Log.d(TAG, "DIRECT L2 PSM=" + psm);


        gatS = bluetoothManager.openGattServer(ctx, mGattServer);
        if (gatS == null) {
            Log.d(TAG, "Failed to open GATT server");
            return;
        }
        BluetoothGattService service = new BluetoothGattService(dmeshGattUUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        receivePort = new BluetoothGattCharacteristic(
                dmeshRxUUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE | BluetoothGattCharacteristic.PERMISSION_READ);
        service.addCharacteristic(receivePort);

        sendPort = new BluetoothGattCharacteristic(
                dmeshTxUUID,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_WRITE | BluetoothGattCharacteristic.PERMISSION_READ);

        BluetoothGattDescriptor notDescriptor =
                new BluetoothGattDescriptor(BLE_DESC_CLIENT_CONFIG,
                        BluetoothGattDescriptor.PERMISSION_WRITE);
        sendPort.addDescriptor(notDescriptor);
        service.addCharacteristic(sendPort);
        gatS.addService(service);
        } catch (Throwable e) {
            e.printStackTrace();
        }

    }

    public void connect(String addr) {
        Device d = devices.get(addr);
        if (d == null) {
            String id = deviceIdsByAddress.get(addr);
            d = id == null ? null : devices.get(id);
        }
        if (d == null) {
            for (Device candidate : devices.values()) {
                if (candidate.dev != null && addr.equals(deviceAddress(candidate.dev))) {
                    d = candidate;
                    break;
                }
            }
        }
        BluetoothDevice device = d == null ? remoteDeviceFor(addr) : d.dev;
        if (device == null) {
            MsgMux.get(ctx).publish("BLE.PULL", "addr", addr, "state", "missing_device");
            return;
        }
        connectDevice(device, addr, false);
    }

    private BluetoothDevice remoteDeviceFor(String addr) {
        if (addr == null || !BluetoothAdapter.checkBluetoothAddress(addr)
                || mBluetoothAdapter == null) {
            return null;
        }
        return mBluetoothAdapter.getRemoteDevice(addr);
    }

    private String requestedAddress(String requested, BluetoothDevice device) {
        if (requested != null && !requested.isEmpty()) {
            return requested;
        }
        return deviceAddress(device);
    }

    public void pair(String addr) {
        Device d = findPairingDevice(addr);
        BluetoothDevice device = d == null ? remoteDeviceFor(addr) : d.dev;
        if (device == null) {
            MsgMux.get(ctx).publish("BLE.PAIR", "addr", addr == null ? "" : addr,
                    "state", "missing_device");
            return;
        }
        if (activePull != null && activePull.isActive()) {
            MsgMux.get(ctx).publish("BLE.PAIR",
                    "addr", addr,
                    "state", "preempt",
                    "active", activePull.addr);
            disconnectPull(activePull.gatt);
            activePull = null;
            mHandler.postDelayed(() -> connectDevice(device, requestedAddress(addr, device), true), 800);
            return;
        }
        connectDevice(device, requestedAddress(addr, device), true);
    }

    public void command(String addr, String command) {
        Device d = findPairingDevice(addr);
        BluetoothDevice device = d == null ? null : d.dev;
        if (device == null) {
            device = remoteDeviceFor(addr);
        }
        if (device == null) {
            MsgMux.get(ctx).publish("BLE.CMD", "addr", addr == null ? "" : addr,
                    "state", "missing_device");
            return;
        }
        String text = command == null ? "" : command.trim();
        if (text.isEmpty()) {
            MsgMux.get(ctx).publish("BLE.CMD", "addr", deviceAddress(device),
                    "state", "missing_command");
            return;
        }
        if (activePull != null && activePull.isActive()) {
            MsgMux.get(ctx).publish("BLE.CMD",
                    "addr", addr,
                    "state", "preempt",
                    "active", activePull.addr);
            disconnectPull(activePull.gatt);
            activePull = null;
            final BluetoothDevice preemptDevice = device;
            final String commandText = text;
            mHandler.postDelayed(
                    () -> connectDevice(preemptDevice, deviceAddress(preemptDevice), false, commandText),
                    800);
            return;
        }
        connectDevice(device, deviceAddress(device), false, text);
    }

    public void bond(String addr) {
        BluetoothDevice device = null;
        if (activePull != null && activePull.gatt != null) {
            device = activePull.gatt.getDevice();
        }
        if (device == null) {
            Device d = findPairingDevice(addr);
            device = d == null ? null : d.dev;
        }
        if (device == null) {
            device = remoteDeviceFor(addr);
        }
        if (device == null) {
            MsgMux.get(ctx).publish("BLE.PAIR", "addr", addr == null ? "" : addr,
                    "state", "missing_device");
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.PAIR", "addr", deviceAddress(device),
                    "state", "missing_permission");
            return;
        }
        boolean ok = device.createBond();
        MsgMux.get(ctx).publish("BLE.PAIR",
                "addr", deviceAddress(device),
                "state", "bond_request",
                "ok", Boolean.toString(ok));
    }

    public void unbond(String addr) {
        BluetoothDevice device = null;
        if (activePull != null && activePull.gatt != null) {
            device = activePull.gatt.getDevice();
        }
        if (device == null) {
            Device d = findPairingDevice(addr);
            device = d == null ? null : d.dev;
        }
        if (device == null) {
            device = remoteDeviceFor(addr);
        }
        if (device == null) {
            MsgMux.get(ctx).publish("BLE.PAIR", "addr", addr == null ? "" : addr,
                    "state", "missing_device");
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.PAIR", "addr", deviceAddress(device),
                    "state", "missing_permission");
            return;
        }
        boolean ok = false;
        try {
            java.lang.reflect.Method removeBond = BluetoothDevice.class.getMethod("removeBond");
            Object result = removeBond.invoke(device);
            ok = result instanceof Boolean && (Boolean) result;
        } catch (ReflectiveOperationException | RuntimeException err) {
            Log.w(TAG, "removeBond failed", err);
        }
        MsgMux.get(ctx).publish("BLE.PAIR",
                "addr", deviceAddress(device),
                "state", "unbond_request",
                "ok", Boolean.toString(ok),
                "bond", Integer.toString(device.getBondState()));
    }

    private Device findPairingDevice(String addr) {
        if (addr != null && !addr.isEmpty()) {
            Device d = devices.get(addr);
            if (d == null) {
                String id = deviceIdsByAddress.get(addr);
                d = id == null ? null : devices.get(id);
            }
            if (d == null) {
                for (Device candidate : devices.values()) {
                    if (candidate.dev != null && addr.equals(deviceAddress(candidate.dev))) {
                        d = candidate;
                        break;
                    }
                }
            }
            if (d != null) {
                return d;
            }
        }
        Device best = null;
        for (Device candidate : devices.values()) {
            if (candidate.dev == null) {
                continue;
            }
            String proto = candidate.data.getString("proto", "");
            if (!"dmesh_ble".equals(proto) && !"dmesh_pairing".equals(proto)) {
                continue;
            }
            if (best == null || candidate.lastScan > best.lastScan) {
                best = candidate;
            }
        }
        return best;
    }

    private void connectDevice(BluetoothDevice device, String addr, boolean pairingRequest) {
        connectDevice(device, addr, pairingRequest, null);
    }

    private void connectDevice(BluetoothDevice device, String addr, boolean pairingRequest,
                               String commandText) {
        if (device == null) {
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.PULL", "addr", addr, "state", "missing_permission");
            return;
        }
        String id = deviceIdsByAddress.get(addr);
        if (!DMeshCompanionPrefs.isAllowed(ctx, id, addr)) {
            MsgMux.get(ctx).publish("BLE.PULL", "addr", addr, "id", id, "state", "not_companion");
            return;
        }
        if (activePull != null && activePull.isActive()) {
            MsgMux.get(ctx).publish("BLE.PULL", "addr", addr, "state", "busy");
            return;
        }
        ClientCallback mGattCallback = new ClientCallback(id, addr, pairingRequest, commandText);
        activePull = mGattCallback.session;
        MsgMux.get(ctx).publish(commandText != null ? "BLE.CMD" : (pairingRequest ? "BLE.PAIR" : "BLE.PULL"),
                "addr", addr,
                "state", "connecting");
        btGattClient = device.connectGatt(ctx, false, mGattCallback);
        activePull.gatt = btGattClient;
        mHandler.postDelayed(() -> {
            if (activePull == mGattCallback.session && activePull.isActive()
                    && SystemClock.elapsedRealtime() - activePull.lastProgress >= BLE_PULL_TIMEOUT_MS) {
                MsgMux.get(ctx).publish("BLE.PULL",
                        "addr", addr,
                        "state", "timeout",
                        "phase", "connect");
                disconnectPull(activePull.gatt);
            }
        }, BLE_PULL_TIMEOUT_MS);
    }

    // Various callback methods defined by the BLE API, used in the client connection.
    class ClientCallback extends BluetoothGattCallback {
        final PullSession session;

        ClientCallback(String id, String addr, boolean pairingRequest, String commandText) {
            session = new PullSession(id, addr);
            session.pairingRequest = pairingRequest;
            session.commandText = commandText;
        }

        @Override
        public void onPhyUpdate(BluetoothGatt gatt, int txPhy, int rxPhy, int status) {
            super.onPhyUpdate(gatt, txPhy, rxPhy, status);
        }

        @Override
        public void onPhyRead(BluetoothGatt gatt, int txPhy, int rxPhy, int status) {
            super.onPhyRead(gatt, txPhy, rxPhy, status);
        }

        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status,
                                            int newState) {
            String intentAction;
            if (newState == STATE_CONNECTED) {
                mConnectionState = STATE_CONNECTED;
                session.gatt = gatt;
                MsgMux.get(ctx).publish("BLE.PULL", "addr", deviceAddress(gatt.getDevice()), "state", "connected");

                Log.i(TAG, "Connected to GATT server.");
                if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                    boolean ok = gatt.discoverServices();
                    Log.i(TAG, "Attempting to start service discovery:" + ok);
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                mConnectionState = STATE_DISCONNECTED;
                MsgMux.get(ctx).publish("BLE.PULL", "addr", deviceAddress(gatt.getDevice()), "state", "disconnected");
                session.done = true;
                if (activePull == session) {
                    activePull = null;
                }
                gatt.close();
                Log.i(TAG, "Disconnected from GATT server.");
            }
        }

        @Override
        // New services discovered
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                List<BluetoothGattService> services = gatt.getServices();
                MsgMux.get(ctx).publish("BLE.PULL",
                        "addr", deviceAddress(gatt.getDevice()),
                        "state", "services",
                        "count", Integer.toString(services == null ? 0 : services.size()));
                BluetoothGattService service = gatt.getService(dmeshGattUUID);
                if (service == null) {
                    MsgMux.get(ctx).publish("BLE.PULL",
                            "addr", deviceAddress(gatt.getDevice()),
                            "state", "unsupported",
                            "reason", "missing_dmesh_gatt");
                    disconnectPull(gatt);
                    return;
                }
                session.rx = service.getCharacteristic(dmeshRxUUID);
                session.tx = service.getCharacteristic(dmeshTxUUID);
                if (session.rx == null || session.tx == null) {
                    MsgMux.get(ctx).publish("BLE.PULL",
                            "addr", deviceAddress(gatt.getDevice()),
                            "state", "unsupported",
                            "reason", "missing_dmesh_chars");
                    disconnectPull(gatt);
                    return;
                }
                if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                        != PackageManager.PERMISSION_GRANTED) {
                    MsgMux.get(ctx).publish("BLE.PULL",
                            "addr", deviceAddress(gatt.getDevice()),
                            "state", "missing_permission");
                    disconnectPull(gatt);
                    return;
                }
                boolean notify = gatt.setCharacteristicNotification(session.tx, true);
                BluetoothGattDescriptor ccc = session.tx.getDescriptor(BLE_DESC_CLIENT_CONFIG);
                if (!notify || ccc == null) {
                    MsgMux.get(ctx).publish("BLE.PULL",
                            "addr", deviceAddress(gatt.getDevice()),
                            "state", "unsupported",
                            "reason", "missing_notify");
                    disconnectPull(gatt);
                    return;
                }
                ccc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                boolean writeStarted = gatt.writeDescriptor(ccc);
                MsgMux.get(ctx).publish("BLE.PULL",
                        "addr", deviceAddress(gatt.getDevice()),
                        "state", "subscribing",
                        "status", Boolean.toString(writeStarted));

            } else {
                MsgMux.get(ctx).publish("BLE.PULL",
                        "addr", deviceAddress(gatt.getDevice()),
                        "state", "service_error",
                        "status", Integer.toString(status));
                Log.w(TAG, "onServicesDiscovered received: " + status);
            }
        }

        @Override
        // Result of a characteristic read operation
        public void onCharacteristicRead(BluetoothGatt gatt,
                                         BluetoothGattCharacteristic characteristic,
                                         byte[] value,
                                         int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                final byte[] data = characteristic.getValue();
                if (data != null && data.length > 0) {
                    final StringBuilder stringBuilder = new StringBuilder(data.length);
                    for (byte byteChar : data) {
                        stringBuilder.append(String.format("%02X ", byteChar));
                    }
                    Log.d(TAG, "Char: " + stringBuilder.toString());
                }
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
            MsgMux.get(ctx).publish("BLE.PULL",
                    "addr", deviceAddress(gatt.getDevice()),
                    "state", "write",
                    "status", Integer.toString(status));
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, byte []data) {
            handleCharacteristicChanged(data);
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
            handleCharacteristicChanged(characteristic == null ? null : characteristic.getValue());
        }

        private void handleCharacteristicChanged(byte[] data) {
            if (data == null || data.length == 0) {
                return;
            }
            String preview = new String(data, StandardCharsets.UTF_8).replace('\n', ' ').trim();
            if (preview.length() > 80) {
                preview = preview.substring(0, 80);
            }
            MsgMux.get(ctx).publish("BLE.PULL",
                    "addr", session.addr,
                    "state", "notify",
                    "bytes", Integer.toString(data.length),
                    "text", preview);
            session.lastProgress = SystemClock.elapsedRealtime();
            session.append(data);
            parsePullSession(session);
        }

        @Override
        public void onDescriptorRead(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status, byte[] data) {
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                MsgMux.get(ctx).publish("BLE.PULL",
                        "addr", deviceAddress(gatt.getDevice()),
                        "state", "subscribe_error",
                        "status", Integer.toString(status));
                disconnectPull(gatt);
                return;
            }
            MsgMux.get(ctx).publish("BLE.PULL",
                    "addr", deviceAddress(gatt.getDevice()),
                    "state", "subscribed");
            if (session.commandText != null) {
                writeGattText(gatt, session, session.commandText + "\n");
            } else if (session.pairingRequest) {
                writeGattText(gatt, session, "pairing request\n");
            } else {
                writeGattText(gatt, session, "ready max_bytes=" + BLE_READY_MAX_BYTES
                        + " after_seq=" + DMeshCompanionPrefs.lastSeq(ctx) + "\n");
            }
        }

        @Override
        public void onReliableWriteCompleted(BluetoothGatt gatt, int status) {
            super.onReliableWriteCompleted(gatt, status);
        }

        @Override
        public void onReadRemoteRssi(BluetoothGatt gatt, int rssi, int status) {
            super.onReadRemoteRssi(gatt, rssi, status);
        }
    }

    private void writeGattText(BluetoothGatt gatt, PullSession session, String text) {
        if (gatt == null || session == null || session.rx == null || text == null) {
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.PULL", "addr", session.addr, "state", "missing_permission");
            return;
        }
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        int status = gatt.writeCharacteristic(session.rx, data,
                BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE);
        MsgMux.get(ctx).publish("BLE.PULL",
                "addr", session.addr,
                "state", text.startsWith("ack ")
                        ? "ack_write"
                        : (text.startsWith("pairing ") ? "pairing_request_write" : "ready_write"),
                "status", Integer.toString(status));
    }

    private void parsePullSession(PullSession session) {
        while (session.buffer.size() > 0) {
            if (session.pendingLen < 0) {
                byte[] data = session.buffer.toByteArray();
                int nl = indexOf(data, (byte) '\n');
                if (nl < 0) {
                    return;
                }
                String line = new String(data, 0, nl, StandardCharsets.UTF_8).trim();
                session.consume(nl + 1);
                if (line.isEmpty()) {
                    continue;
                }
                if (line.startsWith("msg ") || line.startsWith("messages msg ")) {
                    session.pendingSeq = parseLongField(line, "seq", 0);
                    session.pendingHash = parseField(line, "hash", "");
                    session.pendingLen = (int) parseLongField(line, "len", -1);
                    if (session.pendingLen < 0 || session.pendingLen > 1024 * 1024) {
                        MsgMux.get(ctx).publish("BLE.PULL",
                                "addr", session.addr,
                                "state", "protocol_error",
                                "error", "bad_len");
                        disconnectPull(session.gatt);
                        return;
                    }
                    continue;
                }
                if (line.startsWith("done") || line.startsWith("messages done")) {
                    MsgMux.get(ctx).publish("BLE.PULL",
                            "addr", session.addr,
                            "state", "done",
                            "count", Integer.toString(session.count));
                    disconnectPull(session.gatt);
                    return;
                }
                if (line.startsWith("err") || line.startsWith("error")) {
                    MsgMux.get(ctx).publish("BLE.PULL",
                            "addr", session.addr,
                            "state", "error",
                            "error", line);
                    disconnectPull(session.gatt);
                    return;
                }
                MsgMux.get(ctx).publish("BLE.PULL",
                        "addr", session.addr,
                        "state", "line",
                        "text", line.length() > 80 ? line.substring(0, 80) : line);
                if (session.commandText != null) {
                    MsgMux.get(ctx).publish("BLE.CMD",
                            "addr", session.addr,
                            "state", "response",
                            "text", line.length() > 200 ? line.substring(0, 200) : line);
                    disconnectPull(session.gatt);
                    return;
                }
                continue;
            }

            if (session.buffer.size() < session.pendingLen) {
                maybeTimeoutPull(session);
                return;
            }
            byte[] data = session.buffer.toByteArray();
            byte[] payload = Arrays.copyOfRange(data, 0, session.pendingLen);
            session.consume(session.pendingLen);
            savePulledMessage(session, payload);
            writeGattText(session.gatt, session, "ack seq=" + session.pendingSeq
                    + " hash=" + session.pendingHash + "\n");
            session.pendingLen = -1;
            session.pendingSeq = 0;
            session.pendingHash = "";
        }
    }

    private void savePulledMessage(PullSession session, byte[] payload) {
        File dir = new File(ctx.getFilesDir(), "radio/ble");
        if (!dir.exists() && !dir.mkdirs()) {
            MsgMux.get(ctx).publish("BLE.PULL",
                    "addr", session.addr,
                    "state", "storage_error",
                    "error", "mkdir");
            return;
        }
        File out = new File(dir, "messages.bin");
        String header = "msg addr=" + session.addr
                + " id=" + (session.id == null ? "" : session.id)
                + " seq=" + session.pendingSeq
                + " hash=" + session.pendingHash
                + " len=" + payload.length
                + " time_ms=" + System.currentTimeMillis()
                + "\n";
        try (FileOutputStream fos = new FileOutputStream(out, true)) {
            fos.write(header.getBytes(StandardCharsets.UTF_8));
            fos.write(payload);
            fos.write('\n');
            session.count++;
            DMeshCompanionPrefs.setLastSeq(ctx, session.pendingSeq);
            MsgMux.get(ctx).publish("BLE.MSG",
                    "addr", session.addr,
                    "id", session.id,
                    "seq", Long.toString(session.pendingSeq),
                    "hash", session.pendingHash,
                    "len", Integer.toString(payload.length),
                    "file", out.getAbsolutePath());
        } catch (IOException e) {
            MsgMux.get(ctx).publish("BLE.PULL",
                    "addr", session.addr,
                    "state", "storage_error",
                    "error", e.toString());
        }
    }

    private void maybeTimeoutPull(PullSession session) {
        if (SystemClock.elapsedRealtime() - session.lastProgress <= BLE_PULL_TIMEOUT_MS) {
            return;
        }
        MsgMux.get(ctx).publish("BLE.PULL",
                "addr", session.addr,
                "state", "timeout",
                "count", Integer.toString(session.count));
        disconnectPull(session.gatt);
    }

    private void disconnectPull(BluetoothGatt gatt) {
        if (gatt == null) {
            activePull = null;
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                == PackageManager.PERMISSION_GRANTED) {
            gatt.disconnect();
        } else {
            gatt.close();
            activePull = null;
        }
    }

    private int indexOf(byte[] data, byte needle) {
        for (int i = 0; i < data.length; i++) {
            if (data[i] == needle) {
                return i;
            }
        }
        return -1;
    }

    private long parseLongField(String line, String key, long def) {
        String value = parseField(line, key, null);
        if (value == null || value.isEmpty()) {
            return def;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private String parseField(String line, String key, String def) {
        String prefix = key + "=";
        for (String part : line.split("\\s+")) {
            if (part.startsWith(prefix)) {
                return part.substring(prefix.length());
            }
        }
        return def;
    }

    private static final class PullSession {
        final String id;
        final String addr;
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        BluetoothGatt gatt;
        BluetoothGattCharacteristic rx;
        BluetoothGattCharacteristic tx;
        int pendingLen = -1;
        long pendingSeq;
        String pendingHash = "";
        int count;
        boolean done;
        boolean pairingRequest;
        String commandText;
        long lastProgress = SystemClock.elapsedRealtime();

        PullSession(String id, String addr) {
            this.id = id == null ? "" : id;
            this.addr = addr == null ? "" : addr;
        }

        boolean isActive() {
            return !done;
        }

        void append(byte[] data) {
            buffer.write(data, 0, data.length);
        }

        void consume(int bytes) {
            byte[] data = buffer.toByteArray();
            buffer.reset();
            if (bytes < data.length) {
                buffer.write(data, bytes, data.length - bytes);
            }
        }
    }

    // Callback used for the server.
    private class ServerCallback extends BluetoothGattServerCallback {
        List<BluetoothDevice> mRegisteredDevices = new ArrayList<>();

        @Override
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
            if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                return;
            }
            List<BluetoothDevice> connectedDevices = bluetoothManager.getConnectedDevices(GATT_SERVER);
            if (newState == STATE_CONNECTED) {
                Log.d(TAG, "Connection change connected " + status + " " + newState + " " +
                        device.getAddress() + " " + connectedDevices);
            } else {
                Log.d(TAG, "Connection change disconnected " + status + " " + newState + " " +
                        device.getAddress() + " " + connectedDevices);
            }


            super.onConnectionStateChange(device, status, newState);
        }

        @Override
        public void onServiceAdded(int status, BluetoothGattService service) {
            Log.d(TAG, "serviceAdded " + status + " " + service.getUuid() + " " + service);
            super.onServiceAdded(status, service);
        }

        @Override
        public void onCharacteristicReadRequest(BluetoothDevice device, int requestId, int offset, BluetoothGattCharacteristic characteristic) {
            super.onCharacteristicReadRequest(device, requestId, offset, characteristic);
            Log.d(TAG, "CHAR READ - should not happen" + characteristic.getUuid());
//            BluetoothGattCharacteristic nc = gatS
//                    .getService(eddyUUID)
//                    .getCharacteristic(bodyChar.getUuid());
//            gatS.sendResponse(device,
//                    requestId,
//                    BluetoothGatt.GATT_SUCCESS,
//                    0,
//                    nc.getValue());
        }

        @Override
        public void onCharacteristicWriteRequest(BluetoothDevice device, int requestId, BluetoothGattCharacteristic characteristic, boolean preparedWrite, boolean responseNeeded, int offset, byte[] value) {
//            bodyChar.setValue("HELLO".getBytes());
//            gatS.notifyCharacteristicChanged(device, bodyChar, false);
            BluetoothGattCharacteristic nc = gatS
                    .getService(dmeshGattUUID)
                    .getCharacteristic(sendPort.getUuid());
            byte[] data = "HELLO".getBytes();
            nc.setValue(data);
            if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                return;
            }
            //gatS.writeCharacteristic(device, nc);
            gatS.notifyCharacteristicChanged(device, nc,  false, data);
        }

        @Override
        public void onDescriptorReadRequest(BluetoothDevice device, int requestId, int offset,
                                            BluetoothGattDescriptor descriptor) {
            Log.d(TAG, "DESCR READ - should not happen" + descriptor.getUuid());
//
            if (sendPort.getUuid().equals(descriptor.getUuid())) {
                Log.d(TAG, "Config descriptor read");
                byte[] returnValue;
                if (mRegisteredDevices.contains(device)) {
                    returnValue = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE;
                } else {
                    returnValue = BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE;
                }
                gatS.sendResponse(device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        0,
                        returnValue);
            } else {
                Log.w(TAG, "Unknown descriptor read request");
                gatS.sendResponse(device,
                        requestId,
                        BluetoothGatt.GATT_FAILURE,
                        0,
                        null);
            }
        }

        @Override
        public void onDescriptorWriteRequest(BluetoothDevice device, int requestId,
                                             BluetoothGattDescriptor descriptor,
                                             boolean preparedWrite, boolean responseNeeded,
                                             int offset, byte[] value) {
            if (BLE_DESC_CLIENT_CONFIG.equals(descriptor.getUuid())) {
                if (Arrays.equals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE, value)) {
                    Log.d(TAG, "Subscribe device to notifications: " + device);
                    mRegisteredDevices.add(device);
                } else if (Arrays.equals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE, value)) {
                    Log.d(TAG, "Unsubscribe device from notifications: " + device);
                    mRegisteredDevices.remove(device);
                }

                if (responseNeeded) {
                    gatS.sendResponse(device,
                            requestId,
                            BluetoothGatt.GATT_SUCCESS,
                            0,
                            null);
                }
            } else {
                Log.w(TAG, "Unknown descriptor write request");
                if (responseNeeded) {
                    gatS.sendResponse(device,
                            requestId,
                            BluetoothGatt.GATT_FAILURE,
                            0,
                            null);
                }
            }
        }


        @Override
        public void onExecuteWrite(BluetoothDevice device, int requestId, boolean execute) {
            super.onExecuteWrite(device, requestId, execute);
        }

        @Override
        public void onNotificationSent(BluetoothDevice device, int status) {
            super.onNotificationSent(device, status);
        }

        @Override
        public void onPhyUpdate(BluetoothDevice device, int txPhy, int rxPhy, int status) {
            Log.d(TAG, "PHY_UPDATE" + txPhy + " " + rxPhy + " " + status);
            super.onPhyUpdate(device, txPhy, rxPhy, status);
        }

        @Override
        public void onMtuChanged(BluetoothDevice device, int mtu) {
            Log.d(TAG, "MTU CHANGE" + mtu);
            super.onMtuChanged(device, mtu);
        }

        @Override
        public void onPhyRead(BluetoothDevice device, int txPhy, int rxPhy, int status) {
            Log.d(TAG, "PHY_READ" + txPhy + " " + rxPhy + " " + status);
            super.onPhyRead(device, txPhy, rxPhy, status);
        }
    }

}
