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
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

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
    // Temporary compact discovery identity.  The connected GATT service stays
    // on DMESH_GATT until DMesh receives its own assigned 16-bit UUID.
    public static ParcelUuid DMESH_IPSP = ParcelUuid.fromString("00001820-0000-1000-8000-00805f9b34fb");
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
    private static final long BLE_DIAGNOSTIC_SCAN_MS = 5000;
    private static final int BLE_READY_MAX_BYTES = 1200;
    private static final long BLE_PULL_TIMEOUT_MS = 15000;
    private final BluetoothManager bluetoothManager;
    LocalMesh wifi;
    boolean mScanning = false;
    /** Changes whenever the current scan is stopped or replaced. */
    private int scanGeneration;
    Handler mHandler;
    Context ctx;
    BluetoothLeScanner leScanner;
    BluetoothAdapter mBluetoothAdapter;
    int discoveryCnt;
    int scanCnt;
    boolean debugUnfilteredScan;
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
    long wakeRequestUntilMs;
    String wakeCommand;


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
            if (debugUnfilteredScan) {
                String address = deviceAddress(device);
                if (!lastDmeshPairingAt.containsKey("raw:" + address)) {
                    lastDmeshPairingAt.put("raw:" + address, SystemClock.elapsedRealtime());
                    // Diagnostic scans are test evidence too. Keep one bounded
                    // structured record per address in service history instead
                    // of requiring logcat to discover the ESP's live address.
                    MsgMux.get(ctx).publish("BLE.RAW_SCAN",
                            "addr", address,
                            "name", deviceName(device, sr),
                            "rssi", Integer.toString(result.getRssi()),
                            "services", String.valueOf(sr.getServiceUuids()));
                }
            }

            Map<ParcelUuid, byte[]> sd = sr.getServiceData();
            if (sd != null) {
                byte[] record = sd.get(DMESH_IPSP);
                if (record == null) {
                    record = sd.get(DMESH_OPERATIONAL);
                }
                if (record != null && processDiscovery(device, record, result.getRssi())) {
                    super.onScanResult(callbackType, result);
                    return;
                }
            }

            List<ParcelUuid> suid = sr.getServiceUuids();
            if (suid == null || suid.size() == 0) {
                return;
            }
            if (suid.contains(DMESH_PAIRING) || suid.contains(DMESH_IPSP)
                    || suid.contains(DMESH_OPERATIONAL)) {
                Log.i(TAG, "scan addr=" + deviceAddress(device)
                        + " name=" + deviceName(device, sr)
                        + " rssi=" + result.getRssi()
                        + " services=" + suid);
            }
            if (suid.contains(MESHTASTIC)) {
                processExternalDiscovery(device, sr, result.getRssi(),
                        "meshtastic", MESHTASTIC.toString(), "");
            }
            if (suid.contains(DMESH_PAIRING)) {
                processPairingDiscovery(device, sr, result.getRssi());
            }
            if (!suid.contains(DMESH_IPSP) && !suid.contains(DMESH_OPERATIONAL)) {
                return;
            }

            if (sd == null) {
                return;
            }

            byte[] record = sd.get(DMESH_IPSP);
            if (record == null) {
                record = sd.get(DMESH_OPERATIONAL);
            }
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
        bd.data.putString(Device.RADIO_ADDR, "/ble/" + id);
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
        boolean companionAllowed = DMeshCompanionPrefs.isAllowed(ctx, id, addr);
        boolean wakeResponse = SystemClock.elapsedRealtime() < wakeRequestUntilMs
                && "idle_hello".equals(dmeshEvent(data));
        if ((pending || wakeResponse) && companionAllowed) {
            if (wakeResponse && wakeCommand != null && !wakeCommand.isEmpty()) {
                String command = wakeCommand;
                wakeCommand = null;
                command(addr, command);
            } else {
                maybePullPending(id, addr);
            }
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
                "pull", (pending || wakeResponse) && companionAllowed ? "coc" : "none");
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

    /**
     * A DMesh pending-data advertisement is only a CoC rendezvous signal.
     * There is no DMesh GATT payload service: after discovery Android opens
     * the advertised ESP by its stable address and requests bounded compact
     * CBOR status on the fixed lab CoC PSM.
     */
    private void maybePullPending(String id, String addr) {
        long now = SystemClock.elapsedRealtime();
        Long last = lastDmeshPullAt.get(id);
        if (last != null && now - last < DMESH_PULL_REPEAT_MS) {
            return;
        }
        lastDmeshPullAt.put(id, now);
        MsgMux.get(ctx).publish("BLE.PENDING",
                "id", id,
                "addr", addr,
                "transport", "coc",
                "action", "status");
        cocPendingStatus(addr);
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
        bd.data.putString(Device.RADIO_ADDR, "/ble/" + address);
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
        advertise(urlb, AdvertiseSettings.ADVERTISE_MODE_LOW_POWER);
    }

    private void advertise(byte[] urlb, int advertiseMode) {
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
                .setAdvertiseMode(advertiseMode)
                .setConnectable(false)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();

        // Android serializes the Service Data AD type as UUID16 followed by
        // this payload. The shared DMesh encoder includes UUID16 for raw
        // ESP32 packets, so remove that header here rather than advertising
        // it twice (which shifts the ESP event byte by two positions).
        byte[] serviceData = advBytes;
        if (advBytes.length >= 2 && advBytes[0] == 0x20 && advBytes[1] == 0x18) {
            serviceData = Arrays.copyOfRange(advBytes, 2, advBytes.length);
        }
        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(DMESH_IPSP)
                .addServiceData(DMESH_IPSP, serviceData)
                .build();

        mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
        }
        mBluetoothLeAdvertiser.startAdvertising(settings, data, mAdvertiseCallback);
        MsgMux.get(ctx).publish("BLE.advertise", "state", "starting", "uuid", DMESH_IPSP.toString());
    }

    /**
     * Advertise a bounded non-connectable wake request while Android has
     * outbound work. The sleeping ESP scans during its raw-NAN awake window,
     * then becomes connectable only after observing this record.
     */
    public void advertiseWake(byte[] payload, long windowMs) {
        advertiseWake(payload, windowMs, "");
    }

    public void advertiseWake(byte[] payload, long windowMs, String command) {
        byte[] deviceId = wifi.deviceIdBytes();
        byte[] record = MeshNode.buildBleServiceData("wake_request", deviceId,
                payload == null ? new byte[0] : payload, 0, 0);
        wakeRequestUntilMs = SystemClock.elapsedRealtime() + Math.max(100, Math.min(windowMs, 20_000)) + 5000;
        wakeCommand = command == null ? "" : command.trim();
        // The ESP only scans briefly once per raw-NAN duty interval. Use a
        // balanced advertising cadence for this bounded wake request so a
        // 250 ms ESP scan has several chances to overlap without retaining
        // Android advertising after the rendezvous completes.
        advertise(record, AdvertiseSettings.ADVERTISE_MODE_BALANCED);
        long bounded = Math.max(100, Math.min(windowMs, 20_000));
        mHandler.postDelayed(() -> {
            if (currentAdvBytes != null && Arrays.equals(currentAdvBytes, record)) {
                advertise(null);
            }
        }, bounded);
        MsgMux.get(ctx).publish("BLE.rendezvous", "state", "wake_advertising",
                "window_ms", Long.toString(bounded));
    }

    public void scanStop() {
        scanGeneration++;
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
        final int generation = ++scanGeneration;
        mHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (generation == scanGeneration) {
                    startScan();
                }
            }
        }, 500);
    }

    public void startScan() {
        mScanning = true;

        // can pass UUID[] of GATT services.

        List<ScanFilter> filters = new ArrayList<>();
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(DMESH_IPSP)
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(DMESH_PAIRING)
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceData(DMESH_IPSP, new byte[0], new byte[0])
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

    public void scanAll() {
        if (leScanner == null || ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)
                != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.ERR.permission", "permission", "BLUETOOTH_SCAN");
            return;
        }
        scanStop();
        final int generation = ++scanGeneration;
        debugUnfilteredScan = true;
        lastDmeshPairingAt.clear();
        final int scanStartCount = scanCnt;
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .setReportDelay(0)
                .build();
        try {
            leScanner.startScan(null, settings, mScanCallback);
            mScanning = true;
            MsgMux.get(ctx).publish("BLE.scan", "filters", "none", "mode", "diagnostic",
                    "settings", "low_latency");
            mHandler.postDelayed(() -> {
                if (generation != scanGeneration || !mScanning) {
                    return;
                }
                leScanner.stopScan(mScanCallback);
                mScanning = false;
                MsgMux.get(ctx).publish("BLE.scan",
                        "mode", "diagnostic", "state", "complete",
                        "callbacks", Integer.toString(scanCnt - scanStartCount),
                        "window_ms", Long.toString(BLE_DIAGNOSTIC_SCAN_MS));
            }, BLE_DIAGNOSTIC_SCAN_MS);
        } catch (RuntimeException e) {
            mScanning = false;
            MsgMux.get(ctx).publish("BLE.ERR.scanStart", "mode", "diagnostic",
                    "error", e.toString());
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
        if ("wake".equals(action) || "rendezvous".equals(action)) {
            long windowMs = 2000;
            if (frame != null && frame.fields.containsKey("window_ms")) {
                try {
                    windowMs = Long.parseLong(frame.fields.get("window_ms"));
                } catch (NumberFormatException ignored) {
                    // Bounded default.
                }
            }
            String command = frame == null ? "" : frame.fields.get("command");
            if ((command == null || command.isEmpty()) && argv != null && argv.length > 3) {
                StringBuilder sb = new StringBuilder();
                for (int i = 3; i < argv.length; i++) {
                    if (i > 3) {
                        sb.append(' ');
                    }
                    sb.append(argv[i]);
                }
                command = sb.toString();
            }
            byte[] payload = command == null || command.isEmpty()
                    ? new byte[0] : command.getBytes(StandardCharsets.UTF_8);
            advertiseWake(payload, windowMs, command);
        }
        if ("scan".equals(action)) {
            debugUnfilteredScan = false;
            scan();
        }
        if ("scanall".equals(action)) {
            scanAll();
        }
        if ("pair".equals(action) || "pairing".equals(action)) {
            pair(argAddr);
        }
        if ("probe".equals(action) || "sleep_probe".equals(action)) {
            long delayMs = 4500;
            if (frame != null && frame.fields.containsKey("delay_ms")) {
                try {
                    delayMs = Long.parseLong(frame.fields.get("delay_ms"));
                } catch (NumberFormatException ignored) {
                    // Keep the bounded default for shell/debug callers.
                }
            }
            sleepProbe(argAddr, Math.max(1000, Math.min(delayMs, 12000)));
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
        if ("coc".equals(action) || "coc_probe".equals(action)
                || "coc_status".equals(action) || "coc_wake".equals(action)
                || "coc_wake_status".equals(action)) {
            int requestedPsm = 0x80;
            if (frame != null && frame.fields.containsKey("psm")) {
                try {
                    requestedPsm = Integer.decode(frame.fields.get("psm"));
                } catch (NumberFormatException ignored) {
                    // Use the lab default below.
                }
            }
            if ("coc_wake_status".equals(action)) {
                cocWakeStatus(argAddr, requestedPsm);
            } else if ("coc_wake".equals(action)) {
                cocWakeProbe(argAddr, requestedPsm);
            } else if ("coc_status".equals(action)) {
                cocStatus(argAddr, requestedPsm);
            } else {
                cocProbe(argAddr, requestedPsm);
            }
        }
        if ("stop".equals(action)) {
            scanStop();
        }
    }

    /**
     * Opens Android's public LE CoC client and verifies the firmware's
     * opt-in echo server. This is deliberately a dynamic-PSM transport probe,
     * not an IPSP/IPv6 implementation: IPSP uses assigned PSM 0x0023 whereas
     * Android's app-facing API accepts dynamic LE PSMs (0x0080..0x00ff).
     */
    public void cocProbe(String addr, int requestedPsm) {
        cocExchange(addr, requestedPsm, "probe",
                "dmesh-coc-ping".getBytes(StandardCharsets.UTF_8));
    }

    /** Send the compact-CBOR firmware status request ({0: 33}) over CoC. */
    public void cocStatus(String addr, int requestedPsm) {
        cocExchange(addr, requestedPsm, "status",
                new byte[] {(byte) 0xa1, 0x00, 0x18, 0x21});
    }

    /**
     * Retry a CoC status request after seeing an ESP payload advertisement.
     * The ESP repeats that advertisement on subsequent raw-NAN wake windows,
     * so Android retries the link but never advertises its own wake request in
     * this direction.
     */
    private void cocPendingStatus(String addr) {
        // {0: 37, 6: {197: "true"}}: firmware `messages pull=true`.
        // The response is bounded to one CoC SDU and contains the queued
        // LoRa/raw-radio record that caused the advertisement.
        cocDiscoveryExchange(addr, 0x80, "pending_pull",
                new byte[] {(byte) 0xa2, 0x00, 0x18, 0x25, 0x06, (byte) 0xa1,
                        0x18, (byte) 0xc5, 0x64, 0x74, 0x72, 0x75, 0x65});
    }

    /**
     * Advertise an Android pending request, then retry CoC until the sleeping
     * ESP observes it and opens its next short response window. This never
     * uses GATT and does not require Android to receive a scan callback.
     */
    public void cocWakeProbe(String addr, int requestedPsm) {
        cocWakeExchange(addr, requestedPsm, "probe",
                "dmesh-coc-ping".getBytes(StandardCharsets.UTF_8));
    }

    /** Send compact-CBOR status through the bounded advertising/CoC rendezvous. */
    public void cocWakeStatus(String addr, int requestedPsm) {
        cocWakeExchange(addr, requestedPsm, "status",
                new byte[] {(byte) 0xa1, 0x00, 0x18, 0x21});
    }

    private void cocWakeExchange(String addr, int requestedPsm, String operation, byte[] request) {
        if (addr == null || addr.isEmpty()) {
            MsgMux.get(ctx).publish("BLE.COC", "state", "missing_device", "op", operation);
            return;
        }
        final long windowMs = 16_000;
        final long deadline = SystemClock.elapsedRealtime() + windowMs;
        final AtomicBoolean completed = new AtomicBoolean(false);
        final AtomicBoolean inFlight = new AtomicBoolean(false);
        advertiseWake(request, windowMs, "");
        MsgMux.get(ctx).publish("BLE.COC", "state", "wake_advertising", "op", operation,
                "addr", addr, "window_ms", Long.toString(windowMs));
        Runnable[] attempt = new Runnable[1];
        attempt[0] = () -> {
            if (completed.get()) {
                return;
            }
            if (SystemClock.elapsedRealtime() >= deadline) {
                advertise(null);
                MsgMux.get(ctx).publish("BLE.COC", "state", "wake_timeout", "op", operation,
                        "addr", addr);
                return;
            }
            if (inFlight.compareAndSet(false, true)) {
                cocExchange(addr, requestedPsm, operation, request, completed, inFlight);
            }
            mHandler.postDelayed(attempt[0], 1_000);
        };
        // The ESP scans during its next raw-NAN wake, then advertises the
        // response window. Start near that cadence and keep at most one LE
        // socket request outstanding so Android's CoC resource pool is not
        // exhausted by overlapping retries.
        mHandler.postDelayed(attempt[0], 4_500);
    }

    private void cocDiscoveryExchange(String addr, int requestedPsm, String operation,
                                      byte[] request) {
        if (addr == null || addr.isEmpty()) {
            MsgMux.get(ctx).publish("BLE.COC", "state", "missing_device", "op", operation);
            return;
        }
        final long windowMs = 8_000;
        final long deadline = SystemClock.elapsedRealtime() + windowMs;
        final AtomicBoolean completed = new AtomicBoolean(false);
        final AtomicBoolean inFlight = new AtomicBoolean(false);
        MsgMux.get(ctx).publish("BLE.COC", "state", "pending_discovered", "op", operation,
                "addr", addr, "window_ms", Long.toString(windowMs));
        Runnable[] attempt = new Runnable[1];
        attempt[0] = () -> {
            if (completed.get()) {
                return;
            }
            if (SystemClock.elapsedRealtime() >= deadline) {
                MsgMux.get(ctx).publish("BLE.COC", "state", "pending_timeout", "op", operation,
                        "addr", addr);
                return;
            }
            if (inFlight.compareAndSet(false, true)) {
                cocExchange(addr, requestedPsm, operation, request, completed, inFlight, false);
            }
            mHandler.postDelayed(attempt[0], 1_000);
        };
        attempt[0].run();
    }

    private void cocExchange(String addr, int requestedPsm, String operation, byte[] request) {
        cocExchange(addr, requestedPsm, operation, request, null, null);
    }

    private void cocExchange(String addr, int requestedPsm, String operation, byte[] request,
                             AtomicBoolean completed, AtomicBoolean inFlight) {
        cocExchange(addr, requestedPsm, operation, request, completed, inFlight, true);
    }

    private void cocExchange(String addr, int requestedPsm, String operation, byte[] request,
                             AtomicBoolean completed, AtomicBoolean inFlight,
                             boolean stopWakeAdvertisement) {
        if (android.os.Build.VERSION.SDK_INT < 29) {
            MsgMux.get(ctx).publish("BLE.COC", "state", "unsupported_api", "api",
                    Integer.toString(android.os.Build.VERSION.SDK_INT));
            return;
        }
        if (requestedPsm < 0x80 || requestedPsm > 0xff) {
            MsgMux.get(ctx).publish("BLE.COC", "state", "invalid_psm", "psm",
                    String.format("0x%04x", requestedPsm));
            return;
        }
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) {
            MsgMux.get(ctx).publish("BLE.ERR.permission", "permission",
                    Manifest.permission.BLUETOOTH_CONNECT);
            return;
        }
        BluetoothDevice device = remoteDeviceFor(addr);
        if (device == null) {
            MsgMux.get(ctx).publish("BLE.COC", "state", "missing_device", "addr",
                    addr == null ? "" : addr);
            return;
        }
        final int psm = requestedPsm;
        final String target = deviceAddress(device);
        new Thread(() -> {
            try (BluetoothSocket socket = device.createInsecureL2capChannel(psm)) {
                MsgMux.get(ctx).publish("BLE.COC", "state", "connecting", "op", operation,
                        "addr", target, "psm", String.format("0x%04x", psm));
                socket.connect();
                socket.getOutputStream().write(request);
                socket.getOutputStream().flush();
                byte[] reply = new byte[256];
                int offset = 0;
                while (offset < reply.length) {
                    int read = socket.getInputStream().read(reply, offset, reply.length - offset);
                    if (read < 0) {
                        break;
                    }
                    offset += read;
                    if ("probe".equals(operation) || socket.getInputStream().available() == 0) {
                        break;
                    }
                }
                boolean echoed = "probe".equals(operation) && offset == request.length
                        && Arrays.equals(request, Arrays.copyOf(reply, offset));
                String state = "probe".equals(operation)
                        ? (echoed ? "echo_ok" : "short_reply")
                        : (offset > 0 ? "response" : "short_reply");
                if (("echo_ok".equals(state) || "response".equals(state))
                        && completed != null && completed.compareAndSet(false, true)) {
                    if (stopWakeAdvertisement) {
                        advertise(null);
                    }
                }
                MsgMux.get(ctx).publish("BLE.COC", "state", state, "op", operation,
                        "addr", target, "psm", String.format("0x%04x", psm),
                        "rx", Integer.toString(offset), "hex", hex(reply, offset));
                if ("response".equals(state) && "pending_pull".equals(operation)) {
                    byte[] received = Arrays.copyOf(reply, offset);
                    // The CoC socket is short lived. Persist/ack on a separate
                    // task after this pull has been published and its socket is
                    // allowed to close; an unpersisted frame is deliberately
                    // not acknowledged and will be offered again.
                    mHandler.post(() -> persistAndAckPending(target, psm, received));
                }
            } catch (IOException | SecurityException e) {
                MsgMux.get(ctx).publish("BLE.COC", "state", "failed", "op", operation, "addr", target,
                        "psm", String.format("0x%04x", psm), "error", e.toString());
            } finally {
                if (inFlight != null) {
                    inFlight.set(false);
                }
            }
        }, "dmesh-coc-" + operation).start();
    }

    /** Persist a pulled companion record before acknowledging its ESP queue entry. */
    private void persistAndAckPending(String addr, int psm, byte[] reply) {
        PendingReceipt receipt = pendingReceipt(reply);
        if (receipt == null) {
            MsgMux.get(ctx).publish("BLE.COC", "state", "no_pending_record", "op", "pending_pull",
                    "addr", addr);
            return;
        }
        byte[] stored = MeshNode.radioMessage("radio.coc.store_frame",
                "src_device=" + addr + " seq=" + receipt.seq + " hash="
                        + Integer.toUnsignedString(receipt.hash), receipt.payload, -1);
        String result = new String(stored, StandardCharsets.UTF_8);
        if (!result.contains("\"status\":\"stored\"")) {
            MsgMux.get(ctx).publish("BLE.COC", "state", "persist_failed", "op", "pending_pull",
                    "addr", addr, "seq", Integer.toString(receipt.seq), "error", result);
            return;
        }
        MsgMux.get(ctx).publish("BLE.COC", "state", "persisted", "op", "pending_pull",
                "addr", addr, "seq", Integer.toString(receipt.seq),
                "hash", String.format("0x%08x", receipt.hash));
        // The ESP may already be back in its BLE-off raw-NAN interval after
        // the pull. Retry against its next pending advertisement rather than
        // retaining a connection or treating a first reconnect miss as loss.
        cocDiscoveryExchange(addr, psm, "pending_ack", pendingAckRequest(receipt));
    }

    /** Build `{0:37,6:{121:"true",220:"seq",164:"hash"}}` for firmware `messages ack`. */
    private static byte[] pendingAckRequest(PendingReceipt receipt) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(20);
        out.write(0xa2); out.write(0x00); out.write(0x18); out.write(0x25);
        out.write(0x06); out.write(0xa3);
        out.write(0x18); out.write(0x79); out.write(0x64);
        out.write('t'); out.write('r'); out.write('u'); out.write('e');
        out.write(0x18); out.write(0xdc); writeCborText(out, Integer.toString(receipt.seq));
        out.write(0x18); out.write(0xa4);
        writeCborText(out, String.format(Locale.ROOT, "0x%08x", receipt.hash));
        return out.toByteArray();
    }

    private static void writeCborText(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 24) {
            out.write(0x60 | bytes.length);
        } else {
            out.write(0x78); out.write(bytes.length);
        }
        out.write(bytes, 0, bytes.length);
    }

    /** Extract the one bounded telemetry record returned by `messages pull=true`. */
    private static PendingReceipt pendingReceipt(byte[] reply) {
        String text = cborTextValue(reply, 32);
        if (text == null || !text.startsWith("msg ")) {
            return null;
        }
        int seq = -1;
        long hash = -1;
        String data = null;
        for (String token : text.substring(0, text.indexOf('\n') >= 0 ? text.indexOf('\n') : text.length())
                .split("\\s+")) {
            if (token.startsWith("seq=")) {
                try { seq = Integer.parseInt(token.substring(4)); } catch (NumberFormatException ignored) { }
            } else if (token.startsWith("hash=0x")) {
                try { hash = Long.parseLong(token.substring(7), 16); } catch (NumberFormatException ignored) { }
            } else if (token.startsWith("data=hex:")) {
                data = token.substring(9);
            }
        }
        if (seq < 0 || hash < 0 || hash > 0xffff_ffffL || data == null || data.length() % 2 != 0) {
            return null;
        }
        try {
            byte[] payload = new byte[data.length() / 2];
            for (int i = 0; i < payload.length; i++) {
                payload[i] = (byte) Integer.parseInt(data.substring(i * 2, i * 2 + 2), 16);
            }
            return new PendingReceipt(seq, (int) hash, payload);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    /** Return the text value for a known compact-CBOR integer key (tag 32 here). */
    private static String cborTextValue(byte[] data, int key) {
        for (int i = 0; i + 2 < data.length; i++) {
            if ((data[i] & 0xff) != 0x18 || (data[i + 1] & 0xff) != key) continue;
            int header = data[i + 2] & 0xff;
            if ((header & 0xe0) != 0x60) continue;
            int len = header & 0x1f;
            int start = i + 3;
            if (len == 24 && start < data.length) { len = data[start] & 0xff; start++; }
            else if (len == 25 && start + 1 < data.length) {
                len = ((data[start] & 0xff) << 8) | (data[start + 1] & 0xff); start += 2;
            }
            if (len >= 0 && start + len <= data.length) {
                return new String(data, start, len, StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static final class PendingReceipt {
        final int seq;
        final int hash;
        final byte[] payload;

        PendingReceipt(int seq, int hash, byte[] payload) {
            this.seq = seq;
            this.hash = hash;
            this.payload = payload;
        }
    }

    private static String hex(byte[] bytes, int length) {
        StringBuilder out = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) {
            out.append(String.format("%02x", bytes[i] & 0xff));
        }
        return out.toString();
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
        String normalized = addr == null ? "" : addr.trim().toUpperCase(Locale.ROOT);
        if (!BluetoothAdapter.checkBluetoothAddress(normalized)
                || mBluetoothAdapter == null) {
            return null;
        }
        return mBluetoothAdapter.getRemoteDevice(normalized);
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

    /**
     * Keep one GATT connection open across a bounded device sleep interval.
     * This is a transport probe, not a product command: it writes a compact
     * text record immediately after CCCD setup and once more after delayMs.
     */
    public void sleepProbe(String addr, long delayMs) {
        sleepProbe(addr, delayMs, SystemClock.elapsedRealtime() + 12_000);
    }

    private void sleepProbe(String addr, long delayMs, long retryUntilMs) {
        Device d = findPairingDevice(addr);
        BluetoothDevice device = d == null ? null : d.dev;
        if (device == null) {
            device = remoteDeviceFor(addr);
        }
        if (device == null) {
            MsgMux.get(ctx).publish("BLE.PROBE", "addr", addr == null ? "" : addr,
                    "state", "missing_device");
            return;
        }
        if (activePull != null && activePull.isActive()) {
            MsgMux.get(ctx).publish("BLE.PROBE", "addr", addr,
                    "state", "preempt", "active", activePull.addr);
            disconnectPull(activePull.gatt);
            activePull = null;
        }
        connectDevice(device, deviceAddress(device), false, null, delayMs, retryUntilMs);
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
        connectDevice(device, addr, pairingRequest, null, 0);
    }

    private void connectDevice(BluetoothDevice device, String addr, boolean pairingRequest,
                               String commandText) {
        connectDevice(device, addr, pairingRequest, commandText, 0);
    }

    private void connectDevice(BluetoothDevice device, String addr, boolean pairingRequest,
                               String commandText, long probeDelayMs) {
        connectDevice(device, addr, pairingRequest, commandText, probeDelayMs, 0);
    }

    private void connectDevice(BluetoothDevice device, String addr, boolean pairingRequest,
                               String commandText, long probeDelayMs, long probeRetryUntilMs) {
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
        ClientCallback mGattCallback = new ClientCallback(
                id, addr, pairingRequest, commandText, probeDelayMs, probeRetryUntilMs);
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

        ClientCallback(String id, String addr, boolean pairingRequest, String commandText,
                       long probeDelayMs, long probeRetryUntilMs) {
            session = new PullSession(id, addr);
            session.pairingRequest = pairingRequest;
            session.commandText = commandText;
            session.probeDelayMs = probeDelayMs;
            session.probeRetryUntilMs = probeRetryUntilMs;
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
                MsgMux.get(ctx).publish("BLE.PULL", "addr", deviceAddress(gatt.getDevice()),
                        "state", "connected", "status", Integer.toString(status));

                Log.i(TAG, "Connected to GATT server.");
                if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                    boolean ok = gatt.discoverServices();
                    Log.i(TAG, "Attempting to start service discovery:" + ok);
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                mConnectionState = STATE_DISCONNECTED;
                MsgMux.get(ctx).publish("BLE.PULL", "addr", deviceAddress(gatt.getDevice()),
                        "state", "disconnected", "status", Integer.toString(status));
                session.done = true;
                if (activePull == session) {
                    activePull = null;
                }
                gatt.close();
                Log.i(TAG, "Disconnected from GATT server: status=" + status
                        + " state=" + newState);
                if (!session.probeSubscribed && session.probeRetryUntilMs
                        > SystemClock.elapsedRealtime()) {
                    long remainingMs = session.probeRetryUntilMs
                            - SystemClock.elapsedRealtime();
                    MsgMux.get(ctx).publish("BLE.PROBE", "addr", session.addr,
                            "state", "retry", "remaining_ms", Long.toString(remainingMs));
                    mHandler.postDelayed(
                            () -> sleepProbe(session.addr, session.probeDelayMs,
                                    session.probeRetryUntilMs),
                            700);
                }
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
                Log.i(TAG, "DMesh GATT services discovered: count="
                        + (services == null ? 0 : services.size()));
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
            Log.i(TAG, "DMesh GATT characteristic write: status=" + status);
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
            Log.i(TAG, "DMesh GATT notification: bytes=" + data.length);
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
            Log.i(TAG, "DMesh GATT notification subscription enabled");
            if (session.probeDelayMs > 0) {
                session.probeSubscribed = true;
                writeGattText(gatt, session, "gatt-probe seq=0\n");
                Log.i(TAG, "DMesh GATT sleep probe scheduled: delay_ms="
                        + session.probeDelayMs);
                mHandler.postDelayed(() -> {
                    if (!session.done && session.gatt != null) {
                        writeGattText(session.gatt, session, "gatt-probe seq=1\n");
                    }
                }, session.probeDelayMs);
            } else if (session.commandText != null) {
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
                "state", text.startsWith("gatt-probe")
                        ? "probe_write"
                        : (text.startsWith("ack ")
                        ? "ack_write"
                        : (text.startsWith("pairing ") ? "pairing_request_write" : "ready_write")),
                "status", Integer.toString(status));
        if (text.startsWith("gatt-probe")) {
            Log.i(TAG, "DMesh GATT sleep probe write: " + text.trim() + " status=" + status);
        }
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
        long probeDelayMs;
        long probeRetryUntilMs;
        boolean probeSubscribed;
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
