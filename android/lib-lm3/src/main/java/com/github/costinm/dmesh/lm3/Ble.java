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
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.Hex;
import com.github.costinm.dmeshnative.MeshNode;

import java.io.IOException;
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

    static UUID dmeshAdvUUID = UUID.fromString("0000FD5D-0000-1000-8000-00805f9b34fb");
    public static ParcelUuid DMESH_ADV = new ParcelUuid(dmeshAdvUUID);
    static UUID meshtasticUUID = UUID.fromString("6ba1b218-15a8-461f-9fa8-5dcae273eafd");
    public static ParcelUuid MESHTASTIC = new ParcelUuid(meshtasticUUID);
    static UUID nordicUartUUID = UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e");
    public static ParcelUuid NORDIC_UART = new ParcelUuid(nordicUartUUID);
    static UUID nordicRxUUID = UUID.fromString("6e400002-b5a3-f393-e0a9-e50e24dcca9e");
    static UUID nordicTxUUID = UUID.fromString("6e400003-b5a3-f393-e0a9-e50e24dcca9e");
    static Map<String, Device> devices = new HashMap<>();
    static Map<String, Long> externalDevices = new HashMap<>();
    static boolean scanFailed = false;
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
                byte[] record = sd.get(DMESH_ADV);
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
            if (suid.contains(NORDIC_UART)) {
                processExternalDiscovery(device, sr, result.getRssi(),
                        "nordic_uart", NORDIC_UART.toString(), "meshcore");
            }
            if (!suid.contains(DMESH_ADV)) {
                return;
            }

            if (sd == null) {
                return;
            }

            byte[] record = sd.get(DMESH_ADV);
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
        String id = jsonField(parsed, "device_id");
        if (id.length() == 0) {
            return false;
        }
        Device bd = new Device(id, parsed);
        bd.dev = device;
        bd.data.putString(Device.P2PAddr, "/ble/" + id);
        bd.data.putString("proto", "dmesh_ble");
        bd.data.putString("ble", parsed);
        bd.data.putInt(Device.LEVEL, rssi);
        Device old = devices.get(id);
        devices.put(id, bd);
        if (old == null || SystemClock.elapsedRealtime() - old.lastScan > 120000) {
            onDiscovery(bd, id, old == null);
        }
        if (parsed.contains("\"connectable_response\":true")) {
            connect(addr);
        }
        MsgMux.get(ctx).publish("BLE.DISC",
                "proto", "dmesh",
                "id", id,
                "addr", addr,
                "rssi", Integer.toString(rssi),
                "json", parsed);
        return true;
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
                .setConnectable(true)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();

        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(DMESH_ADV)
                .addServiceData(DMESH_ADV, advBytes)
                .build();

        mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
        }
        mBluetoothLeAdvertiser.startAdvertising(settings, data, mAdvertiseCallback);
        MsgMux.get(ctx).publish("BLE.advertise", "state", "starting", "uuid", DMESH_ADV.toString());
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
        MsgMux.get(ctx).publish("BLE.stop");
    }

    public void scan() {
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
                .setServiceUuid(DMESH_ADV)
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceData(DMESH_ADV, new byte[0], new byte[0])
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(MESHTASTIC)
                .build());
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(NORDIC_UART)
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
            MsgMux.get(ctx).publish("BLE.scan", "filters", "dmesh,meshtastic,nordic_uart", "wake", "pending_intent");
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
        if (argv != null && argv.length >= 3) {
            action = argv[2];
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
        BluetoothGattService service = new BluetoothGattService(nordicUartUUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        receivePort = new BluetoothGattCharacteristic(
                nordicRxUUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE | BluetoothGattCharacteristic.PERMISSION_READ);
        service.addCharacteristic(receivePort);

        sendPort = new BluetoothGattCharacteristic(
                nordicTxUUID,
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
            return;
        }
        ClientCallback mGattCallback = new ClientCallback();
        if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        btGattClient = d.dev.connectGatt(ctx, false, mGattCallback);
    }

    // Various callback methods defined by the BLE API, used in the client connection.
    class ClientCallback extends BluetoothGattCallback {

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

                Log.i(TAG, "Connected to GATT server.");
                if (ctx.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {

                    boolean ok = btGattClient.discoverServices();
                    Log.i(TAG, "Attempting to start service discovery:" +  ok);
                    btGattClient.requestMtu(2048);
                    gatt.requestMtu(2048);
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                mConnectionState = STATE_DISCONNECTED;
                Log.i(TAG, "Disconnected from GATT server.");
            }
        }

        @Override
        // New services discovered
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                List<BluetoothGattService> services = gatt.getServices();

            } else {
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
            super.onCharacteristicWrite(gatt, characteristic, status);
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, byte []data) {
        }

        @Override
        public void onDescriptorRead(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status, byte[] data) {
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
            super.onDescriptorWrite(gatt, descriptor, status);
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
                    .getService(nordicUartUUID)
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

    private String jsonField(String json, String field) {
        String needle = "\"" + field + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) {
            return "";
        }
        start += needle.length();
        int end = json.indexOf('"', start);
        if (end < 0) {
            return "";
        }
        return json.substring(start, end);
    }
}
