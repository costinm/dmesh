package com.github.costinm.dmesh.lm3;

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
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.util.Log;

import androidx.annotation.RequiresApi;

import com.github.costinm.dmesh.android.msg.ConnUDS;
import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;

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

    // Required for the notification - will be set to enable, 2902.
    public static UUID BLE_DESC_CLIENT_CONFIG = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    // Eddystone UUID: FEAA
    static UUID eddyUUID = UUID.fromString("0000FEAA-0000-1000-8000-00805f9b34fb");
    public static ParcelUuid EDDY = new ParcelUuid(eddyUUID);
    // HTTP Body - 2AB9
    static UUID characteristicHttpBody = UUID.fromString("00002AB9-0000-1000-8000-00805f9b34fb");
    // write char - receive on server
    static UUID characteristicProxy = UUID.fromString("00002ADD-0000-1000-8000-00805f9b34fb");
    static UUID characteristicNotifyProxy = UUID.fromString("00002ADE-0000-1000-8000-00805f9b34fb");
    static Map<String, Device> devices = new HashMap<>();
    static boolean scanFailed = false;
    private final BluetoothManager bluetoothManager;
    Wifi wifi;
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

            List<ParcelUuid> suid = sr.getServiceUuids();
            // Single UUID expected
            if (suid == null || suid.size() == 0 || !suid.get(0).equals(EDDY)) {
                return;
            }

            // One service data inside, using
            Map<ParcelUuid, byte[]> sd = sr.getServiceData();
            if (sd == null) {
                return;
            }

            byte[] record = sd.get(EDDY);

            // ADV Payload size: 37 bytes
            // Connectable: 6 byte address overhead, 31 left

            // Overhead: first 10 bytes ( 3 B flags, 4 B service ID, 3 B len/type for service data) - 21 left
            // Prefix inserted by system (8):LE Ad
            // 03 03 AAFE - 4 bytes service type
            // LEN 16 AAFE - 4 bytes len + attribute type

            // 1 B type - 20 left

            // Actual data. We're using an extension to the protocol, using a new type to represent
            // a binary tunnel.

            //
            // User content starts with 3-byte binary:
            // 10 BA 03 - prefix (incl https://)
            //
            // 20 bytes remaining

            // Type is 0x5x
            if (record == null || record.length < 10 || ((record[0] & 0xF0) != 0x50)) {
                return;
            }

            discoveryCnt++;
            processDiscovery(device, record);

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
            MsgMux.get(ctx).publish("/BLE/ERR/onScanFailed", "error", "" + errorCode);
            super.onScanFailed(errorCode);
            scanFailed = true;
        }
    };
    private AdvertiseCallback mAdvertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.i(TAG, "LE Advertise Started " + settingsInEffect);
            adv = true;
        }

        @Override
        public void onStartFailure(int errorCode) {
            // 1 = data too large (31 is the limit)
            Log.w(TAG, "LE Advertise Failed: " + errorCode);
            MsgMux.get(ctx).publish("/BLE/ERR/advertise", "error", "" + errorCode);
            currentAdvBytes = null;
        }
    };

    //static UUID eddyCharN = UUID.fromString("00002A3D-0000-1000-8000-00805f9b34fb");
    // TODO: if we have visible devices or mesh active, stop scanning
    private BluetoothGattServer gatS;

    public Ble(Context ctx, Wifi wifi, Handler handler) {
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

        try {
            if (mBluetoothLeAdvertiser == null) {
                MsgMux.get(ctx).publish("/BLE/start",
                        "name", mBluetoothAdapter.getName(),
                        "adv", "-1");
            } else {
                MsgMux.get(ctx).publish("/BLE/start",
                        "name", mBluetoothAdapter.getName(),
                        "psm", "" + psm);
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }

    }

    // Will be called when a DMesh device is found, or found again after 60 sec.
    protected void onDiscovery(Device bd, String name, boolean firstTime) {
        MsgMux.get(ctx).publish("/wifi/BLE/DISC",
                "name", name,
                "cnt", "" + discoveryCnt);
        // Update the status.
        wifi.sendWifiDiscoveryStatus("ble", name);
    }

    private boolean processDiscovery(BluetoothDevice device, byte[] record) {
        // We have max 20 bytes, starting at record[1]

        String name = new String(record, 1, record.length - 1);
        String info = name.substring(2);

        // It seems to receive this every second.
        // ~10 sec on pxl
        if (info.length() == 16) {
            Device bd = new Device(device, info);
            if (bd.id == null) {
                return true;
            }
            Device old = devices.get(bd.id);
            if (old == null) {
                devices.put(bd.id, bd);
                connect(device.getAddress());

                onDiscovery(bd, bd.id, true);
            } else {
                // See BLE - it keeps discovering device in range.
                if (SystemClock.elapsedRealtime() - old.lastScan > 120000) {
                    onDiscovery(bd, bd.id, false);
                }
                devices.put(bd.id, bd);
            }
        }

        return false;
    }

    // See Device.updateNode(). Path must be <=21 bytes, first byte will be set to type (0x50)
    public void advertise(byte[] urlb) {
        if (mBluetoothAdapter == null || mBluetoothLeAdvertiser == null) {
            return;
        }
        if (urlb == null) {
            mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
            adv = false;
            currentAdvBytes = null;
            return;

        }

        if (adv) {
            return;
        }

        if (currentAdvBytes != null && Arrays.equals(currentAdvBytes, urlb)) {
            return;
        }

        currentAdvBytes = urlb;

        // LOW_POWER, LOW_LATENCY, BALANCED
        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                // 1 sec (BALANCED=250ms)
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
                .setConnectable(true)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();


        urlb[0] = 0x50;

        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(EDDY)
                .addServiceData(EDDY, urlb)
                .build();

        mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
        }
        mBluetoothLeAdvertiser.startAdvertising(settings, data, mAdvertiseCallback);
    }

    public void scanStop() {
        leScanner.stopScan(mScanCallback);
    }

    public void scan() {
        if (leScanner == null) {
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
                .setServiceUuid(EDDY)
                .build());

        leScanner.startScan(
                filters,
                new ScanSettings.Builder()
                        //.setReportDelay(2000) - breaks KindeFire10
                        .build(), mScanCallback);
    }

    // == GATT client implementation

    @Override
    public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo, String[] argv) {
        if (argv.length >= 2 && "adv".equals(argv[2])) {
            if (argv.length > 3) {
                advertise(argv[3].getBytes());
            } else {
                advertise(null);
            }
        }
        if (argv.length >= 2 && "scan".equals(argv[2])) {
            scan();
        }
        if (argv.length >= 2 && "stop".equals(argv[2])) {
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
        MsgMux.get(ctx).publish("/BT/scon",
                "raddr", s.getRemoteDevice().getAddress(),
                "cid", cid);
    }
    BluetoothServerSocket ss;
    //BluetoothGattCharacteristic notChar;
    void initServer() {
        try {
            // TODO: use normal advertisment to indicate support for L2 channel and the PSM
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ss = bluetoothManager.getAdapter().listenUsingInsecureL2capChannel();
                psm = ss.getPsm();
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        handleServer(ss);
                    }
                }).start();
                Log.d(TAG, "DIRECT L2 PSM=" + psm);

        }

        gatS = bluetoothManager.openGattServer(ctx, mGattServer);
        if (gatS == null) {
            Log.d(TAG, "Failed to open GATT server");
            return;
        }
        BluetoothGattService service = new BluetoothGattService(eddyUUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        if (false) {
            // Old style - a single characteristic with WRITE_NO_RESPONSE and NOTIFICATION
            sendPort = new BluetoothGattCharacteristic(
                    characteristicHttpBody,
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE | BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                    BluetoothGattCharacteristic.PERMISSION_WRITE | BluetoothGattCharacteristic.PERMISSION_READ);

            // To enable notification
            BluetoothGattDescriptor notDescriptor =
                    new BluetoothGattDescriptor(BLE_DESC_CLIENT_CONFIG,
                            BluetoothGattDescriptor.PERMISSION_WRITE);

            sendPort.addDescriptor(notDescriptor);


            service.addCharacteristic(sendPort);
        } else {
            receivePort = new BluetoothGattCharacteristic(
                    characteristicProxy,
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                    BluetoothGattCharacteristic.PERMISSION_WRITE | BluetoothGattCharacteristic.PERMISSION_READ);
            service.addCharacteristic(receivePort);

            sendPort = new BluetoothGattCharacteristic(
                    characteristicNotifyProxy,
                    BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                    BluetoothGattCharacteristic.PERMISSION_WRITE | BluetoothGattCharacteristic.PERMISSION_READ);

            // To enable notification
            BluetoothGattDescriptor notDescriptor =
                    new BluetoothGattDescriptor(BLE_DESC_CLIENT_CONFIG,
                            BluetoothGattDescriptor.PERMISSION_WRITE);
            sendPort.addDescriptor(notDescriptor);


            service.addCharacteristic(sendPort);

        }
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
                Log.i(TAG, "Attempting to start service discovery:" +
                        btGattClient.discoverServices());


                btGattClient.requestMtu(2048);
                gatt.requestMtu(2048);
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
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
            super.onCharacteristicChanged(gatt, characteristic);
        }

        @Override
        public void onDescriptorRead(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
            super.onDescriptorRead(gatt, descriptor, status);
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
                    .getService(eddyUUID)
                    .getCharacteristic(sendPort.getUuid());
            nc.setValue("HELLO".getBytes());
            gatS.notifyCharacteristicChanged(device, nc, false);
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
