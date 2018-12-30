package com.github.costinm.lm;

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
import android.os.Build;
import android.os.Handler;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.github.costinm.dmesh.logs.Events;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;


/**
 * BLE support
 *
 * Advertiser added on L/21 - 18 supports startLeScan with byte[] record
 *
 * Link layer is 27 bytes, announce 31
 *
 * Device address seems to change every ~10 min, so privacy concerns with Bt
 * are resolved.
 *
 * Debugging:
 * - logs with D/BtGatt
 * - Nordic's debug apps
 */
@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
public class Ble {
    static final String TAG = "LM-BLE";

    public static ParcelUuid EDDY = new ParcelUuid(UUID.fromString("0000FEAA-0000-1000-8000-00805f9b34fb"));

    private final BluetoothLeAdvertiser mBluetoothLeAdvertiser;
    private final LMesh lm;
    boolean mScanning = false;

    Map<String, DMeshBle> devices = new HashMap<>();

    Handler mHandler;
    Context ctx;
    BluetoothLeScanner leScanner;

    BluetoothAdapter mBluetoothAdapter;

    int discoveryCnt;

    private ScanCallback mScanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            BluetoothDevice device = result.getDevice();
            ScanRecord sr = result.getScanRecord();
            List<ParcelUuid> suid = sr.getServiceUuids();
            if (suid == null || suid.size() == 0 || !suid.get(0).equals(EDDY)) {
                return;
            }
            Map<ParcelUuid, byte[]> sd = sr.getServiceData();
            if (sd == null) {
                return;
            }

            byte[] record = sd.get(EDDY);
            if (record == null || record.length < 10 || record[0] != 0x10) {
                return;
            }
            discoveryCnt++;
            String name = new String(record, 3, record.length - 3);
            String parts[] = name.split("/");
            if (!parts[0].endsWith(".m")) {
                return;
            }

            // It seems to receive this every second.
            // ~10 sec on pxl
            //
            // TODO: throttle
            // TODO: check what happens when idle
            //
            //Log.d(TAG, "FOUND BLE " + name + " " + device.getAddress());
            DMeshBle bd = devices.get(parts[0]);
            if (bd == null) {
                bd = new DMeshBle(lm, device, parts);
                devices.put(parts[0], bd);
                onDiscovery(bd, name, true);
            } else {
                if( SystemClock.elapsedRealtime() - bd.node.lastScan > 120000) {
                    onDiscovery(bd, name, false);
                }
                bd.updateNode(parts);
            }
            super.onScanResult(callbackType, result);
        }

        @Override
        public void onBatchScanResults(List<ScanResult> results) {
            Log.d(TAG, "Batched results " + results.size());
            for (ScanResult sr: results) {
                onScanResult(0, sr);
            }
            super.onBatchScanResults(results);
        }

        @Override
        public void onScanFailed(int errorCode) {
            if (scanFailed) {
                return;
            }
            Events.get().add("BLE", "Dev","Scan failed " + errorCode);
                    super.onScanFailed(errorCode);
            scanFailed = true;
        }
    };

    static boolean scanFailed = false;

    private AdvertiseCallback mAdvertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.i(TAG, "LE Advertise Started " + currentAdv + " " + settingsInEffect);
        }

        @Override
        public void onStartFailure(int errorCode) {
            // 1 = data too large (31 is the limit)
            Log.w(TAG, "LE Advertise Failed: "+errorCode);
            Events.get().add("BLE", "ERR", "BLE advertise error " + errorCode);
            currentAdv = null;
        }
    };

    public Ble(Context ctx, Handler handler, LMesh lMesh) {
        this.ctx = ctx;
        this.mHandler = handler;
        this.lm = lMesh;

        BluetoothManager bluetoothManager =
                (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
        mBluetoothAdapter = bluetoothManager.getAdapter();

        mBluetoothLeAdvertiser = mBluetoothAdapter.getBluetoothLeAdvertiser();
        leScanner = mBluetoothAdapter.getBluetoothLeScanner();

        Events.get().add("BT", "BLE", mBluetoothAdapter.getName()
                    +  (mBluetoothLeAdvertiser == null ? " NO_ADV":"") +
                    (leScanner == null ? " NO_SCAN" : ""));

    }

    // Will be called when a DMesh device is found, or found again after 60 sec.
    protected void onDiscovery(DMeshBle bd, String name, boolean firstTime) {

        Events.get().add("BLE", "", bd.device.getAddress() + " " +
                 name + " " + discoveryCnt);

    }

    static String currentAdv = "";

    public void advertise(LMesh lm) {
        String mn = lm.getMeshName();
        if (mn.length() > 0) {
            StringBuilder sb = new StringBuilder();

            sb.append("   ").append(mn).append(".m/");

            if (lm.hasWifiInternet()) {
                sb.append("w");
            }
            if (lm.hasMobileInternet()) {
                sb.append("i");
            }
            advertise(sb.toString());
        }

    }

    public void advertise(String path) {
        if (mBluetoothAdapter == null || mBluetoothLeAdvertiser == null) {
            return;
        }
        if (currentAdv != null && currentAdv.equals(path)) {
            return;
        }

        // 31 bytes.
        // 3 0x03 0xAAFE - 4 bytes service type
        // 26 0x16 0xAAFE 10 BA 03 - 7 bytes prefix (incl https://)
        // 20 bytes remaining
        //
        // Old: dmesh.io/ is 9 bytes leaving 11 for content
        // New:
        // 8 bytes required Service/attribute (3 0x03 0xAAFE LEN 0x16 0xAAFE)
        // 3 bytes binary prefix
        // 11 bytes - 8byte-base64-ID
        // 3 bytes - .m/
        // Remaining: 6

        // Alternative:
        // 8+3 - binary prefix, 20 remaining
        // 4 - hash of SSID - 16 remaining
        // .w/ - 13
        // 8..10 PSK = 3 remaining
        //

        // LOW_POWER, LOW_LATENCY, BALANCED
        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                // 1 sec (BALANCED=250ms)
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
                .setConnectable(false)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();


        // path includes 3 spaces at start (for the binary prefix)
        if (path.length() > 23) {
            path = path.substring(0, 23);
        }
        byte[] urlb = path.getBytes();
        // 0: URL_FRAME_TYPE=0x10
        urlb[0] = 0x10;
        // 1: 0xBA ( power level) ?
        urlb[1] = (byte) 0xba;
        // 0x03 (https://)
        urlb[2] = 0x03;

        // 0x03 (.net/)

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

        currentAdv = path;
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

    // TODO: if we have visible devices or mesh active, stop scanning

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

    static class DMeshBle {
        BluetoothDevice device;
        LNode node;

        public DMeshBle(LMesh lm, BluetoothDevice device, String[] name) {
            this.device = device;
            String n0 = name[0];
            node = lm.byMeshName(n0.substring(0, n0.length() - 2));
            updateNode(name);
        }

        public void updateNode(String[] ssidFlags) {
            long now = SystemClock.elapsedRealtime();
            node.lastScan = now;
            if (ssidFlags.length == 0) {
                return;
            }
        }
    }

}
