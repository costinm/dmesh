package com.github.costinm.dmesh.lm3;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.Parcelable;
import android.os.SystemClock;
import android.util.Log;

import androidx.core.app.ActivityCompat;

import com.github.costinm.dmesh.android.msg.ConnUDS;
import com.github.costinm.dmesh.android.msg.MessageHandler;
import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Legacy (GB to KK) device provisioning using BT.
 * <p>
 * Using RFCOMM Bluetooth (10+).
 * <p>
 * Use for:
 * - devices without BLE
 * - GB..JB where Wifi P2P is missing. KK is present - but not supported (mostly because
 * VPN lacks some functionality, so the line for 'modern' is cut at LMP)
 * - devices with broken P2P
 * <p>
 * The legacy device will provide a menu/button to become discoverable and expose
 * the provisioning service. Pairing is not required. BT discovery requires user interaction
 * to confirm discoverable state.
 * <p>
 * The legacy device should initiate discoverability - 5 min is the default.
 * In this interval the other devices can connect and provision the Wifi networks.
 * The modern device will scan BT, possibly based on user request/UI, and
 * send Wifi provisioning data to the device.
 * <p>
 * DMesh may collect a database with the BT addresses of the devices in the
 * mesh - they might communicate without discovery and send further updates
 * in case a device disconnects from the mesh while the app keys are changed.
 * <p>
 * Once provisioned, the device will have a number of DIRECT- app networks,
 * and may connect to them.
 * <p>
 * For security it is recommended to no connect old, un-updated devices to a normal
 * internet/intranet/private network. DIRECT connections are point to point and
 * all traffic is controlled by dmesh policies.
 * <p>
 * * Limitations:
 * - discovery time is 5 min, requires user interaction on one device
 * - likely a second device will need user interaction to provision
 * - max devices: 7 (4 on 4.3)
 * <p>
 * TODO: include the device public key / cert and support private networks.
 * TODO: legacy device can also BT-scan and provision other legacy devices.
 */
public class Bt2 implements MessageHandler {

    private static final String TAG = "BT2";

    // Standard serial profile - using this will select any serial port device
    public static UUID dmeshUUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");

    // Key is MAC address
    public Map<String, BluetoothDevice> devices = new HashMap<>();

    protected long scanStart = 0;
    protected int lastScan = 0;

    protected Context ctx;
    protected Handler mHandler;
    protected BluetoothAdapter mBluetoothAdapter;

    Map<String, String> foreign = new HashMap<>();
    Map<String, BluetoothDevice> sdb = new HashMap<>();
    int scanFound = 0;
    int scanUUIDFound = 0;

    int scanMode;
    long discStarted;
    BluetoothServerSocket ss;

    private BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            try {
                if (BluetoothDevice.ACTION_UUID.equals(action)) {
                    BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    Parcelable[] uuid = intent.getParcelableArrayExtra(BluetoothDevice.EXTRA_UUID);
                    Log.d(TAG, "ACTION_UUID: " + device.getName() + " " + device.getAddress() + " " + uuid +
                            " " + device.getUuids() + " " + intent.getExtras());
                    if (device.getUuids() != null) {
                        scanUUIDFound++;
                    }
                    if (uuid != null && uuid.equals(dmeshUUID)) {
                        onFound(device, device.getName(), device.getAddress());
                    }
                }
                if (BluetoothAdapter.ACTION_SCAN_MODE_CHANGED.equals(action)) {
                    int oldScanMode = scanMode;
                    // 23
                    scanMode = intent.getIntExtra(BluetoothAdapter.EXTRA_SCAN_MODE, 0);
                    Log.d(TAG, "ACTION_SCAN_MODE_CHANGED: " + oldScanMode + " " + scanMode + " " + intent.getExtras());

                }
                if (BluetoothAdapter.ACTION_DISCOVERY_STARTED.equals(action)) {
                    BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    Log.d(TAG, "ACTION_DISCOVERY_STARTED: " + device + " " + intent.getExtras());
                    discStarted = SystemClock.elapsedRealtime();
                }
                if (BluetoothAdapter.ACTION_DISCOVERY_FINISHED.equals(action)) {
                    for (BluetoothDevice d : sdb.values()) {
                        boolean ok = d.fetchUuidsWithSdp();
                        if (!ok) {
                            Log.d(TAG, "Failed to fetch SDP");
                        }
                    }
                    Log.d(TAG, "Discovery done " + (SystemClock.elapsedRealtime() - discStarted));
                    discStarted = 0;
                }
                if (BluetoothDevice.ACTION_FOUND.equals(action)) {
                    // Discovery has found a device. Get the BluetoothDevice
                    // object and its info from the Intent.
                    BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    String deviceName = device.getName();
                    String deviceHardwareAddress = device.getAddress(); // MAC address
                    scanFound++;
                    lastScan++;

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1) {
                        ParcelUuid[] uuids = device.getUuids();
                        if (uuids != null) {
                            for (ParcelUuid u : uuids) {
                                Log.d(TAG, "UUID: " + u + " " + deviceName);
                                if (u.getUuid().equals(dmeshUUID)) {
                                    onFound(device, deviceName, deviceHardwareAddress);
                                }
                            }
                        } else {
                            sdb.put(deviceHardwareAddress, device);
                        }
                        // If empty - fetchUuidsWithSdp
                    }
                    if (deviceName == null || !deviceName.startsWith("DM-")) {
                        //Log.d(TAG, "Non DM device " + deviceName + " " + deviceHardwareAddress);
                        return;
                    }
                    onFound(device, deviceName, deviceHardwareAddress);
                }

            } catch (SecurityException ex) {
                return;
            }
        }
    };

    public Bt2(Context ctx, Handler h) {
        this.ctx = ctx;
        mHandler = h;
            BluetoothManager bluetoothManager =
                    (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
            if (bluetoothManager == null) {
                return;
            }
            mBluetoothAdapter = bluetoothManager.getAdapter();
        if (mBluetoothAdapter == null) {
            return;
        }

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_UUID);
        filter.addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED);
        filter.addAction(BluetoothAdapter.ACTION_DISCOVERY_STARTED);
        filter.addAction(BluetoothDevice.ACTION_FOUND);
        filter.addAction(BluetoothAdapter.ACTION_SCAN_MODE_CHANGED);
        ctx.registerReceiver(mReceiver, filter);

        if (ActivityCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            // TODO: Consider calling
            //    ActivityCompat#requestPermissions
            // here to request the missing permissions, and then overriding
            //   public void onRequestPermissionsResult(int requestCode, String[] permissions,
            //                                          int[] grantResults)
            // to handle the case where the user grants the permission. See the documentation
            // for ActivityCompat#requestPermissions for more details.
            return;
        }
        String name = mBluetoothAdapter.getName();

        MsgMux.get(ctx).publish("/bt/start",
                "name", name,
                "addr", "" + mBluetoothAdapter.getAddress(),
                "status", mBluetoothAdapter.getScanMode() + " " + mBluetoothAdapter.getState());

        Set<BluetoothDevice> pairedDevices = mBluetoothAdapter.getBondedDevices();
        if (pairedDevices.size() > 0) {
            // There are paired devices. Get the name and address of each paired device.
            for (BluetoothDevice device : pairedDevices) {
                String deviceName = device.getName();
                if (!deviceName.startsWith("DM")) {
                    continue;
                }
                String deviceHardwareAddress = device.getAddress(); // MAC address

                Log.d("BT", "Pair: " + deviceName + " " + deviceHardwareAddress);
            }
        }

        try {
            // Will create a SDP entry - name, UID and channel.
            // Unfortunately not accessible from android clients. Name prefix
            // is the only way to discover at the moment.
            ss = mBluetoothAdapter.listenUsingInsecureRfcommWithServiceRecord("dmesh",
                    dmeshUUID);
            new Thread(new Runnable() {
                @Override
                public void run() {
                    handleServer(ss);
                }
            }).start();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void onFound(BluetoothDevice device, String deviceName, String deviceHardwareAddress) {
        Log.d(TAG, "!!!Found " + deviceName + " " + deviceHardwareAddress);

        MsgMux.get(ctx).publish("/bt/discovery",
                "name", deviceName,
                "addr", "" + deviceHardwareAddress);

        devices.put(deviceHardwareAddress, device);
    }

    public void close() {
        ctx.unregisterReceiver(mReceiver);
        if (ss != null) {
            try {
                ss.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            ss = null;
        }
    }


    /**
     * Connects to all known DM- bluetooth devices and sends a message.
     */
    public void syncAll(final String msg) {
        Map<String, String> response = new HashMap<>();
        new Thread(new Runnable() {
            @Override
            public void run() {
                Set<BluetoothDevice> pairedDevices = mBluetoothAdapter.getBondedDevices();
                if (pairedDevices.size() > 0) {
                    // There are paired devices. Get the name and address of each paired device.
                    for (BluetoothDevice device : pairedDevices) {
                        String deviceName = device.getName();
                        if (!deviceName.startsWith("DM")) {
                            continue;
                        }
                        String deviceHardwareAddress = device.getAddress(); // MAC address

                        Log.d("BT", "Pair: " + deviceName + " " + deviceHardwareAddress);
                        connect(device.getAddress(), "");
                    }
                }
                for (String s : devices.keySet()) {
                    BluetoothDevice b = devices.get(s);
                    connect(s, msg);
                }
            }
        }).start();
    }

    /**
     * Connects to all known DM- bluetooth devices and sends a message.
     */
    public void bond1(final String msg) {
        Map<String, String> response = new HashMap<>();
        new Thread(new Runnable() {
            @Override
            public void run() {
                for (String s : devices.keySet()) {
                    BluetoothDevice b = devices.get(s);
                    if (b.createBond()) {
                        return;
                    };
                }
            }
        }).start();
    }

    /**
     * Requires a system pop-up
     * Should be called from the legacy device ( without support for P2P ), to
     * bootstrap itself.
     */
    public void makeDiscoverable() {
        // This is the only way I know to bypass the lack of SDP.
        String name = mBluetoothAdapter.getName();
        // UUID and SDP doesn't seem to be working.
        //if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
        if (name != null && !name.startsWith("DM-")) {
            name = "DM-" + name;
            boolean ok = mBluetoothAdapter.setName(name);
            if (!ok) {
                Log.d(TAG, "Failed to rename device for disovery");
            }
        }
        //}

        // Shows popup
        Intent discoverableIntent =
                new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
        // default: 120, max 1h. 0 means forever
        discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION,
                300);
        // if this is called from an activity, will get a result with the time
        discoverableIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        ctx.startActivity(discoverableIntent);
    }

    public void connect(String address, String message) {
        BluetoothDevice d = mBluetoothAdapter.getRemoteDevice(address);
        BluetoothSocket s = null;
        try {
            s = d.createInsecureRfcommSocketToServiceRecord(dmeshUUID);
            s.connect();
            if (s == null || s.getOutputStream() == null) {
                Log.d(TAG, "Failed to open " + address);
            }
            handleClientConnection(s, address, message);
        } catch (IOException e) {
            Log.d(TAG, "Error connecting " + address + " " + e.toString());
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e) {
                    Log.d(TAG, "Error closing " + address + " " + e.toString());
                }
            }
        }
    }

    public void scan() {
        if (mBluetoothAdapter.isDiscovering()) {
            boolean canceled = mBluetoothAdapter.cancelDiscovery();
        }

        sdb.clear();
        scanFound = 0;
        scanUUIDFound = 0;
        lastScan = 0;
        // TODO: paired devices handled separatedly.
        devices.clear();

        // Normal discovery should be about 12 seconds
        mHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                scanStart = 0;
                Log.d(TAG, "Canceling discovery: " + scanFound + " " + scanUUIDFound + " " + devices.size());
                mBluetoothAdapter.cancelDiscovery();
                Log.d(TAG, "BT scan done: " + scanFound + " " + scanUUIDFound + " " + devices.size());
            }
        }, 14000);

        boolean s = mBluetoothAdapter.startDiscovery();
        if (!s) {
            Log.w(TAG, "Failed to start regular scan");
            return;
        }

        // Should take ~12 sec plus some extra


        Log.d(TAG, "Starting BT scan");

        scanStart = SystemClock.elapsedRealtime();

        // can pass UUID[] of GATT services.
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
        devices.put(s.getRemoteDevice().getAddress(), s.getRemoteDevice());
    }

    private void handleClientConnection(BluetoothSocket s, String address, String message) throws IOException {
        String cid = ConnUDS.proxyConnection(s.getInputStream(), s.getOutputStream());
        if (cid == "") {
            s.close();
            return;
        }
        MsgMux.get(ctx).publish("/BT/ccon",
                "raddr", address,
                "cid", cid);
    }

    @Override
    public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo, String[] argv) {
        if (argv.length >= 2 && argv[2].equals("disc")) {
            makeDiscoverable();
        } else if (argv.length >= 2 && argv[2].equals("con")) {
            connect(argv[3], "");
        } else if (argv.length >= 2 && argv[2].equals("sync")) {
            syncAll("SYNC");
        } else if (argv.length >= 2 && argv[2].equals("bond")) {
            bond1("SYNC");
        } else if (argv.length >= 2 && argv[2].equals("scan")) {
            // TODO: specify a port
            scan();
        }
    }
}
