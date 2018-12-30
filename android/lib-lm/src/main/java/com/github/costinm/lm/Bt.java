package com.github.costinm.lm;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.logs.Events;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static android.content.ContentValues.TAG;

/**
 * RFCOMM Bluetooth handling (10+).
 *
 * Use:
 * - devices without BLE
 * - GB..JB where Wifi P2P is missing
 * - devices with P2P broken
 *
 * The legacy device should initiate discoverability - 5 min is the default.
 * In this interval the other devices can connect and provision the Wifi networks.
 *
 * DMesh may collect a database with the BT addresses of the devices in the
 * mesh - they might communicate without discovery and send further updates
 * in case a device disconnects from the mesh while the wifi keys are changed.
 *
 * Limitations:
 * - discovery time is 5 min, requires user interaction on one device
 * - likely a second device will need user interaction to provision
 *
 *
 */
public class Bt {
    private static final int STATE_DISCONNECTED = 0;
    private static final int STATE_CONNECTING = 1;
    private static final int STATE_CONNECTED = 2;
    long scanStart = 0;

    // Key is MAC address
    public Map<String, BluetoothDevice> devices = new HashMap<>();

    private BluetoothAdapter mBluetoothAdapter;
    private int mConnectionState = STATE_DISCONNECTED;
    static UUID dmeshUUID = new UUID(1973, 15);
    Context ctx;

    Handler mHandler;

    class Node {
        BluetoothDevice dev;
        long lastSeen;
        Map<String,String> status;
    }

    public Bt(Context ctx, Handler h) {
        this.ctx = ctx;
        mHandler = h;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            BluetoothManager bluetoothManager =
                    (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
            mBluetoothAdapter = bluetoothManager.getAdapter();
        } else {
            mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        }

        IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_FOUND);
        ctx.registerReceiver(mReceiver, filter);

        String name = mBluetoothAdapter.getName();

        // This is the only way I know to bypass the lack of SDP.
        if (!name.startsWith("DM-")) {
            name = "DM-" + name;
            mBluetoothAdapter.setName(name);
        }

        Events.get().add("BT", "Address", name +  " " + mBluetoothAdapter.getAddress()
         + " " + mBluetoothAdapter.getScanMode() + " " + mBluetoothAdapter.getState());


        try {
            // Will create a SDP entry - name, UID and channel.
            // Unfortunately not accessible from android clients. Name prefix
            // is the only way to discover at the moment.
            final BluetoothServerSocket ss = mBluetoothAdapter.listenUsingInsecureRfcommWithServiceRecord("dmesh",
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

    public void close() {
        ctx.unregisterReceiver(mReceiver);
    }

    private void handleServer(BluetoothServerSocket ss) {
        while (true) {
            try {
                final BluetoothSocket s = ss.accept();
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        handleServerConnection(s);
                    }
                }).start();
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
    }

    private void handleServerConnection(BluetoothSocket s) {
        Events.get().add("BT", "SCon",
                s.getRemoteDevice().getAddress());
        devices.put(s.getRemoteDevice().getAddress(), s.getRemoteDevice());
        // TODO: sync up discovery for wifi networks.
        try {
            s.getOutputStream().write("Hello\n".getBytes());
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            Events.get().add("BT", "SRD", s.getRemoteDevice().getAddress() + " " + br.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                s.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     *  Connects to all known DM- bluetooth devices and sends a message.
     */
    public void syncAll(final String msg) {
        Map<String, String> response = new HashMap<>();
        new Thread(new Runnable() {
            @Override
            public void run() {
                for (String s: devices.keySet()) {
                    BluetoothDevice b = devices.get(s);
                    if (b.getName() != null && b.getName().startsWith("DM-")) {
                        connect(s, msg);
                    }
                }
            }
        }).start();
    }

    /**
     *  Requires a system pop-up
     *  Should be called from the legacy device ( without support for P2P ), to
     *  bootstrap itself.
     */
    public void makeDiscoverable() {
        // Shows popup
        Intent discoverableIntent =
                new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
        discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION,
                300);
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
            s.getOutputStream().write("Hello\n".getBytes());
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            Events.get().add("BT", "RD", address + " " + br.readLine());
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


    private BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (BluetoothDevice.ACTION_FOUND.equals(action)) {
                // Discovery has found a device. Get the BluetoothDevice
                // object and its info from the Intent.
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                String deviceName = device.getName();
                String deviceHardwareAddress = device.getAddress(); // MAC address

                lastScan++;
                if (deviceName == null || !deviceName.startsWith("DM-")) {
                    Log.d(TAG, "Non DM device " + deviceName + " " + deviceHardwareAddress);
                    return;
                }
                Events.get().add("BT", "Found", deviceName + " "
                        + deviceHardwareAddress);

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1) {
                    //                    uuids = device.getUuids();
                    //null
                }


                devices.put(deviceHardwareAddress, device);
            }
        }
    };

    int lastScan = 0;

    public void scan() {
        if (mBluetoothAdapter.isDiscovering()) {
            boolean canceled = mBluetoothAdapter.cancelDiscovery();
        }
        lastScan = 0;
        Events.get().add("BT", "Scan", "Start");

        Set<BluetoothDevice> pairedDevices = mBluetoothAdapter.getBondedDevices();

        if (pairedDevices.size() > 0) {
            // There are paired devices. Get the name and address of each paired device.
            for (BluetoothDevice device : pairedDevices) {
                String deviceName = device.getName();
                String deviceHardwareAddress = device.getAddress(); // MAC address
                Events.get().add("BT", "Pair", deviceName + " " + deviceHardwareAddress);
            }
        }
        mHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                scanStart = 0;
                mBluetoothAdapter.cancelDiscovery();
            }
        }, 15000);
        boolean s = mBluetoothAdapter.startDiscovery();
        if (!s) {
            Log.w(TAG, "Failed to start regular scan");
            return;
        }
        // Should take ~12 sec plus some extra


        Log.d(TAG, "Starting scan");

        scanStart = SystemClock.elapsedRealtime();

        // can pass UUID[] of GATT services.
    }


}
