package com.github.costinm.dmesh.lm3;

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
import android.os.Message;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.util.Log;

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
 *
 * Using RFCOMM Bluetooth (10+).
 *
 * Use for:
 * - devices without BLE
 * - GB..JB where Wifi P2P is missing. KK is present - but not supported (mostly because
 *  VPN lacks some functionality, so the line for 'modern' is cut at LMP)
 * - devices with broken P2P
 *
 * The legacy device will provide a menu/button to become discoverable and expose
 * the provisioning service. Pairing is not required. BT discovery requires user interaction
 * to confirm discoverable state.
 *
 * The legacy device should initiate discoverability - 5 min is the default.
 * In this interval the other devices can connect and provision the Wifi networks.
 *
 * The modern device will scan BT, possibly based on user request/UI, and
 * send Wifi provisioning data to the device.
 *
 * DMesh may collect a database with the BT addresses of the devices in the
 * mesh - they might communicate without discovery and send further updates
 * in case a device disconnects from the mesh while the app keys are changed.
 *
 * Once provisioned, the device will have a number of DIRECT- app networks,
 * and may connect to them.
 *
 * For security it is recommended to no connect old, un-updated devices to a normal
 * internet/intranet/private network. DIRECT connections are point to point and
 * all traffic is controlled by dmesh policies.
 *
 *  * Limitations:
 * - discovery time is 5 min, requires user interaction on one device
 * - likely a second device will need user interaction to provision
 * - max devices: 7 (4 on 4.3)
 *
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
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1) {
                    ParcelUuid[] uuids = device.getUuids();
                    for (ParcelUuid u:  uuids){
                        Log.d(TAG, "UUID: " + u + " " + deviceName);
                    }
                    // If empty - fetchUuidsWithSdp
                }
                if (deviceName == null || !deviceName.startsWith("DM-")) {
                    Log.d(TAG, "Non DM device " + deviceName + " " + deviceHardwareAddress);
                    return;
                }
                Log.d(TAG, "!!!Found " + deviceName + " " + deviceHardwareAddress);

                MsgMux.get(ctx).publish("/bt/discovery",
                        "name", deviceName,
                        "addr", "" + deviceHardwareAddress);

                devices.put(deviceHardwareAddress, device);
            }
        }
    };

    public Bt2(Context ctx, Handler h) {
        this.ctx = ctx;
        mHandler = h;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            BluetoothManager bluetoothManager =
                    (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
            if (bluetoothManager == null) {
                return;
            }
            mBluetoothAdapter = bluetoothManager.getAdapter();
        } else {
            mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        }
        if (mBluetoothAdapter == null) {
            return;
        }

        IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_FOUND);
        ctx.registerReceiver(mReceiver, filter);

        String name = mBluetoothAdapter.getName();

        MsgMux.get(ctx).publish("/bt/start",
                "name", name,
                "addr", "" + mBluetoothAdapter.getAddress(),
                "status", mBluetoothAdapter.getScanMode() + " " + mBluetoothAdapter.getState());

        // This is the only way I know to bypass the lack of SDP.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            if (name != null && !name.startsWith("DM-")) {
                name = "DM-" + name;
                mBluetoothAdapter.setName(name);
            }
        }

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


    /**
     * Connects to all known DM- bluetooth devices and sends a message.
     */
    public void syncAll(final String msg) {
        Map<String, String> response = new HashMap<>();
        new Thread(new Runnable() {
            @Override
            public void run() {
                for (String s : devices.keySet()) {
                    BluetoothDevice b = devices.get(s);
                    if (b.getName() != null && b.getName().startsWith("DM-")) {
                        connect(s, msg);
                    }
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
            s.getOutputStream().write(message.getBytes());
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));

            MsgMux.get(ctx).publish("/BT/Message",
                    "caddr", address,
                    "msg", br.readLine());
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

        lastScan = 0;

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


        Log.d(TAG, "Starting BT scan");

        scanStart = SystemClock.elapsedRealtime();

        // can pass UUID[] of GATT services.
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


    protected void handleServerConnection(BluetoothSocket s) {
        MsgMux.get(ctx).publish("/bt/srvcon",
                "c", s.getRemoteDevice().getAddress());
        devices.put(s.getRemoteDevice().getAddress(), s.getRemoteDevice());
        try {
            s.getOutputStream().write("Hello\n".getBytes());
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));

            while(true) {
                String line = br.readLine();
                if (line == null) {
                    return;
                }
                if (line.equals("WIFI")) {
                    String ssid = br.readLine();
                    String pass = br.readLine();
                    MsgMux.get(ctx).publish("WIFI", "ADD", "", "ssid", ssid, "psk", pass);
                } else {
                    MsgMux.get(ctx).publish("/bt/msg",
                            "c", s.getRemoteDevice().getAddress(),
                            "data", line);
                }
            }
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


    @Override
    public void handleMessage(String topic, String msgType, Message msg, MsgConn replyTo, String[] argv) {
        if (argv.length >= 2 && argv[2] == "disc" ) {
            makeDiscoverable();
        } else if (argv.length >= 2 && argv[2] == "con" ) {
            connect(argv[3], "");
        } else if (argv.length >= 2 && argv[2] == "sync" ) {
            syncAll("SYNC");
        } else {
            scan();
        }
    }
}
