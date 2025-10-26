package com.github.costinm.dmeshnative;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.UUID;

/**
 * Legacy device provisioning using BT.
 *
 * RFCOMM Bluetooth handling (10+).
 *
 * Use:
 * - devices without BLE
 * - GB..JB where Wifi P2P is missing
 * - devices with P2P broken
 *
 * The legacy device will provide a menu/button to become discoverable and expose
 * the provisioning service. Pairing is not required.
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
 *
 * TODO: include the device public key / cert and support private networks.
 * TODO: legacy device can also BT-scan and provision other legacy devices.
 */
public class Bt2ProvServer {

    // Standard serial profile
    public static UUID dmeshUUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");

    protected Context ctx;
    protected Handler mHandler;
    protected BluetoothAdapter mBluetoothAdapter;

    public Bt2ProvServer(Context ctx, Handler h) {
        this.ctx = ctx;
        mHandler = h;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            BluetoothManager bluetoothManager =
                    (BluetoothManager) ctx.getApplicationContext().getSystemService(Context.BLUETOOTH_SERVICE);
            mBluetoothAdapter = bluetoothManager.getAdapter();
        } else {
            mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        }

        String name = mBluetoothAdapter.getName();

        // This is the only way I know to bypass the lack of SDP.
        if (name != null && !name.startsWith("DM-")) {
            name = "DM-" + name;
            mBluetoothAdapter.setName(name);
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
//        MsgMux.get(ctx).publish("/BT/SCon",
//                "addr", s.getRemoteDevice().getAddress());
        ConnectLegacy con = new ConnectLegacy();
        WifiManager  mWifiManager = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);

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

                    con.connect(mWifiManager, ssid, pass);
                }
                //Wpgate.send("/BT/Message", (s.getRemoteDevice().getAddress() + " " + line).getBytes());
//                MsgMux.get(ctx).publish("/BT/Message",
//                        "addr", s.getRemoteDevice().getAddress(),
//                        "msg", line);
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
}
