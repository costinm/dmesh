package com.github.costinm.dmesh.android.util;

import android.app.PendingIntent;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static android.content.ContentValues.TAG;

/**
 * A base service exposing a Messenger interface and accepting a Messanger callback.
 *
 * Works on GB+
 */
public class BaseMsgService extends Service implements Handler.Callback {

    protected Handler mHandler = new Handler(this);
    Messenger out;
    PendingIntent pi;

    @Override
    public IBinder onBind(Intent intent) {
        Messenger b = new Messenger(mHandler);
        out = intent.getParcelableExtra("m");
        pi = intent.getParcelableExtra("p");
        return b.getBinder();
    }

    @Override
    public boolean onUnbind(Intent intent) {
        //lm.observer = null;
        pi = null;
        return super.onUnbind(intent);
    }

    public void send(int what) {
        if (out == null) {
            return;
        }
        Message m = Message.obtain();
        m.what = what;

        try {
            out.send(m);
        } catch (RemoteException e) {
            e.printStackTrace();
            out = null;
        }
    }

    @Override
    public boolean handleMessage(Message msg) {
        handleCmd(msg.what, msg.getData());
        return false;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            return START_NOT_STICKY;
        }

        Messenger m = intent.getParcelableExtra("m");
        if (m != null) {
            out = m;
        }

        int cmd = intent.getIntExtra("cmd", 0);
        handleCmd(cmd, intent.getExtras());

        return super.onStartCommand(intent, flags, startId);
    }

    public void handleCmd(int what, Bundle extra) {

    }
}
