package com.github.costinm.dmesh.lm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;

import com.github.costinm.dmeshnative.AndroidTransportBridge;

public final class UsbPermissionReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        boolean granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false);
        // Forward the device so the owner can reject broadcasts that do not
        // name the pending request: this receiver is exported, so a forged
        // action broadcast must not clear the real request.
        UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
        AndroidTransportBridge.get(context).onUsbPermission(device, granted);
    }
}
