package com.github.costinm.dmesh.lm;

import android.companion.AssociationInfo;
import android.companion.CompanionDeviceService;
import android.content.Intent;

import com.github.costinm.dmesh.android.msg.MsgMux;

/**
 * Presence callback used to nudge the foreground service for the single companion.
 */
public class DMeshCompanionService extends CompanionDeviceService {
    @Override
    public void onDeviceAppeared(AssociationInfo associationInfo) {
        publish("appeared", associationInfo);
        try {
            startForegroundService(new Intent(this, DMService.class));
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void onDeviceDisappeared(AssociationInfo associationInfo) {
        publish("disappeared", associationInfo);
    }

    private void publish(String state, AssociationInfo info) {
        String association = info == null ? "" : Integer.toString(info.getId());
        String addr = "";
        if (info != null && info.getDeviceMacAddress() != null) {
            addr = info.getDeviceMacAddress().toString();
        }
        MsgMux.get(getApplicationContext()).publish("COMPANION.DEVICE",
                "state", state,
                "association", association,
                "addr", addr);
    }
}
