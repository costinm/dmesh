package com.github.costinm.dmesh.wifi;

import android.companion.AssociationInfo;
import android.companion.CompanionDeviceService;
import com.github.costinm.dmesh.MeshClient;
import com.github.costinm.dmesh.MeshStream;

/**
 * Presence callback used to nudge the foreground service for the single companion.
 */
public class DMeshCompanionService extends CompanionDeviceService {
    @Override
    public void onDeviceAppeared(AssociationInfo associationInfo) {
        publish("appeared", associationInfo);
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
        MeshStream stream = new MeshStream("COMPANION.DEVICE");
        stream.type = "event";
        stream.data.putString("state", state);
        stream.data.putString("association", association);
        stream.data.putString("addr", addr);
        MeshClient.get(getApplicationContext()).sendStream(stream);
    }
}
