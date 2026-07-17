package com.github.costinm.dmesh.lm;

import android.app.Activity;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.le.ScanFilter;
import android.companion.AssociationInfo;
import android.companion.AssociationRequest;
import android.companion.BluetoothLeDeviceFilter;
import android.companion.CompanionDeviceManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.android.util.DMeshCompanionPrefs;
import com.github.costinm.dmesh.lm3.Ble;

/**
 * Platform-only Companion Device Manager adapter.
 */
final class DMeshCompanionManager {
    static final int REQUEST_ASSOCIATE = 42;
    private static final String TAG = "DMeshCompanion";
    private static final long PAIRING_WINDOW_MS = 60000;
    private static final long RECENT_PAIRING_MS = 5 * 60 * 1000;

    private DMeshCompanionManager() {
    }

    static void associate(Activity activity) {
        CompanionDeviceManager cdm = manager(activity);
        if (cdm == null) {
            publish(activity, "COMPANION.ERROR", "error", "missing_manager");
            return;
        }
        try {
            if (startPairingWindow(activity)) {
                return;
            }
            ScanFilter scanFilter = new ScanFilter.Builder()
                    .setServiceUuid(Ble.DMESH_PAIRING)
                    .build();
            BluetoothLeDeviceFilter filter = new BluetoothLeDeviceFilter.Builder()
                    .setScanFilter(scanFilter)
                    .build();
            AssociationRequest request = new AssociationRequest.Builder()
                    .addDeviceFilter(filter)
                    .setSingleDevice(true)
                    .setDisplayName("DMesh ESP companion")
                    .build();
            cdm.associate(request, new CompanionDeviceManager.Callback() {
                @Override
                public void onAssociationPending(IntentSender intentSender) {
                    try {
                        activity.startIntentSenderForResult(intentSender, REQUEST_ASSOCIATE,
                                null, 0, 0, 0);
                    } catch (IntentSender.SendIntentException e) {
                        publish(activity, "COMPANION.ERROR", "error", e.toString());
                    }
                }

                @Override
                public void onAssociationCreated(AssociationInfo associationInfo) {
                    saveAssociation(activity, associationInfo);
                }

                @Override
                public void onFailure(int errorCode, CharSequence error) {
                    publish(activity, "COMPANION.ERROR",
                            "code", Integer.toString(errorCode),
                            "error", error == null ? "" : error.toString());
                }

                @Override
                public void onFailure(CharSequence error) {
                    publish(activity, "COMPANION.ERROR",
                            "error", error == null ? "" : error.toString());
                }
            }, new Handler(Looper.getMainLooper()));
            publish(activity, "COMPANION.ASSOCIATE", "state", "requested");
        } catch (Throwable t) {
            Log.w(TAG, "Association failed", t);
            publish(activity, "COMPANION.ERROR", "error", t.toString());
        }
    }

    static boolean startPairingWindow(Context ctx) {
        clear(ctx);
        long now = SystemClock.elapsedRealtime();
        String recentAddr = DMeshCompanionPrefs.recentPairingAddress(ctx, now, RECENT_PAIRING_MS);
        if (!recentAddr.isEmpty()) {
            saveDirect(ctx, recentAddr, DMeshCompanionPrefs.recentPairingName(ctx));
            publish(ctx, "COMPANION.ASSOCIATE",
                    "state", "recent_scan",
                    "addr", recentAddr);
            return true;
        }
        DMeshCompanionPrefs.startPairingWindow(ctx,
                now + PAIRING_WINDOW_MS);
        publish(ctx, "COMPANION.ASSOCIATE",
                "state", "direct_scan_requested",
                "window_ms", Long.toString(PAIRING_WINDOW_MS));
        return false;
    }

    static void saveDirect(Context ctx, String address, String name) {
        if (address == null || address.trim().isEmpty()) {
            publish(ctx, "COMPANION.ERROR", "error", "missing_addr");
            return;
        }
        DMeshCompanionPrefs.clear(ctx);
        DMeshCompanionPrefs.save(ctx, -1, "", address.trim(), name == null ? "" : name.trim());
        DMeshCompanionPrefs.stopPairingWindow(ctx);
        publish(ctx, "COMPANION.ASSOCIATE",
                "state", "direct",
                "addr", address.trim(),
                "name", name == null ? "" : name.trim());
    }

    static void handleActivityResult(Activity activity, int resultCode, Intent data) {
        if (resultCode != Activity.RESULT_OK || data == null) {
            publish(activity, "COMPANION.ASSOCIATE", "state", "canceled");
            return;
        }
        AssociationInfo info = data.getParcelableExtra(CompanionDeviceManager.EXTRA_ASSOCIATION);
        if (info != null) {
            saveAssociation(activity, info);
            return;
        }
        BluetoothDevice device = data.getParcelableExtra(CompanionDeviceManager.EXTRA_DEVICE);
        if (device != null) {
            String address = "";
            String name = "";
            try {
                address = device.getAddress();
                name = device.getName();
                device.createBond();
            } catch (SecurityException ignored) {
            }
            DMeshCompanionPrefs.save(activity, -1, "", address, name);
            publish(activity, "COMPANION.ASSOCIATE",
                    "state", "associated",
                    "addr", address,
                    "name", name);
            return;
        }
        publish(activity, "COMPANION.ERROR", "error", "missing_result");
    }

    static void clear(Context ctx) {
        CompanionDeviceManager cdm = manager(ctx);
        int associationId = DMeshCompanionPrefs.associationId(ctx);
        if (cdm != null && associationId >= 0) {
            try {
                cdm.disassociate(associationId);
            } catch (Throwable t) {
                Log.w(TAG, "Failed to disassociate " + associationId, t);
            }
        }
        DMeshCompanionPrefs.clear(ctx);
        publish(ctx, "COMPANION.CLEAR", "ok", "true");
    }

    static String status(Context ctx) {
        return DMeshCompanionPrefs.describe(ctx);
    }

    static void saveAssociation(Context ctx, AssociationInfo info) {
        if (info == null) {
            return;
        }
        String address = "";
        Object mac = info.getDeviceMacAddress();
        if (mac != null) {
            address = mac.toString();
        }
        String name = "";
        CharSequence displayName = info.getDisplayName();
        if (displayName != null) {
            name = displayName.toString();
        }
        DMeshCompanionPrefs.save(ctx, info.getId(), "", address, name);
        DMeshCompanionPrefs.stopPairingWindow(ctx);
        publish(ctx, "COMPANION.ASSOCIATE",
                "state", "associated",
                "association", Integer.toString(info.getId()),
                "addr", address,
                "name", name);
    }

    private static CompanionDeviceManager manager(Context ctx) {
        return (CompanionDeviceManager) ctx.getSystemService(Context.COMPANION_DEVICE_SERVICE);
    }

    private static void publish(Context ctx, String method, String... fields) {
        MsgMux.get(ctx.getApplicationContext()).publish(method, fields);
    }
}
