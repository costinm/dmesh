package com.github.costinm.dmesh.wifi;

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
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.util.Log;

import com.github.costinm.dmesh.MeshClient;
import com.github.costinm.dmesh.MeshStream;

/**
 * Platform-only Companion Device Manager adapter.
 */
public final class DMeshCompanionManager {
    public static final int REQUEST_ASSOCIATE = 42;
    private static final String TAG = "DMeshCompanion";
    private static final long PAIRING_WINDOW_MS = 60000;
    private static final long RECENT_PAIRING_MS = 5 * 60 * 1000;

    private DMeshCompanionManager() {
    }

    public static void associate(Activity activity) {
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
                    .setServiceUuid(android.os.ParcelUuid.fromString(
                            "5f6b6f80-4f2a-4a6f-8c42-4d6573680001"))
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

    public static boolean startPairingWindow(Context ctx) {
        clear(ctx);
        long now = SystemClock.elapsedRealtime();
        String recentAddr = Prefs.recentPairingAddress(ctx, now, RECENT_PAIRING_MS);
        if (!recentAddr.isEmpty()) {
            saveDirect(ctx, recentAddr, Prefs.recentPairingName(ctx));
            publish(ctx, "COMPANION.ASSOCIATE",
                    "state", "recent_scan",
                    "addr", recentAddr);
            return true;
        }
        Prefs.startPairingWindow(ctx,
                now + PAIRING_WINDOW_MS);
        publish(ctx, "COMPANION.ASSOCIATE",
                "state", "direct_scan_requested",
                "window_ms", Long.toString(PAIRING_WINDOW_MS));
        return false;
    }

    public static void saveDirect(Context ctx, String address, String name) {
        if (address == null || address.trim().isEmpty()) {
            publish(ctx, "COMPANION.ERROR", "error", "missing_addr");
            return;
        }
        Prefs.clear(ctx);
        Prefs.save(ctx, -1, "", address.trim(), name == null ? "" : name.trim());
        Prefs.stopPairingWindow(ctx);
        publish(ctx, "COMPANION.ASSOCIATE",
                "state", "direct",
                "addr", address.trim(),
                "name", name == null ? "" : name.trim());
    }

    public static void handleActivityResult(Activity activity, int resultCode, Intent data) {
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
            Prefs.save(activity, -1, "", address, name);
            publish(activity, "COMPANION.ASSOCIATE",
                    "state", "associated",
                    "addr", address,
                    "name", name);
            return;
        }
        publish(activity, "COMPANION.ERROR", "error", "missing_result");
    }

    public static void clear(Context ctx) {
        CompanionDeviceManager cdm = manager(ctx);
        int associationId = Prefs.associationId(ctx);
        if (cdm != null && associationId >= 0) {
            try {
                cdm.disassociate(associationId);
            } catch (Throwable t) {
                Log.w(TAG, "Failed to disassociate " + associationId, t);
            }
        }
        Prefs.clear(ctx);
        publish(ctx, "COMPANION.CLEAR", "ok", "true");
    }

    public static String status(Context ctx) {
        return Prefs.describe(ctx);
    }

    public static String address(Context ctx) {
        return Prefs.address(ctx);
    }

    public static void saveAssociation(Context ctx, AssociationInfo info) {
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
        Prefs.save(ctx, info.getId(), "", address, name);
        Prefs.stopPairingWindow(ctx);
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
        MeshStream stream = new MeshStream(method);
        stream.type = "event";
        for (int i = 0; i + 1 < fields.length; i += 2) {
            if (fields[i] != null && fields[i + 1] != null) {
                stream.data.putString(fields[i], fields[i + 1]);
            }
        }
        MeshClient.get(ctx.getApplicationContext()).sendStream(stream);
    }

/**
 * Single-companion state shared by app-dmesh and the BLE adapter.
 */
private static final class Prefs {
    private static final String PREFS = "dmesh_companion";
    private static final String KEY_ASSOCIATION_ID = "association_id";
    private static final String KEY_DEVICE_ID = "device_id";
    private static final String KEY_ADDRESS = "address";
    private static final String KEY_NAME = "name";
    private static final String KEY_LAST_SEQ = "last_seq";
    private static final String KEY_PAIRING_UNTIL = "pairing_until";
    private static final String KEY_LAST_PAIRING_ADDRESS = "last_pairing_address";
    private static final String KEY_LAST_PAIRING_NAME = "last_pairing_name";
    private static final String KEY_LAST_PAIRING_SEEN = "last_pairing_seen";

    private Prefs() {
    }

    public static void save(Context ctx, int associationId, String deviceId,
                            String address, String name) {
        prefs(ctx).edit()
                .putInt(KEY_ASSOCIATION_ID, associationId)
                .putString(KEY_DEVICE_ID, clean(deviceId))
                .putString(KEY_ADDRESS, clean(address))
                .putString(KEY_NAME, clean(name))
                .apply();
    }

    public static void clear(Context ctx) {
        prefs(ctx).edit()
                .remove(KEY_ASSOCIATION_ID)
                .remove(KEY_DEVICE_ID)
                .remove(KEY_ADDRESS)
                .remove(KEY_NAME)
                .remove(KEY_LAST_SEQ)
                .remove(KEY_PAIRING_UNTIL)
                .apply();
    }

    public static void startPairingWindow(Context ctx, long untilElapsedMs) {
        prefs(ctx).edit().putLong(KEY_PAIRING_UNTIL, untilElapsedMs).apply();
    }

    public static void stopPairingWindow(Context ctx) {
        prefs(ctx).edit().remove(KEY_PAIRING_UNTIL).apply();
    }

    public static boolean isPairingActive(Context ctx, long nowElapsedMs) {
        return prefs(ctx).getLong(KEY_PAIRING_UNTIL, 0) > nowElapsedMs;
    }

    public static void recordPairingDiscovery(Context ctx, String address, String name,
                                              long nowElapsedMs) {
        if (address == null || address.trim().isEmpty()) {
            return;
        }
        prefs(ctx).edit()
                .putString(KEY_LAST_PAIRING_ADDRESS, clean(address))
                .putString(KEY_LAST_PAIRING_NAME, clean(name))
                .putLong(KEY_LAST_PAIRING_SEEN, nowElapsedMs)
                .apply();
    }

    public static String recentPairingAddress(Context ctx, long nowElapsedMs, long maxAgeMs) {
        SharedPreferences p = prefs(ctx);
        long seen = p.getLong(KEY_LAST_PAIRING_SEEN, 0);
        if (seen <= 0 || nowElapsedMs - seen > maxAgeMs) {
            return "";
        }
        return p.getString(KEY_LAST_PAIRING_ADDRESS, "");
    }

    public static String recentPairingName(Context ctx) {
        return prefs(ctx).getString(KEY_LAST_PAIRING_NAME, "");
    }

    public static boolean isConfigured(Context ctx) {
        SharedPreferences p = prefs(ctx);
        return p.getInt(KEY_ASSOCIATION_ID, -1) >= 0
                || !p.getString(KEY_DEVICE_ID, "").isEmpty()
                || !p.getString(KEY_ADDRESS, "").isEmpty();
    }

    public static boolean isAllowed(Context ctx, String deviceId, String address) {
        SharedPreferences p = prefs(ctx);
        String storedId = p.getString(KEY_DEVICE_ID, "");
        String storedAddr = normalizeAddress(p.getString(KEY_ADDRESS, ""));
        if (storedId.isEmpty() && storedAddr.isEmpty()) {
            return true;
        }
        String candidateId = clean(deviceId);
        String candidateAddr = normalizeAddress(address);
        return (!storedId.isEmpty() && storedId.equals(candidateId))
                || (!storedAddr.isEmpty() && storedAddr.equals(candidateAddr));
    }

    public static String deviceId(Context ctx) {
        return prefs(ctx).getString(KEY_DEVICE_ID, "");
    }

    public static String address(Context ctx) {
        return prefs(ctx).getString(KEY_ADDRESS, "");
    }

    public static int associationId(Context ctx) {
        return prefs(ctx).getInt(KEY_ASSOCIATION_ID, -1);
    }

    public static long lastSeq(Context ctx) {
        return prefs(ctx).getLong(KEY_LAST_SEQ, 0);
    }

    public static void setLastSeq(Context ctx, long seq) {
        prefs(ctx).edit().putLong(KEY_LAST_SEQ, seq).apply();
    }

    public static String describe(Context ctx) {
        SharedPreferences p = prefs(ctx);
        return "association=" + p.getInt(KEY_ASSOCIATION_ID, -1)
                + " id=" + p.getString(KEY_DEVICE_ID, "")
                + " addr=" + p.getString(KEY_ADDRESS, "")
                + " name=" + p.getString(KEY_NAME, "")
                + " last_seq=" + p.getLong(KEY_LAST_SEQ, 0);
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizeAddress(String value) {
        return clean(value).toUpperCase();
    }
}
}
