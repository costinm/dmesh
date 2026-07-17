package com.github.costinm.dmesh.android.util;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Single-companion state shared by app-dmesh and the BLE adapter.
 */
public final class DMeshCompanionPrefs {
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

    private DMeshCompanionPrefs() {
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
