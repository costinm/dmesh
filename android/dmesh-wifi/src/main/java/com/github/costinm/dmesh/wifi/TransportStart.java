package com.github.costinm.dmesh.wifi;

import android.os.Bundle;

/**
 * Typed projection of dmesh_server::control::Request::TransportStart.
 * Canonical fields and tags are defined in crates/dmesh-server/src/control.rs;
 * this is deliberately not another Android wire format.
 */
public final class TransportStart {
    public enum Kind { NAN, STA }
    public final String correlationId;
    public final long generation;
    public final Kind kind;
    public final String ssid;
    public final String passphrase;
    public final byte[] bssid;
    public final int channel;
    // Exact optional TransportConfig fields. -1 means omitted; 0/1 represent
    // a supplied boolean. Adapters report unsupported supplied fields rather
    // than silently turning them into an Android-specific mode.
    public final int rawTxRate;
    public final int staDriverTx;
    public final int staBssidCheckDisabled;
    public final int staAmpduEnabled;
    public final int sta11bRatesDisabled;
    public final int staRawRxEnabled;
    public final int espnowCapture;
    public final int nanDwInterval;
    public final int now;
    public final int ndp;
    public final int ap;
    /** Explicit unauthenticated AP/STA selection; -1 means omitted. */
    public final int open;
    public final int uart;

    public TransportStart(String correlationId, long generation, Kind kind, String ssid,
                          String passphrase, byte[] bssid, int channel,
                          int nanDwInterval, int now, int ndp, int ap) {
        this(correlationId, generation, kind, ssid, passphrase, bssid, channel,
                -1, -1, -1, -1, -1, -1, -1, nanDwInterval, now, ndp, ap, -1, -1);
    }

    public TransportStart(String correlationId, long generation, Kind kind, String ssid,
                          String passphrase, byte[] bssid, int channel, int rawTxRate,
                          int staDriverTx, int staBssidCheckDisabled, int staAmpduEnabled,
                          int sta11bRatesDisabled, int staRawRxEnabled, int espnowCapture,
                          int nanDwInterval, int now, int ndp, int ap, int uart) {
        this(correlationId, generation, kind, ssid, passphrase, bssid, channel,
                rawTxRate, staDriverTx, staBssidCheckDisabled, staAmpduEnabled,
                sta11bRatesDisabled, staRawRxEnabled, espnowCapture, nanDwInterval,
                now, ndp, ap, -1, uart);
    }

    public TransportStart(String correlationId, long generation, Kind kind, String ssid,
                          String passphrase, byte[] bssid, int channel, int rawTxRate,
                          int staDriverTx, int staBssidCheckDisabled, int staAmpduEnabled,
                          int sta11bRatesDisabled, int staRawRxEnabled, int espnowCapture,
                          int nanDwInterval, int now, int ndp, int ap, int open, int uart) {
        this.correlationId = correlationId == null ? "" : correlationId;
        this.generation = generation;
        this.kind = kind;
        this.ssid = ssid == null ? "" : ssid;
        this.passphrase = passphrase == null ? "" : passphrase;
        this.bssid = bssid == null ? new byte[0] : bssid.clone();
        this.channel = channel;
        this.rawTxRate = rawTxRate;
        this.staDriverTx = staDriverTx;
        this.staBssidCheckDisabled = staBssidCheckDisabled;
        this.staAmpduEnabled = staAmpduEnabled;
        this.sta11bRatesDisabled = sta11bRatesDisabled;
        this.staRawRxEnabled = staRawRxEnabled;
        this.espnowCapture = espnowCapture;
        this.nanDwInterval = nanDwInterval;
        this.now = now;
        this.ndp = ndp;
        this.ap = ap;
        this.open = open;
        this.uart = uart;
    }

    public static TransportStart nan() {
        return new TransportStart("", 0, Kind.NAN, "", "", null, 0, -1, -1, -1, -1);
    }

    /**
     * Typed Bundle projection of the canonical common transport.start fields.
     * This accepts Android's transport container only; it is not a second
     * command schema.  -1 preserves an omitted optional numeric field.
     */
    public static TransportStart fromBundle(Bundle values) {
        Bundle source = values == null ? Bundle.EMPTY : values;
        String mode = source.getString("mode", "nan");
        Kind kind;
        if ("sta".equals(mode)) kind = Kind.STA;
        else if ("nan".equals(mode) || "aware".equals(mode)) kind = Kind.NAN;
        else throw new IllegalArgumentException("transport.start mode must be sta or nan");
        return new TransportStart(
                source.getString("id", ""),
                longValue(source, "generation", 0),
                kind,
                source.getString("ssid", ""),
                source.getString("passphrase", ""),
                hexBytes(source, "bssid_hex"),
                intValue(source, "channel", 0),
                intValue(source, "raw_tx_rate", -1),
                intValue(source, "sta_driver_tx", -1),
                intValue(source, "sta_bssid_check_disabled", -1),
                intValue(source, "sta_ampdu_enabled", -1),
                intValue(source, "sta_11b_rates_disabled", -1),
                intValue(source, "sta_raw_rx_enabled", -1),
                intValue(source, "espnow_capture", -1),
                intValue(source, "nan_dw_interval", -1),
                intValue(source, "now", -1),
                intValue(source, "ndp", -1),
                intValue(source, "ap", 0),
                intValue(source, "open", -1),
                intValue(source, "uart", -1));
    }

    private static byte[] hexBytes(Bundle values, String key) {
        String value = values.getString(key, "");
        if (value.isEmpty()) return new byte[0];
        if ((value.length() & 1) != 0) throw new IllegalArgumentException(key + " must be even length");
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("invalid " + key);
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    private static int intValue(Bundle values, String key, int fallback) {
        if (!values.containsKey(key)) return fallback;
        Object value = values.get(key);
        if (value instanceof Number) return ((Number) value).intValue();
        try { return Integer.parseInt(values.getString(key)); }
        catch (NumberFormatException error) { throw new IllegalArgumentException(key + " must be an integer"); }
    }

    private static long longValue(Bundle values, String key, long fallback) {
        if (!values.containsKey(key)) return fallback;
        Object value = values.get(key);
        if (value instanceof Number) return ((Number) value).longValue();
        try { return Long.parseLong(values.getString(key)); }
        catch (NumberFormatException error) { throw new IllegalArgumentException(key + " must be a long"); }
    }
}
