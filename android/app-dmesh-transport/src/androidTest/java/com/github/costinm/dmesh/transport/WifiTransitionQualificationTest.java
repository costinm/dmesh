package com.github.costinm.dmesh.transport;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import android.os.Bundle;

import com.github.costinm.dmesh.wifi.TransportStart;
import com.github.costinm.dmesh.wifi.WifiController;
import com.github.costinm.dmesh.wifi.WifiTransitionQualification;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Real-radio regression gate. Run with volatile AP arguments; no credential is
 * stored by the test or controller:
 * adb shell am instrument -w -e sta_ssid ... -e sta_passphrase ...
 * com.github.costinm.dmesh.transport.test/androidx.test.runner.AndroidJUnitRunner
 */
@RunWith(AndroidJUnit4.class)
public final class WifiTransitionQualificationTest {
    @Test public void transportStartBundlePreservesEveryCommonField() {
        Bundle data = new Bundle();
        data.putString("id", "android-contract");
        data.putLong("generation", 17);
        data.putString("mode", "sta");
        data.putString("ssid", "DIRECT-dmesh");
        data.putString("passphrase", "correct-horse-battery-staple");
        data.putString("bssid_hex", "001122334455");
        data.putInt("channel", 6);
        data.putInt("raw_tx_rate", 54);
        data.putInt("sta_driver_tx", 1);
        data.putInt("sta_bssid_check_disabled", 0);
        data.putInt("sta_ampdu_enabled", 1);
        data.putInt("sta_11b_rates_disabled", 0);
        data.putInt("sta_raw_rx_enabled", 1);
        data.putInt("espnow_capture", 0);
        data.putInt("nan_dw_interval", 2);
        data.putInt("now", 1);
        data.putInt("ndp", 0);
        data.putInt("ap", 1);
        data.putInt("open", 1);
        data.putInt("uart", 0);

        TransportStart request = TransportStart.fromBundle(data);
        assertTrue(request.kind == TransportStart.Kind.STA);
        assertTrue("android-contract".equals(request.correlationId));
        assertTrue(request.generation == 17);
        assertTrue(request.bssid.length == 6 && request.bssid[0] == 0
                && request.bssid[5] == 0x55);
        assertTrue(request.rawTxRate == 54 && request.staDriverTx == 1
                && request.staBssidCheckDisabled == 0 && request.staAmpduEnabled == 1
                && request.sta11bRatesDisabled == 0 && request.staRawRxEnabled == 1
                && request.espnowCapture == 0 && request.nanDwInterval == 2
                && request.now == 1 && request.ndp == 0 && request.ap == 1
                && request.open == 1 && request.uart == 0);
    }

    @Test public void nanP2pNanStaNanIsOneControllerSequence() throws Exception {
        String ssid = InstrumentationRegistry.getArguments().getString("sta_ssid", "");
        // Normal local builds do not know the ephemeral lab AP. CI/probe runs
        // supply it and execute the full non-skipped radio qualification.
        Assume.assumeTrue("supply -e sta_ssid and -e sta_passphrase", !ssid.isEmpty());
        String passphrase = InstrumentationRegistry.getArguments().getString("sta_passphrase", "");
        String bssidHex = InstrumentationRegistry.getArguments().getString("sta_bssid_hex", "");
        byte[] bssid = decodeHex(bssidHex);
        TransportStart sta = new TransportStart("instrumented-sta", 10,
                TransportStart.Kind.STA, ssid, passphrase, bssid, 6,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1);
        WifiController controller = WifiController.get(
                InstrumentationRegistry.getInstrumentation().getTargetContext());
        CountDownLatch complete = new CountDownLatch(1);
        WifiTransitionQualification.Report[] report = { null };
        WifiTransitionQualification.run(controller, sta, value -> {
            report[0] = value;
            complete.countDown();
        });
        assertTrue("qualification timed out", complete.await(170, TimeUnit.SECONDS));
        assertNotNull(report[0]);
        assertTrue(report[0].step + ": " + report[0].detail + " final=" + report[0].finalState,
                report[0].success);
    }

    private static byte[] decodeHex(String value) {
        if (value == null || value.isEmpty()) return new byte[0];
        if (value.length() != 12) throw new IllegalArgumentException("sta_bssid_hex must be 12 hex chars");
        byte[] out = new byte[6];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("invalid sta_bssid_hex");
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}
