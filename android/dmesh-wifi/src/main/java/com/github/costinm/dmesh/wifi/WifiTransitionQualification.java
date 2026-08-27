package com.github.costinm.dmesh.wifi;

import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import android.os.SystemClock;

/**
 * Device qualification sequence shared by the ADB repro and future DMesh
 * control-plane probes. It uses only WifiController's public API: no test may
 * reach around the Wi-Fi owner to manipulate sessions or framework managers.
 */
public final class WifiTransitionQualification {
    private WifiTransitionQualification() { }
    /** Hard upper bound for one shell/instrumentation qualification request. */
    public static final long MAX_DURATION_MS = 90_000L;

    public static final class Report {
        public final boolean success;
        public final String step;
        public final String detail;
        public final String finalState;

        Report(boolean success, String step, String detail, String finalState) {
            this.success = success;
            this.step = step;
            this.detail = detail;
            this.finalState = finalState;
        }
    }

    /**
     * Runs NAN publish/subscribe -> P2P GO -> NAN -> STA -> NAN -> unchanged
     * NAN. STA credentials are volatile input from a controller or test; they
     * are never saved by this library.
     */
    public static void run(WifiController controller, TransportStart sta,
                           Completion<Report> done) {
        new Thread(() -> {
            final long deadline = SystemClock.elapsedRealtime() + MAX_DURATION_MS;
            if (sta == null || sta.kind != TransportStart.Kind.STA || sta.ssid.isEmpty()) {
                done.complete(new Report(false, "sta_input", "missing_sta_target", controller.snapshot()));
                return;
            }
            String configured = awaitValue(callback -> controller.setAnnounce(
                    new Announce(new byte[] {(byte) 0xa1, 0x01, (byte) 0xa2, 0x02,
                            0x63, 0x6e, 0x61, 0x6e}, Collections.singletonList("active")), callback));
            if (configured == null) {
                done.complete(new Report(false, "announce", "timeout", controller.snapshot()));
                return;
            }
            String discovered = awaitValue(callback -> controller.setDiscover(
                    new Discover(new byte[] {(byte) 0xa1, 0x01}, Collections.singletonList("active")), callback));
            if (discovered == null) {
                done.complete(new Report(false, "discover", "timeout", controller.snapshot()));
                return;
            }
            TransportResult result = awaitStart(controller, nan("qualify-nan", 1, 0), deadline);
            if (!applied(result)) { done.complete(report("nan", result, controller)); return; }
            result = awaitStart(controller, nan("qualify-p2p", 2, 1), deadline);
            if (!applied(result)) { done.complete(report("p2p", result, controller)); return; }
            result = awaitStart(controller, nan("qualify-nan-return", 3, 0), deadline);
            if (!applied(result)) { done.complete(report("nan_return", result, controller)); return; }
            result = awaitStart(controller, sta, deadline);
            if (!applied(result)) { done.complete(report("sta", result, controller)); return; }
            TransportStart finalNan = nan("qualify-final-nan", 4, 0);
            result = awaitStart(controller, finalNan, deadline);
            if (!applied(result)) { done.complete(report("final_nan", result, controller)); return; }
            result = awaitStart(controller, finalNan, deadline);
            if (result == null || result.outcome != TransportResult.Outcome.UNCHANGED) {
                done.complete(report("idempotent_nan", result, controller));
                return;
            }
            done.complete(new Report(true, "complete", "NAN->P2P->NAN->STA->NAN", controller.snapshot()));
        }, "DmeshWifiQualification").start();
    }

    private static boolean applied(TransportResult result) {
        return result != null && (result.outcome == TransportResult.Outcome.APPLIED
                || result.outcome == TransportResult.Outcome.UNCHANGED);
    }

    private static Report report(String step, TransportResult result, WifiController controller) {
        String detail = result == null ? "timeout" : result.outcome + ":" + result.error
                + " restored=" + result.previousTransportRestored;
        return new Report(false, step, detail, controller.snapshot());
    }

    private static TransportResult awaitStart(WifiController controller, TransportStart request,
                                              long deadline) {
        final TransportResult[] result = { null };
        CountDownLatch latch = new CountDownLatch(1);
        controller.start(request, value -> { result[0] = value; latch.countDown(); });
        long remaining = deadline - SystemClock.elapsedRealtime();
        if (remaining <= 0) return null;
        try { latch.await(Math.min(40_000L, remaining), TimeUnit.MILLISECONDS); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        return result[0];
    }

    private interface ValueStart { void start(Completion<String> callback); }

    private static String awaitValue(ValueStart start) {
        final String[] result = { null };
        CountDownLatch latch = new CountDownLatch(1);
        start.start(value -> { result[0] = value; latch.countDown(); });
        try { latch.await(5, TimeUnit.SECONDS); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        return result[0];
    }

    private static TransportStart nan(String id, long generation, int ap) {
        return new TransportStart(id, generation, TransportStart.Kind.NAN,
                "", "", null, 0, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, ap, -1);
    }
}
