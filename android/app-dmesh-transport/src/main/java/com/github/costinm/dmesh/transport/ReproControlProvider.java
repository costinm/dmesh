package com.github.costinm.dmesh.transport;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Handler;
import android.os.Looper;
import android.os.Bundle;
import android.os.Process;

import com.github.costinm.dmesh.wifi.Announce;
import com.github.costinm.dmesh.wifi.Ble;
import com.github.costinm.dmesh.wifi.Discover;
import com.github.costinm.dmesh.wifi.TransportStart;
import com.github.costinm.dmesh.wifi.WifiController;
import com.github.costinm.dmesh.wifi.WifiTransitionQualification;

import java.util.Arrays;
import java.util.Collections;

/** Shell-only ADB control surface for the minimal radio reproducer. */
public final class ReproControlProvider extends ContentProvider {
    private static Ble ble;

    @Override public boolean onCreate() { return true; }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        int uid = Binder.getCallingUid();
        if (uid != 0 && uid != 2000 && uid != Process.myUid()) {
            throw new SecurityException("ADB shell or in-process only");
        }
        String command = "command".equals(method) ? arg : method;
        WifiController controller = WifiController.get(getContext());
        Ble ble = ble();
        boolean terminalObserved = false;
        if ("p2p.start".equals(command)) terminalObserved = controller.startP2pGroupAndAwait();
        else if ("p2p.start_advertised".equals(command)) {
            terminalObserved = controller.startP2pGroupWithServiceAndAwait();
        }
        else if ("p2p.stop".equals(command)) controller.stopP2p(() -> { });
        else if ("nan.start".equals(command)) terminalObserved = controller.startNanAfterP2pAndAwait();
        else if ("nan.stop".equals(command)) controller.stopNan();
        else if ("lohs.start".equals(command)) controller.startLocalOnlyHotspot();
        else if ("lohs.stop".equals(command)) controller.stopLocalOnlyHotspot();
        else if ("ble.scan".equals(command)) ble.scan();
        else if ("ble.scan.stop".equals(command)) ble.scanStop();
        else if ("ble.advertise".equals(command)) ble.advertise(hexBytes(extras));
        else if ("ble.advertise.stop".equals(command)) ble.advertise(null);
        else if ("announce.set".equals(command)) {
            controller.setAnnounce(new Announce(hexBytes(extras), options(extras)), ignored -> { });
        } else if ("announce.clear".equals(command)) {
            controller.setAnnounce(Announce.empty(), ignored -> { });
        } else if ("discover.set".equals(command)) {
            controller.setDiscover(new Discover(hexBytes(extras), options(extras)), ignored -> { });
        } else if ("discover.clear".equals(command)) {
            controller.setDiscover(Discover.empty(), ignored -> { });
        } else if ("transport.start".equals(command)) {
            TransportStart request = TransportStart.fromBundle(extras);
            final Object monitor = new Object();
            final String[] outcome = { "pending" };
            controller.start(request, result -> {
                synchronized (monitor) {
                    outcome[0] = result.outcome + " state=" + result.state + " error=" + result.error
                            + " reply_available=" + result.replyTransportAvailable
                            + " restored=" + result.previousTransportRestored;
                    monitor.notifyAll();
                }
            });
            synchronized (monitor) {
                try { monitor.wait(35_000); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            terminalObserved = !"pending".equals(outcome[0]);
            Bundle result = baseResult(command, terminalObserved, controller);
            result.putString("transport_result", outcome[0]);
            return result;
        } else if ("qualify.transition".equals(command)) {
            TransportStart sta = transportStart(extras, "sta", 0);
            final Object monitor = new Object();
            final WifiTransitionQualification.Report[] report = { null };
            WifiTransitionQualification.run(controller, sta, value -> {
                synchronized (monitor) {
                    report[0] = value;
                    monitor.notifyAll();
                }
            });
            synchronized (monitor) {
                // Keep the Binder/content shell bounded even if a framework
                // callback disappears. The library has the same 90 s budget.
                try { monitor.wait(WifiTransitionQualification.MAX_DURATION_MS + 5_000L); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            Bundle result = baseResult(command, report[0] != null, controller);
            if (report[0] == null) {
                result.putString("qualification", "timeout");
            } else {
                result.putBoolean("success", report[0].success);
                result.putString("step", report[0].step);
                result.putString("detail", report[0].detail);
                result.putString("final_state", report[0].finalState);
            }
            return result;
        }
        else if (!"status".equals(command)) throw new IllegalArgumentException("unknown command " + command);
        Bundle result = baseResult(command, terminalObserved, controller);
        result.putString("ble_state", ble.snapshot());
        return result;
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Cursor query(Uri uri, String[] p, String s, String[] a, String sort) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String s, String[] a) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String s, String[] a) { return 0; }

    private static Bundle baseResult(String command, boolean terminalObserved, WifiController controller) {
        Bundle result = new Bundle();
        result.putString("command", command);
        result.putBoolean("terminal_observed", terminalObserved);
        result.putString("state", controller.snapshot());
        result.putString("log", controller.logText());
        return result;
    }

    private synchronized Ble ble() {
        if (ble == null) {
            ble = new Ble(getContext().getApplicationContext(), new Handler(Looper.getMainLooper()));
        }
        return ble;
    }

    private static byte[] hexBytes(Bundle extras) {
        String value = extras == null ? "" : extras.getString("payload_hex", "");
        if ((value.length() & 1) != 0) throw new IllegalArgumentException("payload_hex must be even length");
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("invalid payload_hex");
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    private static java.util.List<String> options(Bundle extras) {
        String value = extras == null ? "" : extras.getString("options", "");
        return value.isEmpty() ? Collections.emptyList() : Arrays.asList(value.split(","));
    }

    private static TransportStart transportStart(Bundle extras, String mode, int ap) {
        Bundle values = extras == null ? new Bundle() : new Bundle(extras);
        values.putString("mode", mode);
        values.putInt("ap", ap);
        return TransportStart.fromBundle(values);
    }
}
