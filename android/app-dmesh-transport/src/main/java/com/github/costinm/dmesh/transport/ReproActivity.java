package com.github.costinm.dmesh.transport;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.github.costinm.dmesh.wifi.WifiController;

/**
 * Deliberately boring framework-only reproduction for a Wi-Fi Direct to
 * Wi-Fi Aware transition. There is no DMesh transport, JNI, foreground
 * service, discovery protocol, or private packet handling in this APK.
 */
public final class ReproActivity extends Activity {
    private TextView state;
    private TextView log;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestRuntimePermissions();
        // Start while the activity is visible: Android 14+ does not allow a
        // background caller to create a foreground service for a while-in-use
        // resource. This is a connected-device service, not a location one.
        startForegroundService(new Intent(this, ReproForegroundService.class));

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);

        Button p2p = new Button(this);
        p2p.setText("Start P2P GO");
        p2p.setOnClickListener(view -> WifiController.get(this).startP2pGroup());
        layout.addView(p2p);

        Button nan = new Button(this);
        nan.setText("Start NAN");
        nan.setOnClickListener(view -> WifiController.get(this).startNanAfterP2p());
        layout.addView(nan);

        state = new TextView(this);
        state.setTextSize(14);
        layout.addView(state);
        log = new TextView(this);
        log.setTextSize(12);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(log);
        layout.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(layout);
    }

    @Override public void onResume() {
        super.onResume();
        WifiController.get(this).setObserver(this::render);
        render();
    }

    @Override public void onPause() {
        WifiController.get(this).setObserver(null);
        super.onPause();
    }

    private void render() {
        WifiController controller = WifiController.get(this);
        state.setText(controller.snapshot());
        log.setText(controller.logText());
    }

    private void requestRuntimePermissions() {
        if (android.os.Build.VERSION.SDK_INT < 33) return;
        boolean nearby = checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES)
                == PackageManager.PERMISSION_GRANTED;
        boolean scan = checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)
                == PackageManager.PERMISSION_GRANTED;
        boolean connect = checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                == PackageManager.PERMISSION_GRANTED;
        boolean advertise = checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
                == PackageManager.PERMISSION_GRANTED;
        if (!nearby || !scan || !connect || !advertise) requestPermissions(new String[] {
                Manifest.permission.NEARBY_WIFI_DEVICES,
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
        }, 1);
    }
}
