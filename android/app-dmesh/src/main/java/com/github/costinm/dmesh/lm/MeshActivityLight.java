package com.github.costinm.dmesh.lm;

import android.Manifest;
import android.app.ActionBar;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.Window;
import android.widget.TextView;

import com.github.costinm.dmesh.wifi.DMeshCompanionManager;
import com.github.costinm.dmeshnative.MeshNode;

import java.net.InterfaceAddress;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Lightweight platform-only status and permission handling for app-dmesh.
 *
 * The command UI lives in the ssh-mesh admin web surface. This Activity only starts
 * the foreground service, handles Android permission/VPN UI flows, shows concise
 * local status, and may open the isolated WebActivity.
 */
public class MeshActivityLight extends Activity {
    private static final String TAG = "Mesh";
    public static final String ACTION_START_VPN = "com.github.costinm.dmesh.START_VPN";
    public static final String ACTION_REQUEST_PERMISSIONS =
            "com.github.costinm.dmesh.REQUEST_PERMISSIONS";
    public static final String EXTRA_VPN_ADDRESS = "address6";
    public static final String EXTRA_PERMISSIONS = "permissions";
    private static final String ADMIN_URL = "http://127.0.0.1:18480/_m/adm/";
    private static final int MENU_OPEN_WEB = 1;
    private static final int MENU_PAIR_COMPANION = 2;
    public static final int A_REQUEST_LOCATION = 10;
    public static final int A_REQUEST_VPN = 9;
    private static final byte[] DEFAULT_VPN_ADDRESS = new byte[] {
            (byte) 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1
    };

    private static final String[] PERMISSIONS = {
            Manifest.permission.POST_NOTIFICATIONS,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.NEARBY_WIFI_DEVICES,
    };

    private TextView conText;
    private TextView ifText;
    private TextView msgText;
    private Intent pendingStartupIntent;
    private boolean pendingVpnStart;

    static List<String> checkPermissions(Context ctx) {
        List<String> missing = new ArrayList<>();
        for (String permission : PERMISSIONS) {
            if (ctx.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                missing.add(permission);
            }
        }
        return missing;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_ACTION_BAR_OVERLAY);
        setContentView(R.layout.main_activity);

        ActionBar actionBar = getActionBar();
        if (actionBar != null) {
            actionBar.setDisplayOptions(ActionBar.DISPLAY_SHOW_TITLE | ActionBar.DISPLAY_SHOW_HOME);
            actionBar.setHideOnContentScrollEnabled(true);
        }

        conText = findViewById(R.id.con_text);
        ifText = findViewById(R.id.if_text);
        msgText = findViewById(R.id.msg_text);
        ifText.setOnClickListener(v -> updateInterfaces());
        msgText.setText("Open Web for DMesh status and controls");

        List<String> missing = checkPermissions(getApplicationContext());
        if (!missing.isEmpty()) {
            Log.d(TAG, "Missing permissions " + missing);
            pendingStartupIntent = getIntent();
            requestPermissions(missing.toArray(new String[]{}), A_REQUEST_LOCATION);
            return;
        }

        startDMeshService();
        refreshStatus();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void startDMeshService() {
        try {
            startForegroundService(new Intent(this, DMService.class));
            setServiceStatus("Service requested");
        } catch (Throwable ex) {
            Log.d(TAG, "Failed to start service", ex);
            setServiceStatus("Service start failed: " + ex.getMessage());
        }
    }

    private void handleIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (ACTION_START_VPN.equals(intent.getAction())) {
            startVpnFromIntent(intent);
        } else if (ACTION_REQUEST_PERMISSIONS.equals(intent.getAction())) {
            requestPermissionsFromIntent(intent);
        }
    }

    private void requestPermissionsFromIntent(Intent intent) {
        List<String> wanted = new ArrayList<>();
        String requested = intent.getStringExtra(EXTRA_PERMISSIONS);
        if (requested != null && !requested.trim().isEmpty()) {
            for (String raw : requested.split(",")) {
                String normalized = normalizePermission(raw.trim());
                if (normalized != null
                        && checkSelfPermission(normalized) != PackageManager.PERMISSION_GRANTED) {
                    wanted.add(normalized);
                }
            }
        }
        if (wanted.isEmpty()) {
            wanted.addAll(checkPermissions(getApplicationContext()));
        }
        if (!wanted.isEmpty()) {
            requestPermissions(wanted.toArray(new String[]{}), A_REQUEST_LOCATION);
        }
    }

    private static String normalizePermission(String permission) {
        if (permission == null || permission.isEmpty()) {
            return null;
        }
        if (permission.startsWith("android.permission.")) {
            return permission;
        }
        return "android.permission." + permission;
    }

    private void startVpnFromIntent(Intent intent) {
        VpnService.address6 = vpnAddressFromIntent(intent);
        final Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent != null) {
            pendingVpnStart = true;
            startActivityForResult(prepareIntent, A_REQUEST_VPN);
            return;
        }
        startService(new Intent(this, VpnService.class));
    }

    private byte[] vpnAddressFromIntent(Intent intent) {
        byte[] address = intent.getByteArrayExtra(EXTRA_VPN_ADDRESS);
        if (address != null && address.length == 16) {
            return address;
        }
        String addressText = intent.getStringExtra(EXTRA_VPN_ADDRESS);
        if (addressText != null && !addressText.isEmpty()) {
            try {
                byte[] parsed = InetAddress.getByName(addressText).getAddress();
                if (parsed.length == 16) {
                    return parsed;
                }
                Log.w(TAG, "VPN address extra is not IPv6: " + addressText);
            } catch (Throwable t) {
                Log.w(TAG, "Invalid VPN address extra: " + addressText, t);
            }
        }
        return DEFAULT_VPN_ADDRESS.clone();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != A_REQUEST_LOCATION) {
            return;
        }
        List<String> missing = checkPermissions(getApplicationContext());
        if (!missing.isEmpty()) {
            setServiceStatus("Missing permissions: " + missing);
            return;
        }
        Intent startupIntent = pendingStartupIntent;
        pendingStartupIntent = null;
        startDMeshService();
        refreshStatus();
        handleIntent(startupIntent != null ? startupIntent : getIntent());
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (A_REQUEST_VPN == requestCode && pendingVpnStart) {
            pendingVpnStart = false;
            startService(new Intent(this, VpnService.class));
        } else if (DMeshCompanionManager.REQUEST_ASSOCIATE == requestCode) {
            DMeshCompanionManager.handleActivityResult(this, resultCode, data);
            refreshStatus();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, MENU_OPEN_WEB, 0, "Web").setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
        menu.add(0, MENU_PAIR_COMPANION, 1, "Pair companion");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == MENU_OPEN_WEB) {
            openWebAdmin();
            return true;
        }
        if (item.getItemId() == MENU_PAIR_COMPANION) {
            DMeshCompanionManager.associate(this);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void openWebAdmin() {
        Intent intent = new Intent(this, WebActivity.class);
        intent.putExtra(WebActivity.EXTRA_URL, ADMIN_URL);
        startActivity(intent);
    }


    private void updateInterfaces() {
        if (ifText == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                String name = ni.getName();
                if (ni.getInterfaceAddresses().isEmpty() || !ni.isUp()
                        || name.contains("dummy") || "lo".equals(name)) {
                    continue;
                }
                sb.append(name).append(": ");
                for (InterfaceAddress address : ni.getInterfaceAddresses()) {
                    sb.append(address.getAddress().getHostAddress()).append(" ");
                }
                sb.append("\n");
            }
        } catch (SocketException e) {
            sb.append("Interface error: ").append(e.getMessage()).append("\n");
        }
        ifText.setText(sb.length() == 0 ? "No active interfaces" : sb.toString());
    }

    /** Render Rust's bounded cross-bearer status; Java does not interpret discovery state. */
    private void refreshStatus() {
        updateInterfaces();
        try {
            setServiceStatus(MeshNode.statusText());
        } catch (Exception ignored) {
            setServiceStatus("DMesh starting");
        }
    }

    private void setServiceStatus(String text) {
        if (conText != null) {
            conText.setText(text);
        }
    }
}
