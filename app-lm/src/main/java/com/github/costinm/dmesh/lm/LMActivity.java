package com.github.costinm.dmesh.lm;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import com.github.costinm.lm.AP;
import com.github.costinm.lm.Connect;
import com.github.costinm.lm.WifiMesh;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Calendar;

/**
 * Control the AP and mesh connection, as well as settings for auto-joining the net.
 * <p>
 * The main use case for using the standalone version is to turn an old phone into an
 * access point for the mesh. Before M devices don't have doze mode - so DHCP will work,
 * even if it is not powered. For M, the mesh will still periodic, but DHCP will not work -
 * workarounds will be used (static IP4, and use IPv6 for communication).
 * <p>
 * Minimal status information.
 * <p>
 * The app targets JB - many ICS devices have trouble with AP and Wifi Direct, even if it
 * is supported. Even with JB I haven't found devices that supports it - but 'legacy' AP
 * tends to work.
 */
public class LMActivity extends Activity {
    private static final int AP_START = 2;
    private static final int START = 1;

    private WifiMesh dmesh;

    Handler h = new Handler() {
        @Override
        public void handleMessage(Message msg) {

            final int what = msg.what;
            switch (what) {
                case START:
                    updateAPStatus();
                    updateConnection();
                    break;
                case AP_START:
                    updateAPStatus();
                    break;
                case LMService.UPDATE:
                    updateAPStatus();
                    updateConnection();
                    break;
            }
            super.handleMessage(msg);
        }
    };
    @SuppressWarnings("FieldCanBeLocal")
    private SharedPreferences prefs;

    private void updateConnection() {
        TextView tv = (TextView) findViewById(com.github.costinm.lm.R.id.con_status);
        String ssid = dmesh.con.getCurrentWifiSSID();
        StringBuilder sb = new StringBuilder();

        if (ssid == null) {
            tv.setText("");
            return;
        }

        sb.append("Connected: ").append(ssid).append(
                "\nIP:").append(dmesh.con.getIp6WifiClient());
        if (Connect.lastSuccess != 0) {
            sb.append("\nLast").append(timeOfDayShort(e2s(Connect.lastSuccess)));
        }
        tv.setText(sb.toString());
    }

    private void updateAPStatus() {
        StringBuilder sb = new StringBuilder();

        long last = AP.lastStop;
        if (dmesh.apRunning) {
            sb.append(" *");
            last = AP.lastStart;
        }
        sb.append("AP: ").append(WifiMesh.ssid)
                .append("\nIP:").append(WifiMesh.ip6)
                .append("\nPass:").append(WifiMesh.pass);

        sb.append("\nRun time:").append(AP.apRunTime / 60000).append("m, ")
            .append(AP.apStartTimes).append(" times, last=")
            .append(timeOfDayShort(e2s(last)));

        setText(R.id.ap_status, sb.toString());
    }

    Intent lmServiceIntent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //R.id.checkBox
        dmesh = WifiMesh.get(this);
        dmesh.onStart(this, h, h.obtainMessage(START));
        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        updateConnection();

        updateDetails();
        lmServiceIntent = new Intent(this, LMService.class);
        this.startService(lmServiceIntent);

        LMService.listeners.add(h);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        LMService.listeners.remove(h);
        // if disabled: stop service
    }

    private void setText(int id, String text) {
        TextView tv = (TextView) findViewById(id);
        tv.setText(text);
    }

    private void updateDetails() {

        // Nexus 6: all capabilities bellow.
        if (Build.VERSION.SDK_INT >= 21) {
            StringBuilder title = new StringBuilder();
            WifiManager mWifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
            // May be used to reduce scans
            if (mWifiManager.isPreferredNetworkOffloadSupported()) {
                title.append("Offload Scan, ");
            }
            // Can be used to decide when to switch
            if (mWifiManager.isDeviceToApRttSupported()) {
                title.append("RTT, ");
            }
            if (mWifiManager.isEnhancedPowerReportingSupported()) {
                title.append("PowerReport, ");
            }
            // It might help reduce battery on the AP, but not sure yet how to use it.
            if (mWifiManager.isTdlsSupported()) {
                // setTdls(ip, true)
                // Tunnel direct
                title.append("TDLS, ");
            }
            // This is very important - but I haven't figured out how to enable it !!!
            if (isAdditionalStaSupported(mWifiManager)) {
                title.append("Additional Sta");
            }
            if (title.length() > 0) {
                setText(R.id.wifi_info, "Interface capabilities: " + title.toString());
            } else {
                findViewById(R.id.wifi_info).setVisibility(View.GONE);
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        updateConnection();
        updateAPStatus();
        super.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu, menu);
        return true;
    }

    @Override
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.debug) {
            startActivityForResult(new Intent(this, LMDebugActivity.class), 1);
        } else if (id == R.id.refresh) {
            Intent i = new Intent(this, LMService.class);
            startService(i);
        } else if (id == R.id.settings) {
            startActivityForResult(new Intent(this, WifiSettingsActivity.class), 1);
        }
        return super.onMenuItemSelected(featureId, item);
    }

    /*


     */
    private boolean isAdditionalStaSupported(WifiManager mWifiManager) {
        try {
            Method m = mWifiManager.getClass().getMethod("isAdditionalStaSupported");
            return (boolean) m.invoke(mWifiManager);
        } catch (NoSuchMethodException ignored) {
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return false;
    }

    // Elapsed to system time
    public static long e2s(long millis) {
        return millis + System.currentTimeMillis() - SystemClock.elapsedRealtime();
    }

    public static String timeOfDayShort(long millis) {
        Calendar c = Calendar.getInstance();
        if (millis >= 0) {
            c.setTimeInMillis(millis);
            return String.format("%tH:%tM", c, c);
        } else {
            return "";
        }
    }

}
