package com.github.costinm.lm;

import android.content.Context;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.lm3.Wifi;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class WifiInstrumentedTest {

    @Test
    public void discoverSD() throws Exception {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        Wifi wifi = Wifi.get(appContext);

        int failures = 0;
        int ok = 0;
        for (int i = 0; i < 10; i++) {
            Wifi.txtDiscoveryByP2P.clear();
            wifi.discoveryWifiP2POnce();

            Thread.sleep(6000);

            if (wifi.txtDiscoveryByP2P.size() == 0) {
                failures++;
            } else {
                ok++;
            }
        }

        if (ok < 5) {
            throw new Exception("Failed: " + failures);
        }
    }

    @Test
    public void discoverSvc() throws Exception {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        MsgConn cli = MsgMux.get(appContext).dial(appContext.getPackageName());
        cli.start();

        for (int i = 0; i < 10; i++) {

            cli.send("/wifi/con/start");

            Thread.sleep(10000);

        }
    }

    @Test
    public void dialQ() throws Exception {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        MsgConn cli = MsgMux.get(appContext).dial(appContext.getPackageName());
        cli.start();

        cli.send("/wifi/discoverPeersStart");
    }

}