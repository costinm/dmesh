package com.github.costinm.dmwifi;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.github.costinm.dmesh.android.util.MsgMux;
import com.github.costinm.dmesh.android.util.MsgClient;
import com.github.costinm.dmesh.lm3.Wifi;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class WifiInstrumentedTest {

    @Test
    public void discoverSD() throws Exception {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        HandlerThread ht = new HandlerThread("test");
        ht.start();
        // all messages from wifi posted here
        Handler h = new Handler(ht.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                super.handleMessage(msg);
            }
        };
        Wifi wifi = new Wifi(appContext, h, ht.getLooper());

        int failures = 0;
        int ok = 0;
        for (int i = 0; i < 10; i++) {
            Wifi.txtDiscoveryByP2P.clear();
            wifi.discoveryWifiP2POnce(Message.obtain());

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

        MsgClient cli = MsgMux.get(appContext).dial(appContext.getPackageName(), new Handler.Callback() {

            @Override
            public boolean handleMessage(Message message) {
                return false;
            }
        });
        cli.bind(appContext);

        for (int i = 0; i < 10; i++) {

            cli.send("/wifi/con/start");

            Thread.sleep(10000);

        }
    }

    @Test
    public void dialQ() throws Exception {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        MsgClient cli = MsgMux.get(appContext).dial(appContext.getPackageName(), new Handler.Callback() {

            @Override
            public boolean handleMessage(Message message) {
                return false;
            }
        });
        cli.bind(appContext);

        cli.send("/wifi/discoverPeersStart");
    }

}