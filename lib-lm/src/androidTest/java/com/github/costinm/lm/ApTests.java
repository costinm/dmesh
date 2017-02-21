package com.github.costinm.lm;

import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
public class ApTests {
    Context ctx;

    @Before
    public void setUp() {
        ctx = InstrumentationRegistry.getTargetContext();
        // tests run in separate package.
        assertEquals("com.github.costinm.dmap.test", ctx.getPackageName());

    }

    /**
     * Tested: 15-ICS (NexusS), 16-JB (NexusS)
     *
     * Failed: 10-GB (Droid)
     */
    //@Test
//    public void legacy() throws Exception {
//        // fixed: JB: Failed to discover soft AP with a running supplicant
//        //   requires to turn of wifi before starting AP
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
//            return;
//        }
//        AP ap = new AP(WifiMesh.get(ctx), ctx);
//
//        ap.stopLegacyAp();
//
//        // NoSuchMethod on N
////        WifiConfiguration wf = ap.getWifiApConfiguration();
////        if (wf != null) {
////            Log.d(AP.TAG, "Got AP Wifi config " + wf.SSID + " " + wf);
////        }
//
//        boolean res = ap.createLegacyAp();
//        if (!res) {
//            fail("ap");
//        }
//        Thread.sleep(30000);
//
//        /*
//        Droid:
//
//        12-05 19:53:20.572 1104-1142/system_process D/Tethering: tiwlan0 is not a tetherable iface, ignoring
//        12-05 19:53:20.814 1012-1029/? E/SoftapController: SIOCGIPRIV failed: -1
//        12-05 19:53:20.814 1012-1029/? E/SoftapController: Softap driver apSessionStop - function not supported
//        12-05 19:53:20.814 1104-1145/system_process E/WifiService: Exception in startAccessPoint()
//
//        TODO: wait until callbacks are generated for actual status
//         */
//        // Callbacks: discover is (2), 4, 0, 1
//
////        wf = ap.getWifiApConfiguration();
////        Log.d("T", "Wifi: " + wf);
////
////        assertTrue(ap.isWifiApEnabled());
//        ap.stopLegacyAp();
//
//        // TODO: 'witness' device to connect to network and ping !
//    }

    @Test
    public void disc() throws Exception {
        final BlockingQueue<String> bq= new LinkedBlockingQueue<>();


        P2PDiscovery disc = new P2PDiscovery(ctx) {
                public void onNewNode(String ssid, String pass, String mac) {
                    bq.add(ssid);
                }
        };

        disc.discover();

        for (int i = 0; i < 10; i++) {
            String s = bq.poll(10, TimeUnit.SECONDS);
            if (s!= null && s.contains("mY-costin")) {
                return;
            }
            Log.d(AP.TAG, "Ignoring " + s);
        }
        fail("Not finding test AP");
    }

    final BlockingQueue bq = new LinkedBlockingQueue();

    @Test
    public void p2p() throws Exception {
        final AP ap = new AP(WifiMesh.get(ctx), ctx);
//        ap.listener = new ApListener() {
//            public void onDone() {
//                Log.d(AP.TAG, "Got onDone");
//                bq.add(this);
//            }
//        };
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN) {
            return;
        }

        ap.start(null); // 1 min

        bq.poll(5, TimeUnit.SECONDS);
        Thread.sleep(15000);

        //Log.d("T", "Wifi" + ap.dump());

        // TODO: wait for a ping from witness !

        bq.clear();

        ap.stop(null);

        bq.poll(5, TimeUnit.SECONDS);

        //Log.d("T", "Wifi" + ap.dump());
    }


//    @Test
//    public void scan() throws Exception {
//        Scan scan = new Scan(ctx) {
//        };
//
//        scan.update();
//
//        // check what we have - display
//
//        //scan.scan(0);
//
//
//        // Expect a callback
//
//        // wait a bit more
//
//        // how many callbacks we got ?  Did we find the witness AP ?
//
//
//    }

}
