package com.github.costinm.lm;

import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
public class ApTests {
    static final String TAG = "LM-TEST";
    static BlockingQueue<Message> bq = new LinkedBlockingQueue<>();
    static Handler h;
    static Context ctx;
    static WifiMesh lm;

    @BeforeClass
    public static void setUpHandler() {
        HandlerThread thread = new HandlerThread("Test");
        thread.start();
        Looper l = thread.getLooper();
        h = new Handler(l) {
            @Override
            public void handleMessage(Message msg) {
                Message clone = Message.obtain();
                clone.copyFrom(msg);
                bq.add(clone); // msg will be recycled after handleMessage is done
            }
        };
        ctx = InstrumentationRegistry.getTargetContext();

        lm = WifiMesh.get(ctx);

        // Will make sure AP is stopped
        lm.onStart(ctx, h, h.obtainMessage(11));
        try {
            Message s = bq.poll(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Before
    public void setUp() {
        // tests run in separate package.
        assertEquals("com.github.costinm.lm.test", ctx.getPackageName());
        bq.clear();
    }

    /**
     * Test scan and discovery. Assumes an environment with at least one DMesh node running
     * in permanent AP mode, expects to find it.
     */
    @Test
    public void disc() throws Exception {
        // TODO: make sure AP is stopped, network disconnected.

        boolean bg = lm.scanner.scan(30000, h.obtainMessage(1));
        if (bg) {
            Message s = bq.poll(10, TimeUnit.SECONDS);
            // If connected to a P2P network, scan can be ignored (ex. Nexus10 LMP)
            // WifiStateMachine L2Connected CMD_START_SCAN source -2 ... ignore because P2P is connected
            if (s != null) {
                assertEquals("Unexpected scan result", s.what, 1);
                assertTrue("No DMesh wifi node, must have an allways on AP for testing",
                        lm.scanner.last.size() > 0);
                Log.d(TAG, "SCAN FOUND " + lm.scanner.last);
            }
        }

        // TODO: run this ~20 times
        bg = lm.disc.start(h, 2, true);
        if (!bg) {
            fail("Failed to start discovery");
            return;
        }
        Message s = bq.poll(12, TimeUnit.SECONDS); // expect to find in 8 seconds.

        assertEquals("Unexpected discovery result", 2, s.what);
        assertTrue("Node not discovered",
                lm.scanner.connectable.size() > 0);
        Log.d(TAG, "FOUND " + lm.scanner.connectable);

        lm.con.start(ctx, null, h, 3);
        s = bq.poll(12, TimeUnit.SECONDS); // expect to find in 8 seconds, plus 2 sec safety

    }

    /**
     * Test starting/stopping the P2P AP.
     */
    @Test
    public void ap() throws Exception {

        // TODO: run this ~100 times...
        lm.ap.start(h.obtainMessage(5)); // 1 min

        Message m = bq.poll(5, TimeUnit.SECONDS);

        assertEquals(m.what, 5);

        // TODO: Should have a witness device that connects, look for the p2p connected event
        // to verify
        Thread.sleep(15000);

        assertEquals(bq.size(), 0);

        bq.clear();

        lm.ap.stop(h.obtainMessage(6));

        m = bq.poll(5, TimeUnit.SECONDS);

        assertEquals(m.what, 6);
    }
}
