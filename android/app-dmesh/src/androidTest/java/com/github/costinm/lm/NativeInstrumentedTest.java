package com.github.costinm.lm;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.github.costinm.dmesh.lm.VpnService;
import com.github.costinm.dmeshnative.MeshNode;
import com.github.costinm.dmeshnative.Rust;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;

@RunWith(AndroidJUnit4.class)
public class NativeInstrumentedTest {

    @Test
    public void nativeRustLoads() {
        Rust.load();
    }

    @Test
    public void meshNodeHealth() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File baseDir = new File(context.getFilesDir(), "dmesh-health");
        MeshNode node = new MeshNode(baseDir.getAbsolutePath());

        try {
            node.start(0, 0);
            String publicKey = node.getPublicKey();
            Assert.assertNotNull(publicKey);
            Assert.assertTrue("public key should be OpenSSH formatted", publicKey.contains(" "));
        } finally {
            node.stop();
        }
    }

    @Test
    public void vpnTunFdHealth() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        Assert.assertNull("VPN consent must be pre-granted for instrumentation",
                VpnService.prepare(context));

        byte[] addr = new byte[] {
                (byte) 0xfd, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 12, 34,
        };

        VpnService.startForTest(context, addr);
        long deadline = System.currentTimeMillis() + 10000;
        while (System.currentTimeMillis() < deadline && VpnService.lastTunTestResult == 0) {
            Thread.sleep(100);
        }

        Assert.assertNull(VpnService.lastTunTestError, VpnService.lastTunTestError);
        Assert.assertTrue("Rust should accept Android VPN fd", VpnService.lastTunTestResult > 0);
    }
}
