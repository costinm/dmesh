package com.github.costinm.lm;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmesh.lm3.LocalMesh;
import com.github.costinm.dmeshnative.Rust;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class NativeInstrumentedTest {

    @Test
    public void nativeRust() throws Exception {
        Rust.load();
        Rust.invokeCallbackViaJNI(new Rust.Callback() {
            public void callback(String s) {
                System.out.println("Callback " + s);
            }
        });
    }
}