package com.github.costinm.lm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Binder;
import android.os.Bundle;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.github.costinm.dmesh.DirectBinder;
import com.github.costinm.dmesh.MeshStream;
import com.github.costinm.dmesh.lm.MessageStreamGateway;
import com.github.costinm.dmeshnative.CborMessageCodec;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;

/** Cross-app DirectBinder regression. The build harness installs app-web first. */
@RunWith(AndroidJUnit4.class)
public final class DirectBinderWebTest {
    private static final ComponentName WEB_SERVICE = new ComponentName(
            "com.github.costinm.dmesh.web",
            "com.github.costinm.dmesh.web.WebBridgeService");

    @Test
    public void preservesTypedBundleValuesAndRejectsUnsupportedValues() {
        MeshStream request = new MeshStream("/web/echo");
        request.id = "direct-web-test";
        request.fields.put("text", "direct-binder-echo");
        request.data.putInt("typed-test-value", 7);
        request.data.putByteArray("bytes", new byte[] { 1, 2, 3 });
        Bundle nested = new Bundle();
        nested.putBoolean("enabled", true);
        request.data.putBundle("nested", nested);
        ArrayList<String> labels = new ArrayList<>();
        labels.add("one");
        labels.add("two");
        request.data.putStringArrayList("labels", labels);

        MeshStream projected = MeshStream.fromDirect(request.payload, request.encoding,
                request.toDirectExtras());
        assertEquals(7, projected.data.getInt("typed-test-value"));
        assertEquals(request.fields.get("text"), projected.fields.get("text"));
        assertEquals(3, projected.data.getByteArray("bytes").length);
        assertTrue(projected.data.getBundle("nested").getBoolean("enabled"));
        assertEquals(labels, projected.data.getStringArrayList("labels"));

        Bundle invalid = new Bundle();
        invalid.putBinder("not-a-message-value", new Binder());
        try {
            DirectBinder.validateExtras(invalid);
            fail("Binder objects must use the dedicated callback slot");
        } catch (IllegalArgumentException expected) {
            // Expected: arbitrary Binder values cannot enter a typed Bundle.
        }

        byte[] cbor = CborMessageCodec.encode(request);
        MeshStream decoded = CborMessageCodec.decode(cbor);
        assertEquals(request.id, decoded.id);
        assertEquals(7, decoded.data.getInt("typed-test-value"));
        assertEquals(3, decoded.data.getByteArray("bytes").length);
        assertTrue(decoded.data.getBundle("nested").getBoolean("enabled"));
        assertEquals(labels, decoded.data.getStringArrayList("labels"));
    }

    @Test
    public void sendsBoundedFrameAndReceivesCorrelatedWebReply() throws Exception {
        MeshStream request = new MeshStream("/web/echo");
        request.id = "direct-web-test";
        request.fields.put("text", "direct-binder-echo");
        request.data.putInt("typed-test-value", 7);

        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        CountDownLatch bound = new CountDownLatch(1);
        CountDownLatch response = new CountDownLatch(1);
        IBinder[] remote = { null };
        MeshStream[] reply = { null };
        ServiceConnection connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                remote[0] = service;
                bound.countDown();
            }

            @Override public void onServiceDisconnected(ComponentName name) {
            }
        };
        Intent bind = new Intent(DirectBinder.ACTION_DIRECT).setComponent(WEB_SERVICE);
        assertTrue("app-web DirectBinder bind failed",
                context.bindService(bind, connection, Context.BIND_AUTO_CREATE));
        try {
            assertTrue("app-web DirectBinder bind timed out", bound.await(10, TimeUnit.SECONDS));
            DirectBinder callback = new DirectBinder((code, message, parcel) -> {
                reply[0] = message.stream;
                response.countDown();
                return true;
            });
            assertTrue("app-web DirectBinder transaction failed", DirectBinder.transact(remote[0],
                    DirectBinder.TRANSACT_MESSAGE, request, callback, null));
            assertTrue("app-web DirectBinder callback timed out", response.await(10, TimeUnit.SECONDS));
            assertNotNull(reply[0]);
            assertEquals("web.echo", reply[0].method);
            assertEquals(request.id, reply[0].id);
            assertEquals(7, reply[0].data.getInt("typed-test-value"));
        } finally {
            context.unbindService(connection);
        }
    }

    @Test
    public void transportNeutralGatewayRoutesAppWebAndReturnsTypedRecord() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        MessageStreamGateway gateway = new MessageStreamGateway(context, () -> {}, target -> {});
        CountDownLatch response = new CountDownLatch(1);
        byte[][] record = { null };
        MessageStreamGateway.Endpoint endpoint = new MessageStreamGateway.Endpoint() {
            @Override public String id() {
                return "test:transport-neutral";
            }

            @Override public boolean send(byte[] responseRecord) {
                record[0] = responseRecord;
                response.countDown();
                return true;
            }
        };
        MeshStream request = new MeshStream("/web/echo");
        request.id = "transport-neutral-echo";
        request.data.putInt("typed-test-value", 17);
        request.to = new Intent(DirectBinder.ACTION_DIRECT)
                .setComponent(WEB_SERVICE)
                .toUri(Intent.URI_INTENT_SCHEME);
        try {
            gateway.onMessage(endpoint, CborMessageCodec.encode(request));
            assertTrue("gateway reply timed out", response.await(10, TimeUnit.SECONDS));
            MeshStream reply = CborMessageCodec.decode(record[0]);
            assertEquals("web.echo", reply.method);
            assertEquals(request.id, reply.id);
            assertEquals(17, reply.data.getInt("typed-test-value"));
        } finally {
            gateway.close(endpoint);
        }
    }

    @Test
    public void appCanSendOneWayAndCorrelatedMessageThroughCallerEndpoint() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        CountDownLatch bound = new CountDownLatch(1);
        CountDownLatch oneWay = new CountDownLatch(1);
        CountDownLatch reverse = new CountDownLatch(1);
        CountDownLatch receipt = new CountDownLatch(1);
        IBinder[] remote = { null };
        ServiceConnection connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                remote[0] = service;
                bound.countDown();
            }

            @Override public void onServiceDisconnected(ComponentName name) {
            }
        };
        Intent bind = new Intent(DirectBinder.ACTION_DIRECT).setComponent(WEB_SERVICE);
        assertTrue("app-web DirectBinder bind failed",
                context.bindService(bind, connection, Context.BIND_AUTO_CREATE));
        try {
            assertTrue("app-web DirectBinder bind timed out", bound.await(10, TimeUnit.SECONDS));
            DirectBinder routerEndpoint = new DirectBinder((code, message, parcel) -> {
                MeshStream stream = message.stream;
                assertNotNull(stream);
                if ("web.oneway".equals(stream.method)) {
                    assertNull("one-way events do not have an ID", stream.id);
                    assertEquals("from-app-web", stream.data.getString("value"));
                    oneWay.countDown();
                    return true;
                }
                if ("web.reverse".equals(stream.method)) {
                    assertEquals("endpoint-test:app-request", stream.id);
                    assertNotNull("correlated app call includes a reply endpoint", message.callback);
                    MeshStream response = new MeshStream("router.reverse.reply");
                    response.replyTo = stream.id;
                    response.data.putString("value", "from-router");
                    assertTrue(DirectBinder.transact(message.callback,
                            DirectBinder.TRANSACT_EVENT, response, null, null));
                    reverse.countDown();
                    return true;
                }
                if ("web.reverse.received".equals(stream.method)) {
                    assertEquals("endpoint-test:app-request", stream.replyTo);
                    assertEquals("from-router", stream.data.getString("value"));
                    receipt.countDown();
                    return true;
                }
                return false;
            });
            MeshStream initial = new MeshStream("/web/endpoint");
            initial.id = "endpoint-test";
            assertTrue("app-web endpoint setup failed", DirectBinder.transact(remote[0],
                    DirectBinder.TRANSACT_MESSAGE, initial, routerEndpoint, null));
            assertTrue("app-web one-way event timed out", oneWay.await(10, TimeUnit.SECONDS));
            assertTrue("app-web correlated request timed out", reverse.await(10, TimeUnit.SECONDS));
            assertTrue("app-web reverse receipt timed out", receipt.await(10, TimeUnit.SECONDS));
        } finally {
            context.unbindService(connection);
        }
    }

}
