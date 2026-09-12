package com.github.costinm.dmesh;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.util.Log;

import java.io.FileDescriptor;
import java.util.ArrayList;
import java.util.List;


/** DirectBinder is a raw, direct binder interface - not using AIDL or generated interface,
 * but closer to a protocol transport.
 *
 * The payload is an opaque {@code byte[]}. The optional encoding label and
 * primitive Bundle extras are transport metadata; neither is interpreted here.
 * Binder is only a bounded control plane: commands, replies, state edges, and
 * file-descriptor handoffs. Bulk content and bidirectional streams must use
 * an FD-backed stream after the initial Binder rendezvous; never raise this
 * limit to transfer packets or file bodies through Binder.
 *  The binder has a limited number of threads - blocking operations can be done, but
 *  if the concurrency is close - it needs to switch to a separate thread pool and
 *  return immediately to allow other request to be processed. That means the response
 *  needs to be sent a a callback to the client, which implies the client needs to
 *  pass it's binder address to the server for 2-way message based communication.
 *
 *  Messenger is processing all the incomming messages on the single looper thread
 *  associated with the messenger - it could also dispatch to a thread pool to insure
 *  concurrency, and use the return Messenger to send back results if needed. The difference
 *  is that with DirectBinder there is less overhead in processing the data and in normal
 *  cases ( low QPS ) it an use the binder thread directly.
 *
 *  Parcel data is in a mmap buffer. If processing directly it doesn't need to be copied -
 *  otherwise (moving to thread pool) it does.
 *
 *  Note: it is not required to have a Service, the DirectBinder can be passed as a parameter
 *  and used without any Service declaration while the app is running. Service is needed to
 *  start or bind (and keep at higher importance) the process.
 *
 */
public class DirectBinder extends Binder {
    private static final String TAG = "DirectBinder";
    public static final String ACTION_DIRECT = "mesh.direct";
    public static final int TRANSACT_MESSAGE = IBinder.FIRST_CALL_TRANSACTION;
    public static final int TRANSACT_EVENT = IBinder.FIRST_CALL_TRANSACTION + 1;
    /** @deprecated Connection open is an application event, not a transport transaction. */
    @Deprecated public static final int TRANSACT_OPEN = TRANSACT_EVENT;
    public static final int MAX_PAYLOAD_BYTES = 64 * 1024;
    /** Shared mesh envelope keys. The payload is the binary data field. */
    public static final String ID = "id";
    public static final String REPLY_TO = "replyTo";
    public static final String SESSION = "session";
    public static final String STREAM = "stream";
    public static final String TYPE = "type";
    public static final String FROM = "from";
    public static final String TO = "to";
    public static final String METHOD = "method";

    private final Receiver receiver;

    public DirectBinder() {
        this(null);
    }

    public DirectBinder(Receiver receiver) {
        this.receiver = receiver;
    }

    @Override
    protected boolean onTransact(int code, Parcel data, Parcel reply,
                                 int flags) throws RemoteException {
        if (code == TRANSACT_MESSAGE || code == TRANSACT_EVENT) {
            DirectMessage msg = readMessage(data, flags, Binder.getCallingUid(), Binder.getCallingPid());
            if (receiver != null) {
                return receiver.onDirectMessage(code, msg, reply);
            }

            return onDirectMessage(code, msg, reply);
        }
        return super.onTransact(code, data, reply, flags);
    }

    protected boolean onDirectMessage(int code, DirectMessage msg, Parcel reply) throws RemoteException {
        return false;
    }

    public static boolean transact(IBinder binder, int code, byte[] payload, String encoding,
                                   Bundle extras, IBinder callback,
                                   List<ParcelFileDescriptor> fds) {
        return transactAsync(binder, code, payload, encoding, extras, callback, fds);
    }

    /**
     * One-way asynchronous transaction. Flags the transaction with IBinder.FLAG_ONEWAY.
     */
    public static boolean transactAsync(IBinder binder, int code, byte[] payload, String encoding,
                                        Bundle extras, IBinder callback,
                                        List<ParcelFileDescriptor> fds) {
        if (binder == null || !validPayload(payload)) return false;
        Parcel in = Parcel.obtain();
        try {
            writeMessage(in, payload, encoding, extras, callback, fds);
            return binder.transact(code, in, null, IBinder.FLAG_ONEWAY);
        } catch (RemoteException | IllegalArgumentException e) {
            Log.d(TAG, "Direct binder async transaction failed", e);
            return false;
        } finally {
            in.recycle();
        }
    }

    /**
     * Synchronous two-way transaction. Waits for the server to populate reply and
     * optionally reads the returned DirectMessage into replyOut[0].
     */
    public static boolean transactSync(IBinder binder, int code, byte[] payload, String encoding,
                                       Bundle extras, List<ParcelFileDescriptor> fds,
                                       DirectMessage[] replyOut) {
        if (binder == null || !validPayload(payload)) return false;
        Parcel in = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            writeMessage(in, payload, encoding, extras, null, fds);
            boolean ok = binder.transact(code, in, reply, 0);
            if (ok && replyOut != null && replyOut.length > 0 && reply.dataAvail() > 0) {
                replyOut[0] = readMessage(reply, 0);
            }
            return ok;
        } catch (RemoteException | IllegalArgumentException e) {
            Log.d(TAG, "Direct binder sync transaction failed", e);
            return false;
        } finally {
            in.recycle();
            reply.recycle();
        }
    }

    /**
     * Java envelope adapter. The MeshStream fields are written as the Binder
     * header and its payload stays opaque.
     */
    @Deprecated
    public static boolean transact(IBinder binder, int code, MeshStream stream, IBinder callback,
                                   List<ParcelFileDescriptor> fds) {
        MeshStream value = stream == null ? new MeshStream(null) : stream;
        return transact(binder, code, value.payload, value.encoding, value.toDirectExtras(), callback, fds);
    }

    public static boolean transactAsync(IBinder binder, int code, MeshStream stream, IBinder callback,
                                        List<ParcelFileDescriptor> fds) {
        MeshStream value = stream == null ? new MeshStream(null) : stream;
        return transactAsync(binder, code, value.payload, value.encoding, value.toDirectExtras(), callback, fds);
    }

    public static boolean transactSync(IBinder binder, int code, MeshStream stream,
                                       List<ParcelFileDescriptor> fds, MeshStream[] replyOut) {
        MeshStream value = stream == null ? new MeshStream(null) : stream;
        DirectMessage[] msgReply = replyOut != null && replyOut.length > 0 ? new DirectMessage[1] : null;
        boolean ok = transactSync(binder, code, value.payload, value.encoding, value.toDirectExtras(), fds, msgReply);
        if (ok && msgReply != null && msgReply[0] != null) {
            replyOut[0] = msgReply[0].stream;
        }
        return ok;
    }

    public static void writeReply(Parcel reply, MeshStream stream) {
        if (reply == null) return;
        MeshStream value = stream == null ? new MeshStream(null) : stream;
        writeMessage(reply, value.payload, value.encoding, value.toDirectExtras(), null, null);
    }

    public static void writeReply(Parcel reply, byte[] payload, String encoding, Bundle extras) {
        if (reply == null) return;
        writeMessage(reply, payload == null ? new byte[0] : payload,
                encoding == null ? "" : encoding, extras, null, null);
    }


    public static void writeMessage(Parcel out, byte[] payload, String encoding, Bundle extras,
                                    IBinder callback, List<ParcelFileDescriptor> fds) {
        if (!validPayload(payload)) throw new IllegalArgumentException("payload exceeds limit");
        validateExtras(extras);
        out.writeInt(1);
        out.writeByteArray(payload);
        out.writeString(encoding == null ? "" : encoding);
        out.writeBundle(extras);
        out.writeStrongBinder(callback);
        int fdCount = fds == null ? 0 : fds.size();
        out.writeInt(fdCount);
        if (fds == null) {
            return;
        }
        for (ParcelFileDescriptor fd : fds) {
            FileDescriptor rawFd = fd == null ? null : fd.getFileDescriptor();
            out.writeFileDescriptor(rawFd);
        }
    }

    /** Build the metadata envelope shared with Rust; body bytes are separate. */
    public static Bundle envelope(String id, String method, String to, String from) {
        Bundle extras = new Bundle();
        put(extras, ID, id);
        put(extras, METHOD, method);
        put(extras, TO, to);
        put(extras, FROM, from);
        return extras;
    }

    private static void put(Bundle extras, String key, String value) {
        if (value != null && !value.isEmpty()) extras.putString(key, value);
    }

    public static DirectMessage readMessage(Parcel in) {
        return readMessage(in, 0, 0, 0);
    }

    public static DirectMessage readMessage(Parcel in, int flags) {
        return readMessage(in, flags, 0, 0);
    }

    public static DirectMessage readMessage(Parcel in, int flags, int callingUid, int callingPid) {
        int version = in.readInt();
        if (version != 1) throw new IllegalArgumentException("unsupported DirectBinder version " + version);
        byte[] payload = in.createByteArray();
        if (!validPayload(payload)) throw new IllegalArgumentException("payload exceeds limit");
        String encoding = in.readString();
        Bundle extras = in.readBundle(DirectBinder.class.getClassLoader());
        validateExtras(extras);
        IBinder callback = in.readStrongBinder();
        int fdCount = in.readInt();
        if (fdCount < 0 || fdCount > 16) throw new IllegalArgumentException("invalid fd count");
        ArrayList<ParcelFileDescriptor> fds = new ArrayList<>(fdCount);
        for (int i = 0; i < fdCount; i++) {
            fds.add(in.readFileDescriptor());
        }
        return new DirectMessage(payload == null ? new byte[0] : payload,
                encoding == null ? "" : encoding, extras, callback, fds, flags, callingUid, callingPid);
    }


    public void dial(Context ctx, String addr) {
        String[] parts = addr.split("/");
        Intent i = new Intent();
        i.setComponent(new ComponentName(parts[0], parts[1]));
        i.setAction(ACTION_DIRECT);

        // TODO: exp backoff, stop after X retries, etc.
        ServiceConnection sc = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {

                //                svc = new Messenger(service);
//                Log.d(TAG, "Connected to " + name);
//
//                Message m = Message.obtain();
//                m.getData().putBoolean(":open", true);
//                send(m);
                transact(service, TRANSACT_EVENT, new byte[0], "", null, DirectBinder.this, null);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
//                svc = null;
//                Log.d(TAG, "LM service disconnected" + name);
//                mux.broadcastHandler.postDelayed(new Runnable() {
//                    @Override
//                    public void run() {
//                        bind(ctx);
//                    }
//                }, 1000);
            }
        };

        boolean b = ctx.bindService(i, sc, Context.BIND_AUTO_CREATE);
        if (!b) {
        }

    }

    public interface Receiver {
        boolean onDirectMessage(int code, DirectMessage msg, Parcel reply) throws RemoteException;
    }

    public static class DirectMessage {
        public final byte[] payload;
        public final String encoding;
        public final Bundle extras;
        public final IBinder callback;
        public final ArrayList<ParcelFileDescriptor> fds;
        public final int flags;
        public final int callingUid;
        public final int callingPid;
        /** Java projection of the Rust envelope; never separately serialized. */
        public final MeshStream stream;

        public DirectMessage(byte[] payload, String encoding, Bundle extras, IBinder callback,
                             ArrayList<ParcelFileDescriptor> fds) {
            this(payload, encoding, extras, callback, fds, 0, 0, 0);
        }

        public DirectMessage(byte[] payload, String encoding, Bundle extras, IBinder callback,
                             ArrayList<ParcelFileDescriptor> fds, int flags) {
            this(payload, encoding, extras, callback, fds, flags, 0, 0);
        }

        public DirectMessage(byte[] payload, String encoding, Bundle extras, IBinder callback,
                             ArrayList<ParcelFileDescriptor> fds, int flags,
                             int callingUid, int callingPid) {
            this.payload = payload;
            this.encoding = encoding;
            this.extras = extras;
            this.callback = callback;
            this.fds = fds;
            this.flags = flags;
            this.callingUid = callingUid;
            this.callingPid = callingPid;
            this.stream = MeshStream.fromDirect(payload, encoding, extras);
        }


        public boolean isOneWay() {
            return (flags & IBinder.FLAG_ONEWAY) != 0;
        }

        public boolean hasCallback() {
            return callback != null;
        }

        public String id() { return extra(ID); }
        public String method() { return extra(METHOD); }
        public String to() { return extra(TO); }
        public String from() { return extra(FROM); }
        public String replyTo() { return extra(REPLY_TO); }
        public String session() { return extra(SESSION); }
        public String stream() { return extra(STREAM); }
        public String type() { return extra(TYPE); }

        private String extra(String key) {
            return extras == null ? "" : extras.getString(key, "");
        }
    }

    private static boolean validPayload(byte[] payload) {
        return payload != null && payload.length <= MAX_PAYLOAD_BYTES;
    }

    /**
     * Keep the Bundle projection bounded and schema-shaped. Binder objects and
     * file descriptors have dedicated Parcel slots; arbitrary Parcelables do
     * not belong in the message payload.
     */
    public static void validateExtras(Bundle extras) {
        if (extras == null) return;
        validateBundle(extras, 0);
        Parcel parcel = Parcel.obtain();
        try {
            parcel.writeBundle(extras);
            if (parcel.dataSize() > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("Bundle exceeds DirectBinder limit");
            }
        } finally {
            parcel.recycle();
        }
    }

    private static void validateBundle(Bundle bundle, int depth) {
        if (depth > 16) throw new IllegalArgumentException("Bundle nesting exceeds limit");
        bundle.setClassLoader(DirectBinder.class.getClassLoader());
        for (String key : bundle.keySet()) {
            validateBundleValue(bundle.get(key), depth);
        }
    }

    private static void validateBundleValue(Object value, int depth) {
        if (value == null || value instanceof String || value instanceof Boolean ||
                value instanceof Integer || value instanceof Long || value instanceof Float ||
                value instanceof Double || value instanceof byte[] || value instanceof String[] ||
                value instanceof boolean[] || value instanceof int[] || value instanceof long[] ||
                value instanceof float[] || value instanceof double[]) {
            return;
        }
        if (value instanceof Bundle) {
            validateBundle((Bundle) value, depth + 1);
            return;
        }
        if (value instanceof ArrayList<?>) {
            for (Object element : (ArrayList<?>) value) validateBundleValue(element, depth + 1);
            return;
        }
        throw new IllegalArgumentException("unsupported DirectBinder Bundle value "
                + value.getClass().getName());
    }
}
