package com.github.costinm.dmesh.android.msg;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
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
 *  The payload is a []byte - not relying on generated code, avoiding String and copy.
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
    public static final int TRANSACT_OPEN = IBinder.FIRST_CALL_TRANSACTION + 1;

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
        if (code == TRANSACT_MESSAGE || code == TRANSACT_OPEN) {
            DirectMessage msg = readMessage(data);
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

    public static boolean transact(IBinder binder, int code, MsgFrame frame, IBinder callback,
                                   List<ParcelFileDescriptor> fds) {
        Parcel in = Parcel.obtain();
        Parcel out = Parcel.obtain();
        try {
            writeMessage(in, frame, callback, fds);
            return binder.transact(code, in, out, 0);
        } catch (RemoteException e) {
            Log.d(TAG, "Direct binder transaction failed", e);
            return false;
        } finally {
            in.recycle();
            out.recycle();
        }
    }

    public static void writeMessage(Parcel out, MsgFrame frame, IBinder callback,
                                    List<ParcelFileDescriptor> fds) {
        out.writeString(frame == null ? null : frame.id);
        out.writeString(frame == null ? null : frame.uri);
        int fieldCount = frame == null ? 0 : frame.fields.size();
        out.writeInt(fieldCount);
        if (frame != null) {
            for (String key : frame.fields.keySet()) {
                out.writeString(key);
                out.writeString(frame.fields.get(key));
            }
        }
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

    public static DirectMessage readMessage(Parcel in) {
        String id = in.readString();
        String uri = in.readString();
        MsgFrame frame = new MsgFrame(uri);
        frame.id = id;
        int fieldCount = in.readInt();
        for (int i = 0; i < fieldCount; i++) {
            frame.fields.put(in.readString(), in.readString());
        }
        IBinder callback = in.readStrongBinder();
        int fdCount = in.readInt();
        ArrayList<ParcelFileDescriptor> fds = new ArrayList<>(fdCount);
        for (int i = 0; i < fdCount; i++) {
            fds.add(in.readFileDescriptor());
        }
        return new DirectMessage(frame, callback, fds);
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
                MsgFrame open = new MsgFrame(null);
                open.fields.put(":open", "1");
                transact(service, TRANSACT_OPEN, open, DirectBinder.this, null);
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
        public final MsgFrame frame;
        public final IBinder callback;
        public final ArrayList<ParcelFileDescriptor> fds;

        DirectMessage(MsgFrame frame, IBinder callback, ArrayList<ParcelFileDescriptor> fds) {
            this.frame = frame;
            this.callback = callback;
            this.fds = fds;
        }
    }
}
