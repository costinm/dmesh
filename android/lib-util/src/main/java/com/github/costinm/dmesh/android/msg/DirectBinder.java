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

/**
 * DirectBinder is a raw, direct binder interface - not using AIDL or generated interface,
 * but closer to a protocol transport.
 * Supports both 1-way (asynchronous, FLAG_ONEWAY) and 2-way (synchronous) transactions.
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
            DirectMessage msg = readMessage(data, flags);
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

    /**
     * Send a one-way (asynchronous) transaction with optional callback binder and file descriptors.
     */
    public static boolean transact(IBinder binder, int code, MsgFrame frame, IBinder callback,
                                   List<ParcelFileDescriptor> fds) {
        return transactAsync(binder, code, frame, callback, fds);
    }

    /**
     * Send a one-way (asynchronous) transaction.
     */
    public static boolean transactAsync(IBinder binder, int code, MsgFrame frame, IBinder callback,
                                        List<ParcelFileDescriptor> fds) {
        Parcel in = Parcel.obtain();
        try {
            writeMessage(in, frame, callback, fds);
            return binder.transact(code, in, null, IBinder.FLAG_ONEWAY);
        } catch (RemoteException e) {
            Log.d(TAG, "Direct binder async transaction failed", e);
            return false;
        } finally {
            in.recycle();
        }
    }

    /**
     * Send a two-way (synchronous) transaction. If replyOut is provided and length >= 1,
     * the reply message frame will be stored in replyOut[0].
     */
    public static boolean transactSync(IBinder binder, int code, MsgFrame frame,
                                       List<ParcelFileDescriptor> fds, MsgFrame[] replyOut) {
        Parcel in = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            writeMessage(in, frame, null, fds);
            boolean ok = binder.transact(code, in, reply, 0);
            if (ok && replyOut != null && replyOut.length > 0 && reply.dataAvail() > 0) {
                DirectMessage replyMsg = readMessage(reply, 0);
                replyOut[0] = replyMsg.frame;
            }
            return ok;
        } catch (RemoteException e) {
            Log.d(TAG, "Direct binder sync transaction failed", e);
            return false;
        } finally {
            in.recycle();
            reply.recycle();
        }
    }

    public static void writeMessage(Parcel out, MsgFrame frame, IBinder callback,
                                    List<ParcelFileDescriptor> fds) {
        out.writeString(frame == null ? null : frame.id);
        out.writeString(frame == null ? null : frame.method);
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
        return readMessage(in, 0);
    }

    public static DirectMessage readMessage(Parcel in, int flags) {
        String id = in.readString();
        String method = in.readString();
        MsgFrame frame = new MsgFrame(method);
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
        return new DirectMessage(frame, callback, fds, flags);
    }

    public void dial(Context ctx, String addr) {
        String[] parts = addr.split("/");
        Intent i = new Intent();
        i.setComponent(new ComponentName(parts[0], parts[1]));
        i.setAction(ACTION_DIRECT);

        ServiceConnection sc = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                MsgFrame open = new MsgFrame(null);
                open.fields.put(":open", "1");
                transact(service, TRANSACT_OPEN, open, DirectBinder.this, null);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
            }
        };

        ctx.bindService(i, sc, Context.BIND_AUTO_CREATE);
    }

    public interface Receiver {
        boolean onDirectMessage(int code, DirectMessage msg, Parcel reply) throws RemoteException;
    }

    public static class DirectMessage {
        public final MsgFrame frame;
        public final IBinder callback;
        public final ArrayList<ParcelFileDescriptor> fds;
        public final int flags;

        DirectMessage(MsgFrame frame, IBinder callback, ArrayList<ParcelFileDescriptor> fds) {
            this(frame, callback, fds, 0);
        }

        DirectMessage(MsgFrame frame, IBinder callback, ArrayList<ParcelFileDescriptor> fds, int flags) {
            this.frame = frame;
            this.callback = callback;
            this.fds = fds;
            this.flags = flags;
        }

        public boolean isOneWay() {
            return (flags & IBinder.FLAG_ONEWAY) != 0;
        }

        public boolean hasCallback() {
            return callback != null;
        }
    }
}
