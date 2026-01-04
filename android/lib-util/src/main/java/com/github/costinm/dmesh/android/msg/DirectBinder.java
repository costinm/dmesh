package com.github.costinm.dmesh.android.msg;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;



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

    protected boolean onTransact(int code, Parcel data, Parcel reply,
                                 int flags) throws RemoteException {
        return super.onTransact(code, data, reply, flags);
    }


    public void dial(Context ctx, String addr) {
        String[] parts = addr.split("/");
        Intent i = new Intent();
        i.setComponent(new ComponentName(parts[0], parts[1]));

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
                Parcel in = Parcel.obtain(service);
                Parcel out = Parcel.obtain();
                try {
                    service.transact(1, in, out, 0);
                } catch (RemoteException e) {
                    throw new RuntimeException(e);
                }
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
}
