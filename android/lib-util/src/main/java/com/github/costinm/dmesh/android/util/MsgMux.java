package com.github.costinm.dmesh.android.util;

import android.app.PendingIntent;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcelable;
import android.util.Log;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * MsgMux controls message dispatching and connection.
 * 
 * Normally should be a singleton - but for testing or special cases you can use multiple instances.
 */
public class MsgMux {

    public static final String URI = ":uri";
    public static final int TXT = 1;
    static MsgMux msg;
    final Context ctx;
    private static final String TAG = "MsgMux";

    // Active clients (outbound connections to other apps)
    static Map<String, MsgClient> active = new HashMap<>();

    final HandlerThread handlerThread;

    // Active server connections (inbound connections from other apps)
    // Active clients - will receive broadcasts. Once a Messanger fails, the clients are removed.
    Map<String, MsgConnection> clients = new HashMap<>();

    // Status contains the current status of all subscribed persistent topics, from all in or out
    // connections.
    // Equivalent with an eventually consistent database.


    public MsgMux(Context applicationContext) {
        this.ctx = applicationContext;
        handlerThread = new HandlerThread("msgMux");
        handlerThread.start();
    }

    /**
     * Messages posted to broadcastHandler will be sent to all connected clients.
     * Equivalent with broadcast(), but runs in the handler thread.
     */
    public Handler broadcastHandler = new Handler() {
        @Override
        public void handleMessage(Message m) {
            broadcast(m);
        }
    };

    /**
     * Send a broadcast message to all connected services.
     * @param cat
     * @param type
     * @param msg
     * @param extra
     * @deprecated
     */
    public static void broadcast(String cat, String type, String msg, String... extra) {
        Message m = Message.obtain();
        Bundle b = m.getData();
        b.putString(":uri", cat + "/" + type);
        if (msg != null && msg.length() > 0) {
            b.putString("txt", msg);
        }
        for (int i = 0; i < extra.length; i+=2) {
            b.putString(extra[i], extra[i+1]);
        }
        get(null).broadcast(m);
    }

    /**
     * Status updates, broadcasted to all listeners.
     */
    public void broadcastParcelable(String msg, Parcelable p, String... extra) {
        Log.d(TAG, msg);
        Message m = broadcastHandler.obtainMessage(MsgMux.TXT);
        m.getData().putString(":uri", msg);
        m.getData().putParcelable("data", p);
        for (int i = 0; i < extra.length; i += 2) {
            m.getData().putString(extra[i], extra[i + 1]);
        }
        m.sendToTarget();
    }

    public void broadcastTxt(String msg, String... extra) {
        Log.d(TAG, msg + " " +  Arrays.asList(extra));
        Message m = broadcastHandler.obtainMessage(TXT);
        m.getData().putString(":uri", msg);
        for (int i = 0; i < extra.length; i+=2) {
            if (i+1 < extra.length && extra[i+1] != null) {
                m.getData().putString(extra[i], extra[i + 1]);
            }
        }
        m.sendToTarget();

    }

    public void broadcast(Message m) {
        for (MsgConnection c: clients.values()) {
            Message m1 = new Message();
            m1.setData(m.getData());
            m1.what = m.what;
            m = m1;
            c.send(m);
        }
    }


    public MsgClient dial(String uri, Handler.Callback callback) {
        String[] parts = uri.split("/");

        // For now the svc name is hardcoded as pkg + ".MsgService"

        MsgClient c = active.get(parts[0]);
        if (c != null) {
            return c;
        }

        c = new MsgClient(this, parts[0], parts[0] + ".DMService", callback);
        active.put(parts[0], c);


        return c;
    }

    public static MsgMux get(Context appCtx) {
        if (msg == null) {
            msg = new MsgMux(appCtx.getApplicationContext());
        }
        return msg;
    }

    public static String getGroup(Message msg) {
        String uri = msg.getData().getString(MsgMux.URI);
        if (uri == null) {
            return "";
        }
        String[] parts = uri.split("/");
        if (parts.length < 2) {
            return "";
        }
        String cat = parts[1];
        return cat;
    }

    /**
     * Add an internal client. Will receive all broadcasts and messages with selected topic.
     */
    public MsgConnection addClient(String id, Handler.Callback callback) {
        MsgConnection con = new MsgConnection(this);
        con.remotePackage = id;
        con.callback = callback;
        clients.put(id, con);
        return con;
    }

    /**
     * Interface for processing incoming messages.
     *
     * Used to be Handler.Callback - but it's harder to search for usages and gets confusing.
     */
    public interface MessageHandler {
        void handleMessage(Message m, Messenger replyTo, String[] args);
    }

    /**
     * Handle a message received from either a client or server.
     * @param msg
     * @return
     */
    boolean handleInMessage(BaseMsgService svc, Message msg) {
        // TODO: verify MsgConnection first call, replyTo
        // TODO: inject debug handler
        getClient(svc, msg);

        Bundle arg = msg.getData();

        final String cmd = arg.getString(":uri");
        if (cmd == null) {
            return false;
        }
        String[] args = cmd.split("/");
        if (args.length < 2) {
            return false;
        }

        MessageHandler open = svc.inHandlers.get(args[1]);
        if (open != null) {
            open.handleMessage(msg, msg.replyTo, args);
        }

        return false;
    }

    /**
     * Return the client associated with the message, based on sendingUid (and PendingIntent for
     * older than Lollipop devices). If this is the first time, the client is added.
     *
     * Clients are removed when send fails or close() is called.
     *
     *
     * @param svc
     * @param msg
     * @return
     */
    public MsgConnection getClient(BaseMsgService svc, Message msg) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {

            MsgConnection c = clients.get("" + msg.sendingUid);
            if (c == null || msg.getData().getBoolean(":open", false)) {
                c = new MsgConnection(this, msg.replyTo, (PendingIntent) msg.getData().getParcelable("p"));
                clients.put("" + msg.sendingUid, c);
                Log.d(TAG, "New Client " + msg.sendingUid);

                MessageHandler open = svc.inHandlers.get(":open");
                if (open != null) {
                    open.handleMessage(msg, msg.replyTo, null);
                }
            }
            return c;

        } else {
            PendingIntent p = (PendingIntent) msg.getData().getParcelable("p");
            if (p == null) {
                return null;
            }
            MsgConnection c = clients.get(p.getTargetPackage());
            if (c == null) {
                c = new MsgConnection(this, msg.replyTo, p);
                clients.put(p.getTargetPackage(), c);
            }
            return c;
        }
    }


}
