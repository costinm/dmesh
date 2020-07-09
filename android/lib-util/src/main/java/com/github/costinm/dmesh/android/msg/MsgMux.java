package com.github.costinm.dmesh.android.msg;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.os.Parcelable;
import android.util.Log;

import com.github.costinm.dmesh.android.util.NetUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MsgMux controls message dispatching and connection.
 * <p>
 * Normally should be a singleton - but for testing or special cases you can use multiple instances.
 */
public class MsgMux {

    public static final String URI = ":uri";
    public static final int TXT = 1;
    private static final String TAG = "MsgMux";
    static MsgMux mux;
    private static int _id = 1;
    final Context ctx;
    final HandlerThread handlerThread;
    // Active activeIn (outbound connections to other apps)
    // Key is the package name / service name for the Messenger connection. Value is a ConnMessenger.
    Map<String, MsgConn> activeOut = new HashMap<>();
    // Active server connections (inbound connections from other apps)
    // Active activeIn - will receive broadcasts. Once a Messanger fails, the activeIn are removed.
    Map<String, MsgConn> activeIn = new HashMap<>();

    // Status contains the current status of all subscribed persistent topics, from all in or out
    // connections.
    // Equivalent with an eventually consistent database.
    // Handler for incoming messages.
    Map<String, MessageHandler> inMessageHandlers = new HashMap<>();
    /**
     * Messages posted to broadcastHandler will be sent to all connected activeIn.
     * Equivalent with broadcast(), but runs in the handler thread.
     */
    Handler broadcastHandler;


    // Testing only.
    public MsgMux(Context applicationContext) {
        this.ctx = applicationContext;
        handlerThread = new HandlerThread("msgMux");
        handlerThread.start();
        broadcastHandler = new Handler(handlerThread.getLooper()) {
            @Override
            public void handleMessage(Message m) {
                broadcast(m, null);
            }
        };
    }

    /**
     * Singleton, initialized with the app context.
     * <p>
     * It is also possible to create separate MsgMux instances.
     */
    public static MsgMux get(Context appCtx) {
        if (mux == null) {
            mux = new MsgMux(appCtx.getApplicationContext());
        }
        return mux;
    }

//    public static void addMap2Bundle(Bundle b, Map<String, ?> map) {
//        for (String k : map.keySet()) {
//            Object o = map.get(k);
//            if (o == null) {
//                continue;
//            }
//            String s = null;
//            if (o instanceof CharSequence) {
//                b.putString(k, o.toString());
//            } else if (o instanceof Bundle) {
//                s = NetUtil.toJSON((Bundle) o).toString();
//                b.putString(k, s);
//            } else if (o != null) {
//                s = o.toString();
//            }
//        }
//    }

    public static List<String> mapToStringList(Map<String, ?> map) {
        List<String> out = new ArrayList<>();
        for (String k : map.keySet()) {
            Object o = map.get(k);
            if (o == null) {
                continue;
            }
            String s = null;
            if (o instanceof CharSequence) {
                out.add(k);
                out.add(o.toString());
            } else if (o instanceof Bundle) {
                out.add(k);
                s = NetUtil.toJSON((Bundle) o).toString();
                out.add(s);
            } else if (o != null) {
                out.add(k);
                s = o.toString();
                out.add(s);
            }
        }
        return out;
    }

    public synchronized void unsubscribe(String prefix, MessageHandler handler) {
        MessageHandler old = inMessageHandlers.get(prefix);
        if (old == null) {
            return;
        } else if (old instanceof ListHandler) {
            ((ListHandler) old).remove(handler);
        } else {
            inMessageHandlers.remove(prefix);
        }
    }

    /**
     * Subscribe a MessageHandler to messages matchig topic.
     * <p>
     * Messages may be local or remote.
     */
    public synchronized void subscribe(String topic, MessageHandler handler) {
        MessageHandler old = inMessageHandlers.get(topic);
        if (old == null) {
            inMessageHandlers.put(topic, handler);
            return;
        } else if (old instanceof ListHandler) {
            ((ListHandler) old).add(handler);
        } else {
            ListHandler lh = new ListHandler();
            lh.add(old);
            lh.add(handler);
            inMessageHandlers.put(topic, lh);
        }
    }

    /**
     * Status updates, broadcasted to all listeners.
     * <p>
     * Used for structured data, byte[], etc. Parcelable will be included in Message,
     * and serialized as message body.
     * <p>
     * Currently internal use (Intent, Bundles) and for passing structured json
     * scan data (/net/status).
     */
    public void publish(String msg, Parcelable p, String... extra) {
        Message m = broadcastHandler.obtainMessage(MsgMux.TXT);
        m.getData().putString(":uri", msg);
        m.getData().putParcelable("data", p);
        for (int i = 0; i < extra.length; i += 2) {
            m.getData().putString(extra[i], extra[i + 1]);
        }
        m.sendToTarget();
    }

    /**
     * Send a Message - will be distributed to all subscribers.
     * <p>
     * Non-blocking, distribution uses a handler thread.
     */
    public void publish(String msg, String... extra) {
        Message m = broadcastHandler.obtainMessage(TXT);
        m.getData().putString(":uri", msg);

        for (int i = 0; i < extra.length; i += 2) {
            if (i + 1 < extra.length && extra[i + 1] != null) {
                m.getData().putString(extra[i], extra[i + 1]);
            }
        }
        m.sendToTarget();
    }

    /**
     * Handle incoming message, received from one of the connections (either as a server or as a
     * client).
     * <p>
     * The "uri" ( topic ) of the message will be used to find a local handler.
     * <p>
     * Message may also be forwarded to all other connections.
     *
     * @param src - identifier of the sender.
     *            - For LMP+ local senders, :SENDER_UID.
     *            - For <=KLP the package of the sender. Based on the pending intent.
     *            - For DMesh remote clients, the IP6 of the sender, based on the hash of public key.
     */
    boolean handleMessage(String src, MsgConn con, Message msg) {
        //Log.d(TAG, "Message from SVC " + src + " " + msg.getData() + " " + msg.what);
        broadcast(msg, con);
        return false;
    }

    /**
     * Main method for sending a message to all subscribers (UDS, Messenger connections).
     */
    private void broadcast(Message m, MsgConn receivedOn) {
        Bundle b = m.getData();
        int id = b.getInt(":id");
        if (id == 0) {
            b.putInt(":id", _id++);
        }

        final String cmd = b.getString(":uri");
        if (cmd == null) {
            return;
        }
        String[] args = cmd.split("/");
        if (args.length < 2) {
            return;
        }
        int hops = b.getInt(":hops");
        if (hops > 5) {
            Log.d(TAG, "Too many hops");
            return;
        }
        b.putInt(":hops", hops + 1);

        String from = b.getString(":from");
        if (from == null) {
            b.putString(":from", ctx.getPackageName() + "/" + ((receivedOn == null) ? "" : receivedOn.name));
        }
        String topic = args[1];

        if (!topic.equals("N")) {
            Log.d(TAG, "Broadcast " + b + " " + receivedOn);
        }

        String msgType = args.length >= 3 ? args[2] : "";
        MessageHandler handler = inMessageHandlers.get(topic);
        if (handler == null) {
            handler = inMessageHandlers.get("");
        }
        if (handler != null) {
            handler.handleMessage(topic, msgType, m, receivedOn, args);
        }

        for (MsgConn c : activeIn.values()) {
            if (receivedOn != null && (receivedOn == c ||
                    receivedOn.name != null && receivedOn.name.equals(c.name))) {
                continue;
            }

            // TODO: filter by subscribed topics in c
            Message m1 = new Message();
            m1.setData(b);
            m1.what = m.what;
            m = m1;
            c.send(m);
        }

        for (MsgConn c : activeOut.values()) {
            if (receivedOn != null && receivedOn == c) {
                continue;
            }

            // TODO: filter by subscribed topics in c
            Message m1 = new Message();
            m1.setData(b);
            m1.what = m.what;
            m = m1;
            c.send(m);
        }
    }

    /**
     * Get or return a client for a particular package.
     */
    public MsgConn dial(String uri) {
        String[] parts = uri.split("/");

        // For now the svc name is hardcoded as pkg + ".MsgService"
        String pkg = parts[0];
        String clsName;
        if (parts.length == 1) {
            clsName = pkg + ".DMService";
        } else {
            clsName = parts[1];
        }

        MsgConn c = activeOut.get(uri);
        if (c != null) {
            return c;
        }

        c = new ConnMessenger(this, pkg, clsName);

        activeOut.put(uri, c);
        return c;
    }

    public void addInConnection(String key, MsgConn con, Message openM) {
        activeIn.put(key, con);
        con.name = key;
        MessageHandler open = inMessageHandlers.get(":open");
        if (open != null) {
            open.handleMessage(":open", "", openM, null, null);
        }

    }

    class ListHandler implements MessageHandler {
        ArrayList<MessageHandler> handlers = new ArrayList<>();


        @Override
        public void handleMessage(String topic, String msgType, Message m, MsgConn replyTo, String[] args) {
            for (MessageHandler h : handlers) {
                h.handleMessage(topic, msgType, m, replyTo, args);
            }
        }

        public void remove(MessageHandler handler) {
            handlers.remove(handler);
        }

        public void add(MessageHandler handler) {
            for (MessageHandler h : handlers) {
                if (h == handler) {
                    return;
                }
            }

            handlers.add(handler);
        }
    }


}
