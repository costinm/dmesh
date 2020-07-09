package com.github.costinm.dmesh.android.msg;

import android.content.Context;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Message;
import android.util.Log;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class MsgServerUDS {
    private static final String TAG = "LMUDSS";
    protected static LocalServerSocket ls;
    private final MsgMux mux;
    public List<ConnUDS> active = new ArrayList<>();
    protected boolean running = true;
    Context ctx;
    String name;

    public MsgServerUDS(Context ctx, MsgMux mux, String dmuds) {
        this.ctx = ctx;
        this.mux = mux;
        name = dmuds;
    }

    protected void onConnect(ConnUDS s) {

    }

    protected void onDisconnect(ConnUDS con) {

    }

    protected void onServerStart() {

    }

    public void start() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Log.d(TAG, "Starting native process");

                while (ls == null) {
                    try {
                        ls = new LocalServerSocket(MsgServerUDS.this.name);
                        Log.d(TAG, "Local socket initialized");
                    } catch (IOException e) {
                        e.printStackTrace();
                        try {
                            Thread.sleep(10000);
                        } catch (InterruptedException e1) {
                            e1.printStackTrace();
                        }
                    }
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
                onServerStart();

                while (running) {
                    try {
                        final LocalSocket s1 = ls.accept();
                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                ConnUDS con = new ConnUDS(ctx, mux, name);
                                try {
                                    con.socket = s1;
                                    onConnect(con);
                                    active.add(con);
                                    // Initial implementation has only one native process.
                                    // TODO: addMap2Bundle the remote crednetials to the name
                                    Message m = Message.obtain();

                                    mux.addInConnection(name, con, m);

                                    // Process the stream
                                    con.handleLocalSocket(s1);

                                } catch (Throwable ex) {

                                }
                                onDisconnect(con);
                                Log.d(TAG, "UDS disconnect");
                                active.remove(con);
                                mux.activeIn.remove(name);
                            }
                        }).start();

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();

    }
}
