package com.github.costinm.lm;


import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import com.github.costinm.dmesh.android.util.BaseClient;

public class LMAPI extends BaseClient {

    public static final int UPDATE = 1207;

    /**
     *  CMD_UPDATE_CYCLE command runs a full updateCycle cycle -
     */
    public static final int CMD_UPDATE_CYCLE = 'u';


    public static final int START = 1200;

    /**
     * Scan result or timeout, result of a scan() request.
     */
    public static final int SCAN = 1201;

    public static final int DISCOVERY = 1202;

    /**
     * Event generated after a connect() attempt is done. Wifi may
     * be connected, or all eligible nodes have been tried.
     */
    public static final int CONNECT = 1203;

    // Events

    public static final int AP_STATE_CHANGED = 1205;


    public static String PKG = "com.github.costinm.lm";
    public static String DBG = "com.github.costinm.lm.LMDebugActivity";
    public static String SVC = "com.github.costinm.lm.LMService";

    public static final int EV_AP_STOP = 1208;

    public static final String TAG = "LM-API";

    public LMAPI() {
        super(PKG, SVC);
    }

    public void init(Context ctx, Handler h, PendingIntent p) {
        fromLMHandler = h;
        fromLM = new Messenger(fromLMHandler);
        pi = p;
    }


}
