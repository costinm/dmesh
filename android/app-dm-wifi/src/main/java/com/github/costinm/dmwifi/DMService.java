package com.github.costinm.dmwifi;

import android.os.Message;
import android.os.Messenger;

import com.github.costinm.dmesh.android.util.BaseMsgService;
import com.github.costinm.dmesh.android.util.MsgMux;
import com.github.costinm.dmesh.lm3.Ble;
import com.github.costinm.dmesh.lm3.Bt2;
import com.github.costinm.dmesh.lm3.Wifi;

public class DMService extends BaseMsgService {

    static Wifi wifi;
    Ble ble;
    Bt2 bt;

    @Override
    public void onCreate() {
        super.onCreate();
        wifi = new Wifi(this.getApplicationContext(), mux.broadcastHandler, getMainLooper());

        ble = new Ble(this, mux.broadcastHandler);
        bt = new Bt2(this, mux.broadcastHandler);

        inHandlers.put("ble", ble);
        inHandlers.put("bt", bt);
        inHandlers.put("wifi", wifi);

        // send status on connect.
        inHandlers.put(":open", new MsgMux.MessageHandler() {
            @Override
            public void handleMessage(Message m, Messenger replyTo, String[] args) {
                wifi.sendWifiDiscoveryStatus("connect");
            }
        });
    }

    public void onDestroy() {
        wifi.onDestroy();
        bt.close();
        super.onDestroy();
    }
}
