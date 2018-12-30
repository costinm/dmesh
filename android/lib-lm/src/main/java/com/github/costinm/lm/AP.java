package com.github.costinm.lm;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pGroup;
import android.net.wifi.p2p.WifiP2pManager;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceInfo;
import android.net.wifi.p2p.nsd.WifiP2pServiceInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.github.costinm.dmesh.logs.Events;

import java.util.HashMap;

import static com.github.costinm.lm.LMAPI.CMD_UPDATE_CYCLE;
import static com.github.costinm.lm.LMesh.AP_STATE_CHANGED;
import static com.github.costinm.lm.LMesh.UPDATE;

/*
TODO:

- call 'WifiP2pManager.setDeviceName("DM-random") for listen-mode P2P discovery
to work reliably. Fallback to Intent or doc for Settings.

- Nexus7a LMP (and others): blacklist autostart
08-09 19:45:48.528 E/wpa_supplicant( 1091): Failed to create interface p2p-p2p0-50: -12 (Out of memory)

- On Nougat-24, the AP is sometimes created in 5GHz band - won't work with older
 devices.

-  accept a 'group idString' and 'group pass' - use it for the legacy AP, and include it
  in the p2p advertisement, encrypting the node with the group pass.
  Use a different _dms._udp, DMS- for non-open networks.
*/

/**
 * Start/Stop AP mode for self-forming local mesh. Once the
 * AP is started, get the generated AP SSID and password and advertise
 * them via P2P DNS-SD.
 * <p>
 *     Since the SSID and password may change, they are not saved and not
 *     used for identification.
 * </p>
 * <p>
 * Note that when device enter doze mode, the AP keep working and is announced,
 * but DHCP fails. See Connect for the workaround.
 * <p>
 * AP max length is 32 bytes.
 * <p>
 * DNS-SD: full domain 255, 63 chars per label
 */
@TargetApi(Build.VERSION_CODES.JELLY_BEAN)
public class AP {

    static final String TAG = "LM-AP";

    // Used for P2P announce
    static final String SD_SUFFIX_PART = "_dm._udp";

    /**
     * Time when the AP stopped. 0 if it never started.
     */
    public static long lastStop;

    /**
     * Duration of previous AP session.
     */
    public static long lastDuration;

    /**
     * Time of last time the AP started.
     * 0 if not running.
     */
    public static long lastStart;

    /**
     * Number of times the AP was started.
     */
    public static int apStartTimes;

    /**
     * Total time the AP has been active, since registerReceiver of the app.
     */
    public static long apRunTime;

    public static int groupOrPassChanges;

    public static int groupStartErrors;
    public static int groupAnnounceErrors;
    public static int groupStopErrors;
    private final Handler serviceHandler;

    Context ctx;
    WifiManager mWifiManager;
    WifiP2pManager mP2PManager;
    WifiP2pManager.Channel mChannel;
    WifiP2pServiceInfo si;
    
    LMesh lm;

    public static long first;

    AP(LMesh wifiMesh, Context ctx, Handler serviceHandler) {
        lm = wifiMesh;
        first = SystemClock.elapsedRealtime();
        this.serviceHandler = serviceHandler;
        this.ctx = ctx.getApplicationContext();
        mWifiManager = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        mP2PManager = (WifiP2pManager) ctx.getApplicationContext().getSystemService(Context.WIFI_P2P_SERVICE);
    }

    /**
     * Must be called once, at process startup, to get to a stable state.
     * If the app dies, or some other app is using WifiDirect we may have the
     * AP running - we need it off so we can scan/discover. In many devices
     * that works only if AP is off.
     *
     * A START event will be posted when done.
     */
    void onStartup() {
        // TODO: relax on startup - persist the next start/stop time, allow for app to exit
        mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
            @RequiresApi(api = Build.VERSION_CODES.ICE_CREAM_SANDWICH)
            @Override
            public void onGroupInfoAvailable(final WifiP2pGroup group) {
                if (group != null && group.isGroupOwner()) {
                    // TODO: on some cases it seems to get BUSY (despite group owner == false)

                    // group created by another app or by us without closing.
                    // We must apSessionStop it - it needs wake lock and a timer to apSessionStop.
                    Log.d(TAG, "Stopping AP, it was running at startup !");
                    // This assumes a single enabled 'scan network manager app'
                    // Do not call: updateSsidAndPass(group);, it may change by the time we need it.
                    serviceHandler.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            stop(serviceHandler.obtainMessage(CMD_UPDATE_CYCLE));
                        }
                    }, 2000);
                } else {
                    // Old behavior: verify we have P2P and get the SSID/pass
                    // No longer used: the SSID/pass may change before we need them, and
                    // this slows down startup, and may confuse other nodes since discovery
                    // is not going to work.
                    if (LMesh.ssid == "") {

                    }
                    serviceHandler.obtainMessage(CMD_UPDATE_CYCLE).sendToTarget();
                }
            }
        });
    }

    /**
     * Start AP or Group.
     * <p/>
     * 1. when we have an urgent message or phone - any device scanning
     * will pick up the beacon and connect. Battery expensive, but
     * only when we initiate
     * <p/>
     * 2. for beacon - periodic, to find nearby devices
     * <p/>
     * 3. if >2 device in the area - round robin, to spread battery
     * expense. If few devices (2..4?) - gaps may exist, ok for
     * latency tolerant - if urgent message we switch to (1)
     *
     * When done, an AP_STATE_CHANGED event is posted, with an optional
     * 'err' string if the start failed.
     */
    public synchronized boolean start() {

        // The wake lock doesn't seem to be sufficient in N, app must be
        // foreground ?

        mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
            @Override
            public void onGroupInfoAvailable(WifiP2pGroup group) {
                // mPassphrase, mNetworkName - but no IP address
                // The callback has IP
                if (group != null && group.isGroupOwner()) {
                    lm.event(UPDATE, "AP 0 " + LMesh.ssid + " " + LMesh.pass);
                    groupStartErrors++;
                    onAPStarted(group);
                } else {
                    createGroup2();
                }

            }
        });

        return true;
    }

    private void createGroup2() {
        mP2PManager.createGroup(getmChannel(), new WifiP2pManager.ActionListener() {
            @Override
            public void onSuccess() {
                // It seems to return null if called immediately !!!
                serviceHandler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
                            @Override
                            public void onGroupInfoAvailable(WifiP2pGroup group) {
                                // mPassphrase, mNetworkName
                                if (group == null) {
                                    return;
                                }
                                WifiP2pDevice p2pDevice = group.getOwner();
                                onAPStarted(group);
                                lm.event(UPDATE, "AP 1 " + LMesh.ssid + " " + LMesh.pass + " " + p2pDevice.deviceAddress + " " + group.getInterface());
                            }
                        });

                    }
                }, 2000);
            }

            @Override
            public void onFailure(int reason) {
                String lastError;
                groupStartErrors++;
                switch (reason) {
                    case WifiP2pManager.BUSY:
                        // May be returned when group already active
                        lastError = "Group failed: BUSY";
                        break;
                    case WifiP2pManager.ERROR:
                        lastError = "Group failed ERROR";
                        break;
                    case WifiP2pManager.P2P_UNSUPPORTED:
                        lastError = "Group failed UNSUPPORTED";
                        break;
                    default:
                        lastError = "Group failed " + reason;
                }
                Events.get().add("AP", "ERR", "START " + lastError);
                lm.event(UPDATE, "AP_ERR START " + lastError);
                Message m = serviceHandler.obtainMessage(AP_STATE_CHANGED);
                m.getData().putString("err", lastError);
                Log.i(TAG, lastError);
            }
        });
    }

    public synchronized void stop(final Message in) {
        mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
            @Override
            public void onGroupInfoAvailable(WifiP2pGroup group) {
                if (group == null || !group.isGroupOwner()) {
                    onApStopped(in);
                    Log.d(TAG, "Group already stopped");
                } else {
                    stopGroup2(in);
                }
            }
        });
    }

    private void stopGroup2(final Message in) {
        unannounce();
        mP2PManager.removeGroup(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        onApStopped(in);
                        Log.d(TAG, "Group stopped");
                    }

                    @Override
                    public void onFailure(int reason) {
                        groupStopErrors++;
                        Events.get().add("AP", "ERR", "STOP " + reason);
                        lm.event(UPDATE, "AP_ERR STOP " + reason);
                        // TODO: flip wifi state ? Direct user to airplane ?
                        // mark the device as bad and apSessionStop attempting to use AP ?
                        onApStopped(in);
                    }
                });
    }

    /**
     * Called when group is create successfully.
     * @param group
     */
    private void onAPStarted(WifiP2pGroup group) {
        updateSsidAndPass(group);
        lm.apRunning = true;

        serviceHandler.obtainMessage(AP_STATE_CHANGED).sendToTarget();
        apStartTimes++;
        lastStart = SystemClock.elapsedRealtime();
        announce();
    }

    void onApStopped(final Message in) {
        if (!lm.apRunning) {
            if (in != null) {
                in.sendToTarget();
            }
            return;
        }
        lm.apRunning = false;
        long prevStop = lastStop;
        long prevDuration = lastStop;
        lastStop = SystemClock.elapsedRealtime();
        lastDuration = lastStop - lastStart;
        apRunTime += lastDuration;

        String msg = "AP_STOP ds=" + lastDuration / 1000 +
                " pds=" + prevDuration/1000 +
                " stopp=" + LMesh.timeOfDayShort(LMesh.e2s(prevStop)) +
                " start=" + LMesh.timeOfDayShort(LMesh.e2s(lastStart)) +
                " stop=" + LMesh.timeOfDayShort(LMesh.e2s(lastStop));
        Events.get().add("AP", "STOP", msg);
        lm.event(UPDATE, msg);

        if (in != null) {
            in.sendToTarget();
        }

        // No need to keep responding to probe requests.
        // TODO: verify if listen state helps (when no connection)
        // unannounce();

        lastStart = 0;
    }


    /**
     * On some devices it seems that announce is lost ( N7/LMP) after some time.
     * For main use case (round robin on battery) it shouldn't matter, for
     * battery permanent APs - we may need to repeat it.
     * <p>
     * Each label is 63 chars, max 255.
     * Password seems to be 8 bytes
     * We need to clear up other announces first.
     */
    public void announce() {
        mP2PManager.clearLocalServices(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        announce2();
                    }

                    @Override
                    public void onFailure(int reason) {
                        Events.get().add("AP", "ERR", "ANNOUNCE " + reason);
                        lm.event(UPDATE, "AP_ERR ANNOUNCE1 " + reason);
                        groupAnnounceErrors++;
                        announce2();
                    }
                });
    }

    void hex(StringBuilder sb, String s) {
        byte[] b0 = s.getBytes();
        for (int i=0; i < b0.length; i++) {
            sb.append(Integer.toHexString(b0[i] & 0xFF));
        }

    }

    /*
08-01 09:17:52.637 24419-24419/com.github.costinm.dmesh.dm D/LM-Wifi-AP: Group created info:  ssid=DIRECT-U5-Android_23be pass=UgvgGY0P if=p2p0 devName= devMAC=ae:37:43:df:1b:a5
08-01 09:17:52.695 892-1191/? D/SupplicantP2pIfaceHal: entering addBonjourService(035f646dc01c000c01, 02646dc027)
08-01 09:17:52.702 892-1191/? D/SupplicantP2pIfaceHal: addBonjourService(035f646dc01c000c01, 02646dc027) completed successfully.
08-01 09:17:52.702 892-1191/? D/SupplicantP2pIfaceHal: leaving addBonjourService(035f646dc01c000c01, 02646dc027)
08-01 09:17:52.703 892-1191/? D/SupplicantP2pIfaceHal: entering addBonjourService(02646d035f646dc01c001001, 0a703d556776674759305008633d636f7374696e18733d4449524543542d55352d416e64726f69645f32336265)
08-01 09:17:52.706 892-1191/? D/SupplicantP2pIfaceHal: addBonjourService(02646d035f646dc01c001001, 0a703d556776674759305008633d636f7374696e18733d4449524543542d55352d416e64726f69645f32336265) completed successfully.
08-01 09:17:52.706 892-1191/? D/SupplicantP2pIfaceHal: leaving addBonjourService(02646d035f646dc01c001001, 0a703d556776674759305008633d636f7374696e18733d4449524543542d55352d416e64726f69645f32336265)

     */

    private void announce2() {
        // Sometimes only the TXT is visible.
        // We really only care about the extraDiscoveryInfo part in either PTR or TXT
        // The problem with TXT is that Android is using lower case on the domain for the TXT
        // announce. For now disabling it, to see if it works reliably enough with PTR only.
        // If needed, will need to b32 or hex encode the password, and possibly send the hash
        // of the network name. Once PSK/private lm is supported, the pass will be encrypted
        // and will have to be b32 or punycoded.

        // Android sends both PTR and TXT (as required by spec)

        // TODO: TXT mode, with only txt, no hex encoding, for testing

        HashMap<String, String> map = null;
        StringBuilder a = new StringBuilder();
        String net = lm.getNet();

        map = new HashMap<>();
        //map.put("t", Build.PRODUCT);
        if ( net != null) {
            map.put("c", net);
        }
        if (LMesh.ssid != null) {
            map.put("s", LMesh.ssid);
        }
        if (lm.privateNet.length() > 0) {
            map.put("n", lm.privateNet);
            if (LMesh.pass != null) {
                map.put("p", crypt(LMesh.pass, lm.privateNetKey));
            }
        } else {
            if (LMesh.pass != null) {
                map.put("p", LMesh.pass);
            }
        }
        String mn = lm.getMeshName();
        if (mn.length() > 0) {
            map.put("i", mn);
        }
        map.put("b", Build.BOARD + "-" + Build.VERSION.SDK_INT);
        a.append("dm");
    // The API requires PTR and TXT. Using only PTR part.
        si = WifiP2pDnsSdServiceInfo.newInstance(a.toString(), SD_SUFFIX_PART, map);

        mP2PManager.addLocalService(getmChannel(), si,
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                    }

                    @Override
                    public void onFailure(int reason) {
                        groupAnnounceErrors++;
                        Events.get().add("AP", "ERR", "ANNOUNCE2 " + reason + " " + si);
                        lm.event(UPDATE, "AP_ERR ANNOUNCE " + reason + " " + si);
                    }
                });
    }

    private String crypt(String pass, String key) {
        // TODO: encrypt password with private Net key
        return pass;
    }

    synchronized void unannounce() {
        mP2PManager.clearLocalServices(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        // ok
                    }

                    @Override
                    public void onFailure(int reason) {
                        groupAnnounceErrors += 256;
                        lm.event(UPDATE, "AP_ERR UNANNOUNCE " + reason);
                    }
                });
    }


    private WifiP2pManager.Channel getmChannel() {
        if (mChannel == null) {
            mChannel = mP2PManager.initialize(ctx, ctx.getMainLooper(), new WifiP2pManager.ChannelListener() {
                @Override
                public void onChannelDisconnected() {
                    Events.get().add("AP", "ERR", "ChannelDisconnected");
                    lm.event(UPDATE, "AP_ERR CHANNEL_DISCONNECTED");
                    mChannel = null;
                }
            });
        }
        return mChannel;
    }

    /**
     * Update ssid/pass in LMesh, after group creation.
     * Log info about changes.
     */
    void updateSsidAndPass(WifiP2pGroup group) {
            /* Example group info:
     network: DIRECT-mY-...
     isGO: true
     GO:
       Device: deviceAddress: a6:70:d6:00:0a:35
       primary type: null
       secondary type: null
       wps: 0
       grpcapab: 0
       devcapab: 0
       status: 4
       wfdInfo: WFD enabled: falseWFD DeviceInfo: 0
       WFD CtrlPort: 0
       WFD MaxThroughput: 0
     interface: p2p-wlan0-1
     networkId: 0
     */
        if (group != null) {
            if (LMesh.ssid != null) {
                if (!LMesh.ssid.equals(group.getNetworkName())) {
                    groupOrPassChanges++;
                    Events.get().add(TAG, "UPDATE", "SSID change: " +
                            LMesh.ssid + " -> " + group.getNetworkName());

                }
                if (!group.getPassphrase().equals(LMesh.pass)) {
                    groupOrPassChanges++;
                    Events.get().add(TAG, "UPDATE", "PASS change: " + LMesh.pass + " -> " + group.getPassphrase());
                }
            }

            lm.setSsid(group.getNetworkName(), group.getPassphrase());
        } else {
            groupStartErrors+=256;
            Log.d(TAG, "Start with null group !!");
        }
    }

    void dump(Bundle b) {
        b.putString("ap.ssid", LMesh.ssid + "/" + LMesh.pass);

        if (lm.apRunning) {
            b.putLong("ap.running", (SystemClock.elapsedRealtime() - lastStart)/1000);
        } else {
            if (lastStop > 0) {
                b.putLong("ap.stopped", (SystemClock.elapsedRealtime() - lastStop) / 1000);
            }
        }
        if (groupStartErrors > 0) {
            b.putLong("ap.errStart", groupStartErrors);
        }
        if (groupStopErrors > 0) {
            b.putLong("ap.errStop", groupStopErrors);
        }
        if (groupAnnounceErrors > 0) {
            b.putLong("ap.errAnnounce", groupAnnounceErrors);
        }
        if (apStartTimes > 0) {
            b.putLong("ap.startcnt", apStartTimes);
            b.putLong("ap.totaltime", apRunTime / 1000);
        }
    }

    // WifiP2pServiceImpl -> WifiNative -> P2P_GROUP_ADD persistent[=netId]

    // TODO: hidden:
    // setChannel (listen ch - 1..11, or 0; op ch 1..165, )
    // setDeviceName(devName) !!!
    // getMessenger - direct comm to WifiP2pService, also p2pstatemachine ?
    // listen(enable/disable)
    //
}

