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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;

/*
TODO:

- Nexus7a LMP:
08-09 19:45:48.528 E/wpa_supplicant( 1091): Failed to create interface p2p-p2p0-50: -12 (Out of memory)

- On Nougat-24, the AP is sometimes created in 5GHz band - won't work with older
 devices.

-  accept a 'group id' and 'group pass' - use it for the legacy AP, and include it
  in the p2p advertisment, encrypting the node with the group pass.
  Use a different _dms._udp, DMS- for non-open networks.
*/

/**
 * Start/Stop AP mode for self-forming mesh.
 * <p>
 * Issue: in doze mode, the AP is announced but DHCP fails
 * <p>
 * AP max length is 32 bytes.
 * <p>
 * DNS-SD: full domain 255, 63 chars per label
 */
@TargetApi(Build.VERSION_CODES.JELLY_BEAN)
public class AP {

    static final String TAG = "LM-Wifi-AP";

    // Used for P2P announce
    static final String SD_SUFFIX_PART = "_dm._udp";

    /**
     *  Time when the AP stopped. 0 if it never started.
     */
    public static long lastStop;

    /**
     *  Duration of previous AP session.
     */
    public static long lastDuration;

    /**
     *  Time of last time the AP started.
     *  0 if not running.
     */
    public static long lastStart;

    /**
     * Number of times the AP was started.
     */
    public static int apStartTimes;

    /**
     * Total time the AP has been active, since start of the app.
     */
    public static long apRunTime;

    Context ctx;
    WifiManager mWifiManager;
    WifiP2pManager mP2PManager;
    WifiP2pManager.Channel mChannel;
    WifiMesh dmesh;
    WifiP2pServiceInfo si;

    AP(WifiMesh wifiMesh, Context ctx) {
        dmesh = wifiMesh;
        this.ctx = ctx;
        mWifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
        mP2PManager = (WifiP2pManager) ctx.getSystemService(Context.WIFI_P2P_SERVICE);
    }

    static ArrayList<String> getInterfaceAddress(WifiP2pGroup info) {
        NetworkInterface iface;
        try {
            iface = NetworkInterface.getByName(info.getInterface());
        } catch (SocketException ex) {
            Log.w(TAG, "Could not obtain address of network interface "
                    + info.getInterface(), ex);
            return null;
        }

        ArrayList<String> res = new ArrayList<>();

        Enumeration<InetAddress> addrs = iface.getInetAddresses();
        while (addrs.hasMoreElements()) {
            InetAddress addr = addrs.nextElement();
            if (addr instanceof Inet6Address) {
                Inet6Address i6 = (Inet6Address) addr;
                if (i6.getAddress()[0] == (byte) 0xf8) {
                    res.add(0, i6.getHostAddress());
                } else {
                    res.add(i6.getHostAddress());
                }
            } else {
                // TODO: if not the expected one, event
                Log.d(TAG, "IP4: " + addr);
            }
        }

        if (res.size() == 0) {
            Log.w(TAG, "Could not obtain address of network interface "
                    + info.getInterface() + " because it had no IPv6 addresses.");
        } else {
            Log.d(TAG, "IP6: " + res);
        }
        return res;
    }


    /**
     * Must be called once, at process startup, to get to a stable state
     */
    void onStartup(final Handler h, final Message msg) {
        // TODO: on some cases it seems to get BUSY (despite group onwer == false)
        mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
            @RequiresApi(api = Build.VERSION_CODES.ICE_CREAM_SANDWICH)
            @Override
            public void onGroupInfoAvailable(final WifiP2pGroup group) {
                if (group != null && group.isGroupOwner()) {
                    // group created by another app or by us without closing.
                    // We must apSessionStop it - it needs wake lock and a timer to apSessionStop.

                    // This assumes a single enabled 'scan network manager app'
                    update(group);
                    stop(null);
                    h.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            stop(null);
                            finish(msg, null);
                        }
                    }, 2000);
                } else {
                    // TODO: briefly periodic, to verify we have P2P and
                    // get the SSID/pass/Ipv6 address
                    mP2PManager.createGroup(getmChannel(), new WifiP2pManager.ActionListener() {
                        @Override
                        public void onSuccess() {
                            mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
                                @Override
                                public void onGroupInfoAvailable(final WifiP2pGroup group) {
                                    update(group);
                                    stop(null);
                                    h.postDelayed(new Runnable() {
                                        @Override
                                        public void run() {
                                            finish(msg, null);
                                        }
                                    }, 5000);
                                }
                            });
                        }

                        @Override
                        public void onFailure(int reason) {
                            String lastError;
                            switch (reason) {
                                case WifiP2pManager.BUSY:
                                    // May be returned when group already active
                                    lastError = "Group failed: BUSY";
                                    mP2PManager.removeGroup(getmChannel(), null);
                                    break;
                                case WifiP2pManager.ERROR:
                                    lastError = "Group failed ERROR";
                                    mP2PManager.removeGroup(getmChannel(), null);
                                    break;
                                case WifiP2pManager.P2P_UNSUPPORTED:
                                    lastError = "Group failed UNSUPPORTED";
                                    break;
                                default:
                                    lastError = "Group failed " + reason;
                            }
                            finish(msg, lastError);
                            dmesh.event(TAG, "Failed to create AP " + lastError);
                        }
                    });
                }
            }
        });
    }

    /**
     *  Update ssid/pass/ip address after group creation.
     */
    void update(WifiP2pGroup group) {
            /* Example group info:
     network: DIRECT-mY-costin-n6-main
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
            WifiMesh.ssid = group.getNetworkName();
            WifiMesh.pass = group.getPassphrase();
            WifiMesh.ip6 = getInterfaceAddress(group);

            WifiP2pDevice p2pDevice = group.getOwner();
            Log.d(TAG, "Group created info: " +
                    " ssid=" + WifiMesh.ssid +
                    " ip6=" + WifiMesh.ip6 +
                    " pass=" + WifiMesh.pass +
                    " if=" + group.getInterface() +
                    " devName=" + p2pDevice.deviceName +
                    " devMAC=" + p2pDevice.deviceAddress
            );
            // client list used for debuggig - no need to complicate code here
        }
    }

    void finish(Message in, String lastError) {

        if (in == null) {
            return;
        }

        if (lastError != null) {
            in.getData().putString("err", lastError);
        }

        in.sendToTarget();
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
     */
    public synchronized boolean start(final Message msg) {

        // The wake lock doesn't seem to be sufficient in N, app must be
        // foreground ?

        mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
            @Override
            public void onGroupInfoAvailable(WifiP2pGroup group) {
                // mPassphrase, mNetworkName - but no IP address
                // The callback has IP
                if (group != null && group.isGroupOwner()) {
                    update(group);
                    finish(msg, null);
                    dmesh.event("wifiDirect", "AP already started " + WifiMesh.ssid + " " + WifiMesh.pass);
                    dmesh.apRunning = true;
                    apStartTimes++;
                    lastStart = SystemClock.elapsedRealtime();
                    announce();

                } else {
                    createGroup2(msg);
                }

            }
        });

        return true;
    }


    private void createGroup2(final Message cb) {
        mP2PManager.createGroup(getmChannel(), new WifiP2pManager.ActionListener() {
            @Override
            public void onSuccess() {
                mP2PManager.requestGroupInfo(getmChannel(), new WifiP2pManager.GroupInfoListener() {
                    @Override
                    public void onGroupInfoAvailable(WifiP2pGroup group) {
                        // mPassphrase, mNetworkName
                        update(group);
                        finish(cb, null);
                        dmesh.event("wifiDirect", "AP started " + WifiMesh.ssid + " " + WifiMesh.pass);
                        lastStart = SystemClock.elapsedRealtime();
                        apStartTimes++;
                        dmesh.apRunning = true;
                        announce();
                    }
                });
            }

            @Override
            public void onFailure(int reason) {
                String lastError;
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
                dmesh.event("wifiDirect", "Failed to discover AP " + lastError);
                finish(cb, lastError);
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
                    dmesh.apRunning = false;
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
                        dmesh.apRunning = false;
                    }

                    @Override
                    public void onFailure(int reason) {
                        dmesh.event("wifiDirect", "Failed to apSessionStop group " + reason);
                        // TODO: flip wifi state ? Direct user to airplane ?
                        // mark the device as bad and apSessionStop attempting to use AP ?
                        onApStopped(in);
                    }
                });
    }

    void onApStopped(final Message in) {
        if (!dmesh.apRunning) {
            return;
        }
        dmesh.apRunning = false;
        lastStop = SystemClock.elapsedRealtime();
        lastDuration = lastStop - lastStart;
        apRunTime += lastDuration;

        Log.d(TAG, "Stop " + lastDuration);

        // No need to keep responding to probe requests.
        unannounce();

        lastStart = 0;

        if (in != null) {
            in.sendToTarget();
        }
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
                        dmesh.event("wifiDirect", "Clear services failed, announce anyways " + reason);
                        announce2();
                    }
                });
    }

    private void announce2() {
        // Sometimes only the TXT is visible.
        // We really only care about the dnsSDDomain part in either PTR or TXT
        HashMap<String, String> map = new HashMap<>();
        map.put("t", Build.PRODUCT);

        String announce2 = "v-" + Build.VERSION.SDK_INT +
                "." + WifiMesh.ssid + "." + WifiMesh.pass;

        //Inet6Address ip6 = Sender.getIp6Wifi(true);
        if (WifiMesh.ip6 != null && WifiMesh.ip6.size() > 0) {
            // Don't care about the scoped interface for announcement, but good for binding
            String[] h = WifiMesh.ip6.get(0).split("%");
            announce2 = "i-" + h[0] + "." + announce2;
        }

        si = WifiP2pDnsSdServiceInfo.newInstance(announce2, SD_SUFFIX_PART, map);

        mP2PManager.addLocalService(getmChannel(), si,
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        Log.d(TAG, "Announcing " + si);
                    }

                    @Override
                    public void onFailure(int reason) {
                        dmesh.event("wifiDirect", "Announce failure " + reason + " " + si);
                    }
                });
    }

    public synchronized void unannounce() {
        mP2PManager.clearLocalServices(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        // ok
                    }

                    @Override
                    public void onFailure(int reason) {
                        dmesh.event("wifiDirect", "Clear services failed, bad wifi state" + reason);
                    }
                });
    }


    WifiP2pManager.Channel getmChannel() {
        if (mChannel == null) {
            mChannel = mP2PManager.initialize(ctx, ctx.getMainLooper(), new WifiP2pManager.ChannelListener() {
                @Override
                public void onChannelDisconnected() {
                    dmesh.event("p2p", "---- P2P DISCONNECTED ------ ");
                    mChannel = null;
                }
            });
        }
        return mChannel;
    }

    StringBuilder dump(Bundle b, StringBuilder sb) {
        b.putString("ap.ssid", WifiMesh.ssid);
        b.putString("ap.pass", WifiMesh.pass);

        if (dmesh.apRunning) {
            b.putLong("ap.running", SystemClock.elapsedRealtime() - lastStart);
        } else {
            if (lastStop > 0) {
                b.putLong("ap.stopped", SystemClock.elapsedRealtime() - lastStop);
            }
        }
        if (apStartTimes > 0) {
            b.putLong("ap.startcnt", apStartTimes);
            b.putLong("ap.totaltime", apRunTime);
        }
        return sb;
    }

    // WifiP2pServiceImpl -> WifiNative -> P2P_GROUP_ADD persistent[=netId]

    // TODO: hidden:
    // setChannel (listen ch - 1..11, or 0; op ch 1..165, )
    // setDeviceName(devName) !!!
    // getMessenger - direct comm to WifiP2pService, also p2pstatemachine ?
}

