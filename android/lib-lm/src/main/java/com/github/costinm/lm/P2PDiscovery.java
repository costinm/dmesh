package com.github.costinm.lm;

import android.annotation.TargetApi;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.WpsInfo;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pManager;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.util.Log;
import android.widget.Toast;

import com.github.costinm.dmesh.logs.Events;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.github.costinm.lm.LMesh.UPDATE;
import static com.github.costinm.lm.LMesh.serviceHandler;

/*
TODO:
- save results ( expire in 24 hours )
- advertise model, version
- advertise internet / mobile

- N7: I/wpa_supplicant: p2p0: Reject P2P_FIND since interface is disabled
  (Discover services failed 0). AP still works !
  Manual recovery: registerReceiver/unregisterReceiver hotspot mode, seems to get device back to good state.
  Also on N6, flipping hotspot fixes "Group not found"/no scan results !

 */

/**
 * Controls P2P discovery, to find the announced password.
 * <p>
 * It's pretty fragile on some devices - it seems better on M+, but still safer to use it
 * carefully.
 * <p>
 * - only if AP is off
 * - one discovery at a time
 * - make sure it's stopped after timeout ( battery )
 */
@TargetApi(Build.VERSION_CODES.JELLY_BEAN)
class P2PDiscovery extends BroadcastReceiver {
    static final String TAG = "LM-Disc";
    static final long DISC_FAST = 6000;
    static final long DISC_TO = 10000;

    WifiDiscoveryListener discoveryListener = new WifiDiscoveryListener();

    // It seems the announce goes for longer than expected
    // Set by the receiver on 'p2p_discovery_started' events.
    // TODO: we shouldn't periodic to discover while another app is discovering.
    //public boolean p2pDiscovery;
    long discoveryStarted; // 0 after it completes
    WifiP2pManager mP2PManager;
    // Devices found while scanning that we should look for.
    // When all devices have been found we generate the updateSsidAndPass notification.

    ArrayList<LNode> remaining = new ArrayList<>();

    int startCnt;
    long lastDiscovery; // time of last discovery periodic
    long discoveryEnd; // time p2pLastDiscoveryAttemptE discovery finished
    long discMaxTime;
    Context ctx;
    // Other things we may want to discover:
    // Firechat: firechat._firechat._tcp.local. ( in p2p, as non-GO !)
    LMesh lm;
    Handler handler;
    int what;
    int found = 0;
    private long timeToFirstDiscovery;
    private long timeToLastDiscovery;
    private WifiP2pManager.Channel mChannel;

    String connect;

    public P2PDiscovery(Context ctx, LMesh lMesh) {
        this.ctx = ctx;
        lm = lMesh;
        mP2PManager = (WifiP2pManager) ctx.getSystemService(Context.WIFI_P2P_SERVICE);
        registerReceiver();
    }

    void registerReceiver() {
        IntentFilter mIntentFilter = new IntentFilter();
        // if some other app starts a peer discovery
        // Note that if other app starts SD discovery - we won't know.
        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION);
        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION);
        ctx.registerReceiver(this, mIntentFilter);
    }

    public void dump(Bundle b) {
        b.putLong("disc.start_cnt", startCnt);

        if (discoveryStarted > 0) {
            b.putLong("disc.active_start_ctime", discoveryStarted);
        }
        if (lastDiscovery > 0) {
            b.putLong("disc.last_ms", (discoveryEnd - lastDiscovery)); // ~8
            b.putLong("disc.max_ms", discMaxTime); // 20s
        }
        if (found > 0) {
            b.putLong("disc.found", found);
        }
        if (lm.lastDiscovery.size() > 0) {
            b.putString("disc.foundLast", lastDiscovery());
        }
        if (timeToFirstDiscovery > 0) {
            b.putLong("disc.ttf_ms", timeToFirstDiscovery); // 1.5;
            b.putLong("disc.ttl_ms", timeToLastDiscovery); // 4.4
        }
    }

    String lastDiscovery() {
        StringBuilder sb = new StringBuilder();
        for (LNode l : lm.lastDiscovery) {
            sb.append(l.ssid).append("/").append(l.pass)
                    .append("/").append(l.p2pDiscoveryCnt)
                    .append("/").append(l.p2pDiscoveryAttemptCnt).append("/").append(l.p2pProp);
            sb.append(' ');
        }
        return sb.toString();
    }

    /**
     * Listen is similar with the BLE beacon - it advertises the existence of
     * a possible mesh device, without using a lot of battery.
     *
     * Listen is hidden - it would allow discovery without one of the devices acting as GO.
     * That would also require some approximate time sync.
     * Device would stay on one of 1/6/11,
     * "should stay in listen state for 500ms each 5s"
     * <p>
     * Testing battery use: set ap_on to 0 (no ap), rescan_no_connection to >1h, private net
     * to random (so it won't connect even if it finds something) and make sure there is no
     * wifi network configured. Compare battery usage over longer interval with setting on
     * and off.
     *
     * @param b
     */
    public void listen(final boolean b) {
        // New devices have better BLE support.
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.N_MR1) {
            // TODO: may be needed later. Right now BLE beacon seems better.
            try {
                WifiP2pManager.ActionListener al = new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        Log.d(TAG, "P2PListen " + b);
                    }

                    @Override
                    public void onFailure(int reason) {
                        Log.d(TAG, "listen err " + b + " " + reason);
                    }
                };
                Reflect.callMethod(mP2PManager, "listen", new Class[]{
                                WifiP2pManager.Channel.class,
                                Boolean.TYPE, WifiP2pManager.ActionListener.class
                        },
                        new Object[]{
                                getmChannel(), new Boolean(b), al
                        });
            } catch (Throwable e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Start discovery. Normally happens after a SCAN, which finds visible nodes.
     * <p>
     * It'll run for 8 seconds - if it finds at least one DMESH node, will return.
     * Otherwise, will keep scanning for 60 seconds.
     * <p>
     * After either 8 or 60 seconds will post a message.
     *
     * @param handler   message will be posted on this handler
     * @param nextState the what, allowing the caller to customize and use its main handler.
     * @param force     run a discovery even if scanner doesn't return show any DIRECT node.
     */
    public synchronized void start(Handler handler, int nextState, boolean force) {
        long now = SystemClock.elapsedRealtime();

        if (lm.con.inProgress()) {
            Log.d(TAG, "Skip discovery, connection in progress");
            handler.obtainMessage(nextState).sendToTarget();
            return;
        }

        if (discoveryStarted != 0 && (now - discoveryStarted < DISC_TO)) {
            Log.d(TAG, "Skip discovery, in progress");
            handler.obtainMessage(nextState).sendToTarget();
            return;
        }

        if (LMesh.toFind.size() == 0) {
            if (!force) {
                handler.obtainMessage(nextState).sendToTarget();
                return;
            }
            remaining = null; // keep discovering until timeout
        } else {
            remaining = new ArrayList<>();
            remaining.addAll(LMesh.toFind);
        }
        this.handler = handler;
        this.what = nextState;
        found = 0;

        LMesh.disStatus.discoveryStart = now;
        discover();

        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                maybeStop();
            }
        }, DISC_FAST); // normal apSessionStop is 2 min - i.e. system will kill it at that point.

    }

    public synchronized void connect(Handler handler, int nextState, String name) {
        connect = name;
        start(handler, nextState, true);
    }

    private void maybeStop() {
        // if non-DMesh groups are visible, we'll be stuck for a full minute.
        // Instead we should return if at least one node was discovered.
        if (found > 0) {
            finish();
        } else {
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    finish();
                }
            }, DISC_TO - DISC_FAST); // normal apSessionStop is 2 min.
        }
    }


    /**
     * Start discovery. Typically called after scanning Wifi, and finding a
     * new DIRECT node.
     */
    synchronized void discover() {
        // Is supposedd to remain active until group created - seems to apSessionStop
        // automatically at least in KK. We apSessionStop it explicitly after finding
        // what we need to find, to minimize waste and reduce latency.

        //toFind = discMAC;

        long now = SystemClock.elapsedRealtime();
        discoveryStarted = now;
        lastDiscovery = now;
        startCnt++;

        // Make sure there is no 'peer discovery' in process
        mP2PManager.stopPeerDiscovery(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        clearAndStart();
                    }

                    @Override
                    public void onFailure(int reason) {
                        clearAndStart();
                    }
                });
    }

    /*
08-01 08:43:19.967 4642-5038/system_process D/SupplicantP2pIfaceHal: entering stopFind()
08-01 08:43:19.968 4642-5038/system_process D/SupplicantP2pIfaceHal: stopFind() completed successfully.
08-01 08:43:19.968 4642-5038/system_process D/SupplicantP2pIfaceHal: leaving stopFind()
08-01 08:43:19.968 4642-5038/system_process D/SupplicantP2pIfaceHal: entering flush()
08-01 08:43:19.968 4642-5038/system_process D/SupplicantP2pIfaceHal: flush() completed successfully.
08-01 08:43:19.968 4642-5038/system_process D/SupplicantP2pIfaceHal: leaving flush()
08-01 08:43:19.974 4642-5038/system_process D/SupplicantP2pIfaceHal: entering requestServiceDiscovery(00:00:00:00:00:00, 020001ffffffb6)
08-01 08:43:19.981 4642-5038/system_process D/SupplicantP2pIfaceHal: requestServiceDiscovery(00:00:00:00:00:00, 020001ffffffb6) completed successfully.
08-01 08:43:19.981 4642-5038/system_process D/SupplicantP2pIfaceHal: leaving requestServiceDiscovery(00:00:00:00:00:00, 020001ffffffb6) with result = 518378898560
08-01 08:43:19.981 4642-5038/system_process D/SupplicantP2pIfaceHal: entering find(120)

     */

    private void clearAndStart() {
        // Clean state.
        mP2PManager.clearServiceRequests(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        addServiceRequest();
                    }

                    @Override
                    public void onFailure(int reason) {
                        lm.event(UPDATE, "DIS_ERR CLEAR " + reason);
                        addServiceRequest();
                    }
                });
        //addServiceRequest();
    }


    void addServiceRequest() {
        mP2PManager.setDnsSdResponseListeners(getmChannel(),
                discoveryListener,
                discoveryListener);
        mP2PManager.setServiceResponseListener(getmChannel(), discoveryListener);

        // newInstance(suffix) -> PTR
        // newInstance(name, suffix) -> TXT
        mP2PManager.addServiceRequest(getmChannel(),
                WifiP2pDnsSdServiceRequest.newInstance(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        afterAddRequests();
                    }

                    @Override
                    public void onFailure(int reason) {
                        lm.event(UPDATE, "DIS_ERR SREQ " + reason);
                        afterAddRequests();
                    }
                });
    }

    // This can be repeated - usually lasts 2 minutes. Instead we just
    // repeat the same job.
    private void afterAddRequests() {

        // No longer calling discoverPeers after add request.
        // peers are discovered as part of discoverServices
        afterDiscoverPeers(3);
    }

    private void afterDiscoverPeers(final int attempt) {

        lm.lastDiscovery.clear();
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        mP2PManager.discoverServices(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        long now = SystemClock.elapsedRealtime();
                        for (LNode dd : LMesh.toFind) {
                            dd.p2pLastDiscoveryAttemptE = now;
                            dd.p2pDiscoveryAttemptCnt++;
                        }
                    }

                    @Override
                    public void onFailure(int reason) {
                        if (reason == WifiP2pManager.BUSY) {
                            if (attempt == 0) {
                                lm.event(UPDATE, "DIS_ERR BUSY0 " + reason);
                            } else {
                                handler.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        afterDiscoverPeers(attempt - 1);
                                    }
                                }, 10000);
                            }
                        } else {
                            lm.event(UPDATE, "DIS_ERR DISC " + reason);
                            finish();
                        }
                    }
                });

    }

    /**
     * Called after 8 sec if at least one node was found, after DISC_TO
     * if no node is found, or after all 'toFind' nodes are found.
     * <p>
     * Also called on failure.
     * <p>
     * Guarded by discoveryStarted > 0.
     */
    private synchronized void finish() {
        if (discoveryStarted <= 0) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        LMesh.disStatus.discoveryEnd = now;

        if (connect != null) {
            // TODO: if connect is "", pick discovered with strongest signal
            connectP2P(connect);
            serviceHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    stopDiscovery();
                }
            }, 3000);
        } else {
            stopDiscovery();
        }
    }

    private void cancelConnectP2P(String arg) {
        mP2PManager.cancelConnect(getmChannel(), null);
    }

    void connectP2P(String arg) {
        WifiP2pConfig cfg = new WifiP2pConfig();
        cfg.deviceAddress = arg;
        cfg.wps.setup = WpsInfo.PBC; // DISPLAY;
        mP2PManager.connect(getmChannel(), cfg, new WifiP2pManager.ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG, "P2P ok");
            }

            @Override
            public void onFailure(int i) {
                Log.d(TAG, "P2P failed " + i);
                Toast.makeText(ctx, "Connect failed. Retry." + i,
                        Toast.LENGTH_SHORT).show();
            }
        });
    }


    private synchronized void stopDiscovery() {
        // Stop discovery
        mP2PManager.clearServiceRequests(getmChannel(), null);
        mP2PManager.stopPeerDiscovery(getmChannel(), null);

        long now = SystemClock.elapsedRealtime();
        discoveryEnd = now;
        long delta = discoveryEnd - lastDiscovery;
        if (delta > discMaxTime && delta < 60000) {
            discMaxTime = delta;
        }

        if (remaining != null) {
            lm.toFind = remaining;
        }
        discoveryStarted = 0;
        if (handler != null) {
            handler.sendMessageDelayed(Message.obtain(handler, what), 2000); // connect won't work while disc still running
        }
        if (what == LMesh.SCAN) {
            // Called from the menu/manual
            Events.get().add("Wifi", "Disc", "Found " +
                    lm.lastDiscovery);
        }
        lm.sendDiscoveryResults();

    }

    // Find the name of the device in the list of scanned devices.
    // Can't look by BSSID - scan and p2p don't match
    // Can't look by SSID - p2p name is suffix
    LNode findByName(List<LNode> r, String name) {
        if (r == null) {
            return null;
        }
        for (LNode l : r) {
            if (l.name != null && l.name.equals(name)) {
                return l;
            }
            if (l.ssid != null && l.ssid.toLowerCase().endsWith("-" + name.toLowerCase())) {
                return l;
            }
        }
        return null;
    }

    /**
     * Called on TXT based discovery.
     * <p>
     * The PTR is now ignored - all devices send both TXT and PTR, and PTR is upper-cased.
     * If we find devices not supporting TXT - we can bring back PTR.
     *
     * @param instanceName dm._dm._udp.local. for TXT discovery
     * @param srcDevice    info about device -
     *                     deviceAddress - last part of SSID (except DIRECT-xx)
     *                     <p>
     *                     MAC is most interesting, but doesn't match ethernet
     *                     Typical:
     *                     primary type: 10-0050F204-5
     *                     secondary type: null
     *                     wps: 392
     *                     grpcapab: 171
     *                     devcapab: 37
     *                     status: 3
     *                     wfdInfo: WFD
     *                     enabled: trueWFD
     *                     DeviceInfo: 0
     *                     WFD CtrlPort: 0
     *                     WFD MaxThroughput: 0
     * @param txt          key values, including s (SSID), p (pass), c (connection)
     */
    void onFound(String instanceName, WifiP2pDevice srcDevice, Map<String, String> txt) {

        Long now = SystemClock.elapsedRealtime();
        if (timeToFirstDiscovery == 0) {
            timeToFirstDiscovery = now - lastDiscovery;
        }
        timeToLastDiscovery = now - lastDiscovery;

        // DNS: max 63 chars per label, 253 total, a-zA-Z0-9 and "-"


        // Not a dmesh device.
        if (!instanceName.equals("dm._dm._udp.local.") || txt == null) {
            if (instanceName.equals("dm")) {
                return;
            }
            LNode n = findByName(remaining, srcDevice.deviceName);

            if (n == null) {
                Log.d(TAG, "Discover non-dmesh device that was not scanned " + srcDevice.deviceName + " " + instanceName);
                return;
            }
            // Had a DIRECT name, but not a dmesh device.
            Log.d(TAG, "Discover non-dmesh device that was scanned " + srcDevice.deviceName + " " + instanceName);
            if (remaining != null) {
                remaining.remove(n);
                if (remaining.size() == 0) {
                    finish();
                }
            }
            n.p2pLastDiscoveredE = SystemClock.elapsedRealtime();
            n.p2pDiscoveryCnt++;
            n.foreign = true;
            return;
        }

        LNode n = null;
        String mid = txt.get("i");
        if (mid != null) {
            n = lm.byMeshName(mid);
        }

        String ssid = txt.get("s");
        if (n == null) {
            n = lm.bySSID(ssid); // need to find by the advertisded SSID, to match scan result.
        } else {
            n.ssid = ssid;
        }

        for (String k : txt.keySet()) {
            String v = txt.get(k);
            if (k.equals("s")) {
            } else if (k.equals("p")) {
                n.pass = v;
            } else if (k.equals("c")) {
                n.net = v;
            } else if (k.equals("n")) {
                n.mesh = v;
            } else if (k.equals("i")) {
                n.meshName = v;
            } else if (k.equals("b")) {
                n.build = v;
            } else {
                n.p2pProp.put(k, txt.get(k));
            }
        }
        n.name = srcDevice.deviceName;
        n.mac = srcDevice.deviceAddress;
        n.extraDiscoveryInfo = n.p2pProp.size() > 0 ? n.p2pProp.toString() : "";
        n.device = srcDevice;
        n.p2pLastDiscoveredE = SystemClock.elapsedRealtime();
        n.p2pDiscoveryCnt++;

        found++;

        boolean rm = remaining == null ? false : remaining.remove(n);

        if (!srcDevice.isGroupOwner()) {
            // Auto Visible: Samsung/CM, Kindle, NexusOne.
            // DMesh sets 'listen(true) using introspection if not connected to Wifi and not AP
            Log.d(TAG, "Found PTR non-GO device " +
                    (rm ? "" : " listening") +
                    srcDevice.deviceAddress + " " +
                    srcDevice.deviceName + " " + txt);
            // Some devices ( palman ) don't seem to declare group owner, but
            // they are active AP.
        } else {
            Log.d(TAG, "Found " +
                    srcDevice.deviceAddress + " " +
                    srcDevice.deviceName + " " + txt);
        }
        lm.scanner.maybeAddConnectable(n);

        if (!lm.lastDiscovery.contains(n)) {
            lm.lastDiscovery.add(n);
        }

        if (remaining != null) {
            if (remaining.size() == 0) {
                finish();
            }
        }


        // Note: MAC address is not useful, different from normal MAC in many cases.

    }

    WifiP2pManager.Channel getmChannel() {
        if (mChannel == null) {
            mChannel = mP2PManager.initialize(ctx, ctx.getMainLooper(), new WifiP2pManager.ChannelListener() {
                @Override
                public void onChannelDisconnected() {
                    lm.event(UPDATE, "DIS_ERR CHANNEL");
                    mChannel = null;
                }
            });
        }
        return mChannel;
    }


    int ptr;
    int txt;

    long discStarted;
    long discLatency;


    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        Bundle extras = intent.getExtras();

        if (WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION.equals(action)) {
            mP2PManager.requestPeers(getmChannel(),
                    new WifiP2pManager.PeerListListener() {
                        @Override
                        public void onPeersAvailable(WifiP2pDeviceList peers) {
                            for (WifiP2pDevice d : peers.getDeviceList()) {
                                if (!d.isServiceDiscoveryCapable()) {
                                    continue; // can't be a dmesh device
                                }
                                LMesh.disStatus.onDiscoveryPeer(d.deviceName, d);

                                LNode ln = findByName(lm.devices, d.deviceName);
                                if (ln == null) {
                                    continue;
                                }
                                ln.name = d.deviceName;
                            }
                        }
                    });

        } else if (WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION.equals(action)) {
            if (extras.getInt(WifiP2pManager.EXTRA_DISCOVERY_STATE) == WifiP2pManager.WIFI_P2P_DISCOVERY_STOPPED) {
                discLatency = SystemClock.elapsedRealtime() - discStarted;
                mP2PManager.requestPeers(getmChannel(),
                        new WifiP2pManager.PeerListListener() {
                            @Override
                            public void onPeersAvailable(WifiP2pDeviceList peers) {
                                Log.d(TAG, "Disc stopped, peersByName " + peers);
                            }
                        });
            } else {
                discStarted = SystemClock.elapsedRealtime();
                Log.d(TAG, "Disc started");
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    class WifiDiscoveryListener implements WifiP2pManager.DnsSdTxtRecordListener, WifiP2pManager.DnsSdServiceResponseListener, WifiP2pManager.ServiceResponseListener {
        /**
         * The requested DNS-SD service response is available -
         * that is a PTR record, as result of a search for _dm._udp or similar.
         *
         * @param instanceName     extraDiscoveryInfo name.<br>
         *                         e.g) "MyPrinter". In our case, DM-SSID-PASS
         * @param registrationType _dm._udp.local or eg. _ipp._tcp.local.
         * @param srcDevice        source device.
         */
        @Override
        public void onDnsSdServiceAvailable(String instanceName,
                                            String registrationType,
                                            WifiP2pDevice srcDevice) {
            ptr++;
            onFound(instanceName, srcDevice, null);
        }

        @Override
        public void onDnsSdTxtRecordAvailable(String fullDomainName,
                                              Map<String, String> txtRecordMap,
                                              WifiP2pDevice srcDevice) {
            txt++;
            LMesh.disStatus.serviceDiscovery++;
            onFound(fullDomainName, srcDevice, txtRecordMap);

        }

        @Override
        public void onServiceAvailable(int protocolType, byte[] responseData, WifiP2pDevice srcDevice) {
            Log.d(TAG, "P2P " + protocolType + " " + srcDevice + " " + responseData);
            onFound("CUSTOM", srcDevice, null);
        }
    }
}
