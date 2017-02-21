package com.github.costinm.lm;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pManager;
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.util.Log;

import java.util.ArrayList;
import java.util.Map;

/*
TODO:
- save results ( expire in 24 hours )
- advertise model, version
- advertise internet / mobile

- N7: I/wpa_supplicant: p2p0: Reject P2P_FIND since interface is disabled
  (Discover services failed 0). AP still works !
  Manual recovery: start/stop hotspot mode, seems to get device back to good state.
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
 * -
 */
@TargetApi(Build.VERSION_CODES.JELLY_BEAN)
public class P2PDiscovery {
    // TODO: since discovery is so painful, collect all data we find
    // and save it.
    public static final String TAG = "LM-Wifi-Disc";
    static final long DISC_FAST = 8000;
    static final long DISC_TO = 60000;
    static final String MESH_SUFFIX = "._dm._udp.local.";

    public WifiDiscoveryListener discoveryListener = new WifiDiscoveryListener();

    // It seems the announce goes for longer than expected
    // Set by the receiver on 'p2p_discovery_started' events.
    // TODO: we shouldn't periodic to discover while another app is discovering.
    //public boolean p2pDiscovery;
    public long discoveryStarted; // 0 after it completes
    public WifiP2pManager mP2PManager;
    // Devices found while scanning that we should look for.
    // When all devices have been found we generate the update notification.

    ArrayList<P2PWifiNode> remaining = new ArrayList<>();

    int startCnt;
    long lastDiscovery; // time of last discovery periodic
    long discoveryEnd; // time p2pLastDiscoveryAttemptE discovery finished
    long discMaxTime;
    Context ctx;
    // Other things we may want to discover:
    // Firechat: firechat._firechat._tcp.local. ( in p2p, as non-GO !)
    WifiMesh dmesh;
    Handler handler;
    int what;
    private long timeToFirstDiscovery;
    private long timeToLastDiscovery;
    private WifiP2pManager.Channel mChannel;

    int found = 0;

    public P2PDiscovery(Context ctx) {
        this.ctx = ctx;
        dmesh = WifiMesh.get(ctx);
        mP2PManager = (WifiP2pManager) ctx.getSystemService(Context.WIFI_P2P_SERVICE);

    }

    public StringBuilder dump(Bundle b, StringBuilder sb) {
        b.putLong("disc.start_cnt", startCnt);

        if (discoveryStarted > 0) {
            b.putLong("disc.active_start_ctime", discoveryStarted);
        }
        if (lastDiscovery > 0) {
            b.putLong("disc.last_ctime", lastDiscovery);
            b.putLong("disc.last_ms", (discoveryEnd - lastDiscovery)); // ~8
            b.putLong("disc.max_ms", discMaxTime); // 20s
        }
        if (found > 0) {
            b.putLong("disc.found", found);
        }
        if (dmesh.lastDiscovery.size() > 0) {
            b.putString("disc.foundLast", dmesh.lastDiscovery.toString());
        }
        if (timeToFirstDiscovery > 0) {
            b.putLong("disc.ttf_ms", timeToFirstDiscovery); // 1.5;
            b.putLong("disc.ttl_ms", timeToLastDiscovery); // 4.4
        }
        return sb;
    }

    public synchronized boolean start(Handler handler, int what,
                                      boolean force) {
        long now = SystemClock.elapsedRealtime();

        if (dmesh.apRunning) {
            // No discovery while AP is running ( will need to switch bands,
            // buggy ).
            return false;
        }
        if (dmesh.con.inProgress() || discoveryStarted != 0) {
            return false;
        }
        if (now - lastDiscovery < DISC_TO) {
            // In progress or too fast
            return false;
        }

        if (dmesh.scanner.toFind.size() > 0 || force) {
            this.handler = handler;
            this.what = what;
            found = 0;
            discover();

            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    maybeStop();
                }
            }, DISC_FAST); // normal apSessionStop is 2 min.

            return true;
        }
        return false;
    }

    void maybeStop() {
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

        remaining.clear();
        remaining.addAll(dmesh.scanner.toFind);

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
                        dmesh.event("discovery", "Clear service request failed " + reason);
                        addServiceRequest();
                    }
                });
    }

    private WifiP2pManager.Channel getmChannel() {
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


    public void addServiceRequest() {
        mP2PManager.setDnsSdResponseListeners(getmChannel(),
                discoveryListener,
                discoveryListener);

        // all bonjour/mDNS services
        // can be specific to service type ( _foo._udp ) or
        // dnsSDDomain name and service type

        // newInstance(suffix) -> PTR
        // newInstance(name, suffix) -> TXT
        mP2PManager.addServiceRequest(getmChannel(),
                WifiP2pDnsSdServiceRequest.newInstance(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        afterAddRequests(3);
                    }

                    @Override
                    public void onFailure(int reason) {
                        dmesh.event("discovery", "Add service request failed " + reason);
                        afterAddRequests(3);
                    }
                });
    }

    // This can be repeated - usually lasts 2 minutes. Instead we just
    // repeat the same job.
    private void afterAddRequests(final int attempt) {
        dmesh.lastDiscovery.clear();
        mP2PManager.discoverServices(getmChannel(),
                new WifiP2pManager.ActionListener() {
                    @Override
                    public void onSuccess() {
                        long now = SystemClock.elapsedRealtime();
                        StringBuilder sb = new StringBuilder();
                        sb.append(" toFind: ");
                        for (P2PWifiNode dd : dmesh.scanner.toFind) {
                            sb.append(dd.ssid).append("/").append(dd.p2pDiscoveryCnt).append("/").append(dd.p2pDiscoveryAttemptCnt).append(" ");
                            dd.p2pLastDiscoveryAttemptE = now;
                            dd.p2pDiscoveryAttemptCnt++;
                        }

                        dmesh.event("discovery", "Discover services started " + sb.toString());
                    }

                    @Override
                    public void onFailure(int reason) {
                        if (reason == WifiP2pManager.BUSY) {
                            if (attempt == 0) {
                                dmesh.event("discovery", "Discover services failed " + reason);
                            } else {
                                handler.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        afterAddRequests(attempt - 1);
                                    }
                                }, 10000);
                            }
                        } else {
                            dmesh.event("discovery", "Discover services failed " + reason);
                            finish();
                        }
                    }
                });

    }

    private synchronized void finish() {
        if (discoveryStarted > 0) {

            // Stop discovery
            mP2PManager.clearServiceRequests(getmChannel(), null);
            mP2PManager.stopPeerDiscovery(getmChannel(), null);

            discoveryEnd = SystemClock.elapsedRealtime();
            long delta = discoveryEnd - lastDiscovery;
            if (delta > discMaxTime && delta < 60000) {
                discMaxTime = delta;
            }

            StringBuilder sb = new StringBuilder();
            for (P2PWifiNode dd : dmesh.lastDiscovery) {
                sb.append(dd.dnsSDDomain).append(" ");
            }
            /*sb.append(" toFind: ");
            for (P2PWifiNode dd : toFind) {
                sb.append(dd.ssid).append("/").append(dd.p2pDiscoveryCnt).append("/").append(dd.p2pDiscoveryAttemptCnt).append(" ");
            }*/
            dmesh.event("discovery", "Discover done after " + (discoveryEnd - discoveryStarted) + "ms, found: "
                    + sb.toString());

            discoveryStarted = 0;
            if (handler != null) {
                handler.sendMessageDelayed(Message.obtain(handler, what), 2000); // connect won't work while disc still running
            }
        }
    }

    void onFound(String instanceName, WifiP2pDevice srcDevice, Map<String, String> txt) {
        if (!srcDevice.isGroupOwner()) {
            // Visible: Samsung/CM, Kindle, NexusOne. TBD: do they use additional power ?
            // Can't be found on nexus7
            Log.d(TAG, "Found PTR non-GO device " +
                    instanceName + " " + // DM-DIRECT-tP-Android_40e9-43i5PYdf._dm._udp.local.
                    srcDevice.deviceAddress + " " +
                    srcDevice.deviceName);
        } else {
            Log.d(TAG, "Found PTR " +
                    instanceName + " " +// DM-DIRECT-tP-Android_40e9-43i5PYdf
                    srcDevice.deviceAddress + " " +
                    srcDevice.deviceName); // from settings !!!
        }

        Long now = SystemClock.elapsedRealtime();
        if (timeToFirstDiscovery == 0) {
            timeToFirstDiscovery = now - lastDiscovery;
        }
        timeToLastDiscovery = now - lastDiscovery;

        // TODO: look at deviceAddress, match it against
        // BSSID - if found and different, add to blacklist
        // and avoid the timeout.

        P2PWifiNode n;

        // DNS: max 63 chars per label, 253 total, a-zA-Z0-9 and "-"
        if (instanceName.endsWith(MESH_SUFFIX)) {
            // _dm._udp.
            String cmp[] = instanceName.substring(0, instanceName.length() - MESH_SUFFIX.length()).split("\\.");
            if (cmp.length < 2) {
                Log.d(TAG, "Invalid SD: " + instanceName);
                return;
            }
            String ssid = cmp[cmp.length - 2];
            String pass = cmp[cmp.length - 1];
            n = dmesh.bySSID(ssid, srcDevice.deviceAddress);
            n.mac = srcDevice.deviceAddress;
            n.pass = pass;
            n.dnsSDDomain = instanceName;
            n.device = srcDevice;
            n.p2pLastDiscoveredE = SystemClock.elapsedRealtime();

            found++;
            //dmesh.notifyNodeUpdate(n);

            // Rest are map of properties
                for (int i = 0; i < cmp.length - 3; i++) {
                    String sp[] = cmp[i].split("-", 2);
                    if (sp.length == 2) {
                        if ("i".equals(sp[0])) {
                            n.ip6 = sp[1];
                        } else {
                            n.p2pProp.putString(sp[0], sp[1]);
                        }
                        //Log.d(TAG, "Property " + sp[0] + " " + sp[1] + " " + cmp);
                    }
                }

            if (n.mac == null || !n.mac.equals(srcDevice.deviceAddress)) {
                Log.d(TAG, "Missmatched MAC between periodic and P2P DNSSD " +
                        ssid + " " + n.mac + " " + srcDevice.deviceAddress);
            }
            // srcDevice.deviceName: name configured in the DNSSD settings

            boolean rm = remaining.remove(n);

            if (!dmesh.scanner.connectable.contains(n)) {
                dmesh.scanner.connectable.add(n);
            }

            if (rm) {
                Log.d(TAG, "Found nodes we were looking for " + instanceName);
            } else {
                Log.d(TAG, "Found nodes we were not looking for " + instanceName);
            }
        } else {
            // Random node - not ours. Still remember it, we'll also eventually return it if anyone
            // wants to know.
            n = dmesh.bySSID(null, srcDevice.deviceAddress);
            n.device = srcDevice;
            n.dnsSDDomain = instanceName;
        }

        if (txt != null) {
            for (String s : txt.keySet()) {
                n.p2pProp.putString(s, txt.get(s));
            }
        }

        if (!dmesh.lastDiscovery.contains(n)) {
            dmesh.lastDiscovery.add(n);
        }
        n.p2pLastDiscoveredE = SystemClock.elapsedRealtime();
        n.p2pDiscoveryCnt++;

        // Note: MAC address is not very good, it is different in P2P from
        // periodic.

    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    class WifiDiscoveryListener implements WifiP2pManager.DnsSdTxtRecordListener, WifiP2pManager.DnsSdServiceResponseListener {
        /**
         * The requested DNS-SD service response is available -
         * that is a PTR record, as result of a search for _dm._udp or similar.
         *
         * @param instanceName     dnsSDDomain name.<br>
         *                         e.g) "MyPrinter". In our case, DM-SSID-PASS
         * @param registrationType _dm._udp.local or eg. _ipp._tcp.local.
         * @param srcDevice        source device.
         */
        @Override
        public void onDnsSdServiceAvailable(String instanceName,
                                            String registrationType,
                                            WifiP2pDevice srcDevice) {
            onFound(instanceName + "." + registrationType, srcDevice, null);
        }

        @Override
        public void onDnsSdTxtRecordAvailable(String fullDomainName, Map<String, String> txtRecordMap, WifiP2pDevice srcDevice) {
            onFound(fullDomainName, srcDevice, txtRecordMap);
            Log.d(TAG, "Found TXT " + fullDomainName + " " + txtRecordMap);
        }
    }
}
