package com.github.costinm.dmesh.android.util;

import android.annotation.TargetApi;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;


public class NetUtil {

    public static InetAddress toInetAddress(int addr) {
        try {
            return InetAddress.getByAddress(toIPByteArray(addr));
        } catch (UnknownHostException e) {
            //should never happen
            return null;
        }
    }

    static byte[] toIPByteArray(int addr) {
        return new byte[]{(byte) addr, (byte) (addr >>> 8), (byte) (addr >>> 16), (byte) (addr >>> 24)};
    }

    static Inet6Address getLinkLocalIP6(NetworkInterface ni) {
        if (ni == null) {
            return null;
        }
        Inet6Address res = null;
        Enumeration<InetAddress> addrs = ni.getInetAddresses();
        while (addrs.hasMoreElements()) {
            InetAddress addr = addrs.nextElement();
            if (addr instanceof Inet6Address) {
                Inet6Address i6 = (Inet6Address) addr;
                if (i6.getAddress()[0] == (byte) 0xfe) { // 0xfe80:...FFFE...
                    res = i6;
                } else {
                    if (res == null) {
                        res = i6;
                    } else {
                        Log.d("ERR", "IP6 additional: " + i6);
                    }
                }
            } else {
                // TODO: if not the expected one, event
                Log.d("IP4", "IP4: " + addr);
            }
        }

        return res;
    }

    public static void copyStream(InputStream input, OutputStream output)
            throws IOException {
        byte[] buffer = new byte[1024]; // Adjust if you want
        int bytesRead;
        while ((bytesRead = input.read(buffer)) != -1) {
            output.write(buffer, 0, bytesRead);
        }
    }

    /**
     * Get non-link local address.
     */
    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public static List<InetAddress> get6(LinkProperties lp) {
        List<InetAddress> ll = new ArrayList<>();
        for (LinkAddress l : lp.getLinkAddresses()) {
            if (l.getAddress() instanceof Inet6Address) {
                Inet6Address ip6 = (Inet6Address) l.getAddress();
                boolean isLL = ip6.isLinkLocalAddress();
                //ip6.getDatagramAddress()[0] == (byte) 0xfe;
                if (!isLL && !ip6.isSiteLocalAddress() && !ip6.isAnyLocalAddress()) {
                    ll.add(ip6);
                }
            }
        }
        return ll;
    }

    public static JSONObject toJSON(Bundle b) {
        JSONObject jso = new JSONObject();
        for (String k : b.keySet()) {
            try {
                Object o1 = b.get(k);

                if (o1 instanceof CharSequence) {
                    jso.put(k, ((CharSequence) o1).toString());
                } else if (o1 instanceof Bundle) {
                    jso.put(k, toJSON((Bundle) o1));
                } else if (o1 instanceof ArrayList) {
                    jso.put(k, toJSON((ArrayList) o1));
                }
            } catch (JSONException ex) {
                ex.printStackTrace();
            }
        }
        return jso;
    }

    public static JSONArray toJSON(ArrayList a) {
        JSONArray ar = new JSONArray();

        for (Object o : a) {
            if (o instanceof Bundle) {
                ar.put(toJSON((Bundle) o));
            } else if (o instanceof ArrayList) {
                ar.put(toJSON((ArrayList) o));
            }
        }
        return ar;
    }
}
