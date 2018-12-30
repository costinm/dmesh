package com.github.costinm.dmesh.android.util;

import android.os.Bundle;

public class Utils {
    public static void bundleToString(StringBuilder sb, Bundle b) {
        for (String k : b.keySet()) {
            Object o = b.get(k);
            if (o instanceof CharSequence) {
                sb.append(k).append(":").append((CharSequence) o).append("\n");
            } else if (o != null) {
                sb.append(k).append(":").append(o.toString()).append("\n");
            }
        }
    }
}
