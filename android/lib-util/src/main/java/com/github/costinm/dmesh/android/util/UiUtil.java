package com.github.costinm.dmesh.android.util;

import android.os.Bundle;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListAdapter;
import android.widget.ListView;

import java.util.Calendar;

/**
 * Small utils used in various places in UI.
 *
 * Created by costin on 12/26/16.
 */
public class UiUtil {
    public static void flip(View c, final View v) {
        c.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (v.isShown()) {
                    v.setVisibility(View.GONE);
                } else {
                    v.setVisibility(View.VISIBLE);
                }
            }
        });
    }

    public static String logTimeOfDayE(long millis) {
        return logTimeOfDay(millis + System.currentTimeMillis() - SystemClock.elapsedRealtime());
    }

    public static String logTimeOfDay(long millis) {
        Calendar c = Calendar.getInstance();
        if (millis >= 0) {
            c.setTimeInMillis(millis);
            // TODO: if older than 1 day-
            //return String.format("%tm-%td %tH:%tM:%tS.%tL", c, c, c, c, c, c);
            return String.format("%tH:%tM:%tS.%tL", c, c, c, c);
        } else {
            return Long.toString(millis);
        }
    }

    public static String logTimeOfDayShort(long millis) {
        Calendar c = Calendar.getInstance();
        if (millis >= 0) {
            c.setTimeInMillis(millis);
            // TODO: if older than 1 day-
            //return String.format("%tm-%td %tH:%tM:%tS.%tL", c, c, c, c, c, c);
            return String.format("%tH:%tM", c, c);
        } else {
            return Long.toString(millis);
        }
    }

    public static String timeOfDayShortSec(long millis) {
        Calendar c = Calendar.getInstance();
        if (millis >= 0) {
            c.setTimeInMillis(millis);
            return String.format("%tH:%tM:%tS", c, c, c);
        } else {
            return "";
        }
    }

    @NonNull
    public static StringBuilder toString(Bundle b) {
        return toString(b, " ");
    }

    @NonNull
    public static StringBuilder toString(Bundle b, String delim) {
        StringBuilder sb = new StringBuilder();
        if (b == null) {
            return sb;
        }
        for (String k: b.keySet()) {
            Object o = b.get(k);
            if (o == null) {
                continue;
            }
            sb.append(k).append(":").append(o.toString()).append(delim);
        }
        return sb;
    }

    // Elapsed to system time
    public static long e2s(long millis) {
        return millis + System.currentTimeMillis() - SystemClock.elapsedRealtime();
    }

    public static String timeOfDayShort(long millis) {
        Calendar c = Calendar.getInstance();
        if (millis >= 0) {
            c.setTimeInMillis(millis);
            return String.format("%tH:%tM", c, c);
        } else {
            return "";
        }
    }

    /**** Method for Setting the Height of the ListView dynamically.
     **** Hack to fix the issue of not showing all the items of the ListView
     **** when placed inside a ScrollView  ****/
    public static void setListViewHeightBasedOnChildren(ListView listView) {
        ListAdapter listAdapter = listView.getAdapter();
        if (listAdapter == null)
            return;

        int desiredWidth = View.MeasureSpec.makeMeasureSpec(listView.getWidth(), View.MeasureSpec.UNSPECIFIED);
        int totalHeight = 0;
        View view = null;
        for (int i = 0; i < listAdapter.getCount(); i++) {
            view = listAdapter.getView(i, view, listView);
            if (i == 0)
                view.setLayoutParams(new ViewGroup.LayoutParams(desiredWidth, ViewGroup.LayoutParams.WRAP_CONTENT));

            view.measure(desiredWidth, View.MeasureSpec.UNSPECIFIED);
            totalHeight += view.getMeasuredHeight();
        }
        ViewGroup.LayoutParams params = listView.getLayoutParams();
        params.height = totalHeight +
                (listView.getDividerHeight() * (listAdapter.getCount() - 1));
        listView.setLayoutParams(params);
    }
}
