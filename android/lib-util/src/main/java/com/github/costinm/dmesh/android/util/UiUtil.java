package com.github.costinm.dmesh.android.util;

import android.os.SystemClock;
import android.view.View;

import java.util.Calendar;

/**
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
}
