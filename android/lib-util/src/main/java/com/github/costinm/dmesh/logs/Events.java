package com.github.costinm.dmesh.logs;

import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class Events {
    // By timestamp.
    LinkedList<Event> events = new LinkedList<>();

    public Handler eventsHandler;

    static Events s = new Events();

    public static Events get() {
        return s;
    }

    public static class Event {
        public long ts;

        // Events with same category can be grouped or filtered
        // A modern UI can use a Card and nested lists.
        public String cat;

        // Identifies a specific event in a group.
        public String type;

        // Text for the message.
        public String msg;

        // Optional list of menu items and command codes for context menu
        Map<String, String> context;

        public Event() {
            ts = System.currentTimeMillis();
        }

        public Event(String cat, String type, long l, String msg) {
            ts = l;
            this.type = type;
            this.msg = msg;
            this.cat = cat;
        }

        public Event context(String k, String v) {
            if (context == null) {
                context = new HashMap<>();
            }
            context.put(k, v);
            return this;
        }

        public Event msg(String msg) {
            this.msg = msg;
            return this;
        }
    }

    public void add(Event e) {
        synchronized (events) {
            events.addFirst(e);
            if (events.size() > 500) {
                events.removeLast();
            }
        }
        refreshUI(1, e);
    }

    public void refreshUI(int msg, Event e) {
        Handler h = eventsHandler;
        if (h != null) {
            Message m = h.obtainMessage(msg);
            m.obj = e;
            m.sendToTarget();
        }
    }

    public Event add(String cat, String type, String msg){
        Event e = new Event(cat, type, System.currentTimeMillis(), msg);
        add(e);

        Log.d(cat, type + " " + msg);

        return e;
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

}
