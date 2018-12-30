package com.github.costinm.dmesh.logs;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.util.Log;
import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.TextView;


import com.github.costinm.dmesh.android.util.R;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Simple debugging/testing activity.
 *
 * Shows a list of 'events' and a command line, plus menu.
 *
 * Gingerbread+, no dependencies on compat libraries.
 */
public class CommandListActivity extends Activity implements AdapterView.OnItemClickListener{

    public static final String TAG = "LM-DBG";

    public static List<Events.Event> events = new ArrayList<>();

    protected SharedPreferences prefs;
    protected Map<String,int[]> tags = new HashMap<>();
    protected ArrayAdapter<Events.Event> mLogAdapter;
    protected ArrayAdapter<Object> mAdapter;
    protected TextView mAPStatusView;

    protected String show = "";

    protected Handler h = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            onMessage(msg);

            super.handleMessage(msg);
        }
    };
    private ListView mLogListView;

    protected void onMessage(Message msg) {
        if (msg.obj instanceof  Events.Event) {
            Events.Event e = (Events.Event) msg.obj;
            if (show.length() == 0 || show.equals(e.cat)) {
                events.add(0, e);
                if (mLogAdapter != null) {
                    mLogAdapter.notifyDataSetChanged();
                    setListViewHeightBasedOnChildren(mLogListView);
                }
            }
        }
    }

    protected void updateLogList() {
        synchronized (events) {
            events.clear();
            for (Events.Event e : Events.get().events) {
                int[] cnt = tags.get(e.cat);
                if (cnt == null) {
                    cnt = new int[1];
                    tags.put(e.cat, cnt);
                }
                cnt[0]++;
                if (show.length() == 0 || show.equals(e.cat)) {
                    events.add(e);
                }
            }
        }
        if (mLogAdapter != null) {
            mLogAdapter.notifyDataSetChanged();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Events.get().eventsHandler = h;
    }

    @Override
    protected void onPause() {
        super.onPause();
        Events.get().eventsHandler = null;
    }

    protected void updateStatus() {
            mAPStatusView.setVisibility(View.GONE);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.lm_devices);

        prefs = PreferenceManager.getDefaultSharedPreferences(CommandListActivity.this);

        Events.get().eventsHandler = h;
        updateLogList();

        mAPStatusView = (TextView) findViewById(R.id.ap_status);

        mLogListView = (ListView) findViewById(R.id.log_list);
        mLogAdapter = new ArrayAdapter<Events.Event>(
                this,
                android.R.layout.two_line_list_item,
                android.R.id.text1,
                events) {
            @NonNull
            @Override
            public View getView(int position, View convertView,
                                @NonNull ViewGroup parent) {
                return getLogsNodeView(this, position, convertView, parent);
            }

        };
        mLogListView.setAdapter(mLogAdapter);
        mLogListView.setOnCreateContextMenuListener(this);
        mLogListView.setOnItemClickListener(this);

        ImageButton r = (ImageButton) findViewById(R.id.runButton);
        final EditText et = findViewById(R.id.editText);

        r.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Events.get().add("CMD", "run", et.getText().toString());
            }
        });
        updateStatus();
    }

    @NonNull
    protected View getLogsNodeView(ArrayAdapter<Events.Event> arrayAdapter, int position,
                                 View convertView, @NonNull ViewGroup parent) {
        View view;
        if (convertView == null) {
            view = getLayoutInflater().inflate(android.R.layout.two_line_list_item, parent, false);
        } else {
            view = convertView;
        }

        TextView text = (TextView) view.findViewById(android.R.id.text1);
        final Events.Event n = arrayAdapter.getItem(position);
        if (n != null) {
            StringBuilder sb = new StringBuilder();
            sb.append(Events.timeOfDayShortSec(n.ts)).append(" ")
                    .append(n.cat).append(" ")
                    .append(n.type).append(" ")
                    .append(n.msg);
            text.setText(sb.toString());
        }
        return view;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.lm_log_menu, menu);
        for (String s: tags.keySet()) {
            MenuItem mi = menu.add(s);
        }
        return true;
    }


    // Context menu for items
    @Override
    public void onCreateContextMenu(ContextMenu menu, final View v,
                                    ContextMenu.ContextMenuInfo menuInfo) {
        final ListView lv = (ListView) v;
        final AdapterView.AdapterContextMenuInfo acmi = (AdapterView.AdapterContextMenuInfo) menuInfo;

        final Context ctx = v.getContext();
        menu.add(3, v.getId(), 0, "Ping")
                .setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem menuItem) {
                //final DMNode mItem = allAdapter.getItem(acmi.position);
                return false;
            }
        });
    }

    @Override
    public void onItemClick(AdapterView<?> adapterView, View view, int position,
                            long id) {
        // Expand the view
        Log.d("V", "Selected " + position + " " + view);
        Events.Event e = (Events.Event) adapterView.getItemAtPosition(position);

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
