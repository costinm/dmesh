package com.github.costinm.dmesh.transport;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Minimal terminal client for the ContentProvider shell that
 * {@link ReproControlProvider} exposes. Lines are parsed into a method and
 * key=value string extras and passed through {@code ContentResolver.call};
 * the result bundle is appended to a bounded scrolling output. The activity
 * interprets nothing except local {@code /} commands: {@code /use
 * <authority>} selects a different provider shell.
 */
public final class TermActivity extends Activity {
    private static final int MAX_OUTPUT_LINES = 500;
    private static final String DEFAULT_AUTHORITY =
            "com.github.costinm.dmesh.transport.control";

    private final StringBuilder buffer = new StringBuilder();
    private final Handler main = new Handler(Looper.getMainLooper());
    private int lines = 0;
    private String authority = DEFAULT_AUTHORITY;
    private ExecutorService shell;
    private TextView output;
    private ScrollView scroll;
    private EditText input;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestRuntimePermissions();
        startForegroundService(new Intent(this, ReproForegroundService.class));
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        shell = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "TermShell");
            thread.setDaemon(true);
            return thread;
        });

        int padding = (int) (8 * getResources().getDisplayMetrics().density);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setBackgroundColor(0xFF000000);
        layout.setPadding(padding, padding, padding, padding);

        output = new TextView(this);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextSize(11);
        output.setTextColor(0xFFEEEEEE);
        scroll = new ScrollView(this);
        scroll.addView(output);
        layout.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        input = new EditText(this);
        input.setTypeface(Typeface.MONOSPACE);
        input.setTextSize(12);
        input.setTextColor(0xFF77DD77);
        input.setHint("command");
        input.setHintTextColor(0xFF555555);
        input.setBackgroundColor(0xFF000000);
        input.setSingleLine(false);
        input.setMaxLines(4);
        input.setGravity(Gravity.BOTTOM | Gravity.START);
        input.setImeOptions(EditorInfo.IME_ACTION_GO);
        input.setOnEditorActionListener((view, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_GO || actionId == EditorInfo.IME_ACTION_DONE) {
                submit();
                return true;
            }
            return false;
        });
        layout.addView(input, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        setContentView(layout);

        append("provider=" + authority + "\n"
                + "<command> [key=value ...] is passed to the provider as-is\n"
                + "/use <authority> selects another provider shell\n\n");
        input.requestFocus();
    }

    @Override public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) {
            input.requestFocus();
            InputMethodManager imm = getSystemService(InputMethodManager.class);
            imm.showSoftInput(input, InputMethodManager.SHOW_IMPLICIT);
        }
    }

    @Override public void onDestroy() {
        shell.shutdownNow();
        super.onDestroy();
    }

    private void submit() {
        String line = input.getText().toString().trim();
        input.setText("");
        if (line.isEmpty()) return;
        append("> " + line + "\n");
        shell.execute(() -> {
            String response = run(line);
            main.post(() -> append(response));
        });
    }

    private String run(String line) {
        try {
            return line.startsWith("/") ? local(line) : callShell(line);
        } catch (Exception e) {
            return e.toString() + "\n\n";
        }
    }

    private String local(String line) {
        String[] parts = line.split("\\s+");
        if (!"/use".equals(parts[0])) return "unknown / command\n\n";
        if (parts.length == 2) authority = parts[1];
        return "provider=" + authority + "\n\n";
    }

    private String callShell(String line) {
        String[] parts = line.split("\\s+");
        Bundle extras = new Bundle();
        for (int i = 1; i < parts.length; i++) {
            int eq = parts[i].indexOf('=');
            if (eq > 0) extras.putString(parts[i].substring(0, eq), parts[i].substring(eq + 1));
        }
        Bundle result = getContentResolver().call(
                Uri.parse("content://" + authority), parts[0], null, extras);
        if (result == null) return "(no result)\n\n";
        StringBuilder out = new StringBuilder();
        for (String key : result.keySet()) {
            if ("log".equals(key)) out.append("log:\n").append(result.get(key)).append("\n");
            else out.append(key).append('=').append(result.get(key)).append("\n");
        }
        return out + "\n";
    }

    private void append(String text) {
        buffer.append(text);
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '\n') lines++;
        }
        while (lines > MAX_OUTPUT_LINES) {
            int newline = buffer.indexOf("\n");
            if (newline < 0) break;
            buffer.delete(0, newline + 1);
            lines--;
        }
        output.setText(buffer);
        scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
    }

    private void requestRuntimePermissions() {
        if (Build.VERSION.SDK_INT < 33) return;
        boolean nearby = checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES)
                == PackageManager.PERMISSION_GRANTED;
        if (!nearby) requestPermissions(new String[] {
                Manifest.permission.NEARBY_WIFI_DEVICES,
        }, 1);
    }
}
