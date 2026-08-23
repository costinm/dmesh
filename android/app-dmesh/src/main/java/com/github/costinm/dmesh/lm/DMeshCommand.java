package com.github.costinm.dmesh.lm;

import android.content.Context;

import com.github.costinm.dmesh.android.msg.MsgConn;
import com.github.costinm.dmesh.android.msg.MsgFrame;
import com.github.costinm.dmesh.android.msg.MsgMux;
import com.github.costinm.dmeshnative.MeshNode;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

final class DMeshCommand {
    private DMeshCommand() {
    }

    static Result run(Context context, MsgMux mux, MeshNode node, String line) {
        try {
            Parsed parsed = parse(line);
            if ("key".equals(parsed.command) || "root-key".equals(parsed.command)) {
                return runKey(context, parsed);
            }
            if ("ssh".equals(parsed.command)) {
                return runSsh(node, parsed);
            }
            if ("msg".equals(parsed.command)) {
                return runMessage(mux, parsed.toFrameFromArgs(0));
            }
            if ("subscribe".equals(parsed.command) || "sub".equals(parsed.command)) {
                return runSubscribe(mux, parsed);
            }
            if ("history".equals(parsed.command) || "snapshot".equals(parsed.command)) {
                return runSnapshot(mux, parsed);
            }
            if ("messages.snapshot".equals(parsed.command) || "messages.history".equals(parsed.command)) {
                return runRequest(mux, parsed.toFrame(parsed.command, 0), parsed);
            }
            if ("messages".equals(parsed.command)) {
                String action = parsed.arg(0, "status");
                return runRequest(mux, parsed.toFrame("messages." + action, 1), parsed);
            }
            if ("companion".equals(parsed.command)) {
                String action = parsed.arg(0, "status");
                return runRequest(mux, parsed.toFrame("companion." + action, 1), parsed);
            }
            if (parsed.command != null && parsed.command.contains(".")) {
                return runMessage(mux, parsed.toFrame(parsed.command, 0));
            }
            if (parsed.frame != null) {
                if (parsed.frame.method != null && parsed.frame.method.startsWith("ssh.")) {
                    return runSshFrame(node, parsed.frame);
                }
                return runMessage(mux, parsed.frame);
            }
            return Result.error("Unknown command: " + parsed.command);
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }

    private static Result runKey(Context context, Parsed parsed) throws Exception {
        String action = parsed.arg(0, "show");
        if ("add".equals(action)) {
            String key = parsed.value("key");
            if (key == null && parsed.args.size() > 1) {
                key = join(parsed.args, 1);
            }
            String target = parsed.value("type", parsed.value("target", DMeshKeys.AUTHORIZED_CAS));
            String path = DMeshKeys.installTrustedPublicKey(
                    context, key, target, parsed.bool("append", true));
            return Result.ok("installed").field("path", path).field("type", target);
        }
        if ("add-url".equals(action) || "url".equals(action)) {
            String url = parsed.value("url");
            if (url == null && parsed.args.size() > 1) {
                url = parsed.args.get(1);
            }
            String path = DMeshKeys.downloadAndInstallRootPublicKey(
                    context, url, parsed.bool("append", true));
            return Result.ok("installed").field("path", path).field("url", url);
        }
        if ("show".equals(action) || "list".equals(action)) {
            String target = parsed.value("type", parsed.value("target", DMeshKeys.AUTHORIZED_CAS));
            return Result.ok(target)
                    .field("path", DMeshKeys.trustedKeyFile(context, target).getAbsolutePath())
                    .field("keys", DMeshKeys.readTrustedPublicKeys(context, target));
        }
        return Result.error("Unknown key action: " + action);
    }

    private static Result runSsh(MeshNode node, Parsed parsed) {
        String action = parsed.arg(0, "");
        if (node == null) {
            return Result.error("Rust mesh node is not running");
        }
        if ("connect".equals(action)) {
            long connId = node.connect(
                    parsed.required("host"),
                    parsed.intValue("port", 22),
                    parsed.value("user", "dmesh"),
                    parsed.required("serverKey"));
            return Result.ok("connected").field("conn", Long.toString(connId));
        }
        if ("exec".equals(action)) {
            String command = parsed.value("command");
            if (command == null && parsed.args.size() > 1) {
                command = join(parsed.args, 1);
            }
            String out = node.exec(parsed.longValue("conn", "connId", 0), command);
            return Result.ok("exec").field("output", out == null ? "" : out);
        }
        if ("forward".equals(action) || "local-forward".equals(action)) {
            node.addLocalForward(
                    parsed.longValue("conn", "connId", 0),
                    parsed.intValue("localPort", "local", 0),
                    parsed.required("remoteHost"),
                    parsed.intValue("remotePort", "remote", 0));
            return Result.ok("forwarded");
        }
        if ("remote-forward".equals(action) || "remote".equals(action)) {
            int port = node.addRemoteForward(
                    parsed.longValue("conn", "connId", 0),
                    parsed.intValue("remotePort", "remote", 0),
                    parsed.value("localHost", "127.0.0.1"),
                    parsed.intValue("localPort", "local", 0));
            return Result.ok("remote-forwarded").field("remotePort", Integer.toString(port));
        }
        return Result.error("Unknown ssh action: " + action);
    }

    private static Result runSshFrame(MeshNode node, MsgFrame frame) {
        Parsed parsed = new Parsed();
        parsed.command = "ssh";
        if (frame.method != null) {
            parsed.args.add(frame.method.substring("ssh.".length()));
        }
        parsed.values.putAll(frame.fields);
        return runSsh(node, parsed);
    }

    private static Result runMessage(MsgMux mux, MsgFrame frame) {
        if (mux == null) {
            return Result.error("MsgMux is not available");
        }
        // A JSON-RPC-style request is allowed to wait for its correlated
        // platform result.  This matters for transport.start: an AP password
        // does not exist until Android invokes LocalOnlyHotspotCallback.
        if (frame.id != null && !frame.id.isEmpty()
                && ("wifi.transport.start".equals(frame.method)
                || "wifi.scan".equals(frame.method))) {
            CapturingConn conn = new CapturingConn(mux, "shell-request:" + System.nanoTime(), 1,
                    "wifi");
            mux.receiveFrame("shell", conn, frame);
            try {
                conn.await(10_000);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return Result.error("interrupted waiting for " + frame.method);
            }
            String response = conn.lines();
            if (!response.isEmpty()) {
                return Result.ok("completed")
                        .field("id", frame.id)
                        .field("method", frame.method)
                        .field("response", response.trim());
            }
            return Result.ok("accepted")
                    .field("id", frame.id)
                    .field("method", frame.method);
        }
        MsgConn conn = new MsgConn(mux);
        conn.name = "shell";
        mux.receiveFrame("shell", conn, frame);
        return Result.ok("sent").field("method", frame.method);
    }

    private static Result runSnapshot(MsgMux mux, Parsed parsed) throws InterruptedException {
        MsgFrame frame = new MsgFrame("messages.snapshot");
        frame.fields.putAll(parsed.values);
        if (!frame.fields.containsKey("keys")) {
            frame.fields.put("keys", parsed.value("filter", parsed.value("topic", "all")));
        }
        if (!frame.fields.containsKey("limit")) {
            frame.fields.put("limit", Integer.toString(parsed.intValue("limit", 512)));
        }
        return runRequest(mux, frame, parsed);
    }

    private static Result runRequest(MsgMux mux, MsgFrame frame, Parsed parsed) throws InterruptedException {
        if (mux == null) {
            return Result.error("MsgMux is not available");
        }
        int durationMs = parsed.intValue("durationMs", "duration", 1000);
        int limit = parsed.intValue("limit", 512);
        if (durationMs < 0) {
            durationMs = 0;
        }
        if (durationMs > 10_000) {
            durationMs = 10_000;
        }
        if (limit <= 0) {
            limit = 512;
        }
        if (limit > 512) {
            limit = 512;
        }
        String keys = frame.fields.getOrDefault("keys", frame.fields.getOrDefault("filter", "all"));
        CapturingConn conn = new CapturingConn(mux, "shell-request:" + System.nanoTime(), limit + 2, "all");
        mux.receiveFrame("shell", conn, frame);
        conn.await(durationMs);
        return Result.ok("requested")
                .field("method", frame.method)
                .field("durationMs", Integer.toString(durationMs))
                .field("keys", keys)
                .field("count", Integer.toString(conn.count()))
                .field("messages", conn.lines());
    }

    private static Result runSubscribe(MsgMux mux, Parsed parsed) throws InterruptedException {
        if (mux == null) {
            return Result.error("MsgMux is not available");
        }
        int durationMs = parsed.intValue("durationMs", "duration", 1000);
        int limit = parsed.intValue("limit", 64);
        if (durationMs < 0) {
            durationMs = 0;
        }
        if (durationMs > 10_000) {
            durationMs = 10_000;
        }
        if (limit <= 0) {
            limit = 64;
        }
        if (limit > 512) {
            limit = 512;
        }

        String name = "shell-sub:" + System.nanoTime();
        String keys = parsed.value("keys", parsed.value("filter", parsed.value("topic", "all")));
        CapturingConn conn = new CapturingConn(mux, name, limit, keys);
        MsgFrame open = new MsgFrame("session.open");
        open.fields.put("from", "adb-shell");
        open.fields.put("subscribe", keys);
        mux.addInConnection(name, conn, open.toMessage());
        try {
            conn.await(durationMs);
        } finally {
            mux.removeInConnection(name);
        }
        return Result.ok("subscribed")
                .field("durationMs", Integer.toString(durationMs))
                .field("keys", keys)
                .field("count", Integer.toString(conn.count()))
                .field("messages", conn.lines());
    }

    private static Parsed parse(String line) throws Exception {
        if (line == null || line.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing command");
        }
        String clean = line.trim();
        if (clean.charAt(0) == '{') {
            JSONObject root = new JSONObject(clean);
            Parsed parsed = new Parsed();
            String method = root.optString("method", null);
            if (method == null || method.isEmpty()) {
                throw new IllegalArgumentException("Missing method");
            }
            parsed.frame = new MsgFrame(method);
            parsed.frame.id = root.optString("id", null);
            JSONObject data = root.optJSONObject("data");
            if (data != null) {
                for (Iterator<String> it = data.keys(); it.hasNext(); ) {
                    String key = it.next();
                    parsed.frame.fields.put(key, String.valueOf(data.get(key)));
                }
            }
            for (Iterator<String> it = root.keys(); it.hasNext(); ) {
                String key = it.next();
                if ("id".equals(key) || "method".equals(key) || "data".equals(key)) {
                    continue;
                }
                parsed.frame.fields.put(":" + key, String.valueOf(root.get(key)));
            }
            return parsed;
        }
        ArrayList<String> tokens = tokenize(clean);
        Parsed parsed = new Parsed();
        parsed.command = tokens.remove(0);
        parsePairs(tokens, parsed);
        return parsed;
    }

    private static void parsePairs(ArrayList<String> tokens, Parsed parsed) {
        for (int i = 0; i < tokens.size(); i++) {
            String token = tokens.get(i);
            if (token.startsWith("--")) {
                String key = token.substring(2);
                String value = "true";
                int eq = key.indexOf('=');
                if (eq >= 0) {
                    value = key.substring(eq + 1);
                    key = key.substring(0, eq);
                } else if (i + 1 < tokens.size() && !tokens.get(i + 1).startsWith("--")) {
                    value = tokens.get(++i);
                }
                parsed.values.put(key, value);
                continue;
            }
            int eq = token.indexOf('=');
            if (eq > 0) {
                parsed.values.put(token.substring(0, eq), token.substring(eq + 1));
            } else {
                parsed.args.add(token);
            }
        }
    }

    private static ArrayList<String> tokenize(String line) {
        ArrayList<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        char quote = 0;
        boolean escape = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (escape) {
                cur.append(c);
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                } else {
                    cur.append(c);
                }
            } else if (c == '\'' || c == '"') {
                quote = c;
            } else if (Character.isWhitespace(c)) {
                if (cur.length() > 0) {
                    out.add(cur.toString());
                    cur.setLength(0);
                }
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) {
            out.add(cur.toString());
        }
        return out;
    }

    private static String join(ArrayList<String> args, int start) {
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < args.size(); i++) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(args.get(i));
        }
        return sb.toString();
    }

    static final class Result {
        final boolean ok;
        final LinkedHashMap<String, String> fields = new LinkedHashMap<>();

        private Result(boolean ok, String status) {
            this.ok = ok;
            fields.put("ok", Boolean.toString(ok));
            fields.put(ok ? "status" : "error", status);
        }

        static Result ok(String status) {
            return new Result(true, status);
        }

        static Result error(String error) {
            return new Result(false, error == null ? "failed" : error);
        }

        Result field(String key, String value) {
            fields.put(key, value == null ? "" : value);
            return this;
        }
    }

    private static final class CapturingConn extends MsgConn {
        private final ArrayList<String> lines = new ArrayList<>();
        private final CountDownLatch done = new CountDownLatch(1);
        private final int limit;
        private final String keys;

        CapturingConn(MsgMux mux, String name, int limit, String keys) {
            super(mux);
            this.name = name;
            this.limit = limit;
            this.keys = keys;
        }

        @Override
        public synchronized boolean sendFrame(MsgFrame frame) {
            if (!frame.matchesKeys(keys)) {
                return true;
            }
            if (lines.size() >= limit) {
                done.countDown();
                return true;
            }
            lines.add(frame.toJsonLine());
            if (lines.size() >= limit) {
                done.countDown();
            }
            return true;
        }

        void await(int durationMs) throws InterruptedException {
            done.await(durationMs, TimeUnit.MILLISECONDS);
        }

        synchronized int count() {
            return lines.size();
        }

        synchronized String lines() {
            StringBuilder out = new StringBuilder();
            for (String line : lines) {
                out.append(line).append('\n');
            }
            return out.toString();
        }
    }

    private static final class Parsed {
        String command;
        MsgFrame frame;
        final ArrayList<String> args = new ArrayList<>();
        final LinkedHashMap<String, String> values = new LinkedHashMap<>();

        String arg(int index, String def) {
            return index < args.size() ? args.get(index) : def;
        }

        String value(String key) {
            return values.get(key);
        }

        String value(String key, String def) {
            String value = values.get(key);
            return value == null ? def : value;
        }

        String required(String key) {
            String value = values.get(key);
            if (value == null || value.isEmpty()) {
                throw new IllegalArgumentException("Missing " + key);
            }
            return value;
        }

        boolean bool(String key, boolean def) {
            String value = values.get(key);
            return value == null ? def : Boolean.parseBoolean(value);
        }

        int intValue(String key, int def) {
            String value = values.get(key);
            return value == null || value.isEmpty() ? def : Integer.parseInt(value);
        }

        int intValue(String key, String alt, int def) {
            String value = values.containsKey(key) ? values.get(key) : values.get(alt);
            return value == null || value.isEmpty() ? def : Integer.parseInt(value);
        }

        long longValue(String key, String alt, long def) {
            String value = values.containsKey(key) ? values.get(key) : values.get(alt);
            return value == null || value.isEmpty() ? def : Long.parseLong(value);
        }

        MsgFrame toFrameFromArgs(int argOffset) {
            if (args.size() <= argOffset) {
                throw new IllegalArgumentException("Missing method");
            }
            return toFrame(args.get(argOffset), argOffset + 1);
        }

        MsgFrame toFrame(String name, int extraArgStart) {
            MsgFrame out = new MsgFrame(name);
            out.fields.putAll(values);
            for (int i = extraArgStart; i < args.size(); i++) {
                String arg = args.get(i);
                int eq = arg.indexOf('=');
                if (eq > 0) {
                    out.fields.put(arg.substring(0, eq), arg.substring(eq + 1));
                }
            }
            return out;
        }
    }
}
