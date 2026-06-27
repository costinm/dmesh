package com.github.costinm.dmesh.lm;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

final class DMeshKeys {
    static final String KEY_DIR = "ssh-mesh";
    static final String AUTHORIZED_CAS = "authorized_cas";

    private DMeshKeys() {
    }

    static File meshDir(Context context) throws IOException {
        File dir = new File(context.getFilesDir(), KEY_DIR);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Failed to create " + dir);
        }
        return dir;
    }

    static File authorizedCas(Context context) throws IOException {
        return new File(meshDir(context), AUTHORIZED_CAS);
    }

    static String installRootPublicKey(Context context, String publicKey, boolean append)
            throws IOException {
        String clean = normalizePublicKey(publicKey);
        File out = authorizedCas(context);
        try (FileOutputStream fos = new FileOutputStream(out, append)) {
            fos.write(clean.getBytes(StandardCharsets.UTF_8));
            fos.write('\n');
        }
        return out.getAbsolutePath();
    }

    static String downloadAndInstallRootPublicKey(Context context, String url, boolean append)
            throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(15000);
        conn.setInstanceFollowRedirects(true);
        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            throw new IOException("HTTP " + code + " from " + url);
        }
        try (InputStream in = conn.getInputStream()) {
            return installRootPublicKey(context, readUtf8(in, 128 * 1024), append);
        } finally {
            conn.disconnect();
        }
    }

    static String readAuthorizedCas(Context context) throws IOException {
        File in = authorizedCas(context);
        if (!in.exists()) {
            return "";
        }
        try (InputStream is = new FileInputStream(in)) {
            return readUtf8(is, 512 * 1024);
        }
    }

    private static String normalizePublicKey(String publicKey) throws IOException {
        if (publicKey == null) {
            throw new IOException("Missing public key");
        }
        String clean = publicKey.trim();
        if (clean.isEmpty()) {
            throw new IOException("Empty public key");
        }
        String first = clean.split("\\s+", 2)[0];
        if (!first.startsWith("ssh-")
                && !first.startsWith("ecdsa-")
                && !first.startsWith("sk-")) {
            throw new IOException("Not an OpenSSH public key: " + first);
        }
        return clean;
    }

    private static String readUtf8(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buf)) >= 0) {
            total += n;
            if (total > maxBytes) {
                throw new IOException("Key data too large");
            }
            bos.write(buf, 0, n);
        }
        return bos.toString(StandardCharsets.UTF_8.name());
    }
}
