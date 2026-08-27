package com.github.costinm.dmesh.web;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

public class WebActivity extends Activity {
    private static final String TAG = "DMeshWeb";
    static final String EXTRA_URL = "url";
    static final String EXTRA_HOST = "host";
    static final String EXTRA_PORT = "port";
    static final String EXTRA_LOCAL_PORT = "localPort";
    static final String DEFAULT_ADMIN_URL = "http://127.0.0.1:18480/_m/adm";
    static final String HOME_URL = "file:///android_asset/index.html";
    private static final String APP_D_MESH_PACKAGE = "com.github.costinm.dmesh.lm";

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(false);
        settings.setDomStorageEnabled(false);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(false);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return handleUri(request.getUrl());
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                return handleUri(Uri.parse(url));
            }
        });

        openFromIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        openFromIntent(intent);
    }

    private void openFromIntent(Intent intent) {
        String url = intent == null ? null : intent.getStringExtra(EXTRA_URL);
        if (url == null || url.length() == 0) {
            url = HOME_URL;
        }
        webView.loadUrl(url);
    }

    private boolean handleUri(Uri uri) {
        if (uri == null || uri.getScheme() == null) {
            return false;
        }
        if ("appweb".equals(uri.getScheme())) {
            if ("open-admin".equals(uri.getHost())) {
                webView.loadUrl(DEFAULT_ADMIN_URL);
                return true;
            }
            if ("open-dmesh".equals(uri.getHost())) {
                openDmeshUi();
                return true;
            }
            if ("forward".equals(uri.getHost())) {
                requestForward(uri);
                return true;
            }
        }
        return false;
    }

    private void openDmeshUi() {
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(APP_D_MESH_PACKAGE,
                APP_D_MESH_PACKAGE + ".MeshActivityLight"));
        try {
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "app-dmesh UI is not available", Toast.LENGTH_SHORT).show();
            Log.w(TAG, "Unable to open app-dmesh UI", e);
        }
    }

    private void requestForward(Uri uri) {
        Intent intent = new Intent(WebBridgeService.FORWARD_PORT_ACTION);
        intent.setComponent(new ComponentName(this, WebBridgeService.class));
        intent.putExtra(EXTRA_HOST, valueOrDefault(uri.getQueryParameter(EXTRA_HOST), "127.0.0.1"));
        intent.putExtra(EXTRA_PORT, valueOrDefault(uri.getQueryParameter(EXTRA_PORT), "22"));
        intent.putExtra(EXTRA_LOCAL_PORT, valueOrDefault(uri.getQueryParameter(EXTRA_LOCAL_PORT), "10022"));
        startService(intent);
        Toast.makeText(this, "Forward request sent to app-dmesh", Toast.LENGTH_SHORT).show();
    }

    private static String valueOrDefault(String value, String fallback) {
        return value == null || value.length() == 0 ? fallback : value;
    }
}
