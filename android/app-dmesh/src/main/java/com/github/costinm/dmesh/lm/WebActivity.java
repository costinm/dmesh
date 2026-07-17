package com.github.costinm.dmesh.lm;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * Isolated WebView host for ssh-mesh admin UI.
 *
 * The Activity runs in the `:web` process and talks to app-dmesh only through
 * HTTP/message interfaces exposed by the foreground service.
 */
public class WebActivity extends Activity {
    private static final int MENU_BACK = 1;
    private static final int MENU_RELOAD = 2;
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
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
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, MENU_BACK, 0, "Back").setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
        menu.add(0, MENU_RELOAD, 1, "Reload").setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == MENU_BACK) {
            goBackOrFinish();
            return true;
        }
        if (item.getItemId() == MENU_RELOAD) {
            webView.reload();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onBackPressed() {
        goBackOrFinish();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        openFromIntent(intent);
    }

    private void openFromIntent(Intent intent) {
        String url = intent == null ? null : intent.getStringExtra(WebUrls.EXTRA_URL);
        if (url == null || url.isEmpty()) {
            url = WebUrls.DEFAULT_ADMIN_URL;
        }
        webView.loadUrl(url);
    }

    private boolean handleUri(Uri uri) {
        if (uri == null || uri.getScheme() == null) {
            return false;
        }
        if ("appweb".equals(uri.getScheme()) && "open-admin".equals(uri.getHost())) {
            webView.loadUrl(WebUrls.DEFAULT_ADMIN_URL);
            return true;
        }
        return false;
    }

    private void goBackOrFinish() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
            return;
        }
        finish();
    }
}
