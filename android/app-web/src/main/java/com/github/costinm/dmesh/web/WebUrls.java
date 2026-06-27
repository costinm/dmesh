package com.github.costinm.dmesh.web;

final class WebUrls {
    static final String EXTRA_URL = "url";
    static final String EXTRA_HOST = "host";
    static final String EXTRA_PORT = "port";
    static final String EXTRA_LOCAL_PORT = "localPort";
    static final String OPEN_ACTION = "com.github.costinm.dmesh.web.OPEN";
    static final String OPEN_URL_ACTION = "com.github.costinm.dmesh.web.OPEN_URL";
    static final String FORWARD_PORT_ACTION = "com.github.costinm.dmesh.web.FORWARD_PORT";
    static final String DEFAULT_ADMIN_URL = "http://127.0.0.1:18480/_m/adm";
    static final String HOME_URL = "file:///android_asset/index.html";
    static final String APP_D_MESH_PACKAGE = "com.github.costinm.dmesh.lm";
    static final String APP_D_MESH_SERVICE = "com.github.costinm.dmesh.lm.DMService";

    private WebUrls() {
    }

    static String adminUrl() {
        return DEFAULT_ADMIN_URL;
    }
}
