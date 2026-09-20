# Mesh web app

This app provides a WebView UI, using the mesh as proxy - and a few handlers
for testing and as basic services.

WIP: the app should not require internet permission, i.e. should not be allowed
direct access to/from internet. The mesh acts as egress/ingress policy controller
and determines what is allowed with finer granularity.
