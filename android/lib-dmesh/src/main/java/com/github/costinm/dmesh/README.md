# DMesh Android API helpers

`MeshStream`, `MeshClient`, and `DirectBinder` are the shared app API.
`CborMessageCodec.encode(MeshStream)` and `decode(byte[])` convert direct
message records; `encodeBundle(Bundle)` is available for typed platform
messages. Third-party apps can use these helpers without depending on
`app-dmesh` Java classes.

An app can consume handlers through `MeshClient.sendStream`. To provide one,
register its method name and `MeshStreamHandler` in `MeshStreamHandlers`, then
return `handlers.asDirectBinder()` from a service bound through app-dmesh.
Handlers receive a typed `MeshStream` and return a correlated reply. The same
registry accepts bounded CBOR `byte[]` records from Rust through
`handleRecord`, without adding a JNI method for each Android feature.

## Old patterns - new patterns

Service.onStartCommand() was simple - but can't handle the modern app management,
where battery/memory/etc is optimized and apps are less trusted, since there
is no ownership and termination.

Bound services are slightly better - the lifecycle and importance are
determined by caller - but it is also hard to use efficiently, i.e. only
as long as it is needed.

It is common for apps to have a single Activity - without navigating to
other same-app activities but swaping the layout. A per-app thread pool
and statics/singletons can handle shared work as long as at least one
activity is running without the overhead of services. The main use of 
service for a UI-based app is mainly to continue some work when the app
is not in foreground - but that's not allowed without at least a notification
unless Jobs are used.

For apps the provide real services to other apps - bound service is best
option, and the lifecycle will be based on anyone using the service app.
Same for providers - which are also services.

### Jobs

The job pattern has stricter limits - 10 min per operation, with provisions
for execution window and urgency. JobService - like Messenger - execute on
the main thread, so requires dispatching to a background thread. The JobParameters
must also be relatively small - using files for larger data.

Jobs may show notifications - for importance, with isUserInitiated() on the 
job parameters, and a call to setNotification() in 10 sec. 

Jobs run with a wake lock held by system.

The Java generic CBOR decoder accepts definite maps, arrays, byte and UTF-8
text strings, signed Java long integers, booleans, null, and 16/32/64-bit
floats. This constrained device codec rejects integers outside the signed long
range and does not support heavyweight general-purpose number types. Component
and method tags in `Envelope` are nonnegative
Java longs or text names; larger integer tags are rejected. The generic decoder
rejects undefined, tags, indefinite containers, and other simple values in
materialized values. `Envelope.decode` skips unknown top-level field values,
including tags, simple values, floats, and indefinite strings and containers;
unknown integer field keys outside the signed long range are also skipped;
skipped text is not UTF-8 validated. Known fields still use the strict generic
decoder. Duplicate envelope keys and trailing bytes are rejected. Input and output
are limited to 1 MiB, containers to 128 entries, values to 4096, and nesting
to 32 levels; these limits also apply while skipping unknown fields, with at
most 128 chunks per indefinite string. Bundle decoding additionally restricts arrays to text and map
keys to text.
