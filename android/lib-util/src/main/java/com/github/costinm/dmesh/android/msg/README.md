# Helpers for Android messaging

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


