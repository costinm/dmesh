package com.github.costinm.dmesh.lm;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.util.Log;

import static android.app.job.JobScheduler.RESULT_SUCCESS;

/**
 * Persistent periodic watchdog for the DMesh foreground service.
 *
 * Runs every 15 minutes (the minimum periodic interval). Each run
 * reconciles the service: if the foreground service is not running, it is
 * started again. The job is persisted, so it survives reboots as long as it
 * was scheduled at least once before the reboot.
 */
public class LMJob extends JobService {
    private static final String TAG = "DMJob";
    public static final long DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

    /**
     * (Re-)schedule the periodic reconciliation job. Safe to call any number
     * of times: the previous job with the same id is replaced.
     */
    public static void schedule(Context ctx, long interval) {
        JobScheduler js = (JobScheduler) ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null) {
            return;
        }
        if (interval <= 0) {
            interval = DEFAULT_INTERVAL_MS;
        }
        interval = Math.max(interval, JobInfo.getMinPeriodMillis());
        JobInfo job = new JobInfo.Builder(1, new ComponentName(
                ctx.getPackageName(), LMJob.class.getName()))
                .setPersisted(true)
                .setPeriodic(interval)
                .build();
        if (RESULT_SUCCESS == js.schedule(job)) {
            Log.d(TAG, "Scheduled periodic reconciliation after " + interval / 1000 + "s");
        } else {
            Log.w(TAG, "Failed to schedule periodic reconciliation");
        }
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        Log.d(TAG, "LMJob " + params.getJobId());
        // Reconcile: the persistent job must bring the foreground service
        // back after a crash, a force stop of the old process, or a boot
        // where the start broadcast was missed.
        if (!DMService.isRunning()) {
            DMService.startBackground(this);
        }
        // Defensive re-schedule: keeps the persisted job fresh even if it
        // was cancelled externally.
        schedule(this, DEFAULT_INTERVAL_MS);
        return false;
    }

    public void onLowMemory() {
        Log.d(TAG, "On Low memory");
    }

    public void onTrimMemory(int level) {
        Log.d(TAG, "On Trim memory " + level);
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        Log.d(TAG, "LMJob stopped ");
        return false;
    }
}
